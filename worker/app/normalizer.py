"""Lossless npm scanner normalization; schema is provisional until DB integration."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

SEVERITIES = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']


def _severity_status(value):
    if value is None or value == '':
        return 'missing'
    if isinstance(value, str) and value.upper() in (*SEVERITIES, 'MODERATE'):
        return 'supported'
    return 'unsupported'


def _id(kind, *parts):
    value = json.dumps(parts, sort_keys=True, ensure_ascii=False)
    return kind + '_' + hashlib.sha256(value.encode()).hexdigest()[:24]


def _severity(value):
    value = str(value or '').upper()
    value = 'MEDIUM' if value == 'MODERATE' else value
    return value if value in SEVERITIES else 'UNKNOWN'


def _object(value, label):
    if not isinstance(value, dict):
        raise ValueError(f'{label}: expected object')
    return value


def _list(value, label):
    if not isinstance(value, list):
        raise ValueError(f'{label}: expected array')
    return value


def _text(value, label):
    if not isinstance(value, str) or not value:
        raise ValueError(f'{label}: expected nonempty string')
    return value


def _strings(value, label):
    return [_text(v, label) for v in _list(value, label)]


def packages_from_lock(package, lock, scope):
    """One Package per installation path, including duplicate name/version installs."""
    _object(package, 'package.json')
    _object(lock, 'lockfile')
    lock_packages = _object(lock.get('packages', {}), 'packages')
    root_package = _object(lock_packages.get('', {}), 'root package')
    if package.get('workspaces') or root_package.get('workspaces'):
        raise ValueError('npm workspaces are outside the single-project contract')
    declarations = {}
    for kind in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
        for name in _object(package.get(kind, {}), kind):
            declarations.setdefault(name, []).append(kind)
    entries = []
    version = lock.get('lockfileVersion')
    if type(version) is not int or version not in (1, 2, 3):
        raise ValueError('Unsupported npm lockfileVersion')
    if version == 1:
        def visit(deps, parent=''):
            for name, value in _object(deps, 'dependencies').items():
                value = _object(value, 'dependency')
                path = f'{parent}/node_modules/{name}'.lstrip('/')
                entries.append((path, name, value))
                visit(value.get('dependencies', {}), path)
        visit(lock.get('dependencies'))
    else:
        for path, value in _object(lock.get('packages'), 'packages').items():
            if not path:
                continue
            value = _object(value, path)
            if value.get('link') or not path.startswith('node_modules/'):
                raise ValueError(f'Unsupported local/workspace package: {path}')
            entries.append((path, path.rsplit('node_modules/', 1)[1], value))
    result = []
    for path, installed_name, value in sorted(entries):
        name = _text(value.get('name', installed_name), 'package name')
        ver = _text(value.get('version'), f'{path} version')
        direct = path == f'node_modules/{installed_name}' and installed_name in declarations
        result.append({'package_id': _id('pkg', scope, path), 'scan_id': scope,
                       'ecosystem': 'npm', 'name': name, 'version': ver, 'lock_path': path,
                       'dependency_type': 'direct' if direct else 'indirect',
                       'declaration_kinds': declarations.get(installed_name, []) if direct else [],
                       'evidence': deepcopy(value)})
    return result


def _records(tool, data):
    """Flatten source records, retaining the exact advisory and package context."""
    _object(data, tool)
    rows = []

    def add(name, version, advisory_id, identifiers, raw_severity, severity_source,
            fixes, raw, pointer, context):
        rows.append({'tool': tool, 'name': _text(name, 'name'),
                     'version': _text(version, 'version'),
                     'advisory_id': _text(advisory_id, 'advisory id'),
                     'identifiers': sorted(set(identifiers)),
                     'severity': {'source_tool': tool, 'source': severity_source,
                                  'raw': raw_severity, 'normalized': _severity(raw_severity),
                                  'normalization_status': _severity_status(raw_severity)},
                     'fixes': fixes, 'pointer': pointer,
                     'evidence': {'source_tool': tool, 'json_pointer': pointer,
                                  'raw': deepcopy(raw), 'context': deepcopy(context)}})

    if tool == 'trivy':
        if type(data.get('SchemaVersion')) is not int:
            raise ValueError('Missing Trivy SchemaVersion')
        results = data.get('Results')
        for ri, result in enumerate(_list([] if results is None else results, 'Trivy Results')):
            _object(result, 'Trivy result')
            if result.get('Type') != 'npm':
                raise ValueError('Expected npm-only Trivy results')
            vulnerabilities = result.get('Vulnerabilities')
            for vi, v in enumerate(_list([] if vulnerabilities is None else vulnerabilities, 'Vulnerabilities')):
                _object(v, 'Trivy vulnerability')
                aid = _text(v.get('VulnerabilityID'), 'VulnerabilityID')
                ids = [aid] + _strings(v.get('VendorIDs', []), 'VendorIDs')
                fixed = v.get('FixedVersion', '')
                if not isinstance(fixed, str):
                    raise ValueError('Expected string FixedVersion')
                fixes = [{'source_tool': tool, 'advisory_id': aid, 'value': part.strip(),
                          'kind': 'tool_expression', 'raw': fixed}
                         for part in fixed.split(',') if part.strip()]
                add(v.get('PkgName'), v.get('InstalledVersion'), aid, ids,
                    v.get('Severity'), v.get('SeveritySource'), fixes, v,
                    f'/Results/{ri}/Vulnerabilities/{vi}',
                    {k: result[k] for k in ('Target', 'Type', 'Class') if k in result})
    else:
        for ri, result in enumerate(_list(data.get('results'), 'OSV results')):
            _object(result, 'OSV result')
            for pi, p in enumerate(_list(result.get('packages'), 'OSV packages')):
                _object(p, 'OSV package entry')
                package = _object(p.get('package'), 'OSV package')
                if package.get('ecosystem') != 'npm':
                    raise ValueError('Expected npm-only OSV results')
                for vi, v in enumerate(_list(p.get('vulnerabilities', []), 'vulnerabilities')):
                    _object(v, 'OSV vulnerability')
                    aid = _text(v.get('id'), 'OSV id')
                    ids = [aid] + _strings(v.get('aliases', []), 'aliases')
                    fixes = []
                    for ai, affected in enumerate(_list(v.get('affected', []), 'affected')):
                        ap = _object(affected.get('package'), 'affected package')
                        if ap.get('name') != package.get('name') or ap.get('ecosystem') != 'npm':
                            continue
                        for rgi, rg in enumerate(_list(affected.get('ranges', []), 'ranges')):
                            for ei, event in enumerate(_list(rg.get('events', []), 'events')):
                                if 'fixed' in event:
                                    fixes.append({'source_tool': tool, 'advisory_id': aid,
                                                  'value': _text(event['fixed'], 'fixed'),
                                                  'kind': 'range_fixed_event',
                                                  'affected_index': ai, 'range_index': rgi,
                                                  'event_index': ei, 'range': deepcopy(rg)})
                    specific = _object(v.get('database_specific', {}), 'database_specific')
                    add(package.get('name'), package.get('version'), aid, ids,
                        specific.get('severity'), 'database_specific.severity', fixes, v,
                        f'/results/{ri}/packages/{pi}/vulnerabilities/{vi}',
                        {'package': package, 'source': result.get('source'),
                         'groups': p.get('groups', [])})
    return rows


def _consolidate_explicit_ghsa(findings, rows, neighbors, scan_id):
    """Collapse repeated explicit identities, never general alias components.

    All members must name exactly the same single GHSA in the same npm package
    version. Distinct/multiple GHSAs, CVE-only links and manual NSWG records stay
    separate. Every raw record, observation and candidate is retained.
    """
    buckets = {}
    for position, finding in enumerate(findings):
        ghsas = [v for v in finding['identifiers'] if v.startswith('GHSA-')]
        safe = (len(ghsas) == 1 and
                'NSWG-ECO-516' not in finding['identifiers'])
        key = ('ghsa', finding['package_name'], finding['installed_version'], ghsas[0]) if safe else ('single', position)
        buckets.setdefault(key, []).append(finding)

    result, merged = [], []
    row_positions = {row['record_id']: i for i, row in enumerate(rows)}
    for key, members in buckets.items():
        if len(members) == 1:
            result.append(members[0])
            continue
        combined = deepcopy(members[0])
        evidence = [e for member in members for e in member['evidence']]
        record_ids = {e['record_id'] for e in evidence}
        # Keep source order and preserve the exact original evidence objects.
        evidence.sort(key=lambda e: row_positions[e['record_id']])
        positions = [row_positions[e['record_id']] for e in evidence]
        sources = [rows[i] for i in positions]
        reasons = {reason for member in members for reason in member['review_reasons']}
        if not any(rows[j]['record_id'] not in record_ids
                   for i in positions for j, _ in neighbors.get(i, [])):
            reasons.discard('ambiguous_advisory_mapping')
        observations = [s['severity'] for s in sources]
        values = {s['normalized'] for s in observations}
        combined.update(
            finding_id=_id('finding', scan_id, combined['package_name'],
                           combined['installed_version'], sorted(record_ids)),
            identifiers=sorted({v for member in members for v in member['identifiers']}),
            source_tools=sorted({s['tool'] for s in sources}),
            severity=max(values, key=SEVERITIES.index),
            severity_observations=deepcopy(observations),
            severity_conflict=len(values - {'UNKNOWN'}) > 1,
            priority_input_eligible=all(s['normalization_status'] != 'unsupported' for s in observations),
            fixed_version_candidates=[deepcopy(fix) for s in sources for fix in s['fixes']],
            fix_information='candidates_available' if any(s['fixes'] for s in sources) else 'not_reported',
            evidence=deepcopy(evidence),
            merge_basis={'kind': 'explicit_ghsa_identity', 'shared_identifiers': [key[3]],
                         'source_finding_ids': [member['finding_id'] for member in members]},
            review_status='needs_review' if reasons else 'reported',
            review_reasons=sorted(reasons),
        )
        merged.append({'finding_id': combined['finding_id'],
                       'package_name': combined['package_name'],
                       'installed_version': combined['installed_version'],
                       'shared_identifier': key[3],
                       'source_finding_ids': combined['merge_basis']['source_finding_ids']})
        result.append(combined)
    return result, merged


def normalize_results(package, lock, tool_results, tool_status, *, scan_id):
    """Normalize successful tool results only. tool_status uses scanner report entries.

    Preserve malformed tool payloads in raw_results and mark that tool failed; never
    treat unavailable results as a clean scan. scan_id may be the attempt ID until DB integration.
    """
    _text(scan_id, 'scan_id')
    packages = packages_from_lock(package, lock, scan_id)
    index = {}
    for p in packages:
        index.setdefault((p['name'], p['version']), []).append(p)
    rows, statuses = [], {}
    for tool in ('trivy', 'osv'):
        status = deepcopy(tool_status.get(tool, {'status': 'failed', 'error': {'kind': 'missing_tool'}}))
        if status.get('status') == 'completed':
            try:
                parsed = _records(tool, tool_results.get(tool))
            except (ValueError, TypeError, AttributeError) as exc:
                status.update(status='failed', error={'kind': 'normalization_error', 'message': str(exc)})
            else:
                rows.extend(parsed)
        statuses[tool] = status
    for row in rows:
        row['record_id'] = _id('raw', scan_id, row['tool'], row['pointer'])
        row['evidence']['record_id'] = row['record_id']
    # Prefer a tool's primary advisory ID explicitly named by the other tool.
    # Only fall back to shared GHSA/CVE aliases when neither side has such an edge.
    ts = [i for i, r in enumerate(rows) if r['tool'] == 'trivy']
    osvs = [i for i, r in enumerate(rows) if r['tool'] == 'osv']
    strong, direct, weak = [], [], []
    for a in ts:
        for b in osvs:
            x, y = rows[a], rows[b]
            if (x['name'], x['version']) != (y['name'], y['version']):
                continue
            if 'NSWG-ECO-516' in x['identifiers'] + y['identifiers']:
                continue
            # Distinct explicit GHSA identities stay separate even if they share a CVE.
            x_ghsa = {v for v in x['identifiers'] if v.startswith('GHSA-')}
            y_ghsa = {v for v in y['identifiers'] if v.startswith('GHSA-')}
            if x_ghsa and y_ghsa and not x_ghsa & y_ghsa:
                continue
            shared = sorted(set(x['identifiers']) & set(y['identifiers']))
            shared = [s for s in shared if s.startswith(('GHSA-', 'CVE-'))]
            if not shared:
                continue
            edge = (a, b, shared)
            if any(aid.startswith('GHSA-') and aid in shared
                   for aid in (x['advisory_id'], y['advisory_id'])):
                strong.append(edge)
            elif x['advisory_id'] in shared or y['advisory_id'] in shared:
                direct.append(edge)
            else:
                weak.append(edge)
    strong_nodes = {n for a, b, _ in strong for n in (a, b)}
    edges = strong + [e for e in direct if e[0] not in strong_nodes and e[1] not in strong_nodes]
    direct_nodes = {n for a, b, _ in edges for n in (a, b)}
    edges += [e for e in weak if e[0] not in direct_nodes and e[1] not in direct_nodes]
    neighbors = {}
    for a, b, shared in edges:
        neighbors.setdefault(a, []).append((b, shared))
        neighbors.setdefault(b, []).append((a, shared))
    pairs = {a: (b, shared) for a, ns in neighbors.items() for b, shared in ns
             if len(ns) == 1 and len(neighbors[b]) == 1}
    findings, consumed = [], set()
    for i, row in enumerate(rows):
        if i in consumed:
            continue
        members = [i]
        shared = []
        if i in pairs:
            j, shared = pairs[i]
            members.append(j)
        consumed.update(members)
        sources = [rows[n] for n in members]
        matches = index.get((row['name'], row['version']), [])
        reasons = []
        if any('NSWG-ECO-516' in s['identifiers'] for s in sources):
            reasons.append('NSWG-ECO-516_requires_manual_review')
        if any(n in neighbors and n not in pairs for n in members):
            reasons.append('ambiguous_advisory_mapping')
        if not matches:
            reasons.append('package_not_found_in_lock')
        observations = [s['severity'] for s in sources]
        eligible = all(s['normalization_status'] != 'unsupported' for s in observations)
        if not eligible:
            reasons.append('unsupported_severity_label')
        severity_values = {s['normalized'] for s in observations}
        # Conservative display policy, separate from priority; retain all original observations.
        severity = max(severity_values, key=SEVERITIES.index)
        identifiers = sorted({ident for s in sources for ident in s['identifiers']})
        findings.append({'finding_id': _id('finding', scan_id, row['name'], row['version'],
                                            sorted(s['record_id'] for s in sources)),
                         'scan_id': scan_id, 'package_name': row['name'],
                         'installed_version': row['version'],
                         'package_ids': [p['package_id'] for p in matches],
                         'lock_paths': [p['lock_path'] for p in matches],
                         'dependency_types': sorted({p['dependency_type'] for p in matches}),
                         'package_mapping': 'unmatched' if not matches else
                                            'multiple_installations' if len(matches) > 1 else 'exact',
                         'identifiers': identifiers, 'source_tools': sorted({s['tool'] for s in sources}),
                         'severity': severity, 'severity_observations': observations,
                         'severity_conflict': len(severity_values - {'UNKNOWN'}) > 1,
                         'priority_input_eligible': eligible,
                         'fixed_version_candidates': [fix for s in sources for fix in s['fixes']],
                         'fix_information': 'candidates_available' if any(s['fixes'] for s in sources) else 'not_reported',
                         'evidence': [s['evidence'] for s in sources],
                         'merge_basis': {'kind': 'direct_identifier_match' if len(sources) == 2 else 'unmerged',
                                         'shared_identifiers': shared},
                         'review_status': 'needs_review' if reasons else 'reported',
                         'review_reasons': reasons})
    # A one-to-one tool match can leave repeated reports of a single explicit
    # GHSA identity unmerged. Resolve only that narrower, auditable condition.
    matched_pairs = sum(len(f['evidence']) == 2 for f in findings)
    before_deduplication = len(findings)
    findings, deduplicated = _consolidate_explicit_ghsa(findings, rows, neighbors, scan_id)
    # Alias connectivity is deliberately NOT used to merge Findings.
    remaining = set(range(len(findings)))
    groups = []
    while remaining:
        seed = min(remaining)
        remaining.remove(seed)
        component, pending = [seed], [seed]
        while pending:
            a = pending.pop()
            fa = findings[a]
            for b in sorted(remaining):
                fb = findings[b]
                if ((fa['package_name'], fa['installed_version']) ==
                    (fb['package_name'], fb['installed_version']) and
                    set(fa['identifiers']) & set(fb['identifiers'])):
                    remaining.remove(b)
                    component.append(b)
                    pending.append(b)
        members = [findings[n] for n in sorted(component)]
        # An unlinked manual-only record is not a confirmed alias group.
        if all('NSWG-ECO-516_requires_manual_review' in f['review_reasons'] for f in members):
            continue
        gid = _id('alias', scan_id, sorted(f['finding_id'] for f in members))
        for f in members:
            f['alias_group_id'] = gid
        groups.append({'alias_group_id': gid, 'scan_id': scan_id,
                       'finding_ids': [f['finding_id'] for f in members],
                       'identifiers': sorted({v for f in members for v in f['identifiers']})})
    successes = sum(s.get('status') == 'completed' for s in statuses.values())
    document = {'schema_version': 'normalization-v1', 'scan_id': scan_id,
            'status': {0: 'failed', 1: 'partial', 2: 'completed'}[successes],
            'severity_policy': 'highest_reported_label; MODERATE=MEDIUM; no CVSS vector calculation',
            'tool_status': statuses, 'packages': packages, 'findings': findings,
            'alias_groups': groups, 'raw_results': deepcopy(tool_results),
            'summary': {'packages': len(packages),
                        'direct_packages': sum(p['dependency_type'] == 'direct' for p in packages),
                        'indirect_packages': sum(p['dependency_type'] == 'indirect' for p in packages),
                        'raw_records': len(rows), 'findings': len(findings),
                        'merged_pairs': matched_pairs,
                        'manual_review': sum(f['review_status'] == 'needs_review' for f in findings),
                        'alias_groups': len(groups)}}
    if deduplicated:
        document['deduplication'] = {
            'rule_version': 'explicit-ghsa-v1',
            'before_finding_count': before_deduplication,
            'after_finding_count': len(findings),
            'removed_duplicate_count': before_deduplication - len(findings),
            'groups': deduplicated,
        }
    return document


def normalize_scan(scan_dir, *, scan_id=None):
    """Consume portable scanner artifacts; verify both input snapshots by hash."""
    root = Path(scan_dir).resolve()
    manifest = json.loads((root / 'manifest.json').read_text())
    inputs = {}
    for name in ('package.json', 'package-lock.json'):
        content = (root / 'inputs' / name).read_bytes()
        if hashlib.sha256(content).hexdigest() != manifest['inputs'][name]['sha256']:
            raise ValueError(f'Input hash mismatch: {name}')
        inputs[name] = json.loads(content)
    data, statuses = {}, deepcopy(manifest['tools'])
    for tool in ('trivy', 'osv'):
        if statuses.get(tool, {}).get('status') != 'completed':
            continue
        try:
            data[tool] = json.loads((root / f'{tool}.json').read_text())
        except (OSError, ValueError) as exc:
            statuses[tool].update(status='failed', error={'kind': 'invalid_output', 'message': str(exc)})
    result = normalize_results(inputs['package.json'], inputs['package-lock.json'], data, statuses,
                               scan_id=scan_id or manifest['attempt_id'])
    result['execution_manifest'] = manifest
    return result


def main():
    parser = argparse.ArgumentParser(description='Normalize an existing Trivy/OSV scan')
    parser.add_argument('--scan-dir', required=True)
    parser.add_argument('--scan-id')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        output = Path(args.output).resolve()
        root = Path(args.scan_dir).resolve()
        if output == root / 'manifest.json' or output == root / 'trivy.json' or output == root / 'osv.json' or root / 'inputs' in output.parents:
            raise ValueError('Output must not overwrite scan evidence')
        result = normalize_scan(root, scan_id=args.scan_id)
        output.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive create protects an earlier normalization result, too.
        with output.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
        print(json.dumps({'status': result['status'], **result['summary'], 'output': str(output)}))
        return 0 if result['status'] == 'completed' else 1
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({'status': 'failed', 'error': str(exc)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
