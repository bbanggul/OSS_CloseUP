"""Deterministic comparison of stored npm observations. No DB, clock, I/O or AI."""
from collections import defaultdict
from datetime import datetime
import hashlib
import json
import re
from urllib.parse import urlsplit

from .fix_versions import compare as compare_versions
from .package_view import result_state

SCHEMA_VERSION = 'scan-compare-v1'
POLICY_VERSION = 'compare-policy-v1'
LIMITS = {'installations': 10000, 'finding_links': 50000, 'unlinked_findings': 10000,
          'candidate_pairs': 100000}
TOOLS = ('trivy', 'osv')
NSWG = 'NSWG-ECO-516'
NSWG_REASON = 'NSWG-ECO-516_requires_manual_review'
GHSA = re.compile(r'GHSA-[23456789CFGHJMPQRVWX]{4}(?:-[23456789CFGHJMPQRVWX]{4}){2}', re.I)
CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,}', re.I)
SHA256 = re.compile(r'[0-9a-f]{64}')


class ComparisonError(Exception):
    def __init__(self, code, status=500, scan_ids=(), limit=None):
        super().__init__(code)
        self.status = status
        messages = {
            'same_scan': '서로 다른 두 검사를 선택하세요.',
            'scan_not_found': '검사를 찾을 수 없습니다.',
            'different_project': '같은 프로젝트의 검사만 비교할 수 있습니다.',
            'scan_processing': '검사가 진행 중입니다.',
            'comparison_limit_exceeded': '비교 처리 상한을 초과했습니다.',
            'comparison_invariant_failed': '저장 결과의 연결 정보를 확인할 수 없습니다.',
            'database_unavailable': '검사 결과를 조회할 수 없습니다.',
        }
        self.detail = dict(code=code, message=messages[code],
                           scan_ids=[str(s) for s in scan_ids], limit=limit)


def require(condition):
    if not condition:
        raise ComparisonError('comparison_invariant_failed')


def check_limit(name, actual):
    if actual > LIMITS[name]:
        raise ComparisonError('comparison_limit_exceeded', 422,
                              limit=dict(dimension=name, maximum=LIMITS[name], actual=actual))


def check_pair(base, target):
    if str(base['scan_id']) == str(target['scan_id']):
        raise ComparisonError('same_scan', 422, [base['scan_id']])
    if str(base['project_id']) != str(target['project_id']):
        raise ComparisonError('different_project', 422, [base['scan_id'], target['scan_id']])
    processing = [s['scan_id'] for s in (base, target) if s['status'] in ('queued', 'running')]
    if processing:
        raise ComparisonError('scan_processing', 409, processing)


def strings(values):
    return sorted({v for v in values or [] if isinstance(v, str) and v.strip()})


def text_or_none(value):
    return value if isinstance(value, str) and value.strip() else None


def canonical(value):
    if isinstance(value, dict):
        return {str(k): canonical(v) for k, v in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [canonical(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def digest(value, prefix):
    raw = json.dumps(canonical(value), ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
    return prefix + hashlib.sha256(raw).hexdigest()


def input_snapshot(material):
    # DB row order has no meaning; order inside source evidence (e.g. range events) does.
    stable = dict(material)
    for table, columns in [('packages', ('package_id',)), ('findings', ('finding_id',)),
            ('links', ('finding_id', 'package_id')), ('source_runs', ('tool_run_id',)), ('artifacts', ('artifact_id',))]:
        stable[table] = sorted(material[table], key=lambda row: tuple(str(row[k]) for k in columns))
    return digest([POLICY_VERSION, stable], 'compare_input_')


def iso(value):
    return value.isoformat() if isinstance(value, datetime) else value


def indexed(rows, key, sid):
    result = {}
    for row in rows:
        rid = str(row[key])
        require(rid not in result and str(row.get('scan_id', sid)) == sid)
        result[rid] = row
    return result


def finding_public(finding):
    norm = (finding.get('evidence') or {}).get('normalized') or {}
    primary, references = [], []
    for observation in norm.get('evidence', []):
        raw, tool = observation.get('raw') or {}, observation.get('source_tool')
        if tool == 'trivy':
            primary.append(raw.get('VulnerabilityID'))
            references.extend(raw.get('References') or [])
        elif tool == 'osv':
            primary.append(raw.get('id'))
            references.extend(r.get('url') for r in raw.get('references', []) if isinstance(r, dict))
    # Exact reference strings are review evidence only. Never visit or rewrite a URL.
    urls = []
    for value in strings(references):
        try:
            parsed = urlsplit(value)
            if parsed.scheme in ('http', 'https') and parsed.netloc and not parsed.username and not parsed.password:
                urls.append(value)
        except ValueError:
            pass
    reasons = strings([*norm.get('review_reasons', []),
                       *(finding.get('manual_review_reason') or '').split(';')])
    return dict(finding_id=str(finding['finding_id']), identifiers=strings(finding.get('identifiers')),
        primary_ids=strings(primary), severity=finding.get('severity') or 'UNKNOWN',
        source_tools=sorted(set(finding.get('source_tools', [])) & set(TOOLS)),
        manual_review_required=bool(finding.get('manual_review_required')), review_reasons=reasons,
        merge_identifiers=strings((norm.get('merge_basis') or {}).get('shared_identifiers')),
        reference_urls=urls)


def prepare(material):
    scan = material['scan']
    sid = str(scan['scan_id'])
    require(scan['status'] in ('completed', 'partial', 'failed'))
    require(material.get('project') and str(material['project']['project_id']) == str(scan['project_id']))
    packages = indexed(material['packages'], 'package_id', sid)
    findings = indexed(material['findings'], 'finding_id', sid)
    require(len({p['lockfile_path'] for p in packages.values()}) == len(packages))
    require(all(f.get('type', 'vulnerability') == 'vulnerability' for f in findings.values()))
    external = {pid: p for pid, p in packages.items() if p['relationship'] != 'root'}
    require(all(p['ecosystem'] == 'npm' and p['name'] and p['lockfile_path'] for p in external.values()))
    attached, seen = defaultdict(list), set()
    for link in material['links']:
        fid, pid = str(link['finding_id']), str(link['package_id'])
        require(str(link.get('scan_id', sid)) == sid and fid in findings and pid in packages)
        require((fid, pid) not in seen)
        seen.add((fid, pid))
        if link['role'] == 'affected' and pid in external:
            attached[pid].append(fid)
    linked = {fid for ids in attached.values() for fid in ids}
    unlinked = sorted(findings.keys() - linked)
    states = scan.get('tool_status') or {}
    storage, norm = states.get('package_storage') or {}, states.get('normalization') or {}
    # A missing inventory count is unknown, including for zero rows.
    inventory = (storage.get('status') == 'completed' and
                 storage.get('total_including_root') == len(packages) and
                 storage.get('root') == len(packages) - len(external) and
                 storage.get('direct') == sum(p['relationship'] == 'direct' for p in external.values()) and
                 storage.get('indirect') == sum(p['relationship'] == 'indirect' for p in external.values()))
    runs = indexed(material['source_runs'], 'tool_run_id', sid)
    artifacts = indexed(material['artifacts'], 'artifact_id', sid)
    current = {}
    for rid, run in runs.items():
        if run['attempt_no'] == scan['attempt_count'] and run['tool_name'] in TOOLS:
            require(run['tool_name'] not in current)
            current[run['tool_name']] = run
    provenance = norm.get('source_artifacts') or {}
    sources, verified_tools = {}, set()
    raw_per_run = defaultdict(int)
    for artifact in artifacts.values():
        if artifact['kind'] == 'raw_result':
            raw_per_run[str(artifact['tool_run_id'])] += 1
    for tool in TOOLS:
        run = current.get(tool)
        sources[tool] = dict(status=run['status'] if run else 'unavailable',
            tool_run_id=str(run['tool_run_id']) if run else None,
            tool_version=text_or_none(run.get('tool_version')) if run else None,
            database_version=text_or_none(run.get('database_version')) if run else None,
            queried_at=iso(run.get('finished_at')) if run and tool == 'osv' else None)
        ref = provenance.get(tool) or {}
        artifact = artifacts.get(str(ref.get('artifact_id')))
        if (run and run['status'] == 'completed' and ref.get('attempt_no') == scan['attempt_count'] and
                str(ref.get('tool_run_id')) == str(run['tool_run_id']) and artifact and
                raw_per_run[str(run['tool_run_id'])] == 1 and
                str(artifact['tool_run_id']) == str(run['tool_run_id']) and artifact['kind'] == 'raw_result' and
                SHA256.fullmatch(ref.get('sha256') or '') and ref['sha256'] == artifact['sha256'] and
                (norm.get('tool_status') or {}).get(tool, {}).get('status') == 'completed'):
            verified_tools.add(tool)
    success_tools = {t for t in TOOLS if (norm.get('tool_status') or {}).get(t, {}).get('status') == 'completed'}
    verified = bool(success_tools) and success_tools == verified_tools == set(provenance)
    fingerprint = norm.get('fingerprint')
    fingerprint = fingerprint if isinstance(fingerprint, str) and SHA256.fullmatch(fingerprint) else None
    state = result_state(scan)
    usable = state in ('ready', 'partial') and bool(fingerprint) and verified
    if usable:
        # These totals were published by the normalizer's roundtrip transaction.
        require(norm.get('findings') == len(findings))
        require(norm.get('finding_package_links') == len(material['links']))
        for finding in findings.values():
            evidence = finding.get('evidence') or {}
            normalized = evidence.get('normalized') or {}
            require(evidence.get('normalizer') == 'normalization-v1' and
                    canonical(evidence.get('source_artifacts')) == canonical(provenance) and
                    str(normalized.get('scan_id')) == sid and
                    strings(normalized.get('identifiers')) == strings(finding.get('identifiers')) and
                    normalized.get('severity') == finding.get('severity') and
                    set(normalized.get('source_tools', [])) == set(finding.get('source_tools', [])) and
                    bool(finding.get('source_tools')) and set(finding['source_tools']) <= verified_tools)
        for pid, fids in attached.items():
            for fid in fids:
                normalized = findings[fid]['evidence']['normalized']
                # Historical schemas may omit these fields; a present mapping must agree.
                if 'package_name' in normalized:
                    require(normalized['package_name'] == packages[pid]['name'])
                if 'installed_version' in normalized:
                    require(normalized['installed_version'] == packages[pid]['installed_version'])
                if 'lock_paths' in normalized:
                    require(packages[pid]['lockfile_path'] in normalized['lock_paths'])
    if not usable and state in ('ready', 'partial'):
        state = 'unavailable'
    provenance_status = 'verified' if verified else 'legacy_unverified' if not provenance else 'unavailable'
    security = usable and state == 'ready' and verified_tools == set(TOOLS)
    blockers = []
    if not inventory: blockers.append('inventory_incomplete')
    if not usable: blockers.append('findings_unavailable')
    if not security: blockers.append('security_incomplete')
    if not verified: blockers.append('provenance_unverified')
    if usable and unlinked: blockers.append('unlinked_findings')
    meta = dict(scan_id=sid, project_id=str(scan['project_id']), status=scan['status'], result_state=state,
        created_at=iso(scan['created_at']), finished_at=iso(scan.get('finished_at')),
        input_package_lock_sha256=scan.get('input_package_lock_sha256'),
        normalization_fingerprint=fingerprint, inventory_complete=inventory, findings_usable=usable,
        security_complete=security, absence_eligible=not blockers, absence_blockers=blockers,
        provenance_status=provenance_status, sources=sources,
        snapshot_id=input_snapshot(material))
    return dict(meta=meta, packages=external, catalog={fid: finding_public(f) for fid, f in findings.items()} if usable else {},
                attached={pid: sorted(ids) for pid, ids in attached.items()} if usable else {},
                unlinked=unlinked if usable else [], raw_unlinked=len(unlinked),
                raw_links=sum(len(v) for v in attached.values()))


def installations(base, target, comparison_id):
    left, right = dict(base['packages']), dict(target['packages'])
    pairs = []
    key = lambda p: (p['ecosystem'], p['name'], p['lockfile_path'])
    right_by_key = {key(p): pid for pid, p in right.items()}
    for pid, p in list(left.items()):
        other = right_by_key.get(key(p))
        if other is not None:
            q = right.pop(other)
            left.pop(pid)
            known = text_or_none(p['installed_version']) and text_or_none(q['installed_version'])
            pairs.append((p, q, 'matched' if known else 'not_comparable',
                          'exact' if known else 'unresolved', None if known else 'exact_path_version_unknown'))
    lg, rg = defaultdict(list), defaultdict(list)
    for pid, p in left.items(): lg[(p['ecosystem'], p['name'])].append(pid)
    for pid, p in right.items(): rg[(p['ecosystem'], p['name'])].append(pid)
    if base['meta']['inventory_complete'] and target['meta']['inventory_complete']:
        for name in sorted(lg.keys() & rg.keys()):
            if len(lg[name]) == len(rg[name]) == 1:
                a, b = lg[name][0], rg[name][0]
                if text_or_none(left[a]['installed_version']) and text_or_none(right[b]['installed_version']):
                    pairs.append((left.pop(a), right.pop(b), 'matched', 'inferred', 'single_remaining_install'))
    for side, remaining, opposite, group in [('base', left, target, rg), ('target', right, base, lg)]:
        for p in remaining.values():
            complete = opposite['meta']['inventory_complete']
            known = bool(text_or_none(p['installed_version']))
            state = ('removed' if side == 'base' else 'added') if complete and known else 'not_comparable'
            evidence = ('opposite_inventory_incomplete' if not complete else
                        'multiple_remaining_installs' if (p['ecosystem'], p['name']) in group else None)
            pairs.append((p if side == 'base' else None, p if side == 'target' else None,
                          state, side + '_only', evidence))
    output = []
    for a, b, state, match, evidence in pairs:
        p = a or b
        av, bv = text_or_none(a['installed_version']) if a else None, text_or_none(b['installed_version']) if b else None
        if (a and av is None) or (b and bv is None):
            kind, direction = 'unknown', 'unknown'
        elif a is None or b is None:
            kind, direction = 'not_applicable', 'not_applicable'
        elif av == bv:
            kind, direction = 'same', 'none'
        else:
            kind = 'changed'
            direction = {-1: 'increased', 1: 'decreased', 0: 'equivalent', None: 'unknown'}[compare_versions(av, bv)]
        flags = ['relationship_changed'] if a and b and a['relationship'] != b['relationship'] else []
        def public(row):
            if row is None: return None
            return dict(package_id=str(row['package_id']), lockfile_path=row['lockfile_path'],
                        installed_version=text_or_none(row['installed_version']), relationship=row['relationship'])
        output.append(dict(installation_id=digest([comparison_id, str(a['package_id']) if a else None,
                          str(b['package_id']) if b else None], 'installation_'), ecosystem=p['ecosystem'], name=p['name'],
                          base=public(a), target=public(b), state=state, location_match=match,
                          location_evidence=evidence, version_change=dict(kind=kind, direction=direction), flags=flags))
    return sorted(output, key=lambda i: (i['ecosystem'], i['name'],
        (i['base'] or i['target'])['lockfile_path'], (i['target'] or {}).get('lockfile_path', ''), i['installation_id']))


def identity(finding):
    ids = {v.upper() for v in finding['identifiers'] if GHSA.fullmatch(v) or CVE.fullmatch(v)}
    ghsa = {v for v in ids if v.startswith('GHSA-')}
    cve = ids - ghsa
    primary = {v.upper() for v in finding['primary_ids']}
    manual = (finding['identifiers'] == [NSWG] and primary == {NSWG} and
              finding['manual_review_required'] and finding['review_reasons'] == [NSWG_REASON])
    primary_ghsa = {v for v in primary if GHSA.fullmatch(v)}
    review = (len(ghsa) > 1 or bool(primary_ghsa - ghsa) or NSWG in finding['identifiers'] or
              any('mapping' in reason for reason in finding['review_reasons']))
    return dict(ids=ids | ({NSWG} if NSWG in finding['identifiers'] else set()), ghsa=ghsa, cve=cve,
                primary=primary, manual=manual, review=review,
                missing=not ghsa and not (cve & primary) and not manual)


def candidates(left, right, catalog, budget):
    identities = {side: {fid: identity(catalog[side][fid]) for fid in ids}
                  for side, ids in [('base', left), ('target', right)]}
    by_identifier, by_url = defaultdict(set), defaultdict(set)
    for fid, ident in identities['target'].items():
        for value in ident['ids']: by_identifier[value].add(fid)
        for value in catalog['target'][fid]['reference_urls']: by_url[value].add(fid)
    edges, distinct = [], set()
    for a in left:
        x, fa = identities['base'][a], catalog['base'][a]
        possible = set()
        for value in x['ids']: possible.update(by_identifier[value])
        for value in fa['reference_urls']:
            possible.update(b for b in by_url[value] if x['review'] or fa['manual_review_required'] or
                            identities['target'][b]['review'] or catalog['target'][b]['manual_review_required'])
        budget[0] += len(possible)
        check_limit('candidate_pairs', budget[0])
        for b in sorted(possible):
            y, fb = identities['target'][b], catalog['target'][b]
            shared = x['ids'] & y['ids']
            refs = set(fa['reference_urls']) & set(fb['reference_urls'])
            kind, identifiers = None, []
            if x['manual'] and y['manual']:
                kind, identifiers = 'same_manual_record', [NSWG]
            elif not x['review'] and not y['review'] and len(x['ghsa']) == len(y['ghsa']) == 1 and x['ghsa'] == y['ghsa']:
                kind, identifiers = 'exact_ghsa', sorted(x['ghsa'])
            elif len(x['ghsa']) == len(y['ghsa']) == 1 and x['ghsa'] != y['ghsa'] and x['cve'] & y['cve']:
                distinct.update([('base', a), ('target', b)])
                continue
            elif not x['review'] and not y['review'] and len(x['cve'] & y['cve']) == 1:
                common = x['cve'] & y['cve']
                if common & (x['primary'] | y['primary']):
                    kind, identifiers = 'direct_cve', sorted(common)
            if kind is None and shared:
                kind, identifiers = 'shared_identifier_review', sorted(shared)
            if kind is None and refs and (x['review'] or y['review'] or fa['manual_review_required'] or fb['manual_review_required']):
                kind = 'reference_review_only'
            if kind:
                edges.append(dict(base_finding_id=a, target_finding_id=b, basis=kind, identifiers=identifiers))
    return edges, distinct, identities


def compare_installation(inst, base, target, comparison_id, budget):
    prepared = {'base': base, 'target': target}
    catalog = {side: data['catalog'] for side, data in prepared.items()}
    ids = {side: data['attached'].get(inst[side]['package_id'], []) if inst[side] else []
           for side, data in prepared.items()}
    output = []
    def emit(left, right, status, reason, *, edges=(), kind='none', identifiers=(), unit='installation_finding', flags=()):
        flags = set(flags) | set(inst['flags'])
        if any(catalog[side][fid]['manual_review_required'] for side, fids in [('base', left), ('target', right)] for fid in fids):
            flags.add('manual_review_required')
        if status == 'persisting' and catalog['base'][left[0]]['severity'] != catalog['target'][right[0]]['severity']:
            flags.add('severity_changed')
        output.append(dict(item_id=digest([comparison_id, inst['installation_id'], unit, left, right], 'item_'),
            installation_id=inst['installation_id'], unit=unit, status=status, reason=reason,
            base_finding_ids=sorted(left), target_finding_ids=sorted(right),
            match=dict(kind=kind, identifiers=sorted(identifiers), candidate_edges=list(edges)), flags=sorted(flags)))
    if inst['state'] == 'not_comparable':
        reason = 'version_unknown' if inst['version_change']['kind'] == 'unknown' else (
            'target_incomplete' if inst['base'] else 'base_incomplete')
        for side in ('base', 'target'):
            for fid in ids[side]: emit([fid] if side == 'base' else [], [fid] if side == 'target' else [], 'not_comparable', reason)
        return output
    edges, distinct, identities = candidates(ids['base'], ids['target'], catalog, budget)
    adjacency, edge_index = defaultdict(set), defaultdict(list)
    for edge in edges:
        a, b = ('base', edge['base_finding_id']), ('target', edge['target_finding_id'])
        adjacency[a].add(b); adjacency[b].add(a)
        edge_index[a].append(edge)
    consumed = set()
    for seed in sorted(adjacency):
        if seed in consumed: continue
        component, pending = {seed}, [seed]
        while pending:
            node = pending.pop()
            for neighbor in adjacency[node] - component:
                component.add(neighbor); pending.append(neighbor)
        consumed.update(component)
        left = sorted(fid for side, fid in component if side == 'base')
        right = sorted(fid for side, fid in component if side == 'target')
        component_edges = [e for fid in left for e in edge_index[('base', fid)]]
        flags = ['distinct_ghsa_shared_cve'] if component & distinct else []
        if len(left) == len(right) == 1 and component_edges[0]['basis'] in ('exact_ghsa', 'direct_cve', 'same_manual_record'):
            e = component_edges[0]
            emit(left, right, 'persisting', 'matched_identity', edges=component_edges,
                 kind=e['basis'], identifiers=e['identifiers'], flags=flags)
        else:
            emit(left, right, 'not_comparable', 'identifier_review_required', edges=component_edges,
                 kind='ambiguous', unit='identifier_conflict', flags=flags)
    for side in ('base', 'target'):
        opposite = 'target' if side == 'base' else 'base'
        for fid in ids[side]:
            if (side, fid) in consumed: continue
            ident = identities[side][fid]
            flags = ['distinct_ghsa_shared_cve'] if (side, fid) in distinct else []
            status, reason = 'not_comparable', None
            if ident['review']: reason = 'identifier_review_required'
            elif ident['missing']: reason = 'identifier_missing'
            elif not prepared[opposite]['meta']['absence_eligible']:
                reason = opposite + ('_unlinked_findings' if prepared[opposite]['unlinked'] else '_incomplete')
            else:
                status = 'not_detected' if side == 'base' else 'new'
                reason = ('package_removed' if side == 'base' else 'package_added') if inst[opposite] is None else (
                    'version_changed' if inst['version_change']['kind'] == 'changed' else 'same_version')
            emit([fid] if side == 'base' else [], [fid] if side == 'target' else [], status, reason, flags=flags)
    return sorted(output, key=lambda i: (i['unit'], i['base_finding_ids'], i['target_finding_ids']))


def compare_scans(base_material, target_material):
    check_pair(base_material['scan'], target_material['scan'])
    base, target = prepare(base_material), prepare(target_material)
    require(not (base['packages'].keys() & target['packages'].keys()))
    require(not ({str(f['finding_id']) for f in base_material['findings']} &
                 {str(f['finding_id']) for f in target_material['findings']}))
    check_limit('installations', len(base['packages']) + len(target['packages']))
    check_limit('finding_links', base['raw_links'] + target['raw_links'])
    check_limit('unlinked_findings', base['raw_unlinked'] + target['raw_unlinked'])
    cid = digest([POLICY_VERSION, base['meta']['scan_id'], target['meta']['scan_id'],
                  base['meta']['snapshot_id'], target['meta']['snapshot_id']], 'compare_')
    installs = installations(base, target, cid)
    budget = [0]
    items = [item for inst in installs for item in compare_installation(inst, base, target, cid, budget)]
    summary = {state: sum(i['status'] == state for i in items) for state in ('new', 'not_detected', 'persisting', 'not_comparable')}
    summary['not_comparable_units'] = {unit: sum(i['status'] == 'not_comparable' and i['unit'] == unit for i in items)
                                      for unit in ('installation_finding', 'identifier_conflict')}
    counts, warnings = {}, []
    for side, data in [('base', base), ('target', target)]:
        counts[side] = (dict(stored=len(data['catalog']), linked=len(data['catalog']) - len(data['unlinked']), unlinked=len(data['unlinked']))
                        if data['meta']['findings_usable'] else dict(stored=None, linked=None, unlinked=None))
        warnings.extend(side + '_' + b for b in data['meta']['absence_blockers'])
        if any(f['manual_review_required'] for f in data['catalog'].values()): warnings.append(side + '_manual_review_required')
        expected = {(pid, fid) for pid, fids in data['attached'].items() for fid in fids}
        install_by_id = {i['installation_id']: i for i in installs}
        actual = [(install_by_id[item['installation_id']][side]['package_id'], fid)
                  for item in items for fid in item[side + '_finding_ids']]
        require(len(actual) == len(set(actual)) and set(actual) == expected)
    if datetime.fromisoformat(base['meta']['created_at'].replace('Z', '+00:00')) > datetime.fromisoformat(target['meta']['created_at'].replace('Z', '+00:00')):
        warnings.append('base_after_target')
    changes = []
    for tool in TOOLS:
        for field in ('tool_version', 'database_version'):
            a, b = base['meta']['sources'][tool][field], target['meta']['sources'][tool][field]
            changes.append(dict(tool=tool, field=field, base=a, target=b,
                                state='unknown' if a is None or b is None else 'same' if a == b else 'changed'))
    return dict(schema_version=SCHEMA_VERSION, policy_version=POLICY_VERSION, comparison_id=cid,
        project=dict(project_id=base['meta']['project_id'], name=target_material['project']['name']),
        base=base['meta'], target=target['meta'], count_basis='installation_comparison_item', summary=summary,
        finding_counts=dict(count_basis='stored_finding', **counts), installations=installs, items=items,
        finding_catalog=dict(base=base['catalog'], target=target['catalog']),
        unlinked_findings=dict(base=base['unlinked'], target=target['unlinked']), context_changes=changes,
        comparison_complete=base['meta']['absence_eligible'] and target['meta']['absence_eligible'] and summary['not_comparable'] == 0,
        warnings=sorted(set(warnings)))
