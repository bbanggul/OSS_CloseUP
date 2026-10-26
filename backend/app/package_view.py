"""Read-only package grouping. Ranking is global within one stored snapshot."""
from collections import defaultdict
from copy import deepcopy
import hashlib
import json

SCHEMA_VERSION = 'vulnerable-packages-v1'
SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')
PRIORITIES = ('P0', 'P1', 'P2', 'P3')


def fingerprint(value, prefix):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode()
    return prefix + hashlib.sha256(raw).hexdigest()


def result_state(scan):
    states = scan.get('tool_status') or {}
    norm = states.get('normalization') or {}
    if (norm.get('roundtrip_verified') is True and
            states.get('package_storage', {}).get('status') == 'completed' and
            norm.get('status') in ('completed', 'partial')):
        return 'ready' if norm['status'] == 'completed' else 'partial'
    if norm.get('status') == 'failed':
        return 'failed'
    if scan['status'] in ('queued', 'running'):
        return 'processing'
    return 'failed' if scan['status'] == 'failed' else 'unavailable'


def build_view(scan, packages, findings, links, priority_state, priority_result):
    """Inputs are from one repeatable-read transaction; never rewrite evidence."""
    sid = str(scan['scan_id'])
    snapshot = fingerprint([SCHEMA_VERSION, scan, packages, findings, links,
                            priority_state, priority_result], 'snapshot_')
    packages = {str(p['package_id']): deepcopy(p) for p in packages}
    findings = {str(f['finding_id']): deepcopy(f) for f in findings}
    state = result_state(scan)
    ready = state in ('ready', 'partial')
    norm = (scan.get('tool_status') or {}).get('normalization') or {}
    priority_state = deepcopy(priority_state)
    eligible_links = [l for l in links if str(l['finding_id']) in findings and
                      str(l['package_id']) in packages and l['role'] == 'affected' and
                      packages[str(l['package_id'])]['relationship'] != 'root']
    calculated = {(str(l['finding_id']), str(l['package_id'])): l
                  for l in (priority_result or {}).get('link_results', [])}
    expected = {(str(l['finding_id']), str(l['package_id'])) for l in eligible_links}
    usable = ready and priority_state.get('current_result_available') is True
    def source_changed(link):
        published = calculated.get((str(link['finding_id']), str(link['package_id'])), {})
        context = published.get('finding_context', {})
        finding = findings[str(link['finding_id'])]
        return (published.get('fixed_version_candidates') != link.get('fixed_version_candidates') or
                context.get('severity') != finding.get('severity') or
                context.get('evidence') != finding.get('evidence'))
    evidence_changed = usable and any(source_changed(l) for l in eligible_links)
    if usable and (evidence_changed or (priority_result or {}).get('security_status') != norm.get('status') or
                   len(calculated) != len((priority_result or {}).get('link_results', [])) or
                   set(calculated) != expected or
                   (priority_result or {}).get('summary', {}).get('finding_count') != len(findings) or
                   any(l.get('priority') not in (*PRIORITIES, None) for l in calculated.values())):
        priority_state.update(status='unavailable', current_result_available=False,
                              unavailable_reason='stored_result_scope_mismatch')
        usable = False
    if not ready:
        priority_state['current_result_available'] = False
    inactive_status = priority_state.get('status', 'not_computed')
    if inactive_status not in ('invalid_input', 'failed', 'unavailable'):
        inactive_status = 'unavailable' if inactive_status == 'completed' else 'not_computed'
    groups, group_for_package, linked = {}, {}, set()
    for pid, p in packages.items():
        if p['relationship'] == 'root':
            continue
        # Missing versions are never assumed to describe the same installation.
        identity = [sid, p['ecosystem'], p['name'], p['installed_version']]
        if p['installed_version'] is None:
            identity.append(pid)
        gid = fingerprint(identity, 'pkg_group_')
        group_for_package[pid] = gid
        groups.setdefault(gid, {'package_group_id': gid, 'ecosystem': p['ecosystem'],
            'name': p['name'], 'installed_version': p['installed_version'],
            'installations': [], '_links': [], '_finding_ids': set()})
        groups[gid]['installations'].append({k: deepcopy(p.get(k)) for k in (
            'package_id', 'lockfile_path', 'relationship', 'licenses', 'purl',
            'repository_url', 'repository_full_name')})
    all_links = defaultdict(list)
    for l in links:
        fid, pid = str(l['finding_id']), str(l['package_id'])
        if fid not in findings or pid not in packages:
            continue
        p = packages[pid]
        row = {k: deepcopy(l.get(k)) for k in ('finding_id', 'package_id', 'role',
               'fixed_version_candidates', 'recommended_fixed_version', 'evidence')}
        row.update(lockfile_path=p['lockfile_path'], relationship=p['relationship'],
                   fix_information=(l.get('evidence') or {}).get('fix_information', 'unknown'))
        current = calculated.get((fid, pid), {}) if usable else {}
        row.update(priority=current.get('priority'),
                   priority_status=current.get('priority_status', inactive_status))
        all_links[fid].append(row)
        if l['role'] == 'affected' and p['relationship'] != 'root':
            group = groups[group_for_package[pid]]
            group['_links'].append(row)
            group['_finding_ids'].add(fid)
            linked.add(fid)
    for fid, finding in findings.items():
        values = [l['priority'] for l in all_links[fid]
                  if l['role'] == 'affected' and l['relationship'] != 'root' and l['priority'] in PRIORITIES]
        finding['priority'] = min(values, key=PRIORITIES.index) if usable and values else None
        finding['priority_status'] = ('calculated' if values else 'severity_unknown' if fid in linked else 'unlinked') if usable else inactive_status
    items = []
    for group in groups.values():
        fids = sorted(group.pop('_finding_ids'))
        if not fids:
            continue
        rows = sorted(group.pop('_links'), key=lambda l: (str(l['finding_id']), str(l['package_id'])))
        levels = [r['priority'] for r in rows if r['priority'] in PRIORITIES]
        priority = min(levels, key=PRIORITIES.index) if usable and levels else None
        representative = [r for r in rows if r['priority'] == priority] if priority else []
        rep_ids = sorted({str(r['finding_id']) for r in representative})
        counts = {severity: sum((findings[fid].get('severity') or 'UNKNOWN') == severity for fid in fids)
                  for severity in SEVERITIES}
        group['installations'].sort(key=lambda p: (p['lockfile_path'], str(p['package_id'])))
        group.update(priority=priority,
            priority_status=('calculated' if priority else 'severity_unknown') if usable else
                            inactive_status,
            finding_ids=fids, finding_count=len(fids), severity_counts=counts,
            representative_finding_ids=rep_ids if usable else None,
            representative_finding_count=len(rep_ids) if usable else None,
            has_fix_candidate_at_priority=any(r['fixed_version_candidates'] for r in representative) if usable else None,
            representative_links=deepcopy(representative) if usable else None,
            full_remediation_status='not_evaluated', incomplete=state != 'ready', global_rank=None,
            _findings=[{**deepcopy(findings[fid]), 'installation_links':
                        [deepcopy(r) for r in rows if str(r['finding_id']) == fid]} for fid in fids])
        items.append(group)
    def order(g):
        name_key = (g['name'], g['installed_version'] or '', g['package_group_id'])
        if not usable or g['priority'] is None:
            return (4, 0, 0, *name_key)
        return (PRIORITIES.index(g['priority']), int(not g['has_fix_candidate_at_priority']),
                -g['representative_finding_count'], *name_key)
    items.sort(key=order)
    for index, group in enumerate(items):
        if usable and group['priority'] is not None:
            group['global_rank'] = index + 1
    review_count = sum(bool(f.get('manual_review_required')) for f in findings.values())
    review = (scan.get('tool_status') or {}).get('deduplication_review') or {}
    reviewed = (state == 'ready' and review_count == 0 and bool(norm.get('fingerprint')) and
                review.get('status') == 'completed' and
                review.get('normalization_fingerprint') == norm['fingerprint'] and
                all(isinstance(review.get(k), str) and review[k].strip()
                    for k in ('reviewed_by', 'reviewed_at', 'evidence_ref')))
    meta = {'schema_version': SCHEMA_VERSION, 'scan_id': sid, 'snapshot_id': snapshot,
            'scan_status': scan['status'], 'result_state': state,
            'security_status': norm.get('status') if norm.get('status') in ('completed', 'partial', 'failed') else None,
            'normalization': {k: norm[k] for k in ('status', 'roundtrip_verified', 'fingerprint', 'deduplication') if k in norm},
            'priority_evaluation': priority_state,
            'deduplication_status': 'completed' if reviewed else 'review_pending' if ready else 'not_ready',
            'manual_review_finding_count': review_count,
            'automatic_deduplication': deepcopy(norm.get('deduplication')),
            'total_unfiltered': len(items), 'unique_finding_count': len(findings),
            'linked_unique_finding_count': len(linked), 'unlinked_finding_count': len(findings.keys() - linked),
            'ranked_total': sum(g['global_rank'] is not None for g in items),
            'zero_findings_confirmed': state == 'ready' and not findings}
    # Do not publish half-written rows from normalization transactions/stages.
    if not ready:
        items = []
        for k in ('total_unfiltered', 'unique_finding_count', 'linked_unique_finding_count',
                  'unlinked_finding_count', 'ranked_total'):
            meta[k] = None
    return {'meta': meta, 'items': items, 'findings': findings, 'links': all_links,
            'unlinked_ids': sorted(findings.keys() - linked) if ready else []}


def public_group(group, detail=False):
    result = {k: deepcopy(v) for k, v in group.items() if not k.startswith('_')}
    if detail:
        result['findings'] = deepcopy(group['_findings'])
    return result


def filter_groups(items, *, q='', priority=None, severity=None, relationship=None):
    return [g for g in items if (not q or q.casefold() in g['name'].casefold())
            and (priority is None or g['priority'] == priority)
            and (severity is None or g['severity_counts'][severity] > 0)
            and (relationship is None or any(p['relationship'] == relationship for p in g['installations']))]
