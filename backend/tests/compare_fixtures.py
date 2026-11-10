"""Stored-row fixtures reconstructed from the independently authored Nov 1 contract."""
from copy import deepcopy
import json
from pathlib import Path
from uuid import uuid5, NAMESPACE_URL

FIXTURES = Path(__file__).parent / 'fixtures' / 'scan_compare'


def uid(value):
    return str(uuid5(NAMESPACE_URL, value))


def material(example, side):
    meta = example[side]
    sid = meta['scan_id']
    packages = {}
    for inst in example['installations']:
        p = inst[side]
        if p:
            packages[p['package_id']] = dict(deepcopy(p), scan_id=sid, ecosystem=inst['ecosystem'], name=inst['name'], evidence={})
    states = {'package_storage': dict(status='completed' if meta['inventory_complete'] else 'partial',
        total_including_root=len(packages), root=0,
        direct=sum(p['relationship'] == 'direct' for p in packages.values()),
        indirect=sum(p['relationship'] == 'indirect' for p in packages.values()))}
    runs, artifacts, provenance = [], [], {}
    for tool, source in meta['sources'].items():
        rid = source['tool_run_id'] or uid(sid + tool)
        runs.append(dict(scan_id=sid, tool_run_id=rid, tool_name=tool, attempt_no=1,
            status=source['status'], tool_version=source['tool_version'], database_version=source['database_version'],
            started_at=meta['created_at'], finished_at=source['queried_at'] or meta['finished_at']))
        if source['status'] == 'completed':
            aid = uid(rid + 'artifact')
            artifacts.append(dict(scan_id=sid, artifact_id=aid, tool_run_id=rid, kind='raw_result', sha256='a'*64))
            provenance[tool] = dict(artifact_id=aid, tool_run_id=rid, sha256='a'*64, attempt_no=1)
    if meta['provenance_status'] != 'verified': provenance = {}
    catalog = example['finding_catalog'][side]
    links = {}
    installation_map = {i['installation_id']: i for i in example['installations']}
    for item in example['items']:
        for fid in item[side + '_finding_ids']:
            pid = installation_map[item['installation_id']][side]['package_id']
            links[fid, pid] = dict(scan_id=sid, finding_id=fid, package_id=pid, role='affected')
    states['normalization'] = dict(status='completed' if meta['result_state'] == 'ready' else meta['result_state'],
        roundtrip_verified=meta['findings_usable'], fingerprint=meta['normalization_fingerprint'],
        source_artifacts=provenance, findings=len(catalog), finding_package_links=len(links),
        tool_status={t: {'status': s['status']} for t, s in meta['sources'].items()})
    findings = []
    for fid, finding in catalog.items():
        evidence = []
        for primary in finding['primary_ids']:
            tool = 'osv' if primary.upper().startswith('GHSA-') else 'trivy'
            if tool not in finding['source_tools']: tool = finding['source_tools'][0]
            raw = ({'id': primary, 'references': [{'url': url} for url in finding['reference_urls']]} if tool == 'osv'
                   else {'VulnerabilityID': primary, 'References': finding['reference_urls']})
            evidence.append(dict(source_tool=tool, raw=raw))
        norm = dict(scan_id=sid, identifiers=deepcopy(finding['identifiers']), severity=finding['severity'],
            source_tools=finding['source_tools'], evidence=evidence, review_reasons=finding['review_reasons'],
            merge_basis={'shared_identifiers': finding['merge_identifiers']})
        findings.append(dict(scan_id=sid, finding_id=fid, type='vulnerability',
            identifiers=finding['identifiers'], severity=finding['severity'], source_tools=finding['source_tools'],
            manual_review_required=finding['manual_review_required'], manual_review_reason=';'.join(finding['review_reasons']) or None,
            evidence=dict(normalizer='normalization-v1', normalized=norm, source_artifacts=deepcopy(provenance))))
    scan = {k: deepcopy(meta[k]) for k in ('scan_id', 'project_id', 'status', 'created_at', 'finished_at', 'input_package_lock_sha256')}
    scan.update(started_at=meta['created_at'], input_package_json_sha256='b'*64, tool_status=states, attempt_count=1, worker_id='fixture')
    return dict(scan=scan, project=deepcopy(example['project']), packages=list(packages.values()),
                findings=findings, links=list(links.values()), source_runs=runs, artifacts=artifacts)


def pair(name='01-persisting'):
    example = json.loads((FIXTURES / 'examples' / (name + '.json')).read_text())
    return material(example, 'base'), material(example, 'target'), example


def refresh_counts(data):
    norm = data['scan']['tool_status']['normalization']
    norm.update(findings=len(data['findings']), finding_package_links=len(data['links']))
    storage = data['scan']['tool_status']['package_storage']
    storage.update(total_including_root=len(data['packages']), root=sum(p['relationship'] == 'root' for p in data['packages']),
        direct=sum(p['relationship'] == 'direct' for p in data['packages']),
        indirect=sum(p['relationship'] == 'indirect' for p in data['packages']))


def duplicate_finding(data, index=0, *, identifiers=None, primary=None):
    row = deepcopy(data['findings'][index])
    old = row['finding_id']
    row['finding_id'] = uid(old + str(len(data['findings'])))
    if identifiers is not None:
        row['identifiers'] = identifiers
        row['evidence']['normalized']['identifiers'] = identifiers
    if primary:
        row['evidence']['normalized']['evidence'] = [{'source_tool': 'trivy', 'raw': {'VulnerabilityID': primary}}]
    data['findings'].append(row)
    for link in list(data['links']):
        if link['finding_id'] == old:
            data['links'].append(dict(link, finding_id=row['finding_id']))
    refresh_counts(data)
    return row
