"""Persist normalization-v1 losslessly; verify database round-trip before commit."""
import argparse
import hashlib
import json
from uuid import UUID
from psycopg.types.json import Jsonb
from .normalizer import normalize_results

PREFIX = 'normalizer:v1:'


def load_results(conn, scan_id, root):
    results, statuses, provenance = {}, {}, {}
    for tool in ('trivy', 'osv'):
        run = conn.execute('''SELECT tool_run_id,status,attempt_no FROM scan_tool_runs
            WHERE scan_id=%s AND tool_name=%s ORDER BY attempt_no DESC LIMIT 1''',
            (scan_id, tool)).fetchone()
        statuses[tool] = {'status': run['status'] if run else 'failed'}
        if not run or run['status'] != 'completed':
            continue
        rows = conn.execute('''SELECT artifact_id,storage_key,sha256,size_bytes FROM scan_artifacts
            WHERE scan_id=%s AND tool_run_id=%s AND kind='raw_result' AND deleted_at IS NULL''',
            (scan_id, run['tool_run_id'])).fetchall()
        if len(rows) != 1:
            raise ValueError('missing_or_duplicate_raw_artifact:' + tool)
        row = rows[0]
        path = (root / row['storage_key']).resolve()
        if not path.is_relative_to((root / str(scan_id)).resolve()):
            raise ValueError('invalid_raw_path:' + tool)
        content = path.read_bytes()
        if len(content) != row['size_bytes'] or hashlib.sha256(content).hexdigest() != row['sha256']:
            raise ValueError('raw_hash_mismatch:' + tool)
        results[tool] = json.loads(content)
        provenance[tool] = {'artifact_id': str(row['artifact_id']),
            'tool_run_id': str(run['tool_run_id']), 'sha256': row['sha256'], 'attempt_no': run['attempt_no']}
    return results, statuses, provenance


def persist(conn, scan_id, doc, provenance):
    """Caller holds scan row lock in a transaction. Never accepts another scan's IDs."""
    if doc['scan_id'] != str(scan_id) or doc['schema_version'] != 'normalization-v1':
        raise ValueError('normalization_scope_mismatch')
    if doc['status'] == 'failed':
        raise ValueError('no_valid_scanner_results')
    packages = {r['lockfile_path']: r for r in conn.execute(
        'SELECT package_id,lockfile_path,name,installed_version FROM packages WHERE scan_id=%s',
        (scan_id,)).fetchall()}
    mapped = {}
    for p in doc['packages']:
        row = packages.get(p['lock_path'])
        if p['scan_id'] != str(scan_id) or not row or (row['name'], row['installed_version']) != (p['name'], p['version']):
            raise ValueError('package_storage_mismatch:' + p['lock_path'])
        mapped[p['package_id']] = row['package_id']
    if len(mapped) != len(doc['packages']):
        raise ValueError('duplicate_normalized_package')
    fingerprint = hashlib.sha256(json.dumps(doc, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    prior = conn.execute("SELECT tool_status->'normalization' AS previous FROM scan_runs WHERE scan_id=%s", (scan_id,)).fetchone()['previous']
    if prior and prior.get('fingerprint') and prior['fingerprint'] != fingerprint:
        raise ValueError('normalized_source_changed_upload_as_new_scan')
    ids, expected = {}, {}
    for f in doc['findings']:
        key = PREFIX + f['finding_id']
        if f['scan_id'] != str(scan_id) or key in expected:
            raise ValueError('invalid_finding_scope_or_duplicate')
        observations = {}
        for observation in f['severity_observations']:
            observations.setdefault(observation['source_tool'], []).append(observation)
        evidence = {'normalizer': 'normalization-v1', 'normalized': f,
                    'source_artifacts': provenance, 'severity_policy': doc['severity_policy']}
        values = dict(identifiers=f['identifiers'], severity=f['severity'], severity_by_tool=observations,
            severity_conflict=f['severity_conflict'], source_tools=f['source_tools'],
            manual_review_required=f['review_status']=='needs_review',
            manual_review_reason=';'.join(f['review_reasons']) or None, evidence=evidence)
        row = conn.execute('''INSERT INTO findings(scan_id,finding_key,type,identifiers,severity,
            severity_by_tool,severity_conflict,source_tools,manual_review_required,manual_review_reason,evidence)
            VALUES(%s,%s,'vulnerability',%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT(scan_id,finding_key) DO UPDATE SET finding_key=EXCLUDED.finding_key RETURNING finding_id''',
            (scan_id,key,Jsonb(values['identifiers']),values['severity'],Jsonb(observations),
             values['severity_conflict'],values['source_tools'],values['manual_review_required'],
             values['manual_review_reason'],Jsonb(evidence))).fetchone()
        ids[f['finding_id']] = row['finding_id']; expected[key] = values
        for pid in f['package_ids']:
            conn.execute('''INSERT INTO finding_packages(scan_id,finding_id,package_id,fixed_version_candidates,evidence)
                VALUES(%s,%s,%s,%s,%s) ON CONFLICT(finding_id,package_id) DO NOTHING''',
                (scan_id,row['finding_id'],mapped[pid],Jsonb(f['fixed_version_candidates']),
                 Jsonb({'normalizer_package_id':pid, 'fix_information':f['fix_information']})))
    groups = {}
    for g in doc['alias_groups']:
        if g['scan_id'] != str(scan_id) or g['alias_group_id'] in groups:
            raise ValueError('invalid_alias_scope_or_duplicate')
        row = conn.execute('''INSERT INTO advisory_alias_groups(scan_id,group_key,identifiers,evidence)
            VALUES(%s,%s,%s,%s) ON CONFLICT(scan_id,group_key) DO UPDATE SET group_key=EXCLUDED.group_key
            RETURNING alias_group_id''',
            (scan_id,PREFIX+g['alias_group_id'],Jsonb(g['identifiers']),Jsonb({'normalized':g}))).fetchone()
        groups[g['alias_group_id']] = row['alias_group_id']
        for fid in g['finding_ids']:
            conn.execute('''INSERT INTO advisory_alias_group_members(scan_id,alias_group_id,finding_id)
                VALUES(%s,%s,%s) ON CONFLICT(alias_group_id,finding_id) DO NOTHING''',
                (scan_id,row['alias_group_id'],ids[fid]))
    # Compare full structured evidence, flattened display fields, links and candidates.
    actual = conn.execute("SELECT * FROM findings WHERE scan_id=%s AND starts_with(finding_key,%s)", (scan_id,PREFIX)).fetchall()
    if {r['finding_key'] for r in actual} != set(expected):
        raise ValueError('roundtrip_finding_set_mismatch')
    for row in actual:
        if any(row[k] != v for k,v in expected[row['finding_key']].items()):
            raise ValueError('roundtrip_finding_content_mismatch')
    links = conn.execute('''SELECT fp.* FROM finding_packages fp JOIN findings f USING(scan_id,finding_id)
        WHERE fp.scan_id=%s AND starts_with(f.finding_key,%s)''', (scan_id,PREFIX)).fetchall()
    want = {(ids[f['finding_id']],mapped[p]): (f['fixed_version_candidates'],
        {'normalizer_package_id':p,'fix_information':f['fix_information']})
        for f in doc['findings'] for p in f['package_ids']}
    if {(r['finding_id'],r['package_id']):(r['fixed_version_candidates'],r['evidence']) for r in links} != want:
        raise ValueError('roundtrip_package_links_mismatch')
    actual_groups = conn.execute('''SELECT * FROM advisory_alias_groups WHERE scan_id=%s
        AND starts_with(group_key,%s)''', (scan_id,PREFIX)).fetchall()
    if {r['group_key']:(r['identifiers'],r['evidence']) for r in actual_groups} != {
        PREFIX+g['alias_group_id']:(g['identifiers'],{'normalized':g}) for g in doc['alias_groups']}:
        raise ValueError('roundtrip_alias_content_mismatch')
    members = conn.execute('''SELECT m.alias_group_id,m.finding_id FROM advisory_alias_group_members m
        JOIN advisory_alias_groups g USING(scan_id,alias_group_id)
        WHERE m.scan_id=%s AND starts_with(g.group_key,%s)''', (scan_id,PREFIX)).fetchall()
    if {(r['alias_group_id'],r['finding_id']) for r in members} != {
        (groups[g['alias_group_id']],ids[f]) for g in doc['alias_groups'] for f in g['finding_ids']}:
        raise ValueError('roundtrip_alias_members_mismatch')
    summary = {**doc['summary'], 'status':doc['status'], 'roundtrip_verified':True,
        'finding_package_links':len(links), 'fingerprint':fingerprint,
        'source_artifacts':provenance, 'tool_status':doc['tool_status']}
    if 'deduplication' in doc:
        # Returned by the findings API through its existing normalization field.
        summary['deduplication'] = doc['deduplication']
    conn.execute('UPDATE scan_runs SET tool_status=tool_status || %s WHERE scan_id=%s',
        (Jsonb({'normalization':summary}),scan_id))
    return summary


def store_findings(conn, scan_id, paths, root, allow_running=False):
    with conn.transaction():
        scan = conn.execute('SELECT status FROM scan_runs WHERE scan_id=%s FOR UPDATE',(scan_id,)).fetchone()
        if not scan: raise ValueError('scan_not_found')
        if not allow_running and scan['status'] in ('running','queued'): raise ValueError('scan_not_finished')
        data, states, provenance = load_results(conn,scan_id,root)
        doc = normalize_results(json.loads(paths['package_json'].read_bytes()),
            json.loads(paths['package_lock'].read_bytes()),data,states,scan_id=str(scan_id))
        return persist(conn,scan_id,doc,provenance)


def finalize(conn, scan_id):
    row = conn.execute('SELECT tool_status FROM scan_runs WHERE scan_id=%s',(scan_id,)).fetchone()
    states = row['tool_status']
    names = ('trivy','osv','syft','package_storage','normalization','github')
    complete = all(states.get(n,{}).get('status') == 'completed' for n in names)
    if 'priority' in states:
        complete = complete and states['priority'].get('status') == 'completed'
    final = 'completed' if complete else ('partial' if any(states.get(n,{}).get('status')=='completed' for n in ('trivy','osv','syft')) else 'failed')
    conn.execute('''UPDATE scan_runs SET status=%s,error_message=%s WHERE scan_id=%s''',
        (final,None if complete else 'incomplete_stages; see tool_status',scan_id))
    return final


def main():
    from .main import connect,verify_inputs,OUTPUT_ROOT
    parser = argparse.ArgumentParser(description='Normalize verified saved scanner output and verify DB round-trip')
    parser.add_argument('scan_id',type=UUID)
    args = parser.parse_args()
    with connect() as conn:
        with conn.transaction():
            summary = store_findings(conn,args.scan_id,verify_inputs(conn,args.scan_id),OUTPUT_ROOT)
            summary['scan_status'] = finalize(conn,args.scan_id)
        print(json.dumps(summary,ensure_ascii=False,indent=2))

if __name__ == '__main__': main()
