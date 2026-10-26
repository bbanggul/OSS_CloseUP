"""Opt-in PostgreSQL tests. Each test creates and drops its own schema."""
import os
import json
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
import pytest

from worker.app.priority_storage import evaluate_scan, source_snapshot, PostgresPriorityStore
from worker.app.priority_stage import PriorityStagePersistenceError
from backend.app.priority_view import load_priority, present_findings


@pytest.fixture
def database():
    dsn = os.getenv('PRIORITY_TEST_DSN')
    if not dsn:
        pytest.skip('PRIORITY_TEST_DSN is required for isolated PostgreSQL tests')
    schema = 'priority_test_' + uuid4().hex
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        conn.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
        conn.execute(sql.SQL('SET search_path TO {}').format(sql.Identifier(schema)))
        try:
            root = Path(__file__).resolve().parents[2]
            for name in ('oss_closeup_v2.sql', 'oss_closeup_v2_2_priority.sql'):
                body = (root / 'db' / name).read_text(encoding='utf-8')
                conn.execute('\n'.join(line for line in body.splitlines() if not line.startswith('\\')))
            yield conn
        finally:
            conn.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))


def seed(conn):
    project, sid, pid, fid = [uuid4() for _ in range(4)]
    states = {'package_storage': {'status': 'completed'}, 'normalization': {
        'status': 'partial', 'roundtrip_verified': True,
        'tool_status': {'trivy': {'status': 'completed'}, 'osv': {'status': 'failed'}}}}
    conn.execute('INSERT INTO projects(project_id,name) VALUES(%s,%s)', (project,'test'))
    conn.execute("""INSERT INTO scan_runs(scan_id,project_id,status,started_at,worker_id,attempt_count,tool_status)
        VALUES(%s,%s,'running',now(),'worker-test',1,%s)""", (sid,project,Jsonb(states)))
    conn.execute("""INSERT INTO packages(package_id,scan_id,name,installed_version,lockfile_path,relationship)
        VALUES(%s,%s,'demo','1.0.0','node_modules/demo','indirect')""", (pid,sid))
    evidence = {'normalized': {'priority_input_eligible': True, 'severity_observations': []}}
    conn.execute("""INSERT INTO findings(finding_id,scan_id,type,finding_key,severity,evidence)
        VALUES(%s,%s,'vulnerability','test-key','CRITICAL',%s)""", (fid,sid,Jsonb(evidence)))
    conn.execute("""INSERT INTO finding_packages(scan_id,finding_id,package_id,evidence)
        VALUES(%s,%s,%s,%s)""", (sid,fid,pid,Jsonb({'fix_information':'not_reported'})))
    return {'scan_id':sid,'worker_id':'worker-test','attempt_count':1}, fid, pid


def test_publish_and_api_read_preserve_scanner_evidence(database):
    conn=database
    scan,fid,pid=seed(conn)
    before=source_snapshot(conn,scan['scan_id'])
    outcome=evaluate_scan(conn,scan)
    assert outcome['status']=='completed', outcome.get('error')
    assert source_snapshot(conn,scan['scan_id'])==before
    marker=conn.execute('SELECT tool_status FROM scan_runs').fetchone()['tool_status']
    state,result=load_priority(conn,scan['scan_id'],marker)
    assert state['current_result_available'] is True
    assert result['security_status']=='partial'
    item={'finding_id':fid,'packages':[{'package_id':pid}]}
    assert present_findings([item],state,result)[0]['packages'][0]['priority']=='P0'


def test_failed_publication_rolls_back_and_masks_old_grade(database,monkeypatch):
    conn=database
    scan,fid,pid=seed(conn)
    assert evaluate_scan(conn,scan)['status']=='completed'
    original=PostgresPriorityStore.publish_state
    def fail_after_writes(self, record):
        if record['status']=='completed':
            raise OSError('simulated secret must not be saved')
        return original(self,record)
    monkeypatch.setattr(PostgresPriorityStore,'publish_state',fail_after_writes)
    outcome=evaluate_scan(conn,scan)
    assert outcome['status']=='failed'
    assert conn.execute('SELECT priority FROM finding_packages').fetchone()['priority']=='P0'
    rows=conn.execute('SELECT status,result,error,attempted_payload FROM priority_evaluations ORDER BY created_at').fetchall()
    assert [r['status'] for r in rows]==['completed','failed']
    assert rows[1]['result'] is None
    assert rows[1]['error']['message_policy'] == 'safe-stage-summary-v1'
    assert 'rolled back' in rows[1]['error']['message']
    assert 'simulated secret' not in json.dumps(rows)
    assert rows[1]['attempted_payload'] == outcome['attempted_payload']
    assert rows[0]['attempted_payload'] is None
    marker=conn.execute('SELECT tool_status FROM scan_runs').fetchone()['tool_status']
    state,result=load_priority(conn,scan['scan_id'],marker)
    item={'finding_id':fid,'packages':[{'package_id':pid,'priority':'P0'}]}
    assert present_findings([item],state,result)[0]['packages'][0]['priority'] is None


def test_stale_worker_cannot_publish(database):
    scan,_,_=seed(database)
    scan['worker_id']='old-worker'
    with pytest.raises(PriorityStagePersistenceError):
        evaluate_scan(database,scan)
    assert database.execute('SELECT count(*) AS n FROM priority_evaluations').fetchone()['n']==0


def test_unknown_severity_keeps_null_grade(database):
    scan,_,_=seed(database)
    database.execute("UPDATE findings SET severity='UNKNOWN'")
    outcome=evaluate_scan(database,scan)
    assert outcome['status']=='completed'
    assert outcome['result']['link_results'][0]['priority'] is None
    assert outcome['result']['summary']['unknown_finding_count']==1


def test_empty_valid_scan_is_not_a_calculation_failure(database):
    scan,_,_=seed(database)
    database.execute('DELETE FROM findings')
    outcome=evaluate_scan(database,scan)
    assert outcome['status']=='completed'
    assert outcome['result']['link_results']==[]


def test_source_change_prevents_publication(database,monkeypatch):
    scan,_,_=seed(database)
    original=PostgresPriorityStore.save_priority_result
    def change_source(self,record):
        self.conn.execute("UPDATE findings SET severity='LOW'")
        return original(self,record)
    monkeypatch.setattr(PostgresPriorityStore,'save_priority_result',change_source)
    outcome=evaluate_scan(database,scan)
    assert outcome['status']=='failed'
    assert database.execute('SELECT priority FROM finding_packages').fetchone()['priority'] is None


def test_real_normalized_fixture_reaches_api_and_ai(database,monkeypatch):
    from worker.app.normalizer import normalize_results
    from worker.app.finding_storage import persist
    from backend.app import uploads
    from backend.app.ai_service import snapshot_for
    conn=database
    scan,_,_=seed(conn)
    conn.execute('DELETE FROM findings')
    conn.execute('DELETE FROM packages')
    root=Path(__file__).resolve().parents[2]
    fixture=json.loads((root/'worker/tests/fixtures/normalized-final.json').read_text(encoding='utf-8'))
    sample=root/'samples/poc77'
    doc=normalize_results(json.loads((sample/'package.json').read_text(encoding='utf-8')),
        json.loads((sample/'package-lock.json').read_text(encoding='utf-8')),
        fixture['raw_results'],fixture['tool_status'],scan_id=str(scan['scan_id']))
    for p in doc['packages']:
        conn.execute('''INSERT INTO packages(scan_id,name,installed_version,lockfile_path,relationship)
            VALUES(%s,%s,%s,%s,%s)''',
            (scan['scan_id'],p['name'],p['version'],p['lock_path'],p['dependency_type']))
    with conn.transaction():
        persist(conn,scan['scan_id'],doc,{})
    # Re-saving identical normalized evidence must preserve IDs, rows, and full JSON.
    first_rows = conn.execute('SELECT * FROM findings ORDER BY finding_key').fetchall()
    first_links = conn.execute('SELECT * FROM finding_packages ORDER BY finding_id,package_id').fetchall()
    first_groups = conn.execute('SELECT * FROM advisory_alias_groups ORDER BY group_key').fetchall()
    first_members = conn.execute('SELECT * FROM advisory_alias_group_members ORDER BY alias_group_id,finding_id').fetchall()
    with conn.transaction():
        persist(conn,scan['scan_id'],doc,{})
    assert conn.execute('SELECT * FROM findings ORDER BY finding_key').fetchall() == first_rows
    assert conn.execute('SELECT * FROM finding_packages ORDER BY finding_id,package_id').fetchall() == first_links
    assert conn.execute('SELECT * FROM advisory_alias_groups ORDER BY group_key').fetchall() == first_groups
    assert conn.execute('SELECT * FROM advisory_alias_group_members ORDER BY alias_group_id,finding_id').fetchall() == first_members
    before=source_snapshot(conn,scan['scan_id'])
    outcome=evaluate_scan(conn,scan)
    assert outcome['status']=='completed', outcome.get('error')
    assert source_snapshot(conn,scan['scan_id'])==before
    @contextmanager
    def connect():
        yield conn
    monkeypatch.setattr(uploads,'connect',connect)
    response=uploads.get_findings(scan['scan_id'],limit=100,offset=0)
    assert response['total']==53
    normalized = {f['finding_id']: f for f in doc['findings']}
    assert len(normalized) == len(response['items'])
    for item in response['items']:
        original = item['evidence']['normalized']
        assert original == normalized[original['finding_id']]
        for entry in original['evidence']:
            raw = doc['raw_results'][entry['source_tool']]
            for part in entry['json_pointer'].strip('/').split('/'):
                raw = raw[int(part)] if isinstance(raw,list) else raw[part.replace('~1','/').replace('~0','~')]
            assert entry['raw'] == raw
    assert response['priority_evaluation']['current_result_available'] is True
    assert all(p['priority'] in ('P0','P1','P2','P3',None)
               for f in response['items'] for p in f['packages'])
    conn.execute("UPDATE scan_runs SET status='partial'")
    report=snapshot_for(conn,scan['scan_id'])
    assert report['priority_evaluation']['current_result_available'] is True
    assert report['layout']=='narrative-v3'
    assert report['primary']['finding_id']==outcome['result']['link_results'][0]['finding_id']
    assert report['primary']['advisories']
    detail=snapshot_for(conn,scan['scan_id'],response['items'][0]['finding_id'])
    assert detail['items'][0]['priority'] in ('P0','P1','P2','P3',None)

def test_1001_rows_real_postgres_http_pagination(database, monkeypatch):
    from backend.app import uploads
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    conn = database
    scan, _, _ = seed(conn)
    sid = scan['scan_id']
    conn.execute('DELETE FROM findings')
    conn.execute('DELETE FROM packages')
    conn.execute("""INSERT INTO packages(scan_id,name,installed_version,lockfile_path,relationship)
        SELECT %s, 'synthetic-' || lpad(i::text,4,'0'),'1.0.0',
        'node_modules/synthetic-' || lpad(i::text,4,'0'),'direct'
        FROM generate_series(1,1001) i""", (sid,))
    conn.execute("""INSERT INTO findings(scan_id,type,finding_key,severity,evidence)
        SELECT %s,'vulnerability','synthetic-' || lpad(i::text,4,'0'),'HIGH',
        jsonb_build_object('test_record',i) FROM generate_series(1,1001) i""", (sid,))
    @contextmanager
    def connect():
        yield conn
    monkeypatch.setattr(uploads,'connect',connect)
    app = FastAPI(); app.include_router(uploads.router)
    client = TestClient(app)
    for resource, key in [('packages','package_id'),('findings','finding_id'),('maintenance','package_id')]:
        items = []
        for offset, expected in [(0,500),(500,500),(1000,1)]:
            response = client.get(f'/scans/{sid}/{resource}?limit=500&offset={offset}')
            assert response.status_code == 200
            body = response.json()
            assert body['total'] == 1001
            assert len(body['items']) == expected
            items.extend(body['items'])
        assert len({r[key] for r in items}) == 1001
        assert client.get(f'/scans/{sid}/{resource}?limit=500&offset=1001').json()['items'] == []
        assert client.get(f'/scans/{sid}/{resource}?limit=501').status_code == 422
        if resource == 'findings':
            assert sorted(r['evidence']['test_record'] for r in items) == list(range(1,1002))


def test_explicit_ghsa_deduplication_survives_storage_api_and_priority(database, monkeypatch):
    """Multiple source IDs, one explicit GHSA; two installs, one Finding."""
    from worker.app.normalizer import normalize_results
    from worker.app.finding_storage import persist
    from backend.app import uploads
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    conn = database
    scan, _, _ = seed(conn)
    sid = scan['scan_id']
    conn.execute('DELETE FROM findings WHERE scan_id=%s', (sid,))
    conn.execute('DELETE FROM packages WHERE scan_id=%s', (sid,))
    package = {'dependencies': {'demo': '1.0.0'}}
    lock = {'lockfileVersion': 3, 'packages': {'': {},
        'node_modules/demo': {'version': '1.0.0'},
        'node_modules/parent/node_modules/demo': {'version': '1.0.0'}}}
    trivy = {'SchemaVersion': 2, 'Results': [{'Type': 'npm', 'Vulnerabilities': [
        {'VulnerabilityID': 'CVE-example-a', 'VendorIDs': ['GHSA-example'],
         'PkgName': 'demo', 'InstalledVersion': '1.0.0', 'Severity': 'CRITICAL', 'FixedVersion': '1.1.0'},
        {'VulnerabilityID': 'CVE-example-b', 'VendorIDs': ['GHSA-example'],
         'PkgName': 'demo', 'InstalledVersion': '1.0.0', 'Severity': 'HIGH', 'FixedVersion': '2.0.0'}]}]}
    osv = {'results': [{'packages': [{'package': {'ecosystem': 'npm', 'name': 'demo', 'version': '1.0.0'},
        'vulnerabilities': [{'id': 'GHSA-example', 'aliases': ['CVE-example-a', 'CVE-example-b'],
                             'database_specific': {'severity': 'HIGH'}}]}]}]}
    doc = normalize_results(package, lock, {'trivy': trivy, 'osv': osv},
        {t: {'status': 'completed'} for t in ('trivy', 'osv')}, scan_id=str(sid))
    assert doc['summary']['findings'] == 1
    for p in doc['packages']:
        conn.execute('INSERT INTO packages(scan_id,name,installed_version,lockfile_path,relationship) VALUES(%s,%s,%s,%s,%s)',
                     (sid, p['name'], p['version'], p['lock_path'], p['dependency_type']))
    with conn.transaction():
        summary = persist(conn, sid, doc, {'synthetic_fixture': True})
    assert summary['deduplication']['before_finding_count'] == 3
    assert summary['deduplication']['after_finding_count'] == 1
    stored = conn.execute('SELECT * FROM findings WHERE scan_id=%s', (sid,)).fetchall()
    links = conn.execute('SELECT * FROM finding_packages WHERE scan_id=%s ORDER BY package_id', (sid,)).fetchall()
    assert len(stored) == 1 and len(links) == 2
    assert stored[0]['evidence']['normalized'] == doc['findings'][0]
    with conn.transaction():
        persist(conn, sid, doc, {'synthetic_fixture': True})
    assert conn.execute('SELECT * FROM findings WHERE scan_id=%s', (sid,)).fetchall() == stored
    assert conn.execute('SELECT * FROM finding_packages WHERE scan_id=%s ORDER BY package_id', (sid,)).fetchall() == links
    before = source_snapshot(conn, sid)
    outcome = evaluate_scan(conn, scan)
    assert outcome['status'] == 'completed'
    assert outcome['result']['summary']['finding_count'] == 1
    assert outcome['result']['summary']['link_count'] == 2
    assert all(x['priority'] == 'P0' for x in outcome['result']['package_results'])
    assert source_snapshot(conn, sid) == before
    @contextmanager
    def connect():
        yield conn
    monkeypatch.setattr(uploads, 'connect', connect)
    app = FastAPI(); app.include_router(uploads.router)
    client = TestClient(app)
    response = client.get(f'/scans/{sid}/findings')
    assert response.status_code == 200
    body = response.json()
    assert body['total'] == 1
    assert body['normalization']['deduplication'] == doc['deduplication']
    assert body['items'][0]['evidence']['normalized'] == doc['findings'][0]
    assert len(body['items'][0]['packages']) == 2
    assert all(p['priority'] == 'P0' for p in body['items'][0]['packages'])
    assert all([c['value'] for c in p['fixed_version_candidates']] == ['1.1.0', '2.0.0']
               for p in body['items'][0]['packages'])
    assert body['priority_evaluation']['summary']['finding_count'] == 1
    assert client.get(f'/scans/{sid}/findings?limit=1&offset=1').json()['items'] == []
    # Changed normalization must never silently rewrite an existing scan.
    changed = json.loads(json.dumps(doc))
    changed['deduplication']['rule_version'] = 'different-policy'
    with pytest.raises(ValueError, match='normalized_source_changed_upload_as_new_scan'):
        with conn.transaction():
            persist(conn, sid, changed, {})


@pytest.mark.parametrize('mode', ['invalid_input', 'build_failure'])
def test_d07_error_preserves_input_and_safe_message(database, monkeypatch, mode):
    from worker.app import priority_storage as storage
    conn = database
    scan, _, _ = seed(conn)
    before = source_snapshot(conn, scan['scan_id'])
    original = storage.build_payload
    def broken(snapshot):
        if mode == 'build_failure':
            raise ValueError('postgresql://user:synthetic-password@db/private')
        payload = original(snapshot)
        payload['test_only'] = True
        return payload
    monkeypatch.setattr(storage, 'build_payload', broken)
    outcome = evaluate_scan(conn, scan)
    row = conn.execute('SELECT * FROM priority_evaluations').fetchone()
    assert row['status'] == ('invalid_input' if mode == 'invalid_input' else 'failed')
    assert row['result'] is None
    assert row['attempted_payload'] == outcome['attempted_payload']
    if mode == 'invalid_input':
        assert row['attempted_payload']['test_only'] is True
        assert row['error']['code'] == 'TEST_DATA_NOT_ALLOWED'
        assert row['error']['field_path'] == 'test_only'
    else:
        assert row['attempted_payload'] is None
        assert row['error']['code'] == 'PRIORITY_INPUT_BUILD_FAILED'
    assert row['error']['message']
    assert row['error']['message_policy'] == 'safe-stage-summary-v1'
    assert 'synthetic-password' not in json.dumps(row, default=str)
    assert source_snapshot(conn, scan['scan_id']) == before
    marker = conn.execute('SELECT tool_status FROM scan_runs').fetchone()['tool_status']
    state, result = load_priority(conn, scan['scan_id'], marker)
    assert state['current_result_available'] is False
    assert result is None


def test_d07_additive_migration_preserves_existing_evaluation(database):
    conn = database
    scan, _, _ = seed(conn)
    evaluate_scan(conn, scan)
    before = conn.execute('SELECT * FROM priority_evaluations').fetchone()
    # Simulate the previous deployed table, then apply the real migration twice.
    conn.execute('ALTER TABLE priority_evaluations DROP COLUMN attempted_payload')
    root = Path(__file__).resolve().parents[2]
    body = (root / 'db/oss_closeup_v2_2_priority.sql').read_text()
    sql_body = '\n'.join(line for line in body.splitlines() if not line.startswith('\\'))
    conn.execute(sql_body)
    conn.execute(sql_body)
    assert conn.execute('SELECT * FROM priority_evaluations').fetchone() == before
