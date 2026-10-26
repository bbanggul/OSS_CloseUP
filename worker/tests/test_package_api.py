"""Real PostgreSQL + registered HTTP routes for the package contract."""
from contextlib import contextmanager
from copy import deepcopy
import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb
from test_priority_postgres import database, seed
from worker.app.priority_storage import evaluate_scan
from backend.app import package_api
from backend.app.main import app


@pytest.fixture
def scenario(database, monkeypatch):
    conn = database
    scan, fid, pid = seed(conn)
    states = {'package_storage': {'status': 'completed'}, 'normalization': {
        'status': 'completed', 'roundtrip_verified': True, 'fingerprint': 'normalization-source-1',
        'tool_status': {t: {'status': 'completed'} for t in ('trivy', 'osv')}}}
    conn.execute('UPDATE scan_runs SET tool_status=%s WHERE scan_id=%s', (Jsonb(states), scan['scan_id']))
    @contextmanager
    def connect():
        yield conn
    monkeypatch.setattr(package_api, 'connect', connect)
    return conn, scan, fid, pid, TestClient(app)


def add_package(conn, sid, name, version='1.0.0', relationship='direct', ecosystem='npm'):
    pid = uuid4()
    conn.execute('INSERT INTO packages(package_id,scan_id,ecosystem,name,installed_version,lockfile_path,relationship) VALUES(%s,%s,%s,%s,%s,%s,%s)',
        (pid, sid, ecosystem, name, version, 'node_modules/' + str(pid), relationship))
    return pid


def add_finding(conn, sid, severity='HIGH', normalized=None, manual=False):
    fid = uuid4()
    normalized = normalized or {'priority_input_eligible': True, 'severity_observations': []}
    conn.execute("INSERT INTO findings(finding_id,scan_id,type,finding_key,severity,evidence,manual_review_required) VALUES(%s,%s,'vulnerability',%s,%s,%s,%s)",
        (fid, sid, str(fid), severity, Jsonb({'normalized': normalized}), manual))
    return fid


def link(conn, sid, fid, pid, candidates=None, role='affected'):
    candidates = candidates or []
    conn.execute('INSERT INTO finding_packages(scan_id,finding_id,package_id,role,fixed_version_candidates,evidence) VALUES(%s,%s,%s,%s,%s,%s)',
        (sid, fid, pid, role, Jsonb(candidates), Jsonb({'fix_information': 'candidates_available' if candidates else 'not_reported'})))


def url(scan, suffix='vulnerable-packages'):
    return f"/scans/{scan['scan_id']}/{suffix}"


def get(client, path, **params):
    r = client.get(path, params=params)
    assert r.status_code == 200, r.text
    return r.json()


def test_group_detail_all_fixes_and_global_rank_survive_filter_pagination(scenario):
    conn, scan, fid, pid, client = scenario
    sid = scan['scan_id']
    duplicate = add_package(conn, sid, 'demo', relationship='direct')
    link(conn, sid, fid, duplicate)
    low = add_finding(conn, sid, 'LOW')
    candidate = {'value': '>=2.0.0', 'raw': '>=2.0.0', 'source_tool': 'osv', 'json_pointer': '/synthetic/0'}
    link(conn, sid, low, pid, [candidate])
    first = add_package(conn, sid, 'alpha')
    link(conn, sid, add_finding(conn, sid, 'CRITICAL'), first, [candidate])
    unknown = add_package(conn, sid, 'unknown')
    link(conn, sid, add_finding(conn, sid, 'UNKNOWN'), unknown, [candidate])
    assert evaluate_scan(conn, scan)['status'] == 'completed'
    before = conn.execute('SELECT * FROM findings ORDER BY finding_id').fetchall()
    response = get(client, url(scan))
    assert response['result_state'] == 'ready'
    assert response['total'] == 3 and response['unique_finding_count'] == 4
    assert [g['global_rank'] for g in response['items']] == [1, 2, None]
    demo = response['items'][1]
    assert demo['finding_count'] == 2 and len(demo['installations']) == 2
    assert sum(demo['severity_counts'].values()) == 2
    assert demo['has_fix_candidate_at_priority'] is False  # LOW fixes don't promote CRITICAL.
    assert demo['representative_finding_count'] == 1
    selected = get(client, url(scan), q='DEMO', severity='LOW', relationship='indirect', limit=1,
                   snapshot_id=response['snapshot_id'])
    assert selected['total'] == 1 and selected['total_unfiltered'] == 3
    assert selected['items'][0]['global_rank'] == 2
    page = get(client, url(scan), limit=1, offset=1, snapshot_id=response['snapshot_id'])
    assert page['items'][0] == selected['items'][0]
    detail = get(client, url(scan) + '/' + demo['package_group_id'], snapshot_id=response['snapshot_id'])['item']
    assert detail['global_rank'] == 2 and len(detail['findings']) == 2
    by_id = {f['finding_id']: f for f in detail['findings']}
    assert len(by_id[str(fid)]['installation_links']) == 2
    assert by_id[str(low)]['installation_links'][0]['fixed_version_candidates'] == [candidate]
    assert detail['full_remediation_status'] == 'not_evaluated'
    assert response['items'][-1]['representative_finding_ids'] == []
    assert response['items'][-1]['priority_status'] == 'severity_unknown'
    assert get(client, url(scan), offset=3)['empty_reason'] == 'page_out_of_range'
    assert get(client, url(scan), q='missing')['empty_reason'] == 'no_matches'
    assert conn.execute('SELECT * FROM findings ORDER BY finding_id').fetchall() == before


def test_group_id_boundaries_and_stability(scenario):
    conn, scan, fid, _, client = scenario
    for name, version, eco in [('demo','2.0.0','npm'),('demo','1.0.0','pip'),
                                ('absent',None,'npm'),('absent',None,'npm')]:
        pid = add_package(conn, scan['scan_id'], name, version, ecosystem=eco)
        link(conn, scan['scan_id'], fid, pid)
    evaluate_scan(conn, scan)
    a, b = get(client, url(scan)), get(client, url(scan))
    assert a == b and a['total'] == 5
    assert len({g['package_group_id'] for g in a['items']}) == 5
    assert a['unique_finding_count'] == 1
    assert sum(g['finding_count'] for g in a['items']) == 5  # Never the scan-wide count.
    assert get(client, url(scan, 'unlinked-vulnerabilities'))['total'] == 0


@pytest.mark.parametrize('scan_status,norm,expected', [
    ('queued', {}, 'processing'), ('running', {'status':'running'}, 'processing'),
    ('failed', {'status':'failed'}, 'failed'), ('completed', {}, 'unavailable'),
    ('partial', {'status':'completed','roundtrip_verified':False}, 'unavailable')])
def test_unready_is_not_zero_and_detail_is_unavailable(scenario, scan_status, norm, expected):
    conn, scan, _, _, client = scenario
    conn.execute('UPDATE scan_runs SET status=%s,tool_status=%s', (scan_status, Jsonb({'normalization':norm})))
    data = get(client, url(scan))
    assert data['result_state'] == expected and data['empty_reason'] == expected
    assert data['items'] == [] and data['total'] is None and data['unique_finding_count'] is None
    assert data['zero_findings_confirmed'] is False
    assert client.get(url(scan)+'/anything').status_code == 409
    assert client.get(url(scan,'findings/anything')).status_code == 409


def test_normal_zero_partial_zero_and_unlinked_only_are_distinct(scenario):
    conn, scan, _, _, client = scenario
    conn.execute('DELETE FROM findings')
    evaluate_scan(conn, scan)
    data = get(client, url(scan))
    assert data['total'] == 0 and data['zero_findings_confirmed'] is True
    assert data['empty_reason'] == 'no_vulnerabilities'
    conn.execute("UPDATE scan_runs SET tool_status=jsonb_set(tool_status,'{normalization,status}','\"partial\"')")
    data = get(client, url(scan))
    assert data['result_state'] == 'partial' and data['zero_findings_confirmed'] is False
    fid = add_finding(conn, scan['scan_id'])
    data = get(client, url(scan))
    assert data['total'] == 0 and data['unlinked_finding_count'] == 1
    assert data['unique_finding_count'] == 1
    assert get(client, url(scan,'unlinked-vulnerabilities'))['items'][0]['finding_id'] == str(fid)


def test_root_and_nonaffected_links_do_not_hide_unlinked_findings(scenario):
    conn, scan, _, pid, client = scenario
    sid = scan['scan_id']
    root = add_package(conn, sid, 'project', relationship='root')
    a, b = add_finding(conn, sid), add_finding(conn, sid)
    link(conn, sid, a, root)
    link(conn, sid, b, pid, role='entry_point')
    evaluate_scan(conn, scan)
    listing = get(client, url(scan))
    data = get(client, url(scan,'unlinked-vulnerabilities'))
    assert listing['unique_finding_count'] == 3 and listing['unlinked_finding_count'] == data['total'] == 2
    assert {f['finding_id'] for f in data['items']} == {str(a),str(b)}
    assert all(f['installation_links'] and f['global_rank'] is None for f in data['items'])


def test_failed_evaluation_does_not_reuse_historical_grade(scenario):
    conn, scan, fid, _, client = scenario
    evaluate_scan(conn, scan)
    first = get(client,url(scan))
    assert first['items'][0]['global_rank'] == 1
    conn.execute("UPDATE finding_packages SET priority='P0'")  # Historical link grades must not leak.
    conn.execute("UPDATE scan_runs SET tool_status=jsonb_set(tool_status,'{priority}',%s)",
        (Jsonb({'status':'failed','current_result_available':False,'error_code':'PRIORITY_WRITE_FAILED'}),))
    data = get(client,url(scan))
    assert data['result_state'] == 'ready' and data['items'][0]['finding_count'] == 1
    assert data['items'][0]['priority_status'] == 'failed'
    for key in ('priority','global_rank','representative_finding_ids','representative_links','has_fix_candidate_at_priority'):
        assert data['items'][0][key] is None
    assert get(client,url(scan,'findings/'+str(fid)))['item']['priority'] is None
    assert client.get(url(scan),params={'snapshot_id':first['snapshot_id']}).status_code == 409


def test_changed_links_invalidate_current_priority(scenario):
    conn, scan, _, pid, client = scenario
    evaluate_scan(conn, scan)
    link(conn, scan['scan_id'], add_finding(conn, scan['scan_id']), pid)
    data = get(client,url(scan))
    assert data['priority_evaluation']['current_result_available'] is False
    assert data['items'][0]['global_rank'] is None
    assert data['items'][0]['priority_status'] == 'unavailable'


def test_dedup_review_requires_explicit_current_evidence(scenario):
    conn, scan, _, _, client = scenario
    assert get(client,url(scan))['deduplication_status'] == 'review_pending'
    review={'status':'completed','normalization_fingerprint':'normalization-source-1',
            'reviewed_by':'reviewer','reviewed_at':'2026-10-26T00:00:00Z','evidence_ref':'review/test'}
    conn.execute("UPDATE scan_runs SET tool_status=tool_status || %s", (Jsonb({'deduplication_review':review}),))
    assert get(client,url(scan))['deduplication_status'] == 'completed'
    conn.execute('UPDATE findings SET manual_review_required=true')
    assert get(client,url(scan))['deduplication_status'] == 'review_pending'
    conn.execute('UPDATE findings SET manual_review_required=false')
    review['normalization_fingerprint']='old'
    conn.execute("UPDATE scan_runs SET tool_status=tool_status || %s", (Jsonb({'deduplication_review':review}),))
    assert get(client,url(scan))['deduplication_status'] == 'review_pending'


def test_canonical_resolution_only_uses_recorded_same_scan_merge(scenario):
    conn, scan, fid, _, client = scenario
    norm={'finding_id':'finding-new','merge_basis':{'kind':'explicit_ghsa_identity','source_finding_ids':['finding-old']}}
    conn.execute('UPDATE findings SET evidence=%s WHERE finding_id=%s', (Jsonb({'normalized':norm}),fid))
    direct=get(client,url(scan,'findings/'+str(fid)))
    merged=get(client,url(scan,'findings/finding-old'))
    assert direct['resolution']=='direct' and merged['resolution']=='merged'
    assert merged['canonical_finding_id']==str(fid)
    assert get(client,url(scan,'findings/finding-new'))['canonical_finding_id']==str(fid)
    assert client.get(url(scan,'findings/GHSA-unknown')).status_code == 404
    add_finding(conn,scan['scan_id'],normalized=norm)
    assert client.get(url(scan,'findings/finding-old')).status_code == 409
    other, _, _ = seed(conn)
    assert client.get(url(other,'findings/finding-old')).status_code == 404


def test_http_validation_and_scope(scenario):
    conn, scan, _, _, client=scenario
    for params in ({'limit':501},{'offset':-1},{'priority':'INFO'},{'severity':'BAD'},{'relationship':'root'}):
        assert client.get(url(scan),params=params).status_code==422
    assert client.get('/scans/not-a-uuid/vulnerable-packages').status_code==422
    assert client.get('/scans/'+str(uuid4())+'/vulnerable-packages').status_code==404
    assert client.get(url(scan)+'/missing').status_code==404


def test_more_than_500_groups_keep_global_rank_and_no_omissions(scenario):
    conn,scan,_,_,client=scenario
    sid=scan['scan_id']
    for i in range(501):
        pid=add_package(conn,sid,f'group-{i:04d}')
        link(conn,sid,add_finding(conn,sid,'HIGH'),pid)
    evaluate_scan(conn,scan)
    first=get(client,url(scan),limit=500)
    second=get(client,url(scan),limit=500,offset=500,snapshot_id=first['snapshot_id'])
    assert first['total']==502 and len(second['items'])==2
    rows=first['items']+second['items']
    assert len({x['package_group_id'] for x in rows})==502
    assert [x['global_rank'] for x in rows]==list(range(1,503))
    filtered=get(client,url(scan),q='group-0500')
    assert filtered['items'][0]['global_rank']==502


def test_repeatable_read_and_snapshot_token_handle_concurrent_publication(scenario, monkeypatch):
    import os
    import psycopg
    from psycopg import sql
    conn, scan, _, _, client = scenario
    evaluate_scan(conn, scan)
    schema = conn.execute('SELECT current_schema() AS name').fetchone()['name']
    original = package_api.load_priority
    published = False
    def publish_during_read(connection, sid, states):
        nonlocal published
        if not published:
            with psycopg.connect(os.environ['PRIORITY_TEST_DSN'], autocommit=True) as writer:
                writer.execute(sql.SQL('SET search_path TO {}').format(sql.Identifier(schema)))
                writer.execute("UPDATE scan_runs SET tool_status=jsonb_set(tool_status,'{priority}',%s) WHERE scan_id=%s",
                    (Jsonb({'status':'failed','current_result_available':False}), sid))
            published = True
        return original(connection, sid, states)
    monkeypatch.setattr(package_api, 'load_priority', publish_during_read)
    first = get(client, url(scan))
    assert first['priority_evaluation']['current_result_available'] is True
    assert first['items'][0]['global_rank'] == 1
    second = get(client, url(scan))
    assert second['priority_evaluation']['current_result_available'] is False
    assert second['items'][0]['global_rank'] is None
    assert first['snapshot_id'] != second['snapshot_id']
    assert client.get(url(scan), params={'snapshot_id':first['snapshot_id']}).status_code == 409


def test_database_failure_is_service_error_not_empty_result(scenario, monkeypatch):
    import psycopg
    _, scan, _, _, client = scenario
    @contextmanager
    def broken():
        raise psycopg.OperationalError('synthetic private connection string')
        yield
    monkeypatch.setattr(package_api, 'connect', broken)
    response = client.get(url(scan))
    assert response.status_code == 503
    assert response.json()['detail'] == 'database_unavailable'
    assert 'private' not in response.text


def test_tie_break_counts_unique_representatives_and_unknown_ignores_fixes(scenario):
    conn, scan, _, _, client = scenario
    sid = scan['scan_id']
    zeta = add_package(conn, sid, 'zeta')
    zeta2 = add_package(conn, sid, 'zeta', relationship='indirect')
    one, two = add_finding(conn, sid, 'CRITICAL'), add_finding(conn, sid, 'CRITICAL')
    link(conn,sid,one,zeta); link(conn,sid,one,zeta2); link(conn,sid,two,zeta)
    alpha = add_package(conn,sid,'alpha')
    link(conn,sid,add_finding(conn,sid,'CRITICAL'),alpha)
    for name, candidates in [('unknown-a',[]),('unknown-z',[{'value':'2.0','source_tool':'osv'}])]:
        pid=add_package(conn,sid,name)
        link(conn,sid,add_finding(conn,sid,'UNKNOWN'),pid,candidates)
    evaluate_scan(conn,scan)
    rows=get(client,url(scan))['items']
    assert [g['name'] for g in rows]==['zeta','alpha','demo','unknown-a','unknown-z']
    assert rows[0]['representative_finding_count']==2
    assert [g['global_rank'] for g in rows]==[1,2,3,None,None]


@pytest.mark.parametrize('change',['severity','candidates'])
def test_changed_calculation_evidence_masks_published_rank(scenario, change):
    conn,scan,_,_,client=scenario
    evaluate_scan(conn,scan)
    if change=='severity':
        conn.execute("UPDATE findings SET severity='LOW'")
    else:
        conn.execute("UPDATE finding_packages SET fixed_version_candidates=%s",(Jsonb([{'value':'2.0','source_tool':'osv'}]),))
    data=get(client,url(scan))
    assert data['priority_evaluation']['current_result_available'] is False
    assert data['items'][0]['global_rank'] is None
    assert data['items'][0]['priority_status']=='unavailable'
