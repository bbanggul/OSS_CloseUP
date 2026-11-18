"""Real PostgreSQL tests, isolated schemas only; set COMPARISON_TEST_DSN explicitly."""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker
import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
import pytest

from app import scan_compare_api as api
from app import package_reader
from app.package_view import build_view
from app.main import app
from app.scan_material import load_scan_material, PACKAGE_FIELDS, PACKAGE_SCAN_FIELDS
from app.scan_compare import LIMITS
from compare_fixtures import FIXTURES, pair, uid, refresh_counts

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = Draft202012Validator(json.loads((ROOT/'backend/app/schemas/compare-response.schema.json').read_text()), format_checker=FormatChecker())


@pytest.fixture
def database():
    dsn = os.environ.get('COMPARISON_TEST_DSN')
    if not dsn: pytest.skip('COMPARISON_TEST_DSN required for isolated PostgreSQL tests')
    schema = 'comparison_test_' + uuid4().hex
    @contextmanager
    def connect():
        with psycopg.connect(dsn, autocommit=True, row_factory=dict_row, options=f'-c search_path={schema}') as conn:
            yield conn
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
        try:
            with connect() as conn:
                for path in sorted((ROOT/'db').glob('*.sql'), key=lambda p: (p.name != 'oss_closeup_v2.sql', p.name)):
                    conn.execute('\n'.join(line for line in path.read_text().splitlines() if not line.startswith('\\')))
                yield conn, connect
        finally:
            admin.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))


def insert(conn, table, row):
    json_fields = {'tool_status','identifiers','evidence','metadata'}
    query = sql.SQL('INSERT INTO {} ({}) VALUES ({})').format(sql.Identifier(table),
        sql.SQL(',').join(map(sql.Identifier, row)), sql.SQL(',').join(sql.Placeholder() for _ in row))
    conn.execute(query, [Jsonb(v) if k in json_fields else v for k, v in row.items()])


def seed(conn, a, b):
    insert(conn, 'projects', a['project'])
    if b['project']['project_id'] != a['project']['project_id']: insert(conn, 'projects', b['project'])
    for data in (a, b):
        insert(conn, 'scan_runs', data['scan'])
        for row in data['packages']: insert(conn, 'packages', row)
        for row in data['findings']: insert(conn, 'findings', dict(row, finding_key=row['finding_id']))
        for row in data['links']: insert(conn, 'finding_packages', row)
        for row in data['source_runs']: insert(conn, 'scan_tool_runs', row)
        for row in data['artifacts']:
            insert(conn, 'scan_artifacts', dict(row, storage_key='test/' + row['artifact_id'], size_bytes=1))


def request(client, a, b):
    return client.get(f"/scans/{b['scan']['scan_id']}/compare", params={'base': a['scan']['scan_id']})


def rows(conn):
    return {name: conn.execute(sql.SQL('SELECT * FROM {} ORDER BY 1').format(sql.Identifier(name))).fetchall()
            for name in ('projects','scan_runs','packages','findings','finding_packages','scan_tool_runs','scan_artifacts','ai_analyses','priority_evaluations')}


@pytest.mark.parametrize('name', [p.stem for p in sorted((FIXTURES / 'examples').glob('*.json'))])
def test_http_contract_and_database_are_unchanged(database, monkeypatch, name):
    conn, connect = database
    a, b, expected = pair(name)
    seed(conn, a, b)
    monkeypatch.setattr(api, 'connect', connect)
    before = rows(conn)
    client = TestClient(app)
    response = request(client, a, b)
    assert response.status_code == 200, response.text
    result = response.json()
    VALIDATOR.validate(result)
    assert result['summary'] == expected['summary']
    assert result['finding_counts'] == expected['finding_counts']
    assert request(client, a, b).json() == result
    assert rows(conn) == before


def test_both_scans_use_one_readonly_repeatable_snapshot(database, monkeypatch):
    conn, connect = database
    a, b, _ = pair()
    seed(conn, a, b)
    monkeypatch.setattr(api, 'connect', connect)
    original = api.load_scan_material
    observed = []
    def changing_read(read_conn, sid, **kwargs):
        observed.append((read_conn.execute('SHOW transaction_isolation').fetchone()['transaction_isolation'],
                         read_conn.execute('SHOW transaction_read_only').fetchone()['transaction_read_only']))
        result = original(read_conn, sid, **kwargs)
        if str(sid) == a['scan']['scan_id']:
            with connect() as writer:
                writer.execute('UPDATE projects SET name=%s', ('concurrently-renamed',))
                writer.execute('UPDATE scan_runs SET tool_status=%s WHERE scan_id=%s', (Jsonb({}), b['scan']['scan_id']))
        return result
    monkeypatch.setattr(api, 'load_scan_material', changing_read)
    result = request(TestClient(app), a, b).json()
    assert result['project']['name'] == a['project']['name']
    assert result['target']['findings_usable'] is True
    assert observed == [('repeatable read','on'), ('repeatable read','on')]
    monkeypatch.setattr(api, 'load_scan_material', original)
    later = request(TestClient(app), a, b).json()
    assert later['project']['name'] == 'concurrently-renamed'
    assert later['target']['findings_usable'] is False
    assert later['comparison_id'] != result['comparison_id']


@pytest.mark.parametrize('kind,status,code', [('missing',404,'scan_not_found'), ('project',422,'different_project'),
    ('running',409,'scan_processing'), ('queued',409,'scan_processing'), ('limit',422,'comparison_limit_exceeded')])
def test_real_preflight_errors(database, monkeypatch, kind, status, code):
    conn, connect = database
    a, b, _ = pair()
    if kind == 'project':
        b['project']['project_id'] = b['scan']['project_id'] = uid('another-project')
    if kind in ('running','queued'): b['scan']['status'] = kind
    seed(conn, a, b)
    if kind == 'missing': b['scan']['scan_id'] = uid('nonexistent')
    if kind == 'limit': monkeypatch.setitem(LIMITS, 'installations', 1)
    monkeypatch.setattr(api, 'connect', connect)
    response = request(TestClient(app), a, b)
    assert response.status_code == status, response.text
    assert response.json()['detail']['code'] == code


def test_common_reader_preserves_existing_package_snapshot(database):
    conn, _ = database
    a, b, _ = pair()
    seed(conn, a, b)
    sid = a['scan']['scan_id']
    # Independent old projections, not the new adapter, establish the regression oracle.
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute('SELECT ' + ','.join(PACKAGE_SCAN_FIELDS) + ' FROM scan_runs WHERE scan_id=%s', (sid,))
        scan = cur.fetchone()
        cur.execute('SELECT ' + ','.join(PACKAGE_FIELDS) + ' FROM packages WHERE scan_id=%s ORDER BY package_id', (sid,))
        packages = cur.fetchall()
        cur.execute("SELECT * FROM findings WHERE scan_id=%s AND type='vulnerability' ORDER BY finding_id", (sid,))
        findings = cur.fetchall()
        cur.execute('SELECT * FROM finding_packages WHERE scan_id=%s ORDER BY finding_id,package_id', (sid,))
        links = cur.fetchall()
    state, result = package_reader.load_priority(conn, sid, scan['tool_status'])
    expected = build_view(scan, packages, findings, links, state, result)
    assert package_reader.load_package_view(conn, sid) == expected
    conn.execute("UPDATE scan_runs SET input_package_lock_sha256=%s WHERE scan_id=%s", ('f'*64, sid))
    conn.execute("UPDATE projects SET name='new name'")
    assert package_reader.load_package_view(conn, sid) == expected


def test_previous_attempt_success_is_not_current_evidence(database, monkeypatch):
    conn, connect = database
    a, b, _ = pair('02-version-not-detected')
    seed(conn, a, b)
    conn.execute('UPDATE scan_runs SET attempt_count=2 WHERE scan_id=%s', (b['scan']['scan_id'],))
    monkeypatch.setattr(api, 'connect', connect)
    result = request(TestClient(app), a, b).json()
    assert result['summary']['not_detected'] == 0
    assert result['items'][0]['reason'] == 'target_incomplete'
    assert all(s['tool_run_id'] is None for s in result['target']['sources'].values())


def test_real_normalizer_storage_to_comparison_http(database, monkeypatch):
    """Replay recorded scanner evidence through the actual normalizer and persistence."""
    from worker.app.normalizer import normalize_results
    from worker.app.finding_storage import persist
    conn, connect = database
    a, b, _ = pair()
    # Seed valid run/artifact metadata, then replace synthetic findings via production persist().
    for data in (a, b):
        data['findings'] = []; data['links'] = []; data['packages'] = []
        data['scan']['tool_status']['normalization'] = {}
    seed(conn, a, b)
    fixture = json.loads((ROOT/'worker/tests/fixtures/normalized-final.json').read_text())
    package = json.loads((ROOT/'samples/poc77/package.json').read_text())
    lock = json.loads((ROOT/'samples/poc77/package-lock.json').read_text())
    for data in (a, b):
        sid = data['scan']['scan_id']
        doc = normalize_results(package, lock, fixture['raw_results'], fixture['tool_status'], scan_id=sid)
        for p in doc['packages']:
            insert(conn, 'packages', dict(scan_id=sid, name=p['name'], installed_version=p['version'],
                lockfile_path=p['lock_path'], relationship=p['dependency_type']))
        provenance = {r['tool_name']: dict(tool_run_id=r['tool_run_id'], attempt_no=1,
            artifact_id=next(x['artifact_id'] for x in data['artifacts'] if x['tool_run_id'] == r['tool_run_id']), sha256='a'*64)
            for r in data['source_runs']}
        with conn.transaction():
            persist(conn, sid, doc, provenance)
        storage = dict(status='completed', total_including_root=len(doc['packages']), root=0,
            direct=doc['summary']['direct_packages'], indirect=doc['summary']['indirect_packages'])
        conn.execute('UPDATE scan_runs SET tool_status=tool_status || %s WHERE scan_id=%s', (Jsonb({'package_storage': storage}), sid))
    monkeypatch.setattr(api, 'connect', connect)
    response = request(TestClient(app), a, b)
    assert response.status_code == 200, response.text
    result = response.json()
    VALIDATOR.validate(result)
    assert result['base']['findings_usable'] and result['target']['findings_usable']
    assert result['finding_counts']['base']['stored'] == result['finding_counts']['target']['stored'] == 53
    assert result['summary']['new'] == result['summary']['not_detected'] == 0
    assert result['summary']['persisting'] > 0
    # Same input alone is not a proof: ambiguous original records stay under review.
    assert all(i['reason'] in ('matched_identity','identifier_review_required') for i in result['items'])
    before = rows(conn)
    assert request(TestClient(app), a, b).json() == result
    assert rows(conn) == before


def test_10000_installation_boundary_and_10001_preflight_rejection(database, monkeypatch):
    conn, connect = database
    a, b, _ = pair('15-confirmed-zero')
    for data in (a, b):
        data['packages'] = []
        refresh_counts(data)
    seed(conn, a, b)
    for data in (a, b):
        sid = data['scan']['scan_id']
        conn.execute("""INSERT INTO packages(scan_id,name,installed_version,lockfile_path,relationship)
            SELECT %s,'demo-' || i,'1.0.0','node_modules/demo-' || i,'direct' FROM generate_series(1,5000) AS i""", (sid,))
        storage = dict(status='completed', total_including_root=5000, root=0, direct=5000, indirect=0)
        conn.execute('UPDATE scan_runs SET tool_status=tool_status || %s WHERE scan_id=%s', (Jsonb({'package_storage': storage}), sid))
    monkeypatch.setattr(api, 'connect', connect)
    response = request(TestClient(app), a, b)
    assert response.status_code == 200, response.text[:1000]
    result = response.json()
    assert len(result['installations']) == 5000 and result['items'] == []
    assert result['comparison_complete'] is True
    insert(conn, 'packages', dict(scan_id=b['scan']['scan_id'], name='one-over', installed_version='1.0.0',
        lockfile_path='node_modules/one-over', relationship='direct'))
    def must_not_load(*args, **kwargs): raise AssertionError('limit must be checked before loading evidence')
    monkeypatch.setattr(api, 'load_scan_material', must_not_load)
    response = request(TestClient(app), a, b)
    assert response.status_code == 422
    assert response.json()['detail']['limit'] == {'dimension': 'installations', 'maximum': 10000, 'actual': 10001}
