import io
import json
from contextlib import contextmanager
from unittest.mock import MagicMock
import pytest
import psycopg
from fastapi.testclient import TestClient
from app.main import app
from app import uploads

@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv('SCAN_STORAGE_ROOT', str(tmp_path))
    conn = MagicMock()
    @contextmanager
    def connect():
        yield conn
    monkeypatch.setattr(uploads, 'connect', connect)
    return TestClient(app), tmp_path, conn

def files(package=None, lock=None):
    package = package if package is not None else {'name': 'demo', 'version': '1.0.0'}
    lock = lock if lock is not None else {'name': 'demo', 'lockfileVersion': 3, 'packages': {'': package}}
    return {'package_json': ('package.json', json.dumps(package)), 'package_lock': ('package-lock.json', json.dumps(lock))}

def test_success_and_exact_artifact_bytes(setup):
    client, root, conn = setup
    payload = files()
    r = client.post('/scans', files=payload)
    assert r.status_code == 202, r.text
    assert r.json()['status'] == 'queued'
    d = root / r.json()['scan_id']
    assert (d / 'package.json').read_bytes() == payload['package_json'][1].encode()
    assert (d / 'package-lock.json').exists()
    assert conn.execute.call_count == 4

@pytest.mark.parametrize('bad', ['[]', '{', '{"name": "a", "name": "b"}', '{"name": NaN}'])
def test_bad_json_no_side_effects(setup, bad):
    client, root, conn = setup
    f = files(); f['package_json'] = ('package.json', bad)
    assert client.post('/scans', files=f).status_code == 422
    assert not list(root.iterdir())
    conn.execute.assert_not_called()

def test_missing_file(setup):
    client, _, _ = setup
    assert client.post('/scans', files={'package_json': ('package.json', '{}')}).status_code == 422

@pytest.mark.parametrize('lock', [
    {'lockfileVersion': 1},
    {'lockfileVersion': 3, 'packages': {'': {'name':'other'}}},
    {'lockfileVersion': 3, 'packages': {'': {'dependencies': {'x': '1'}}}},
    {'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/x': {'link': True}}},
])
def test_bad_lock(setup, lock):
    client, root, _ = setup
    assert client.post('/scans', files=files(lock=lock)).status_code == 422
    assert not list(root.iterdir())

def test_path_filename(setup):
    client, root, _ = setup
    f=files();f['package_json']=('../package.json','{}')
    assert client.post('/scans',files=f).status_code == 422
    assert not list(root.iterdir())

def test_file_and_body_limits(setup):
    client, root, _ = setup
    f=files();f['package_json']=('package.json', b' '*(uploads.PACKAGE_LIMIT+1))
    assert client.post('/scans',files=f).status_code == 413
    assert client.post('/scans',content=b'x'*(uploads.BODY_LIMIT+1)).status_code == 413
    assert not list(root.iterdir())

def test_db_failure_preserves_files_for_reconciliation(setup, monkeypatch):
    client, root, _ = setup
    def fail(): raise psycopg.OperationalError('secret-test-password')
    monkeypatch.setattr(uploads,'connect',fail)
    r=client.post('/scans',files=files())
    assert r.status_code == 503
    assert 'secret-test-password' not in r.text
    assert len(list(root.iterdir())) == 1

def test_status_not_found_and_bad_uuid(setup):
    client, _, conn = setup
    conn.cursor.return_value.__enter__.return_value.fetchone.return_value = None
    assert client.get('/scans/00000000-0000-0000-0000-000000000001').status_code == 404
    assert client.get('/scans/not-a-uuid').status_code == 422

def test_real_sample(setup):
    from pathlib import Path
    client, _, _ = setup
    folder=Path(__file__).resolve().parents[2]/'samples'/'poc77'
    with (folder/'package.json').open('rb') as a, (folder/'package-lock.json').open('rb') as b:
        r=client.post('/scans', files={'package_json':('package.json',a),'package_lock':('package-lock.json',b)})
    assert r.status_code == 202, r.text


def test_findings_pending_and_pagination(setup):
    client, _, conn = setup
    cur = conn.cursor.return_value.__enter__.return_value
    cur.fetchone.side_effect = [{'tool_status':{}},{'total':0}]
    cur.fetchall.return_value = []
    r = client.get('/scans/00000000-0000-0000-0000-000000000001/findings?limit=10')
    assert r.status_code == 200
    assert r.json()['normalization']=={'status':'pending'}
    assert r.json()['items']==[]
    assert client.get('/scans/00000000-0000-0000-0000-000000000001/findings?limit=501').status_code==422


def test_findings_not_found(setup):
    client, _, conn = setup
    conn.cursor.return_value.__enter__.return_value.fetchone.return_value = None
    assert client.get('/scans/00000000-0000-0000-0000-000000000001/findings').status_code==404


def test_rescan_reuses_explicit_project_without_overwriting_metadata(setup):
    client, root, conn = setup
    project = '11111111-1111-1111-1111-111111111111'
    conn.execute.return_value.fetchone.return_value = (project,)
    response = client.post('/scans', files=files(), data={'project_id': project})
    assert response.status_code == 202, response.text
    assert response.json()['project_id'] == project
    calls = conn.execute.call_args_list
    assert not any('INSERT INTO projects' in call.args[0] or 'UPDATE projects' in call.args[0] for call in calls)
    insert = next(call for call in calls if 'INSERT INTO scan_runs' in call.args[0])
    assert str(insert.args[1][1]) == project
    assert (root / response.json()['scan_id'] / 'package-lock.json').exists()


def test_unknown_project_rejected_before_file_writes(setup):
    client, root, conn = setup
    conn.execute.return_value.fetchone.return_value = None
    response = client.post('/scans', files=files(), data={'project_id': '11111111-1111-1111-1111-111111111111'})
    assert response.status_code == 404
    assert not list(root.iterdir())
    assert not any('INSERT' in call.args[0] for call in conn.execute.call_args_list)


def test_invalid_project_id_rejected_before_file_writes(setup):
    client, root, conn = setup
    response = client.post('/scans', files=files(), data={'project_id': 'bad-id'})
    assert response.status_code == 422
    assert not list(root.iterdir())
    conn.execute.assert_not_called()


def test_project_history_scoped_and_paginated(setup):
    client, _, conn = setup
    project = '11111111-1111-1111-1111-111111111111'
    cur = conn.cursor.return_value.__enter__.return_value
    cur.fetchone.side_effect = [{'project_id': project, 'name': 'demo'}, {'total': 51}]
    cur.fetchall.return_value = [{'scan_id': '22222222-2222-2222-2222-222222222222', 'project_id': project, 'status': 'completed'}]
    response = client.get(f'/projects/{project}/scans?limit=50&offset=50')
    assert response.status_code == 200, response.text
    assert response.json()['total'] == 51
    query, params = cur.execute.call_args.args
    assert 'WHERE project_id=%s' in query and 'ORDER BY created_at DESC, scan_id DESC' in query
    assert str(params[0]) == project and params[1:] == (50, 50)


def test_unknown_project_history_is_not_empty_success(setup):
    client, _, conn = setup
    conn.cursor.return_value.__enter__.return_value.fetchone.return_value = None
    assert client.get('/projects/11111111-1111-1111-1111-111111111111/scans').status_code == 404

@pytest.mark.parametrize('name, stored', [('  수정 전 검사  ', '수정 전 검사'), ('   ', None)])
def test_rename_scan_persists_trimmed_name(setup, name, stored):
    client, _, conn = setup
    scan_id = '00000000-0000-0000-0000-000000000001'
    cur = conn.cursor.return_value.__enter__.return_value
    cur.fetchone.return_value = {'scan_id': scan_id, 'display_name': stored}
    response = client.patch(f'/scans/{scan_id}', json={'display_name': name})
    assert response.status_code == 200
    assert response.json()['display_name'] == stored
    query, params = cur.execute.call_args.args
    assert 'UPDATE scan_runs SET display_name=%s WHERE scan_id=%s' in query
    assert params[0] == stored and str(params[1]) == scan_id

@pytest.mark.parametrize('body', [{}, {'display_name': 'a' * 81}, {'display_name': 'bad\nname'}, {'display_name': None}])
def test_rename_invalid_name_has_no_writes(setup, body):
    client, _, conn = setup
    assert client.patch('/scans/00000000-0000-0000-0000-000000000001', json=body).status_code == 422
    conn.cursor.assert_not_called()


def test_rename_missing_scan(setup):
    client, _, conn = setup
    conn.cursor.return_value.__enter__.return_value.fetchone.return_value = None
    assert client.patch('/scans/00000000-0000-0000-0000-000000000001', json={'display_name': '검사'}).status_code == 404
