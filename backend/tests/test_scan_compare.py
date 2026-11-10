from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import MagicMock
from uuid import UUID

from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker
import psycopg
import pytest

from app import scan_compare_api as api
from app.main import app
from app.scan_compare import compare_scans, ComparisonError, LIMITS, check_limit
from compare_fixtures import FIXTURES, pair, duplicate_finding, refresh_counts, uid

SCHEMAS = Path(__file__).resolve().parents[1] / 'app' / 'schemas'
VALIDATOR = Draft202012Validator(json.loads((SCHEMAS / 'compare-response.schema.json').read_text()), format_checker=FormatChecker())
ERROR_VALIDATOR = Draft202012Validator(json.loads((SCHEMAS / 'compare-error.schema.json').read_text()), format_checker=FormatChecker())


def valid_compare(a, b):
    before = deepcopy((a, b))
    result = compare_scans(a, b)
    VALIDATOR.validate(result)
    assert (a, b) == before
    assert sum(result['summary'][k] for k in ('new', 'not_detected', 'persisting', 'not_comparable')) == len(result['items'])
    return result


@pytest.mark.parametrize('name', [p.stem for p in sorted((FIXTURES / 'examples').glob('*.json'))])
def test_contract_scenarios_from_stored_rows(name):
    a, b, expected = pair(name)
    result = valid_compare(a, b)
    assert result['summary'] == expected['summary']
    assert result['finding_counts'] == expected['finding_counts']
    assert result['comparison_complete'] == expected['comparison_complete']
    essential = lambda doc: sorted((i['status'], i['reason'], i['unit'], sorted(i['base_finding_ids']), sorted(i['target_finding_ids'])) for i in doc['items'])
    assert essential(result) == essential(expected)
    reverse = valid_compare(b, a)
    assert reverse['comparison_id'] != result['comparison_id']
    assert reverse['summary']['new'] == result['summary']['not_detected']
    assert reverse['summary']['not_detected'] == result['summary']['new']
    assert reverse['summary']['persisting'] == result['summary']['persisting']
    assert reverse['summary']['not_comparable'] == result['summary']['not_comparable']


def test_determinism_does_not_depend_on_database_row_order():
    a, b, _ = pair('05-identifier-conflict')
    first = valid_compare(a, b)
    for data in (a, b):
        for field in ('packages', 'findings', 'links', 'source_runs', 'artifacts'): data[field].reverse()
    assert valid_compare(a, b) == first


def test_source_evidence_order_remains_part_of_input_fingerprint():
    a, b, _ = pair()
    norm = b['findings'][0]['evidence']['normalized']
    norm['fixed_version_candidates'] = [{'events': [{'introduced': '0'}, {'fixed': '2.0.0'}]}]
    first = valid_compare(a, b)
    norm['fixed_version_candidates'][0]['events'].reverse()
    second = valid_compare(a, b)
    assert first['target']['snapshot_id'] != second['target']['snapshot_id']
    assert first['comparison_id'] != second['comparison_id']


def test_ghsa_candidate_does_not_hide_cve_only_candidate():
    a, b, _ = pair()
    duplicate_finding(b, identifiers=['CVE-2099-10001'], primary='CVE-2099-10001')
    result = valid_compare(a, b)
    assert result['summary']['not_comparable'] == 1
    item = result['items'][0]
    assert item['unit'] == 'identifier_conflict' and len(item['target_finding_ids']) == 2
    assert {e['basis'] for e in item['match']['candidate_edges']} == {'exact_ghsa', 'direct_cve'}


def test_primary_cve_is_required_for_cve_only_match():
    a, b, _ = pair()
    for data in (a, b):
        f = data['findings'][0]
        f['identifiers'] = f['evidence']['normalized']['identifiers'] = ['CVE-2099-10001']
        f['evidence']['normalized']['evidence'] = []
    result = valid_compare(a, b)
    assert result['summary']['persisting'] == 0
    assert result['summary']['new'] == result['summary']['not_detected'] == 0
    assert result['items'][0]['reason'] == 'identifier_review_required'
    b['findings'][0]['evidence']['normalized']['evidence'] = [{'source_tool': 'trivy', 'raw': {'VulnerabilityID': 'CVE-2099-10001'}}]
    assert valid_compare(a, b)['items'][0]['match']['kind'] == 'direct_cve'


def test_primary_advisory_mapping_changed_is_reviewed():
    a, b, _ = pair()
    b['findings'][0]['evidence']['normalized']['evidence'][0]['raw']['id'] = 'GHSA-5555-6666-7777'
    result = valid_compare(a, b)
    assert result['summary']['persisting'] == 0
    assert result['items'][0]['reason'] == 'identifier_review_required'


def test_same_cve_without_primary_proof_on_one_side_is_not_called_new():
    a, b, _ = pair('17-same-version-db-change')
    finding = b['findings'][0]
    finding['identifiers'] = finding['evidence']['normalized']['identifiers'] = ['CVE-2099-10001']
    finding['evidence']['normalized']['evidence'] = []
    result = valid_compare(a, b)
    assert result['summary']['new'] == 0
    assert result['items'][0]['reason'] == 'identifier_missing'


@pytest.mark.parametrize('field,value', [('package_name','wrong-package'), ('installed_version','wrong-version'), ('lock_paths',[])])
def test_normalized_mapping_must_agree_with_installed_package(field, value):
    a, b, _ = pair()
    b['findings'][0]['evidence']['normalized'][field] = value
    with pytest.raises(ComparisonError) as err: compare_scans(a, b)
    assert err.value.status == 500


@pytest.mark.parametrize('kind', ['previous_attempt', 'wrong_artifact', 'wrong_hash', 'unpublished', 'no_fingerprint', 'duplicate_artifact'])
def test_missing_or_stale_provenance_cannot_prove_absence(kind):
    a, b, _ = pair('02-version-not-detected')
    norm = b['scan']['tool_status']['normalization']
    if kind == 'previous_attempt': b['scan']['attempt_count'] += 1
    if kind == 'wrong_artifact': norm['source_artifacts']['trivy']['artifact_id'] = uid('wrong')
    if kind == 'wrong_hash': norm['source_artifacts']['trivy']['sha256'] = 'f'*64
    if kind == 'unpublished': norm['roundtrip_verified'] = False
    if kind == 'no_fingerprint': norm['fingerprint'] = None
    if kind == 'duplicate_artifact': b['artifacts'].append(dict(b['artifacts'][0], artifact_id=uid('duplicate-raw')))
    result = valid_compare(a, b)
    assert result['summary']['not_detected'] == 0
    assert result['items'][0]['reason'] == 'target_incomplete'
    assert result['finding_counts']['target']['stored'] is None


@pytest.mark.parametrize('change', ['cross_scan_package', 'cross_scan_finding', 'cross_scan_link', 'duplicate_link',
                                  'duplicate_package', 'duplicate_finding', 'unknown_package', 'changed_publication'])
def test_corrupt_stored_relationships_fail_closed(change):
    a, b, _ = pair()
    if change == 'cross_scan_package': b['packages'][0]['scan_id'] = a['scan']['scan_id']
    if change == 'cross_scan_finding': b['findings'][0]['scan_id'] = a['scan']['scan_id']
    if change == 'cross_scan_link': b['links'][0]['scan_id'] = a['scan']['scan_id']
    if change == 'duplicate_link': b['links'].append(deepcopy(b['links'][0]))
    if change == 'duplicate_package': b['packages'].append(deepcopy(b['packages'][0]))
    if change == 'duplicate_finding': b['findings'].append(deepcopy(b['findings'][0]))
    if change == 'unknown_package': b['links'][0]['package_id'] = uid('missing-package')
    if change == 'changed_publication': b['findings'][0]['identifiers'].append('CVE-2099-99999')
    with pytest.raises(ComparisonError) as err: compare_scans(a, b)
    assert err.value.status == 500


@pytest.mark.parametrize('old,new,direction', [('1.0.0-beta.2','1.0.0-beta.10','increased'),
    ('1.0.0-beta.10','1.0.0-beta.2','decreased'), ('1.0.0-beta.10','1.0.0','increased'),
    ('1.0.0+first','1.0.0+second','equivalent'), ('custom','1.0.0','unknown')])
def test_shared_version_comparison(old, new, direction):
    a, b, _ = pair()
    a['packages'][0]['installed_version'] = old
    b['packages'][0]['installed_version'] = new
    result = valid_compare(a, b)
    assert result['installations'][0]['version_change'] == {'kind': 'changed', 'direction': direction}
    assert result['summary']['persisting'] == 1


def test_multiple_location_candidates_are_not_guessed():
    a, b, _ = pair()
    p = deepcopy(a['packages'][0]); p.update(package_id=uid('second-location'), lockfile_path='node_modules/parent/node_modules/demo-lib')
    a['packages'].append(p)
    b['packages'][0]['lockfile_path'] = 'node_modules/moved/node_modules/demo-lib'
    refresh_counts(a)
    result = valid_compare(a, b)
    assert len(result['installations']) == 3
    assert {i['location_match'] for i in result['installations']} == {'base_only', 'target_only'}


def test_same_path_different_name_is_not_same_installation():
    a, b, _ = pair()
    b['packages'][0]['name'] = 'different-package'
    result = valid_compare(a, b)
    assert result['summary']['persisting'] == 0
    assert result['summary']['new'] == result['summary']['not_detected'] == 1


def test_root_only_link_is_unlinked_and_not_a_vulnerability_item():
    a, b, _ = pair()
    b['packages'][0]['relationship'] = 'root'; b['packages'][0]['lockfile_path'] = ''
    refresh_counts(b)
    result = valid_compare(a, b)
    assert result['finding_counts']['target']['unlinked'] == 1
    assert result['summary']['not_detected'] == 0


def test_zero_requires_verified_inventory_not_empty_arrays():
    a, b, _ = pair('15-confirmed-zero')
    del b['scan']['tool_status']['package_storage']['total_including_root']
    result = valid_compare(a, b)
    assert result['comparison_complete'] is False
    assert result['target']['inventory_complete'] is False


def test_database_context_is_not_claimed_as_cause():
    a, b, _ = pair('17-same-version-db-change')
    result = valid_compare(a, b)
    assert result['items'][0]['reason'] == 'same_version'
    assert any(x['state'] == 'changed' for x in result['context_changes'])


@pytest.mark.parametrize('dimension', list(LIMITS))
def test_limit_exact_boundary_and_one_over(dimension):
    check_limit(dimension, LIMITS[dimension])
    with pytest.raises(ComparisonError) as err: check_limit(dimension, LIMITS[dimension] + 1)
    ERROR_VALIDATOR.validate({'detail': err.value.detail})


def test_candidate_graph_limit_fails_without_truncated_success(monkeypatch):
    a, b, _ = pair()
    duplicate_finding(b)
    monkeypatch.setitem(LIMITS, 'candidate_pairs', 1)
    with pytest.raises(ComparisonError) as err: compare_scans(a, b)
    assert err.value.status == 422
    assert err.value.detail['limit'] == {'dimension': 'candidate_pairs', 'maximum': 1, 'actual': 2}


def fake_read(monkeypatch, a, b):
    conn = MagicMock(); conn.__enter__.return_value = conn
    monkeypatch.setattr(api, 'connect', lambda: conn)
    monkeypatch.setattr(api, 'preflight', lambda *_: None)
    monkeypatch.setattr(api, 'load_scan_material', lambda c, sid, **kw: a if str(sid) == a['scan']['scan_id'] else b)
    return conn


def test_registered_route_transaction_and_openapi(monkeypatch):
    a, b, _ = pair()
    conn = fake_read(monkeypatch, a, b)
    response = TestClient(app).get(f"/scans/{b['scan']['scan_id']}/compare", params={'base': a['scan']['scan_id']})
    assert response.status_code == 200, response.text
    VALIDATOR.validate(response.json())
    conn.execute.assert_called_once_with('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
    schema = app.openapi()['paths']['/scans/{target_scan_id}/compare']['get']['responses']['200']['content']['application/json']['schema']
    Draft202012Validator(schema).validate(response.json())


@pytest.mark.parametrize('kind,status,code', [('same',422,'same_scan'), ('project',422,'different_project'),
    ('running',409,'scan_processing'), ('db',503,'database_unavailable'), ('corrupt',500,'comparison_invariant_failed')])
def test_domain_errors_do_not_expose_internal_details(monkeypatch, kind, status, code):
    a, b, _ = pair()
    fake_read(monkeypatch, a, b)
    if kind == 'same': a = b
    if kind == 'project': b['scan']['project_id'] = uid('other-project')
    if kind == 'running': b['scan']['status'] = 'running'
    if kind == 'corrupt': del b['packages'][0]['name']
    if kind == 'db':
        def unavailable(): raise psycopg.OperationalError('password=secret server/path')
        monkeypatch.setattr(api, 'connect', unavailable)
    response = TestClient(app).get(f"/scans/{b['scan']['scan_id']}/compare", params={'base': a['scan']['scan_id']})
    assert response.status_code == status
    assert response.json()['detail']['code'] == code
    ERROR_VALIDATOR.validate(response.json())
    assert 'secret' not in response.text


@pytest.mark.parametrize('path,params', [('/scans/not-a-uuid/compare', {'base': uid('base')}),
    ('/scans/' + uid('target') + '/compare', {}), ('/scans/' + uid('target') + '/compare', {'base': 'bad'})])
def test_request_validation_uses_existing_fastapi_envelope(path, params):
    response = TestClient(app).get(path, params=params)
    assert response.status_code == 422 and isinstance(response.json()['detail'], list)
