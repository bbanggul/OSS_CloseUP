import json
from copy import deepcopy
import hashlib
from pathlib import Path
from uuid import uuid4
from unittest.mock import MagicMock
import pytest
from worker.app.normalizer import normalize_results
from worker.app.finding_storage import load_results, persist, finalize

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent/'fixtures/normalized-final.json'


def test_real_fixture_reproduced():
    expected=json.loads(FIXTURE.read_text())
    sample=ROOT/'samples/poc77'
    package=json.loads((sample/'package.json').read_text())
    lock=json.loads((sample/'package-lock.json').read_text())
    for name in ('package.json','package-lock.json'):
        assert hashlib.sha256((sample/name).read_bytes()).hexdigest()==expected['execution_manifest']['inputs'][name]['sha256']
    actual=normalize_results(package,lock,expected['raw_results'],expected['tool_status'],scan_id=expected['scan_id'])
    # D02 adds metadata without changing the recorded scanner evidence.
    legacy = deepcopy(actual)
    for f in legacy['findings']:
        assert f.pop('priority_input_eligible') is True
        for observation in f['severity_observations']:
            status = observation.pop('normalization_status')
            assert status == ('missing' if observation['raw'] in (None, '') else 'supported')
    for key in ('packages','findings','alias_groups','summary'):
        assert legacy[key]==expected[key]
    assert actual['summary']['raw_records']==105
    assert len({e['record_id'] for f in actual['findings'] for e in f['evidence']})==105
    for f in actual['findings']:
        for e in f['evidence']:
            raw=actual['raw_results'][e['source_tool']]
            for part in e['json_pointer'].strip('/').split('/'):
                raw=raw[int(part)] if isinstance(raw,list) else raw[part.replace('~1','/').replace('~0','~')]
            assert raw==e['raw']


def test_wrong_scan_rejected_before_query():
    c=MagicMock()
    with pytest.raises(ValueError,match='scope'):
        persist(c,uuid4(),{'scan_id':'different','schema_version':'normalization-v1'}, {})
    c.execute.assert_not_called()


def test_latest_failed_does_not_use_older_success(tmp_path):
    c=MagicMock();c.execute.return_value.fetchone.return_value={'status':'failed'}
    data,states,provenance=load_results(c,uuid4(),tmp_path)
    assert data=={} and provenance=={}
    assert all(s['status']=='failed' for s in states.values())
    assert c.execute.call_count==2


@pytest.mark.parametrize('problem',['hash','path','missing','duplicate'])
def test_raw_artifact_validation(tmp_path,problem):
    sid=uuid4();d=tmp_path/str(sid);d.mkdir();(d/'raw.json').write_bytes(b'{}')
    row={'artifact_id':uuid4(),'storage_key':str(sid)+'/raw.json','sha256':hashlib.sha256(b'{}').hexdigest(),'size_bytes':2}
    if problem=='hash': row['sha256']='0'*64
    if problem=='path': row['storage_key']='../outside'
    c=MagicMock();c.execute.return_value.fetchone.return_value={'status':'completed','tool_run_id':uuid4(),'attempt_no':1}
    c.execute.return_value.fetchall.return_value=[] if problem=='missing' else [row,row] if problem=='duplicate' else [row]
    with pytest.raises(ValueError): load_results(c,sid,tmp_path)


@pytest.mark.parametrize('missing,expected',[(None,'completed'),('normalization','partial'),('github','partial'),('syft','partial')])
def test_final_status_requires_all_stages(missing,expected):
    c=MagicMock();states={n:{'status':'completed'} for n in ('trivy','osv','syft','package_storage','normalization','github')}
    if missing: states[missing]={'status':'failed'}
    c.execute.return_value.fetchone.return_value={'tool_status':states}
    assert finalize(c,uuid4())==expected


def test_malformed_success_is_partial_not_clean():
    x=normalize_results({'dependencies':{}},{'lockfileVersion':3,'packages':{'':{}}},
        {'trivy':{'SchemaVersion':2},'osv':{}}, {t:{'status':'completed'} for t in ('trivy','osv')},scan_id='test')
    assert x['status']=='partial'
    assert x['tool_status']['osv']['error']['kind']=='normalization_error'
