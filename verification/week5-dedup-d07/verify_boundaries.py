import hashlib, json, os
from contextlib import nullcontext
from unittest.mock import patch
from uuid import uuid4
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from verify_service import conn, OUT, CASES, seed, dump, http, check
from worker.app import priority_storage as ps
from worker.app.priority_stage import PriorityStagePersistenceError

def bad_build(snapshot):
    p=ps.build_payload_original(snapshot)
    p['finding_packages'][0]['fixed_version_candidates']=[]
    return p
ps.build_payload_original=ps.build_payload
def wrong_scope(snapshot):
    p=ps.build_payload_original(snapshot);p['scan_id']=str(uuid4());return p
def test_input(snapshot):
    p=ps.build_payload_original(snapshot);p['test_only']=True;return p
def broken_build(snapshot): raise ValueError('synthetic input build failure')
original_publish=ps.PostgresPriorityStore.publish_state
def fail_publish(self,record):
    if record['status']=='completed': raise OSError('synthetic failure after DB writes')
    return original_publish(self,record)

scenarios=[('invalid_candidate','build_payload',bad_build,'invalid_input'),
           ('wrong_scan','build_payload',wrong_scope,'invalid_input'),
           ('test_input','build_payload',test_input,'invalid_input'),
           ('input_build_error','build_payload',broken_build,'failed'),
           ('write_rollback','publish_state',fail_publish,'failed'),
           ('error_storage_failure','error_storage',None,'exception'),
           ('evidence_storage_failure','evidence_storage',None,'exception'),
           ('stale_worker','stale_worker',None,'exception')]
all_results=[]
for name,target,replacement,expected_status in scenarios:
    r=seed(CASES[0],'d07-'+name,CASES[0]['original_input'])
    sid=r['scan_id'];scan={'scan_id':sid,'worker_id':'week5-verifier','attempt_count':1}
    conn.execute("UPDATE scan_runs SET status='running' WHERE scan_id=%s",(sid,))
    raw=json.dumps(r['normalization']['raw_results'],sort_keys=True).encode()
    path=OUT/('d07-'+name+'-raw.json');path.write_bytes(raw)
    hash_before=hashlib.sha256(raw).hexdigest()
    tid=conn.execute("INSERT INTO scan_tool_runs(scan_id,tool_name,status) VALUES(%s,'trivy','completed') RETURNING tool_run_id",(sid,)).fetchone()['tool_run_id']
    conn.execute("INSERT INTO scan_artifacts(scan_id,tool_run_id,kind,storage_key,sha256,size_bytes) VALUES(%s,%s,'raw_result',%s,%s,%s)",(sid,tid,path.name,hash_before,len(raw)))
    # Give a rollback a real changed value to undo: previous row P3, next evaluation P0.
    if name=='write_rollback': conn.execute("UPDATE finding_packages SET priority='P3' WHERE scan_id=%s",(sid,))
    before=ps.source_snapshot(conn,sid)
    old=conn.execute('SELECT finding_id,package_id,priority FROM finding_packages WHERE scan_id=%s ORDER BY finding_id,package_id',(sid,)).fetchall()
    if target=='stale_worker':scan['worker_id']='old-worker'
    target_obj=ps if target=='build_payload' else ps.PostgresPriorityStore
    ctx=patch.object(target_obj,target,replacement) if replacement else nullcontext()
    if target=='error_storage':
        ctx=patch.object(ps.PostgresPriorityStore,'save_priority_error',side_effect=OSError('synthetic error storage failure'))
    if target=='evidence_storage':
        ctx=patch.object(ps.PostgresPriorityStore,'save_scan_evidence',side_effect=OSError('synthetic evidence storage failure'))
    ctx2=patch.object(ps,'build_payload',broken_build) if target=='error_storage' else nullcontext()
    with ctx,ctx2:
        try: outcome=ps.evaluate_scan(conn,scan)
        except PriorityStagePersistenceError as e:
            outcome={'status':'exception','stage':e.stage,'scan_evidence_saved':e.scan_evidence_saved,'record':e.record}
    checks=[]
    check(checks,'expected_outcome',outcome['status'],expected_status)
    # A separate connection sees committed data, not a connection-local view.
    with psycopg.connect(os.environ['PRIORITY_TEST_DSN'],autocommit=True,row_factory=dict_row) as independent:
        check(checks,'committed_source_preserved',ps.source_snapshot(independent,sid),before)
        rows=independent.execute('SELECT * FROM priority_evaluations WHERE scan_id=%s ORDER BY created_at',(sid,)).fetchall()
        now=independent.execute('SELECT finding_id,package_id,priority FROM finding_packages WHERE scan_id=%s ORDER BY finding_id,package_id',(sid,)).fetchall()
        check(checks,'no_partial_priority_write',now,old)
    check(checks,'raw_file_hash_preserved',hashlib.sha256(path.read_bytes()).hexdigest(),hash_before)
    api=http(sid,'findings')
    if expected_status!='exception':
        check(checks,'error_committed',rows[-1]['status'],expected_status)
        check(checks,'failed_result_null',rows[-1]['result'],None)
        check(checks,'HTTP_current_result_unavailable',api['priority_evaluation']['current_result_available'],False)
        check(checks,'HTTP_historical_grade_hidden',[p['priority'] for f in api['items'] for p in f['packages']],[None])
    if expected_status != 'exception':
        check(checks, 'attempted_payload_matches_failure_snapshot', rows[-1]['attempted_payload'], outcome['attempted_payload'])
        check(checks, 'safe_error_message_present', bool(rows[-1]['error'].get('message')), True)
        check(checks, 'safe_error_message_policy', rows[-1]['error'].get('message_policy'), 'safe-stage-summary-v1')
        check(checks, 'raw_exception_not_stored', outcome['error']['message'] not in json.dumps(rows[-1]['error']), True)
    evidence={'scenario':name,'scan_id':sid,'outcome':outcome,'checks':checks,'db_evaluations':rows,'http':api,
        'passed':all(x['passed'] for x in checks),
        'contract_diagnostics':{'attempted_payload_persisted':expected_status != 'exception' and rows[-1].get('attempted_payload') == outcome.get('attempted_payload'),
            'error_message_persisted':'message' in (rows[-1]['error'] or {})}}
    all_results.append(evidence);dump('d07-'+name+'.json',evidence)
    print(name,evidence['passed'],flush=True)
dump('d07-results.json',all_results)

# Same-scan cross-case sorting: every original display_before/after relation.
source=json.loads((OUT/'service-results.json').read_text())['records']
security=[r for r in source if r['case_id'] in ('B01','B02') or r['case_id'].startswith('S')]
project,sid=uuid4(),uuid4()
states=security[0]['http']['']['tool_status'];states.pop('priority',None)
conn.execute('INSERT INTO projects(project_id,name) VALUES(%s,%s)',(project,'SYNTHETIC cross-case ordering'))
conn.execute("INSERT INTO scan_runs(scan_id,project_id,status,worker_id,attempt_count,tool_status) VALUES(%s,%s,'running','week5-verifier',1,%s)",(sid,project,Jsonb(states)))
mapping={}
for r in security:
    p=r['http']['packages']['items'][0];f=r['db']['findings'][0];l=r['db']['links'][0]
    pid,fid=uuid4(),uuid4();mapping[str(fid)]=r['case_id']
    conn.execute('INSERT INTO packages(package_id,scan_id,name,installed_version,lockfile_path,relationship) VALUES(%s,%s,%s,%s,%s,%s)',(pid,sid,p['name'],p['installed_version'],p['lockfile_path'],p['relationship']))
    conn.execute("INSERT INTO findings(finding_id,scan_id,type,finding_key,severity,evidence) VALUES(%s,%s,'vulnerability',%s,%s,%s)",(fid,sid,r['case_id'],f['severity'],Jsonb(f['evidence'])))
    conn.execute('INSERT INTO finding_packages(scan_id,finding_id,package_id,fixed_version_candidates,evidence) VALUES(%s,%s,%s,%s,%s)',(sid,fid,pid,Jsonb(l['fixed_version_candidates']),Jsonb(l['evidence'])))
outcome=ps.evaluate_scan(conn,{'scan_id':sid,'worker_id':'week5-verifier','attempt_count':1})
api=http(sid,'findings');order=[mapping[x['finding_id']] for x in outcome['result']['link_results']]
checks=[]
for r in security:
    cid=r['case_id'];e=r['expected']
    for other in e.get('display_before',[]):check(checks,cid+'_before_'+other,order.index(cid)<order.index(other),True)
    for other in e.get('display_after',[]):check(checks,cid+'_after_'+other,order.index(cid)>order.index(other),True)
    if 'display_before_severity' in e:
        for other in security:
            if other['expected']['severity']==e['display_before_severity']:
                check(checks,cid+'_before_'+other['case_id'],order.index(cid)<order.index(other['case_id']),True)
apiorder=[mapping[x['finding_id']] for x in sorted(api['items'],key=lambda x:x['priority_rank'])]
check(checks,'HTTP_rank_matches_stored_order',apiorder,order)
dump('cross-case-order.json',{'checks':checks,'order':order,'http':api,'mapping':mapping,'passed':all(x['passed'] for x in checks)})
print('cross-case ordering',all(x['passed'] for x in checks),order,flush=True)

assert all(r['passed'] for r in all_results), 'D07 checks failed'
assert all(c['passed'] for c in checks), 'Cross-case ordering checks failed'
