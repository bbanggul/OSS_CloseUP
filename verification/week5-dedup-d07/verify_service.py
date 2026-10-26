"""Isolated synthetic acceptance replay; never run against a shared database.

No scanners or external AI are called. Real normalizer, finding persistence,
PostgreSQL priority adapter and network HTTP API are exercised without patches.
Synthetic candidate values are fixtures, not remediation recommendations.
"""
import json, os, sys, traceback, unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.request import urlopen
from uuid import uuid4
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from worker.app.normalizer import normalize_results
from worker.app.finding_storage import persist
from worker.app.priority_storage import evaluate_scan, source_snapshot, PostgresPriorityStore
from worker.app.review_policy import evaluate_activity, evaluate_license

ROOT = Path('/verification')
OUT = Path(os.environ.get('VERIFICATION_OUTPUT', '/verification/results'))
OUT.mkdir(parents=True, exist_ok=True)
CASES = json.loads(Path('/source/docs/priority-engine/accepted-cases.json').read_text())['cases']
conn = psycopg.connect(os.environ['PRIORITY_TEST_DSN'], autocommit=True, row_factory=dict_row)
assert conn.info.dbname == 'verification' and conn.info.host == 'db'
def dump(name, value):
    (OUT/name).write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str))
def http(sid, resource=''):
    with urlopen(f'http://api:8000/scans/{sid}' + ('/'+resource if resource else ''), timeout=10) as r:
        assert r.status == 200
        return json.load(r)
def check(out, name, actual, expected):
    out.append({'check':name, 'passed':actual == expected, 'expected':expected, 'actual':actual})
def variant_specs(case):
    cid, o = case['id'], case['original_input']
    if cid == 'X01':
        return [(side, {**o[side], 'is_direct':True, 'fix_status':'reported',
                        'dependency_license':o[side]['license']}) for side in ('before','after')]
    if cid == 'B03' or cid.startswith('L'):
        vals = o.get('dependency_licenses_to_test_individually', o.get('expressions_to_test_individually', [o.get('dependency_license')]))
        return [(str(i), {**o, 'dependency_license':v}) for i,v in enumerate(vals)]
    if cid == 'M04':
        return [(str(i), {**o, 'seconds_delta':i}) for i in (-1,0,1)]
    return [('main',o)]

def seed(case, variant, original):
    cid=case['id']; sid,pid,project=uuid4(),uuid4(),uuid4()
    name='case-'+cid.lower()+'-'+variant.replace('-','minus')
    rel={True:'direct',False:'indirect',None:'unknown'}[original.get('is_direct')]
    is_security=cid in ('B01','B02','X01','X02','X04') or cid.startswith('S')
    trivy=[]; osv=[]
    if is_security:
        sev=original.get('raw_severity',original.get('severity','HIGH'))
        severities=['CRITICAL','MEDIUM'] if cid=='X02' else [sev]
        candidates=original.get('fixed_version_candidates', ['1.1.0'] if original.get('fix_status')=='reported' else [])
        for i,severity in enumerate(severities):
            trivy.append({'VulnerabilityID':f'EXAMPLE-{cid}-{variant}-{i}', 'PkgName':name,
                'InstalledVersion':'1.0.0','Severity':severity,'FixedVersion':', '.join(candidates)})
        if cid=='X04':
            osv=[{'packages':[{'package':{'name':name,'version':'1.0.0','ecosystem':'npm'},
                'vulnerabilities':[{'id':'EXAMPLE-X04','database_specific':{'severity':'HIGH'}}]}]}]
            trivy=[]
    statuses={t:{'status':'completed'} for t in ('trivy','osv')}
    if cid in ('X03','X04'): statuses['trivy']={'status':'failed','error':{'kind':'synthetic_failure'}}
    if cid=='X03': statuses['osv']={'status':'failed','error':{'kind':'synthetic_failure'}}
    raw={'trivy':{'SchemaVersion':2,'Results':[{'Type':'npm','Vulnerabilities':trivy}]},'osv':{'results':osv}}
    package_json={'name':'week5-synthetic-'+cid,'dependencies':{name:'1.0.0'}}
    lock={'lockfileVersion':3,'packages':{'':{},'node_modules/'+name:{'version':'1.0.0'}}}
    doc=normalize_results(package_json,lock,raw,statuses,scan_id=str(sid))
    states={**statuses,'package_storage':{'status':'completed'},'github':{'status':'completed'},'syft':{'status':'completed'}}
    if cid=='X03': states['normalization']={'status':'failed','roundtrip_verified':False,'tool_status':statuses}
    conn.execute('INSERT INTO projects(project_id,name) VALUES(%s,%s)',(project,'SYNTHETIC week5 '+cid+' '+variant))
    conn.execute("INSERT INTO scan_runs(scan_id,project_id,status,started_at,worker_id,attempt_count,tool_status) VALUES(%s,%s,'running',now(),'week5-verifier',1,%s)",(sid,project,Jsonb(states)))
    licenses=[] if original.get('dependency_license') is None else [original['dependency_license']]
    conn.execute('INSERT INTO packages(package_id,scan_id,name,installed_version,lockfile_path,relationship,licenses,evidence) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',
        (pid,sid,name,'1.0.0','node_modules/'+name,rel,licenses,Jsonb({'synthetic_fixture':True,'case_id':cid,'variant':variant})))
    if cid!='X03':
        with conn.transaction(): persist(conn,sid,doc,{'synthetic_fixture':True})
    facts=None; expected_activity=None
    if cid=='B04' or cid.startswith('M') or cid=='X01':
        facts=deepcopy(original)
        now=datetime(2026,9,27,tzinfo=timezone.utc)
        for short in ('commit','release'):
            age=original.get('last_'+short+'_age')
            if age: facts['last_'+short+'_at']=(now-timedelta(days={'1일':1,'8개월':243}[age])).isoformat()
        if cid=='M04': facts['last_commit_at']=(now-timedelta(days=243,seconds=original['seconds_delta'])).isoformat()
        if cid=='X01': facts.update(github_status='ok',archived=original['maintenance']=='Archived')
        expected_activity=evaluate_activity(facts,as_of=now.isoformat())
        github='success' if facts.get('github_status')=='ok' else 'failed'
        conn.execute('INSERT INTO maintenance_signals(scan_id,package_id,archived,latest_commit_at,latest_release_published_at,github_status,npm_status,github_checked_at,raw_github_response) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
            (sid,pid,facts.get('archived'),facts.get('last_commit_at'),facts.get('last_release_at'),github,'success',now,Jsonb({'synthetic_fixture':True,'facts':facts})))
    scan={'scan_id':sid,'worker_id':'week5-verifier','attempt_count':1}
    before=source_snapshot(conn,sid)
    outcome=evaluate_scan(conn,scan)
    final='failed' if cid=='X03' else 'partial' if cid=='X04' else 'completed'
    conn.execute('UPDATE scan_runs SET status=%s,finished_at=now() WHERE scan_id=%s',(final,sid))
    responses={r:http(sid,r) for r in ('','findings','packages','maintenance')}
    db={'findings':conn.execute('SELECT * FROM findings WHERE scan_id=%s',(sid,)).fetchall(),
        'links':conn.execute('SELECT * FROM finding_packages WHERE scan_id=%s',(sid,)).fetchall(),
        'evaluations':conn.execute('SELECT * FROM priority_evaluations WHERE scan_id=%s ORDER BY created_at',(sid,)).fetchall()}
    checks=[]
    check(checks,'scanner_evidence_preserved',source_snapshot(conn,sid),before)
    check(checks,'HTTP_finding_count',responses['findings']['total'],len(doc['findings']))
    for f in responses['findings']['items']:
        norm=f['evidence']['normalized']
        check(checks,'HTTP_normalized_evidence_'+f['finding_id'],norm,next(x for x in doc['findings'] if x['finding_id']==norm['finding_id']))
    expected=case['proposed_expected']
    if cid in ('B01','B02') or cid.startswith('S') or cid in ('X01','X02','X04','X05'):
        check(checks,'priority_evaluation_completed',outcome['status'],'completed')
        result=outcome.get('result') or {}
        if result:
            check(checks,'HTTP_current_result_available',responses['findings']['priority_evaluation']['current_result_available'],True)
            if cid in ('B01','B02') or cid.startswith('S'):
                link=result['link_results'][0]
                for key in ('priority','priority_status','has_fix_candidate','fix_information','priority_rule_version'):
                    check(checks,'stored_result_'+key,link[key],expected[key])
                api_f=responses['findings']['items'][0]; api_p=api_f['packages'][0]
                for key in ('priority','priority_status','fix_information','priority_rule_version'):
                    check(checks,'HTTP_'+key,api_p[key],expected[key])
                check(checks,'HTTP_severity',api_f['severity'],expected['severity'])
                check(checks,'DB_link_priority',db['links'][0]['priority'],expected['priority'])
                check(checks,'HTTP_relationship',api_p['relationship'],rel)
                if 'raw_severity' in expected:
                    check(checks,'raw_severity_preserved',api_f['evidence']['normalized']['severity_observations'][0]['raw'],expected['raw_severity'])
                if cid=='S08':
                    check(checks,'unknown_count',result['summary']['unknown_finding_count'],1)
                    check(checks,'unknown_representative_ids',result['package_results'][0]['representative_finding_ids'],[])
                if cid in ('S09','S10'):
                    check(checks,'candidate_values',[c['value'] for c in api_p['fixed_version_candidates']],original['fixed_version_candidates'])
                    check(checks,'no_invented_upgrade',api_p['recommended_fixed_version'],None)
            if cid=='X01': check(checks,'independent_security_grade',result['link_results'][0]['priority'],'P1')
            if cid=='X02':
                check(checks,'package_representative_priority',result['package_results'][0]['priority'],'P0')
                check(checks,'representative_count',len(result['package_results'][0]['representative_finding_ids']),1)
            if cid in ('X04','X05'):
                check(checks,'security_status',result['security_status'],expected['security_status'])
                for key in ('priority','priority_status','incomplete'):
                    check(checks,key,result['package_results'][0][key],expected[key])
                check(checks,'finding_count',result['summary']['finding_count'],expected['finding_count'])
    if cid=='X03':
        # Real storage refuses a failed normalizer, so unavailable priority is expected.
        check(checks,'failed_scan_not_zero_success',responses['']['status'],'failed')
        check(checks,'priority_unavailable',responses['findings']['priority_evaluation']['current_result_available'],False)
        check(checks,'no_findings_created',responses['findings']['total'],0)
    if cid=='B03' or cid.startswith('L') or cid=='X01':
        check(checks,'HTTP_raw_license',responses['packages']['items'][0]['licenses'],licenses)
    if facts is not None:
        api_m=responses['maintenance']['items'][0]
        check(checks,'HTTP_archived',api_m['archived'],facts.get('archived'))
        for field, orig in [('latest_commit_at','last_commit_at'),('latest_release_published_at','last_release_at')]:
            got=api_m[field]; want=facts.get(orig)
            check(checks,'HTTP_'+field,None if got is None else datetime.fromisoformat(got),None if want is None else datetime.fromisoformat(want.replace('Z','+00:00')))
    section='licenses' if cid=='B03' or cid.startswith('L') else 'maintenance' if cid=='B04' or cid.startswith('M') else 'findings'
    record={'case_id':cid,'variant':variant,'scan_id':str(sid),'package_name':name,'expected':expected,
        'source_input':original,'synthetic_fixture':True,'normalization':doc,'outcome':outcome,
        'expected_activity':expected_activity,'db':db,'http':responses,'checks':checks,
        'ui_url':f'http://127.0.0.1:15123/#/scan/{sid}/{section}',
        'passed':all(x['passed'] for x in checks)}
    dump(cid+'-'+variant+'.json',record)
    return record

if __name__ == '__main__':
    records=[]
    for case in CASES:
        for variant, original in variant_specs(case):
            try:
                row=seed(case,variant,original); records.append(row)
                print(case['id'],variant,'PASS' if row['passed'] else 'FAIL',flush=True)
            except Exception:
                row={'case_id':case['id'],'variant':variant,'passed':False,'error':traceback.format_exc()}
                records.append(row); dump(case['id']+'-'+variant+'-error.json',row); print(row,flush=True)
    dump('service-results.json',{'base_commit':'6c122e5329c2104ddc2da2195bc688332358e6b9','working_tree':'deduplication + D07 diagnostic persistence changes; see source-manifest.json','records':records})
    dump('ui-manifest.json',[{k:r[k] for k in ('case_id','variant','scan_id','package_name','ui_url')} for r in records if 'scan_id' in r])
    print('variants',len(records),'passed',sum(x['passed'] for x in records),flush=True)
    assert len({r['case_id'] for r in records}) == 29 and len(records) == 38
    assert all(r['passed'] for r in records), 'DB/API acceptance checks failed'
