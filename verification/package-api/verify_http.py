"""Seed isolated synthetic facts and exercise the real API over HTTP."""
import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import urlopen
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from test_priority_postgres import seed
from test_package_api import add_package, add_finding, link
from worker.app.priority_storage import evaluate_scan

out = Path('/verification/results')
checks, responses = [], {}

def check(name, actual, expected):
    checks.append({'check':name,'actual':actual,'expected':expected,'passed':actual==expected})

def get(name, path, **params):
    address = 'http://api:8000' + path + ('?' + urlencode(params) if params else '')
    try:
        with urlopen(address, timeout=15) as response:
            status, body = response.status, json.load(response)
    except HTTPError as exc:
        status, body = exc.code, json.load(exc)
    responses[name] = {'status':status,'body':body}
    return status, body

with psycopg.connect(os.environ['PRIORITY_TEST_DSN'], autocommit=True, row_factory=dict_row) as conn:
    assert conn.info.dbname == 'verification' and conn.info.host == 'db'
    scan, fid, pid = seed(conn)
    sid = scan['scan_id']
    states = {'package_storage':{'status':'completed'},'normalization':{
        'status':'completed','roundtrip_verified':True,'fingerprint':'synthetic-http-source',
        'tool_status':{t:{'status':'completed'} for t in ('trivy','osv')}}}
    conn.execute('UPDATE scan_runs SET tool_status=%s WHERE scan_id=%s',(Jsonb(states),sid))
    duplicate = add_package(conn,sid,'demo')
    link(conn,sid,fid,duplicate)
    candidate = {'value':'>=2.0.0','raw':'>=2.0.0','source_tool':'osv','json_pointer':'/synthetic/0'}
    low = add_finding(conn,sid,'LOW')
    link(conn,sid,low,pid,[candidate])
    alpha = add_package(conn,sid,'alpha')
    link(conn,sid,add_finding(conn,sid,'CRITICAL'),alpha,[candidate])
    unknown = add_package(conn,sid,'unknown')
    link(conn,sid,add_finding(conn,sid,'UNKNOWN'),unknown,[candidate])
    orphan = add_finding(conn,sid,'HIGH')
    norm={'priority_input_eligible':True,'severity_observations':[], 'finding_id':'finding-new',
          'merge_basis':{'kind':'explicit_ghsa_identity','source_finding_ids':['finding-old']}}
    conn.execute('UPDATE findings SET evidence=%s WHERE finding_id=%s',(Jsonb({'normalized':norm}),fid))
    check('evaluation_completed',evaluate_scan(conn,scan)['status'],'completed')
    base = f'/scans/{sid}'
    status, listing = get('list',base+'/vulnerable-packages')
    check('list_http',status,200)
    check('global_ranks',[r['global_rank'] for r in listing['items']],[1,2,None])
    check('group_count',listing['total'],3)
    check('unique_findings',listing['unique_finding_count'],5)
    check('unlinked_count',listing['unlinked_finding_count'],1)
    demo=listing['items'][1]
    check('merged_installs',len(demo['installations']),2)
    check('lower_grade_fixes_do_not_promote',demo['has_fix_candidate_at_priority'],False)
    _, detail=get('detail',base+'/vulnerable-packages/'+demo['package_group_id'],snapshot_id=listing['snapshot_id'])
    check('detail_all_findings',len(detail['item']['findings']),2)
    lower=next(f for f in detail['item']['findings'] if f['finding_id']==str(low))
    check('detail_lower_fix_evidence',lower['installation_links'][0]['fixed_version_candidates'],[candidate])
    _, filtered=get('filtered',base+'/vulnerable-packages',q='demo',limit=1,snapshot_id=listing['snapshot_id'])
    check('filter_keeps_original_rank',filtered['items'][0]['global_rank'],2)
    _, page=get('second_page',base+'/vulnerable-packages',offset=1,limit=1,snapshot_id=listing['snapshot_id'])
    check('page_matches_filter',page['items'],filtered['items'])
    _, unlinked=get('unlinked',base+'/unlinked-vulnerabilities')
    check('orphan_is_visible',unlinked['items'][0]['finding_id'],str(orphan))
    _, alias=get('alias',base+'/findings/finding-old')
    check('alias_canonical_id',alias['canonical_finding_id'],str(fid))
    check('alias_resolution',alias['resolution'],'merged')
    check('review_not_automatically_complete',listing['deduplication_status'],'review_pending')
    conn.execute("UPDATE scan_runs SET tool_status=jsonb_set(tool_status,'{priority}',%s) WHERE scan_id=%s",
                 (Jsonb({'status':'failed','current_result_available':False}),sid))
    status,_=get('stale_snapshot',base+'/vulnerable-packages',snapshot_id=listing['snapshot_id'])
    check('changed_snapshot_conflict',status,409)
    _,failed=get('priority_failed',base+'/vulnerable-packages')
    check('failed_has_no_ranks',[r['global_rank'] for r in failed['items']],[None,None,None])
    check('failure_preserves_finding_count',failed['unique_finding_count'],5)
    _,row=get('finding_after_failure',base+'/findings/'+str(fid))
    check('old_grade_not_exposed',row['item']['priority'],None)

result={'synthetic_fixture':True,'scan_id':str(sid),'checks':checks,'responses':responses,
        'passed':all(c['passed'] for c in checks)}
(out/'http-results.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'checks':len(checks),'passed':sum(c['passed'] for c in checks)}))
assert result['passed'], 'HTTP acceptance failed'
