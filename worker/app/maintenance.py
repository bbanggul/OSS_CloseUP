"""Read public npm version metadata and GitHub signals. No risk scoring."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import logging
import os
import re
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from urllib.parse import quote, urlparse, urljoin
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from uuid import UUID

from psycopg.types.json import Jsonb

LOG=logging.getLogger(__name__)
CACHE={}
TTL=3600
# npm·GitHub 조회를 동시에 몇 개까지 할지. GitHub 보조 한도를 넘지 않도록 작게 둔다.
WORKERS=max(1,min(16,int(os.getenv('MAINTENANCE_WORKERS','8'))))
MAX_RESPONSE=5*1024*1024


def now(): return datetime.now(timezone.utc).isoformat()


def repository(value):
    directory=value.get('directory') if isinstance(value,dict) else None
    raw=value.get('url') if isinstance(value,dict) else value
    if not isinstance(raw,str) or not raw.strip(): return None,'unmapped',directory
    raw=raw.strip()
    if raw.startswith('github:'): raw='https://github.com/'+raw[7:]
    elif raw.startswith('git@github.com:'): raw='https://github.com/'+raw.split(':',1)[1]
    elif re.fullmatch(r'[\w.-]+/[\w.-]+',raw): raw='https://github.com/'+raw
    if raw.startswith('git+'): raw=raw[4:]
    try: u=urlparse(raw)
    except ValueError: return None,'unmapped',directory
    if u.hostname not in ('github.com','www.github.com'): return None,'unsupported',directory
    parts=u.path.strip('/').split('/')
    if len(parts)<2: return None,'unmapped',directory
    owner,name=parts[:2];name=name.removesuffix('.git')
    if not all(re.fullmatch(r'[A-Za-z0-9_.-]+',v) and v not in ('.','..') for v in (owner,name)):
        return None,'unmapped',directory
    return owner+'/'+name,None,directory


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None


class Client:
    def __init__(self,token=None,tick=lambda:None):
        self.token=token
        self.tick=tick
        self.blocked={}
        self.opener=build_opener(NoRedirect())

    def get(self,url):
        host=urlparse(url).hostname
        if host not in ('registry.npmjs.org','api.github.com') or urlparse(url).scheme!='https':
            return {'status':None,'error':'blocked_url','fetched_at':now()}
        if host=='api.github.com' and not self.token:
            return {'status':None,'error':'token_missing','fetched_at':now()}
        if host in self.blocked: return dict(self.blocked[host])
        # All saved data must be public. Keep cached observation time, not read time.
        cached=CACHE.get(url)
        if cached and time.monotonic()-cached[0]<TTL:
            return dict(cached[1],cache_hit=True)
        self.tick()
        current=url
        for _ in range(4):
            headers={'User-Agent':'OSS-CloseUP-maintenance','Accept':'application/json'}
            if host=='api.github.com':
                headers.update({'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28',
                                'Authorization':'Bearer '+self.token})
            response=None
            try:
                try: response=self.opener.open(Request(current,headers=headers),timeout=15)
                except HTTPError as e: response=e
                status=response.code
                if status in (301,302,307,308):
                    target=urljoin(current,response.headers.get('Location',''))
                    parsed=urlparse(target)
                    if parsed.scheme!='https' or parsed.hostname!=host or parsed.username or parsed.password:
                        return {'status':status,'error':'blocked_redirect','fetched_at':now()}
                    current=target;continue
                raw=response.read(MAX_RESPONSE+1)
                if len(raw)>MAX_RESPONSE: return {'status':status,'error':'response_too_large','fetched_at':now()}
                try: body=json.loads(raw)
                except ValueError: return {'status':status,'error':'invalid_json','fetched_at':now()}
                result={'status':status,'body':body,'fetched_at':now(),'cache_hit':False}
                if isinstance(body,dict) and body.get('private') is True:
                    return {'status':403,'error':'private_repository_not_supported','fetched_at':now()}
                if status!=200: result['error']='http_'+str(status)
                if status in (401,403,429):
                    result['retry_after']=response.headers.get('Retry-After')
                    result['rate_limit_reset']=response.headers.get('X-RateLimit-Reset')
                    self.blocked[host]=result
                if status==200:
                    if len(CACHE)>=2048: CACHE.clear()
                    CACHE[url]=(time.monotonic(),result)
                return result
            except (URLError,OSError,TimeoutError):
                return {'status':None,'error':'network_error','fetched_at':now()}
            finally:
                if response is not None: response.close()
        return {'status':None,'error':'redirect_limit','fetched_at':now()}


def date_value(value):
    if not isinstance(value,str): return None
    try:
        dt=datetime.fromisoformat(value.replace('Z','+00:00'))
        return dt if dt.tzinfo else None
    except ValueError: return None


def inspect_package(client,name,version):
    out={'npm_status':'failed','github_status':'skipped','npm_error':None,'github_error':None,
         'deprecated':None,'archived':None,'repository_full_name':None,'repository_url':None,
         'default_branch':None,'latest_commit_at':None,'latest_release_tag':None,'latest_release_published_at':None,
         'raw_npm_response':{},'raw_github_response':{},'npm_checked_at':None,'github_checked_at':None}
    if not isinstance(version,str) or not version:
        out['npm_error']='missing_installed_version';out['github_error']='npm_unavailable';return out
    n=client.get('https://registry.npmjs.org/'+quote(name,safe='')+'/'+quote(version,safe=''))
    out['raw_npm_response']=n;out['npm_checked_at']=date_value(n.get('fetched_at'))
    body=n.get('body')
    if n.get('status')!=200 or not isinstance(body,dict) or body.get('name')!=name or body.get('version')!=version:
        out['npm_status']='not_found' if n.get('status')==404 else 'failed'
        out['npm_error']=n.get('error') or 'invalid_version_response';out['github_error']='npm_unavailable';return out
    dep=body.get('deprecated')
    if dep is not None and not isinstance(dep,str):
        out['npm_error']='invalid_deprecated';out['github_error']='npm_unavailable';return out
    out['npm_status']='success';out['deprecated']=bool(dep)
    full,reason,directory=repository(body.get('repository'))
    if not full:
        out['github_status']=reason;out['github_error']='repository_'+reason;return out
    out['repository_full_name']=full;out['repository_url']='https://github.com/'+full
    base='https://api.github.com/repos/'+full
    r=client.get(base)
    raw={'repository':r,'npm_repository_directory':directory,
         'mapping':{'source':'installed_version','installed_repository':full,
                    'selected_repository':full,'installed_version':version}}
    out['raw_github_response']=raw
    # A 404 alone does not prove a move. Read the same npm package's latest
    # metadata as an explicitly labelled alternative, preserving the old response.
    if r.get('status')==404:
        latest=client.get('https://registry.npmjs.org/'+quote(name,safe='')+'/latest')
        raw['fallback_npm_latest']=latest
        latest_body=latest.get('body')
        candidate=None
        if (latest.get('status')==200 and isinstance(latest_body,dict)
                and latest_body.get('name')==name
                and isinstance(latest_body.get('version'),str) and latest_body['version']):
            candidate,_,candidate_directory=repository(latest_body.get('repository'))
        if candidate and candidate.lower()!=full.lower():
            raw['mapping']['candidate_repository']=candidate
            alternate=client.get('https://api.github.com/repos/'+candidate)
            raw['fallback_repository']=alternate
            alternate_body=alternate.get('body')
            if (alternate.get('status')==200 and isinstance(alternate_body,dict)
                    and type(alternate_body.get('archived')) is bool):
                raw['installed_repository_response']=r
                r=alternate
                raw['repository']=r
                raw['npm_repository_directory']=candidate_directory
                raw['mapping'].update(source='npm_latest_fallback',selected_repository=candidate,
                    metadata_version=latest_body['version'],reason='installed_repository_404',
                    note='Current package repository; historical source equivalence not verified')
                full=candidate
                out['repository_full_name']=full
                out['repository_url']='https://github.com/'+full
                base='https://api.github.com/repos/'+full
    out['github_checked_at']=date_value(r.get('fetched_at'))
    repo=r.get('body')
    if r.get('status')!=200 or not isinstance(repo,dict) or type(repo.get('archived')) is not bool:
        out['github_status']='skipped' if r.get('error')=='token_missing' else 'failed'
        out['github_error']=r.get('error') or 'invalid_repository_response';return out
    out['archived']=repo['archived'];out['default_branch']=repo.get('default_branch')
    canonical,_,_=repository(repo.get('html_url'))
    if canonical:
        full=canonical;out['repository_full_name']=full;out['repository_url']='https://github.com/'+full
        base='https://api.github.com/repos/'+full
    if not isinstance(out['default_branch'],str) or not out['default_branch']:
        out['github_status']='failed';out['github_error']='missing_default_branch';return out
    commits=client.get(base+'/commits?per_page=1&sha='+quote(out['default_branch'],safe=''))
    release=client.get(base+'/releases/latest')
    raw.update(commits=commits,release=release)
    errors=[]
    data=commits.get('body')
    if commits.get('status')==200 and isinstance(data,list):
        if data:
            try: out['latest_commit_at']=date_value(data[0]['commit']['committer']['date'])
            except (KeyError,TypeError): pass
            if out['latest_commit_at'] is None: errors.append('invalid_commit_date')
    elif commits.get('status')==409: raw['commits_note']='empty_or_conflicting_repository'
    else: errors.append('commits_'+str(commits.get('error') or 'invalid_response'))
    data=release.get('body')
    if release.get('status')==200 and isinstance(data,dict):
        out['latest_release_tag']=data.get('tag_name') if isinstance(data.get('tag_name'),str) else None
        out['latest_release_published_at']=date_value(data.get('published_at'))
        if not out['latest_release_tag'] or not out['latest_release_published_at']: errors.append('invalid_release')
    elif release.get('status')==404: raw['release_note']='no_visible_latest_release'
    else: errors.append('release_'+str(release.get('error') or 'invalid_response'))
    out['github_status']='failed' if errors else 'success';out['github_error']=';'.join(errors) or None
    return out


def fetch_all(client,keys,tick=lambda:None,workers=None):
    """inspect_package for each unique (name, version), several at a time. Results do not depend on order."""
    unique=list(dict.fromkeys(keys))
    if not unique: return {}
    pool=ThreadPoolExecutor(max_workers=min(workers or WORKERS,len(unique)))
    futures={pool.submit(inspect_package,client,*key):key for key in unique}
    results={}
    try:
        pending=set(futures)
        while pending:
            done,pending=wait(pending,timeout=1,return_when=FIRST_COMPLETED)
            tick()
            for future in done: results[futures[future]]=future.result()
    except BaseException:
        pool.shutdown(wait=False,cancel_futures=True)
        raise
    pool.shutdown(wait=True)
    return results


def collect(conn,scan_id,allow_running=False,tick=lambda:None):
    acquired=conn.execute('SELECT pg_try_advisory_lock(hashtextextended(%s,1)) AS ok',(str(scan_id),)).fetchone()['ok']
    if not acquired: raise ValueError('maintenance_already_running')
    try:
        scan=conn.execute('SELECT status FROM scan_runs WHERE scan_id=%s',(scan_id,)).fetchone()
        if scan is None: raise ValueError('scan_not_found')
        if not allow_running and scan['status'] in ('queued','running'): raise ValueError('scan_not_finished')
        packages=conn.execute("SELECT package_id,name,installed_version FROM packages WHERE scan_id=%s AND relationship<>'root' ORDER BY lockfile_path",(scan_id,)).fetchall()
        if not packages: raise ValueError('store_packages_first')
        # HTTP lookups run in worker threads; only this thread touches the DB (tick = heartbeat).
        client=Client(os.getenv('GITHUB_TOKEN') or None)
        counts=Counter();results=fetch_all(client,[(p['name'],p['installed_version']) for p in packages],tick)
        conn.execute('UPDATE scan_runs SET tool_status=tool_status || %s WHERE scan_id=%s',
            (Jsonb({'github':{'status':'running','total':len(packages)}}),scan_id))
        columns=['repository_url','repository_full_name','default_branch','latest_commit_at',
            'latest_release_tag','latest_release_published_at','archived','deprecated',
            'raw_github_response','raw_npm_response','github_status','npm_status','github_error','npm_error',
            'github_checked_at','npm_checked_at']
        for i,p in enumerate(packages,1):
            info=results[(p['name'],p['installed_version'])]
            vals=[Jsonb(info[k]) if k.startswith('raw_') else info[k] for k in columns]
            with conn.transaction():
                # Fixed column list, no user-controlled SQL identifiers.
                conn.execute('INSERT INTO maintenance_signals(scan_id,package_id,'+','.join(columns)+') VALUES ('+
                    ','.join(['%s']*(len(columns)+2))+') ON CONFLICT(scan_id,package_id) DO UPDATE SET '+
                    ','.join(f'{k}=EXCLUDED.{k}' for k in columns),(scan_id,p['package_id'],*vals))
                conn.execute('UPDATE packages SET repository_url=%s,repository_full_name=%s WHERE scan_id=%s AND package_id=%s',
                    (info['repository_url'],info['repository_full_name'],scan_id,p['package_id']))
            counts['npm_'+info['npm_status']]+=1;counts['github_'+info['github_status']]+=1
            LOG.info('maintenance scan=%s progress=%s/%s npm=%s github=%s',scan_id,i,len(packages),info['npm_status'],info['github_status'])
        summary={'status':'completed' if counts['npm_success']==len(packages) and counts['github_success']==len(packages) else 'partial',
            'packages':len(packages),'authenticated':bool(client.token),**dict(counts)}
        conn.execute('UPDATE scan_runs SET tool_status=tool_status || %s WHERE scan_id=%s',(Jsonb({'github':summary}),scan_id))
        return summary
    finally:
        # A lost session releases its advisory locks automatically.
        if not conn.closed: conn.execute('SELECT pg_advisory_unlock(hashtextextended(%s,1))',(str(scan_id),))


def main():
    from .main import connect
    parser=argparse.ArgumentParser();parser.add_argument('scan_id',type=UUID);args=parser.parse_args()
    logging.basicConfig(level=logging.INFO,format='%(message)s')
    with connect() as conn: print(json.dumps(collect(conn,args.scan_id),ensure_ascii=False,indent=2))

if __name__=='__main__':main()
