import json
from unittest.mock import MagicMock
import pytest
from worker.app import maintenance as m

@pytest.mark.parametrize('value,expected',[
    ('github:a/b','a/b'),('git+https://github.com/a/b.git','a/b'),
    ('git@github.com:a/b.git','a/b'),('git+ssh://git@github.com/a/b.git','a/b'),
    ({'url':'https://github.com/a/b','directory':'packages/x'},'a/b'),
    ('https://gitlab.com/a/b',None),('https://github.com.evil/a/b',None),
    ('https://github.com/a/..',None),(None,None)])
def test_repository(value,expected): assert m.repository(value)[0]==expected

class Fake:
    def __init__(self,npm=None,repo=None,commits=None,release=None):
        self.calls=[]
        self.responses=[npm or {'status':200,'body':{'name':'a','version':'1','repository':'x/y'}},
            repo or {'status':200,'body':{'archived':False,'default_branch':'main','html_url':'https://github.com/x/y'}},
            commits or {'status':200,'body':[{'commit':{'committer':{'date':'2020-01-01T00:00:00Z'}}}]},
            release or {'status':404,'body':{'message':'Not Found'}}]
    def get(self,url):
        self.calls.append(url)
        return dict(self.responses.pop(0),fetched_at='2026-10-04T00:00:00Z')

def test_old_commit_not_risk_and_no_release():
    c=Fake();r=m.inspect_package(c,'a','1')
    assert r['github_status']=='success' and r['archived'] is False and r['deprecated'] is False
    assert r['latest_release_tag'] is None
    assert c.calls[0]=='https://registry.npmjs.org/a/1'

def test_deprecated_installed_version():
    c=Fake(npm={'status':200,'body':{'name':'a','version':'1','deprecated':'upgrade','repository':'x/y'}})
    assert m.inspect_package(c,'a','1')['deprecated'] is True

def test_version_mismatch_is_unknown():
    c=Fake(npm={'status':200,'body':{'name':'a','version':'2'}})
    r=m.inspect_package(c,'a','1');assert r['deprecated'] is None and r['npm_status']=='failed' and len(c.calls)==1

def test_archived_retained_when_commit_fails():
    c=Fake(repo={'status':200,'body':{'archived':True,'default_branch':'main'}},commits={'status':403,'error':'http_403'})
    r=m.inspect_package(c,'a','1');assert r['archived'] is True and r['github_status']=='failed'

def test_unmapped_repository_no_github_request():
    c=Fake(npm={'status':200,'body':{'name':'a','version':'1'}})
    r=m.inspect_package(c,'a','1');assert r['github_status']=='unmapped' and len(c.calls)==1

def test_token_missing_never_sent():
    c=m.Client();c.opener=MagicMock()
    assert c.get('https://api.github.com/repos/x/y')['error']=='token_missing'
    c.opener.open.assert_not_called()

def response(status,body,headers=None):
    r=MagicMock();r.code=status;r.headers=headers or {};r.read.return_value=json.dumps(body).encode();return r

def test_token_only_github_cache_and_rate_stop():
    m.CACHE.clear();c=m.Client('test-secret');c.opener=MagicMock()
    c.opener.open.return_value=response(200,{'name':'a'})
    c.get('https://registry.npmjs.org/a/1')
    assert c.opener.open.call_args.args[0].get_header('Authorization') is None
    c.get('https://registry.npmjs.org/a/1');assert c.opener.open.call_count==1
    c.opener.open.return_value=response(403,{'message':'rate limit'})
    c.get('https://api.github.com/repos/x/y');assert c.opener.open.call_count==2
    assert c.opener.open.call_args.args[0].get_header('Authorization')=='Bearer test-secret'
    c.get('https://api.github.com/repos/x/z');assert c.opener.open.call_count==2

def test_redirect_cannot_leak_token():
    c=m.Client('test-secret');c.opener=MagicMock()
    c.opener.open.return_value=response(302,{}, {'Location':'https://evil.example/'})
    assert c.get('https://api.github.com/repos/r/s')['error']=='blocked_redirect'
    assert c.opener.open.call_count==1

def test_non_github_host_blocked():
    c=m.Client('test-secret');c.opener=MagicMock()
    assert c.get('http://127.0.0.1/')['error']=='blocked_url'
    c.opener.open.assert_not_called()

class QueueClient:
    def __init__(self,responses): self.responses=list(responses);self.calls=[]
    def get(self,url):
        self.calls.append(url)
        return dict(self.responses.pop(0),fetched_at='2026-10-04T00:00:00Z')

def fallback_responses():
    return [
        {'status':200,'body':{'name':'minimist','version':'1.2.5','deprecated':'old warning','repository':'substack/minimist'}},
        {'status':404,'error':'http_404','body':{'message':'Not Found'}},
        {'status':200,'body':{'name':'minimist','version':'1.2.8','repository':'minimistjs/minimist'}},
        {'status':200,'body':{'archived':False,'default_branch':'main','html_url':'https://github.com/minimistjs/minimist'}},
        {'status':200,'body':[]},
        {'status':404,'body':{'message':'Not Found'}}]

def test_latest_fallback_preserves_installed_version_and_evidence():
    c=QueueClient(fallback_responses());r=m.inspect_package(c,'minimist','1.2.5')
    assert r['github_status']=='success'
    assert r['repository_full_name']=='minimistjs/minimist'
    assert r['deprecated'] is True
    assert r['raw_npm_response']['body']['version']=='1.2.5'
    raw=r['raw_github_response']
    assert raw['installed_repository_response']['status']==404
    assert raw['mapping']['source']=='npm_latest_fallback'
    assert raw['mapping']['metadata_version']=='1.2.8'
    assert '/repos/minimistjs/minimist/commits?' in c.calls[4]

@pytest.mark.parametrize('case',['same','wrong_name','unsupported','failed_latest','failed_alternate'])
def test_fallback_failure_keeps_original_404(case):
    responses=fallback_responses()
    if case=='same': responses[2]['body']['repository']='substack/minimist'
    if case=='wrong_name': responses[2]['body']['name']='other-package'
    if case=='unsupported': responses[2]['body']['repository']='https://gitlab.com/a/b'
    if case=='failed_latest': responses[2]={'status':503,'error':'http_503'}
    if case=='failed_alternate': responses[3]={'status':404,'error':'http_404'}
    r=m.inspect_package(QueueClient(responses),'minimist','1.2.5')
    assert r['github_status']=='failed' and r['github_error']=='http_404'
    assert r['repository_full_name']=='substack/minimist'
    assert r['raw_github_response']['repository']['status']==404

@pytest.mark.parametrize('status',[401,403,429])
def test_auth_and_limit_errors_do_not_trigger_fallback(status):
    responses=fallback_responses();responses[1]={'status':status,'error':f'http_{status}'}
    c=QueueClient(responses);m.inspect_package(c,'minimist','1.2.5')
    assert len(c.calls)==2


def test_fetch_all_is_concurrent_and_matches_sequential(monkeypatch):
    import threading, time
    calls=[]
    def fake(client,name,version):
        time.sleep(0.3);calls.append(threading.current_thread().name)
        return {'name':name,'version':version}
    monkeypatch.setattr(m,'inspect_package',fake)
    keys=[(f'p{i}','1.0.0') for i in range(8)]+[('p0','1.0.0')]
    ticks=[]
    started=time.monotonic()
    out=m.fetch_all(object(),keys,lambda:ticks.append(threading.current_thread().name),workers=8)
    assert time.monotonic()-started<1.5                   # sequential: 2.4s
    assert out=={k:{'name':k[0],'version':k[1]} for k in keys} and len(calls)==8   # duplicates fetched once
    assert set(ticks)=={threading.main_thread().name}


def test_fetch_all_propagates_errors(monkeypatch):
    def boom(*a): raise ValueError('bad')
    monkeypatch.setattr(m,'inspect_package',boom)
    with pytest.raises(ValueError): m.fetch_all(object(),[('a','1')])
