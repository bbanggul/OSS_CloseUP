import importlib.util
from pathlib import Path
import hashlib
import json
import sys
import threading
from unittest.mock import MagicMock
import pytest

from worker.app import main as w

def test_osv_one_is_success(tmp_path,monkeypatch):
    (tmp_path/'osv.json').write_text('{}')
    monkeypatch.setattr(w,'OUTPUT_ROOT',tmp_path)
    monkeypatch.setattr(w,'execute',lambda *a:1)
    monkeypatch.setattr(w.subprocess,'run',lambda *a,**k:MagicMock(stdout='v2'))
    c=MagicMock()
    assert w.run_tool(c,{'scan_id':'s','attempt_count':1},'osv',['osv-scanner'],[('raw_result','osv.json')],{0,1},tmp_path)=='completed'

def test_zero_without_valid_json_is_failed(tmp_path,monkeypatch):
    monkeypatch.setattr(w,'execute',lambda *a:0)
    monkeypatch.setattr(w.subprocess,'run',lambda *a,**k:MagicMock(stdout='v2'))
    assert w.run_tool(MagicMock(),{'scan_id':'s','attempt_count':1},'osv',['osv-scanner'],[('raw_result','missing.json')],{0,1},tmp_path)=='failed'

def test_timeout_kills_child(tmp_path):
    with pytest.raises(TimeoutError):
        w.execute([sys.executable,'-c','import time;time.sleep(60)'],tmp_path/'log',lambda:None,0,threading.Event())

def test_shutdown_kills_child(tmp_path):
    stop=threading.Event();stop.set()
    with pytest.raises(InterruptedError):
        w.execute([sys.executable,'-c','import time;time.sleep(60)'],tmp_path/'log',lambda:None,60,stop)

def test_database_failure_aborts_process(tmp_path):
    def tick(): raise w.psycopg.OperationalError('lost connection')
    with pytest.raises(w.psycopg.OperationalError):
        w.execute([sys.executable,'-c','import time;time.sleep(60)'],tmp_path/'log',tick,60,threading.Event())

def test_input_hash_and_path(tmp_path,monkeypatch):
    monkeypatch.setattr(w,'INPUT_ROOT',tmp_path)
    d=tmp_path/'s';d.mkdir()
    rows=[]
    for kind in ('package_json','package_lock'):
        (d/kind).write_bytes(b'{}')
        rows.append(dict(kind=kind,storage_key=f's/{kind}',size_bytes=2,sha256=hashlib.sha256(b'{}').hexdigest()))
    c=MagicMock();c.execute.return_value.fetchall.return_value=rows
    assert len(w.verify_inputs(c,'s'))==2
    rows[0]['sha256']='0'*64
    with pytest.raises(ValueError,match='hash'): w.verify_inputs(c,'s')
    rows[0]['storage_key']='../outside'
    with pytest.raises(ValueError,match='path'): w.verify_inputs(c,'s')

def test_raw_success_is_partial(tmp_path,monkeypatch):
    monkeypatch.setattr(w,'evaluate_scan',lambda *a: {'status':'completed'})
    monkeypatch.setattr(w,'finalize',lambda *a:'partial')
    monkeypatch.setattr(w,'OUTPUT_ROOT',tmp_path)
    monkeypatch.setattr(w,'verify_inputs',lambda *a:{'package_lock':tmp_path/'lock'})
    monkeypatch.setattr(w,'store_packages',lambda *a,**kw: {})
    monkeypatch.setattr(w,'collect_maintenance',lambda *a,**kw: {})
    monkeypatch.setattr(w,'store_findings',lambda *a,**kw: {})
    monkeypatch.setattr(w,'run_tools',lambda *a:['completed']*3)
    c=MagicMock();w.process(c,{'scan_id':'s','attempt_count':1})
    assert c.execute.call_args.args[1][0]=='partial'

def test_all_failed(tmp_path,monkeypatch):
    monkeypatch.setattr(w,'evaluate_scan',lambda *a: {'status':'invalid_input'})
    monkeypatch.setattr(w,'finalize',lambda *a:'failed')
    monkeypatch.setattr(w,'OUTPUT_ROOT',tmp_path)
    monkeypatch.setattr(w,'verify_inputs',lambda *a:{'package_lock':tmp_path/'lock'})
    monkeypatch.setattr(w,'store_packages',lambda *a,**kw: {})
    monkeypatch.setattr(w,'collect_maintenance',lambda *a,**kw: {})
    monkeypatch.setattr(w,'store_findings',lambda *a,**kw: {})
    monkeypatch.setattr(w,'run_tools',lambda *a:['failed']*3)
    c=MagicMock();w.process(c,{'scan_id':'s','attempt_count':1})
    assert c.execute.call_args.args[1][0]=='failed'


class MainThreadConn:
    """Fake connection that records which threads touched the DB."""
    def __init__(self):
        self.threads=set()
    def execute(self,*a,**k):
        self.threads.add(threading.current_thread().name)
        return MagicMock()
    def transaction(self):
        import contextlib
        self.threads.add(threading.current_thread().name)
        return contextlib.nullcontext()


def _sleep_spec(name,out,seconds,code=0):
    body=f"import json,time;time.sleep({seconds});json.dump({{}},open(r'{out/(name+'.json')}','w'));raise SystemExit({code})"
    return (name,[sys.executable,'-c',body],[('raw_result',name+'.json')],{0,1})


def test_scanners_run_concurrently_and_db_stays_on_main_thread(tmp_path,monkeypatch):
    monkeypatch.setattr(w,'OUTPUT_ROOT',tmp_path)
    monkeypatch.setattr(w.subprocess,'run',lambda *a,**k:MagicMock(stdout='v'))
    marked=[];monkeypatch.setattr(w.vuln_db,'mark_downloaded',lambda d,n:marked.append(n))
    c=MainThreadConn()
    specs=[_sleep_spec('trivy',tmp_path,1.2),_sleep_spec('osv',tmp_path,1.2,1),_sleep_spec('syft',tmp_path,1.2)]
    started=w.time.monotonic()
    states=w.run_tools(c,{'scan_id':'s','attempt_count':1},specs,tmp_path,{'trivy':False})
    elapsed=w.time.monotonic()-started
    assert states==['completed','completed','completed']
    assert elapsed<2.5, elapsed          # sequential would take at least 3.6s
    assert c.threads=={threading.main_thread().name}
    assert marked==['trivy']             # trivy refreshed successfully; osv never touches the DB policy


def test_failed_refresh_is_not_marked(tmp_path,monkeypatch):
    monkeypatch.setattr(w,'OUTPUT_ROOT',tmp_path)
    monkeypatch.setattr(w.subprocess,'run',lambda *a,**k:MagicMock(stdout='v'))
    marked=[];monkeypatch.setattr(w.vuln_db,'mark_downloaded',lambda d,n:marked.append(n))
    specs=[_sleep_spec('trivy',tmp_path,0.1,3),_sleep_spec('osv',tmp_path,0.1)]
    states=w.run_tools(MagicMock(),{'scan_id':'s','attempt_count':1},specs,tmp_path,{})
    assert states==['failed','completed'] and marked==[]


def test_shutdown_stops_every_running_scanner(tmp_path,monkeypatch):
    monkeypatch.setattr(w,'OUTPUT_ROOT',tmp_path)
    monkeypatch.setattr(w.subprocess,'run',lambda *a,**k:MagicMock(stdout='v'))
    monkeypatch.setattr(w,'STOP',threading.Event())
    threading.Timer(0.5,w.STOP.set).start()
    specs=[_sleep_spec(n,tmp_path,30) for n in ('trivy','osv','syft')]
    started=w.time.monotonic()
    with pytest.raises(InterruptedError):
        w.run_tools(MagicMock(),{'scan_id':'s','attempt_count':1},specs,tmp_path,{})
    assert w.time.monotonic()-started<5


def test_commands_follow_db_refresh_policy(tmp_path):
    fresh={x[0]:x[1] for x in w.commands(tmp_path/'lock',tmp_path,{'trivy':True})}
    stale={x[0]:x[1] for x in w.commands(tmp_path/'lock',tmp_path,{})}
    assert '--skip-db-update' in fresh['trivy'] and '--skip-db-update' not in stale['trivy']
    assert fresh['osv']==stale['osv']    # OSV always queries the API
    assert not any('offline' in a for a in fresh['osv'])
