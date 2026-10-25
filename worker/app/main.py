"""Single active worker MVP: session lock, atomic claim, raw scanner artifacts.
Packages, normalization and maintenance are persisted after scanner execution.
"""
import hashlib
import json
import logging
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from uuid import uuid4

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from .finding_storage import store_findings, finalize
from .package_storage import store_packages
from .maintenance import collect as collect_maintenance
from .priority_storage import evaluate_scan
from .priority_stage import PriorityStagePersistenceError
from . import vuln_db

log = logging.getLogger('worker')
STOP = threading.Event()
LOCK_ID = 784932010  # project-local exclusive consumer; held on the same DB session
INPUT_ROOT = Path(os.getenv('SCAN_STORAGE_ROOT', '/work/uploads'))
OUTPUT_ROOT = Path(os.getenv('SCAN_RESULTS_ROOT', '/work/results'))
TIMEOUT = int(os.getenv('SCAN_TOOL_TIMEOUT_SECONDS', '660'))


def connect():
    return psycopg.connect(host=os.getenv('DB_HOST', 'db'), port=os.getenv('DB_PORT', '5432'),
        user=os.environ['DB_USER'], password=os.environ['DB_PASSWORD'], dbname=os.environ['DB_NAME'],
        connect_timeout=5, autocommit=True, row_factory=dict_row,
        options='-c statement_timeout=15000', tcp_user_timeout=15000,
        keepalives=1, keepalives_idle=10, keepalives_interval=5, keepalives_count=3)


def recover(conn):
    # Safe only while holding the project-wide session lock. Never auto-retry.
    with conn.transaction():
        conn.execute("""UPDATE scan_tool_runs SET status='failed', finished_at=now(),
            error_message='worker_interrupted' WHERE status='running' AND scan_id IN
            (SELECT scan_id FROM scan_runs WHERE status='running')""")
        conn.execute("""UPDATE scan_runs SET status='failed', finished_at=now(),
            error_message='worker_interrupted; upload again to retry',
            tool_status=tool_status || '{"worker":{"status":"failed","reason":"worker_interrupted"},"priority":{"status":"failed","current_result_available":false,"error_code":"WORKER_INTERRUPTED"}}'::jsonb
            WHERE status='running'""")


def claim(conn, worker_id):
    with conn.transaction():
        return conn.execute("""WITH next AS (
            SELECT scan_id FROM scan_runs WHERE status='queued'
            ORDER BY created_at,scan_id FOR UPDATE SKIP LOCKED LIMIT 1)
            UPDATE scan_runs s SET status='running', started_at=now(), finished_at=NULL,
            heartbeat_at=now(), worker_id=%s, attempt_count=attempt_count+1,
            tool_status='{}'::jsonb, error_message=NULL
            FROM next WHERE s.scan_id=next.scan_id RETURNING s.*""", (worker_id,)).fetchone()


def heartbeat(conn, scan_id):
    conn.execute("UPDATE scan_runs SET heartbeat_at=now() WHERE scan_id=%s AND status='running'", (scan_id,))


def status(conn, scan_id, name, value):
    conn.execute('UPDATE scan_runs SET tool_status=tool_status || %s WHERE scan_id=%s',
                 (Jsonb({name:value}), scan_id))


def verify_inputs(conn, scan_id):
    rows=conn.execute("SELECT kind,storage_key,sha256,size_bytes FROM scan_artifacts WHERE scan_id=%s AND kind IN ('package_json','package_lock') AND deleted_at IS NULL",(scan_id,)).fetchall()
    if {r['kind'] for r in rows} != {'package_json','package_lock'} or len(rows)!=2:
        raise ValueError('missing_input_artifacts')
    paths={}
    for r in rows:
        path=(INPUT_ROOT/r['storage_key']).resolve()
        if not path.is_relative_to((INPUT_ROOT/str(scan_id)).resolve()):
            raise ValueError('invalid_input_path')
        data=path.read_bytes()
        if len(data)!=r['size_bytes'] or hashlib.sha256(data).hexdigest()!=r['sha256']:
            raise ValueError('input_hash_mismatch')
        paths[r['kind']]=path
    return paths


def commands(lock, out, fresh=None):
    """fresh: {'trivy': bool}; True means Trivy uses its cached vulnerability DB without updating it.
    OSV queries the OSV API: its offline mode re-reads the whole npm DB archive on every scan
    (measured ~19s vs ~1s for Trivy), which is slower than the online query."""
    fresh = fresh or {}
    trivy_update = ['--skip-db-update', '--skip-java-db-update'] if fresh.get('trivy') else []
    return [
        ('trivy', ['trivy','fs','--scanners','vuln','--format','json','--output',str(out/'trivy.json'),
            '--cache-dir',os.getenv('TRIVY_CACHE_DIR','/cache/trivy'),'--db-repository','ghcr.io/aquasecurity/trivy-db:2',
            *trivy_update,'--disable-telemetry','--skip-version-check','--no-progress','--timeout','10m',str(lock)],
            [('raw_result','trivy.json')], {0}),
        ('osv', ['osv-scanner','scan','source','-L',str(lock),
            '--format','json','--output-file',str(out/'osv.json')],
            [('raw_result','osv.json')], {0,1}),
        ('syft', ['syft',f'file:{lock}','-o',f'syft-json={out / "syft.json"}','-o',f'spdx-json={out / "sbom.spdx.json"}','-q'],
            [('raw_result','syft.json'),('sbom','sbom.spdx.json')], {0}),
    ]
def execute(argv, log_path, tick, timeout, stop=STOP):
    """No shell; kill the process group on timeout, shutdown, or lost DB session."""
    with log_path.open('wb') as output:
        proc=subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        start=time.monotonic()
        try:
            while proc.poll() is None:
                if stop.is_set():
                    raise InterruptedError('worker_shutdown')
                if time.monotonic()-start >= timeout:
                    raise TimeoutError('tool_timeout')
                tick()
                stop.wait(1)
            return proc.returncode
        finally:
            if proc.poll() is None:
                try: os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                proc.wait()


def artifact(conn, scan_id, run_id, kind, path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''): digest.update(chunk)
    conn.execute("""INSERT INTO scan_artifacts(scan_id,tool_run_id,kind,storage_key,sha256,size_bytes,media_type)
        VALUES(%s,%s,%s,%s,%s,%s,%s)""",(scan_id,run_id,kind,
        path.relative_to(OUTPUT_ROOT).as_posix(),digest.hexdigest(),path.stat().st_size,
        'application/json' if path.suffix=='.json' else 'text/plain'))


def _tool_version(name, argv):
    try:
        return subprocess.run([argv[0], 'version' if name=='syft' else '--version'],
                              capture_output=True,text=True,timeout=10).stdout.strip()[:1000]
    except (OSError,subprocess.TimeoutExpired):
        return None


def _start_tool(conn, scan, name, argv):
    sid=scan['scan_id'];rid=uuid4()
    conn.execute("""INSERT INTO scan_tool_runs(tool_run_id,scan_id,tool_name,attempt_no,tool_version,status,started_at)
        VALUES(%s,%s,%s,%s,%s,'running',now())""",(rid,sid,name,scan['attempt_count'],_tool_version(name,argv)))
    status(conn,sid,name,{'status':'running'})
    return rid


def _run_process(name, argv, outputs, accepted, out, tick, stop=STOP):
    """Runs one tool without touching the database. Returns (state, exit_code, error, elapsed_ms)."""
    started=time.monotonic();error=None;code=None;state='failed'
    try:
        code=execute(argv,out/f'{name}.log',tick,TIMEOUT,stop)
        if code not in accepted: raise ValueError('tool_exit_error')
        for _,filename in outputs:
            with (out/filename).open() as f: data=json.load(f)
            if not isinstance(data,dict): raise ValueError('invalid_output_json')
        state='completed'
    except TimeoutError: state='timeout';error='tool_timeout'
    except (OSError,ValueError): error='tool_failed_or_invalid_output'
    return state,code,error,int((time.monotonic()-started)*1000)


def _finish_tool(conn, scan, name, rid, outputs, out, result, extra=None):
    sid=scan['scan_id'];state,code,error,elapsed=result
    # Keep even failed output for diagnosis; status distinguishes success from 0 findings.
    with conn.transaction():
        for kind,filename in outputs+[('log',f'{name}.log')]:
            if (out/filename).is_file(): artifact(conn,sid,rid,kind,out/filename)
        conn.execute('UPDATE scan_tool_runs SET status=%s,finished_at=now(),exit_code=%s,error_message=%s WHERE tool_run_id=%s',
            (state,code,error,rid))
        status(conn,sid,name,{'status':state,'exit_code':code,'reason':error,'elapsed_ms':elapsed,**(extra or {})})
    return state


def run_tool(conn, scan, name, argv, outputs, accepted, out):
    rid=_start_tool(conn,scan,name,argv)
    result=_run_process(name,argv,outputs,accepted,out,lambda:heartbeat(conn,scan['scan_id']))
    return _finish_tool(conn,scan,name,rid,outputs,out,result)


def run_tools(conn, scan, specs, out, fresh=None):
    """Run the scanners concurrently. Only this (main) thread uses the DB connection;
    worker threads just run processes. Any interruption stops every child process."""
    sid=scan['scan_id'];fresh=fresh or {}
    started={spec[0]:_start_tool(conn,scan,spec[0],spec[1]) for spec in specs}
    abort=threading.Event();states={}
    pool=ThreadPoolExecutor(max_workers=len(specs))
    try:
        futures={pool.submit(_run_process,name,argv,outputs,accepted,out,lambda:None,abort):(name,outputs)
                 for name,argv,outputs,accepted in specs}
        pending=set(futures)
        while pending:
            done,pending=wait(pending,timeout=1,return_when=FIRST_COMPLETED)
            if STOP.is_set(): raise InterruptedError('worker_shutdown')
            heartbeat(conn,sid)
            for future in done:
                name,outputs=futures[future]
                result=future.result()
                db=None
                if name=='trivy':
                    db='cached' if fresh.get(name) else 'refreshed' if result[0]=='completed' else 'refresh_failed'
                    if db=='refreshed':
                        vuln_db.mark_downloaded(vuln_db.TRIVY_CACHE,name)
                states[name]=_finish_tool(conn,scan,name,started[name],outputs,out,result,{'vulnerability_db':db} if db else None)
    except BaseException:
        abort.set()
        raise
    finally:
        pool.shutdown(wait=True)
    return [states[name] for name,*_ in specs]


def process(conn, scan):
    sid=scan['scan_id']
    try:
        paths=verify_inputs(conn,sid)
        out=OUTPUT_ROOT/str(sid)/str(scan['attempt_count'])
        out.mkdir(parents=True,exist_ok=False)
        timing={}
        mark=time.monotonic()
        fresh=vuln_db.policy()
        if STOP.is_set(): raise InterruptedError('worker_shutdown')
        run_tools(conn,scan,commands(paths['package_lock'],out,fresh),out,fresh)
        timing['scanners_ms']=int((time.monotonic()-mark)*1000);mark=time.monotonic()
        try:
            summary=store_packages(conn,sid,paths,OUTPUT_ROOT,allow_running=True)
            log.info('scan=%s package_storage=%s',sid,summary)
        except (OSError,ValueError,KeyError,TypeError):
            log.exception('package storage failed: %s',sid)
            status(conn,sid,'package_storage',{'status':'failed','reason':'invalid_package_or_syft_data'})
        try:
            summary=store_findings(conn,sid,paths,OUTPUT_ROOT,allow_running=True)
            log.info('scan=%s normalization=%s',sid,summary)
        except (OSError,ValueError,KeyError,TypeError,psycopg.IntegrityError):
            log.exception('normalization storage failed: %s',sid)
            status(conn,sid,'normalization',{'status':'failed','reason':'normalization_storage_failed'})
        timing['storage_ms']=int((time.monotonic()-mark)*1000);mark=time.monotonic()
        try:
            result = evaluate_scan(conn, scan)
            log.info('scan=%s priority=%s', sid, result['status'])
        except PriorityStagePersistenceError:
            # Evidence is already committed; never turn storage failure into success.
            log.warning('scan=%s priority persistence failed', sid)
            updated = conn.execute('''UPDATE scan_runs SET tool_status=tool_status || %s
                WHERE scan_id=%s AND status='running' AND worker_id=%s AND attempt_count=%s''',
                (Jsonb({'priority': {'status':'failed','current_result_available':False,
                    'error_code':'PRIORITY_PERSISTENCE_FAILED'}}),sid,scan['worker_id'],scan['attempt_count']))
            if updated.rowcount != 1:
                raise RuntimeError('priority_worker_fence_mismatch')
        timing['priority_ms']=int((time.monotonic()-mark)*1000);mark=time.monotonic()
        def maintenance_tick():
            if STOP.is_set(): raise InterruptedError('worker_shutdown')
            heartbeat(conn,sid)
        try:
            collect_maintenance(conn,sid,allow_running=True,tick=maintenance_tick)
        except (ValueError,KeyError,TypeError,OSError):
            log.exception('maintenance failed: %s',sid)
            status(conn,sid,'github',{'status':'failed','reason':'maintenance_collection_failed'})
        timing['maintenance_ms']=int((time.monotonic()-mark)*1000)
        status(conn,sid,'timing',timing)
        log.info('scan=%s timing=%s',sid,timing)
        final=finalize(conn,sid)
        conn.execute('UPDATE scan_runs SET status=%s,finished_at=now(),heartbeat_at=now(),error_message=%s WHERE scan_id=%s',
            (final,None if final=='completed' else 'incomplete_stages; see tool_status',sid))
        log.info('scan=%s status=%s',sid,final)
    except (OSError,ValueError,InterruptedError) as exc:
        with conn.transaction():
            conn.execute("UPDATE scan_tool_runs SET status='failed',finished_at=now(),error_message='worker_failed' WHERE scan_id=%s AND status='running'",(sid,))
            status(conn,sid,'worker',{'status':'failed','reason':type(exc).__name__})
            conn.execute("UPDATE scan_runs SET status='failed',finished_at=now(),error_message=%s WHERE scan_id=%s",(type(exc).__name__,sid))
        log.exception('scan failed: %s',sid)


def main():
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    for sig in (signal.SIGINT,signal.SIGTERM): signal.signal(sig,lambda *_:STOP.set())
    worker_id=str(uuid4())
    while not STOP.is_set():
        try:
            with connect() as conn:
                if not conn.execute('SELECT pg_try_advisory_lock(%s) AS acquired',(LOCK_ID,)).fetchone()['acquired']:
                    STOP.wait(5);continue
                recover(conn)
                log.info('active worker=%s; scanner and storage pipeline ready',worker_id)
                while not STOP.is_set():
                    scan=claim(conn,worker_id)
                    if scan: process(conn,scan)
                    else: STOP.wait(2)
        except psycopg.Error:
            log.exception('DB session lost; reconnecting after 5s')
            STOP.wait(5)

if __name__=='__main__': main()
