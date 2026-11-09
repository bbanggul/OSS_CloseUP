"""Raw scan reads on a caller-owned connection; never begin/commit a transaction."""
from fastapi import HTTPException
from psycopg.rows import dict_row

PACKAGE_SCAN_FIELDS = ('scan_id', 'status', 'attempt_count', 'worker_id', 'tool_status')
PACKAGE_FIELDS = ('package_id', 'ecosystem', 'name', 'installed_version', 'lockfile_path',
                  'relationship', 'licenses', 'purl', 'repository_url', 'repository_full_name')


def load_scan_material(conn, scan_id, *, comparison=False):
    # Keep the old projections exactly: adding comparison metadata must not stale AI caches.
    scan_columns = ','.join(PACKAGE_SCAN_FIELDS)
    package_columns = ','.join(PACKAGE_FIELDS)
    if comparison:
        scan_columns += (',project_id,created_at,started_at,finished_at,'
                         'input_package_json_sha256,input_package_lock_sha256')
        package_columns += ',scan_id,evidence'
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f'SELECT {scan_columns} FROM scan_runs WHERE scan_id=%s', (scan_id,))
        scan = cur.fetchone()
        if scan is None:
            raise HTTPException(404, 'scan_not_found')
        cur.execute(f'SELECT {package_columns} FROM packages WHERE scan_id=%s ORDER BY package_id', (scan_id,))
        packages = cur.fetchall()
        cur.execute("SELECT * FROM findings WHERE scan_id=%s AND type='vulnerability' ORDER BY finding_id", (scan_id,))
        findings = cur.fetchall()
        if comparison:
            cur.execute("""SELECT fp.* FROM finding_packages fp JOIN findings f
                ON f.finding_id=fp.finding_id AND f.scan_id=fp.scan_id
                WHERE fp.scan_id=%s AND f.type='vulnerability' ORDER BY fp.finding_id,fp.package_id""", (scan_id,))
        else:
            cur.execute('SELECT * FROM finding_packages WHERE scan_id=%s ORDER BY finding_id,package_id', (scan_id,))
        links = cur.fetchall()
        material = dict(scan=scan, packages=packages, findings=findings, links=links)
        if comparison:
            cur.execute('SELECT project_id,name FROM projects WHERE project_id=%s', (scan['project_id'],))
            material['project'] = cur.fetchone()
            cur.execute('''SELECT scan_id,tool_run_id,tool_name,attempt_no,status,tool_version,
                database_version,started_at,finished_at FROM scan_tool_runs
                WHERE scan_id=%s AND attempt_no=%s AND tool_name IN ('trivy','osv')
                ORDER BY tool_name,tool_run_id''', (scan_id, scan['attempt_count']))
            material['source_runs'] = cur.fetchall()
            # Only metadata: no filesystem reads, raw logs, storage paths or secrets.
            cur.execute('''SELECT a.scan_id,a.artifact_id,a.tool_run_id,a.kind,a.sha256
                FROM scan_artifacts a JOIN scan_tool_runs r USING(scan_id,tool_run_id)
                WHERE a.scan_id=%s AND r.attempt_no=%s AND r.tool_name IN ('trivy','osv')
                AND a.kind='raw_result' ORDER BY a.artifact_id''', (scan_id, scan['attempt_count']))
            material['artifacts'] = cur.fetchall()
    return material
