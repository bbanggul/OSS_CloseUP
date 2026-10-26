"""PostgreSQL adapter for D07. Scanner evidence is never rewritten here."""
import hashlib
import json
from uuid import uuid4

from psycopg.types.json import Jsonb

from .priority import PriorityInputError, SCHEMA_VERSION
from .priority_stage import run_priority_stage


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def source_snapshot(conn, scan_id):
    scan = conn.execute('SELECT tool_status FROM scan_runs WHERE scan_id=%s', (scan_id,)).fetchone()
    states = scan['tool_status']
    packages = conn.execute("""SELECT package_id::text,name,installed_version,relationship
        FROM packages WHERE scan_id=%s AND relationship<>'root' ORDER BY package_id""", (scan_id,)).fetchall()
    findings = conn.execute("""SELECT finding_id::text,severity,severity_conflict,manual_review_required,evidence
        FROM findings WHERE scan_id=%s AND type='vulnerability' ORDER BY finding_id""", (scan_id,)).fetchall()
    links = conn.execute("""SELECT fp.finding_id::text,fp.package_id::text,fp.fixed_version_candidates,fp.evidence
        FROM finding_packages fp JOIN findings f USING(scan_id,finding_id)
        JOIN packages p USING(scan_id,package_id)
        WHERE fp.scan_id=%s AND f.type='vulnerability' AND fp.role='affected' AND p.relationship<>'root'
        ORDER BY fp.finding_id,fp.package_id""", (scan_id,)).fetchall()
    artifacts = conn.execute("""SELECT artifact_id::text,tool_run_id::text,kind,storage_key,sha256,size_bytes
        FROM scan_artifacts WHERE scan_id=%s AND kind IN ('raw_result','log')
        ORDER BY artifact_id""", (scan_id,)).fetchall()
    return {'scan_id': str(scan_id), 'packages': packages, 'findings': findings,
            'finding_packages': links, 'artifacts': artifacts,
            'tool_status': {k: states.get(k, {}) for k in ('trivy','osv','package_storage','normalization')}}


def build_payload(snapshot):
    states = snapshot['tool_status']
    normalization = states['normalization']
    if (states['package_storage'].get('status') != 'completed'
            or normalization.get('status') not in ('completed', 'partial')
            or normalization.get('roundtrip_verified') is not True):
        raise PriorityInputError('SOURCE_NOT_READY', 'normalization', 'Validated stored scanner results required')
    tools = normalization.get('tool_status', {})
    if not all(t in tools for t in ('trivy', 'osv')):
        raise PriorityInputError('MISSING_TOOL_STATUS', 'tool_status', 'Normalized scanner statuses required')
    successes = sum(tools[t].get('status') == 'completed' for t in ('trivy','osv'))
    security = ('failed', 'partial', 'completed')[successes]
    findings = []
    for row in snapshot['findings']:
        normalized = row['evidence'].get('normalized', {})
        if 'priority_input_eligible' not in normalized or 'severity_observations' not in normalized:
            raise PriorityInputError('LEGACY_SOURCE', 'findings', 'Upload a new scan using current normalization')
        findings.append({**row, 'priority_input_eligible': normalized['priority_input_eligible'],
                         'severity_observations': normalized['severity_observations']})
    links = []
    for row in snapshot['finding_packages']:
        fix = row['evidence'].get('fix_information', 'unknown')
        links.append({**row, 'fix_information': fix})
    return {'schema_version': SCHEMA_VERSION, 'scan_id': snapshot['scan_id'],
            'security_status': security, 'tool_status': tools,
            'packages': snapshot['packages'], 'findings': findings, 'finding_packages': links}


class PostgresPriorityStore:
    def __init__(self, conn, scan, snapshot):
        if not conn.autocommit:
            raise ValueError('priority_requires_autocommit_connection')
        self.conn, self.scan, self.snapshot = conn, scan, snapshot
        self.fingerprint = digest(snapshot)

    def fence(self):
        row = self.conn.execute('''SELECT status,worker_id,attempt_count,tool_status FROM scan_runs
            WHERE scan_id=%s FOR UPDATE''', (self.scan['scan_id'],)).fetchone()
        if (not row or row['status'] != 'running' or row['worker_id'] != self.scan['worker_id']
                or row['attempt_count'] != self.scan['attempt_count']):
            raise ValueError('priority_worker_fence_mismatch')
        return row

    def publish_state(self, record):
        state = {k: record[k] for k in ('evaluation_id','attempt_id','status','current_result_available',
                                      'priority_rule_version')}
        if record.get('error'):
            state['error_code'] = record['error']['code']
        if record.get('result'):
            state['summary'] = record['result']['summary']
            state['security_status'] = record['result']['security_status']
        self.conn.execute('UPDATE scan_runs SET tool_status=tool_status || %s WHERE scan_id=%s',
                          (Jsonb({'priority': state}), self.scan['scan_id']))

    def save_scan_evidence(self, record):
        # Raw artifacts and normalized rows were committed by earlier pipeline stages.
        # Preserve their exact snapshot and references in an independent transaction.
        with self.conn.transaction():
            self.fence()
            if digest(source_snapshot(self.conn, self.scan['scan_id'])) != self.fingerprint:
                raise ValueError('priority_source_changed')
            self.conn.execute('''INSERT INTO priority_evaluations
                (evaluation_id,scan_id,attempt_id,worker_id,attempt_count,source_fingerprint,status,evidence_snapshot)
                VALUES(%s,%s,%s,%s,%s,%s,'running',%s)''',
                (record['evaluation_id'], record['scan_id'], record['attempt_id'], self.scan['worker_id'],
                 self.scan['attempt_count'], self.fingerprint, Jsonb(self.snapshot)))
            self.publish_state({**record, 'status': 'running', 'current_result_available': False})

    def save_priority_result(self, record):
        with self.conn.transaction():
            row = self.fence()
            if row['tool_status'].get('priority', {}).get('evaluation_id') != record['evaluation_id']:
                raise ValueError('priority_evaluation_superseded')
            if digest(source_snapshot(self.conn, self.scan['scan_id'])) != self.fingerprint:
                raise ValueError('priority_source_changed')
            expected = {(x['finding_id'],x['package_id']) for x in self.snapshot['finding_packages']}
            links = record['result']['link_results']
            if {(x['finding_id'],x['package_id']) for x in links} != expected or len(links) != len(expected):
                raise ValueError('priority_link_set_mismatch')
            for link in links:
                updated = self.conn.execute('''UPDATE finding_packages SET priority=%s,priority_rule_version=%s
                    WHERE scan_id=%s AND finding_id=%s AND package_id=%s AND role='affected' ''',
                    (link['priority'],link['priority_rule_version'],record['scan_id'],link['finding_id'],link['package_id']))
                if updated.rowcount != 1:
                    raise ValueError('priority_link_missing')
            updated = self.conn.execute("""UPDATE priority_evaluations SET status='completed',result=%s,
                finished_at=clock_timestamp() WHERE evaluation_id=%s AND status='running'""",
                (Jsonb(record['result']),record['evaluation_id']))
            if updated.rowcount != 1:
                raise ValueError('priority_evaluation_not_running')
            self.publish_state(record)

    def save_priority_error(self, record):
        # Persist the pre-calculation input separately from trusted source evidence.
        # Exception text may contain database credentials; use a stable stage
        # description and preserve structured code/path/type for diagnosis.
        error = {k: record['error'].get(k) for k in ('stage','code','field_path','exception_type')}
        error['message'] = {
            'input_build': 'Priority input could not be constructed; inspect the error code and source evidence.',
            'calculation': ('Priority input validation failed; inspect the error code and field path.'
                            if record['status'] == 'invalid_input' else 'Priority calculation failed.'),
            'priority_storage': 'Priority result could not be saved; priority changes were rolled back.',
        }.get(error['stage'], 'Priority evaluation failed; inspect the structured error fields.')
        error['message_policy'] = 'safe-stage-summary-v1'
        with self.conn.transaction():
            row = self.fence()
            updated = self.conn.execute('''UPDATE priority_evaluations SET status=%s,error=%s,attempted_payload=%s,finished_at=clock_timestamp()
                WHERE evaluation_id=%s AND status='running' ''',
                (record['status'],Jsonb(error),
                 Jsonb(record['attempted_payload']) if record.get('attempted_payload') is not None else None,
                 record['evaluation_id']))
            if updated.rowcount != 1:
                raise ValueError('priority_evaluation_not_running')
            if row['tool_status'].get('priority', {}).get('evaluation_id') == record['evaluation_id']:
                self.publish_state(record)


def evaluate_scan(conn, scan):
    with conn.transaction():
        snapshot = source_snapshot(conn, scan['scan_id'])
    store = PostgresPriorityStore(conn, scan, snapshot)
    return run_priority_stage(scan_id=scan['scan_id'], attempt_id=uuid4(),
        raw_results=snapshot['artifacts'], valid_results=snapshot, tool_status=snapshot['tool_status'],
        build_payload=lambda evidence: build_payload(evidence['valid_results']), store=store)
