"""Read-only HTTP adapter for the stored scan comparison contract."""
import json
import logging
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
import psycopg
from psycopg.rows import dict_row

from .db import connect
from .scan_material import load_scan_material
from .scan_compare import ComparisonError, check_limit, check_pair, compare_scans

router = APIRouter()
log = logging.getLogger(__name__)


def contract_schema(name):
    """Embed the checked-in contract in OpenAPI without unresolved local $defs refs."""
    schema = json.loads((Path(__file__).parent / 'schemas' / name).read_text())
    def expand(value):
        if isinstance(value, list): return [expand(v) for v in value]
        if not isinstance(value, dict): return value
        if '$ref' in value:
            return expand(schema['$defs'][value['$ref'].rsplit('/', 1)[1]])
        return {k: expand(v) for k, v in value.items() if k not in ('$defs', '$schema', '$id')}
    return expand(schema)


def preflight(conn, base_id, target_id):
    ids = [base_id, target_id]
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute('SELECT scan_id,project_id,status FROM scan_runs WHERE scan_id=ANY(%s)', (ids,))
        rows = {str(r['scan_id']): r for r in cur.fetchall()}
        missing = [sid for sid in ids if str(sid) not in rows]
        if missing:
            raise ComparisonError('scan_not_found', 404, missing)
        check_pair(rows[str(base_id)], rows[str(target_id)])
        # Count before loading evidence. No silent truncation or successful partial page.
        cur.execute("SELECT count(*) AS n FROM packages WHERE scan_id=ANY(%s) AND relationship <> 'root'", (ids,))
        check_limit('installations', cur.fetchone()['n'])
        cur.execute("""SELECT count(*) AS n FROM finding_packages fp
            JOIN packages p USING(scan_id,package_id) JOIN findings f USING(scan_id,finding_id)
            WHERE fp.scan_id=ANY(%s) AND fp.role='affected' AND p.relationship <> 'root'
              AND f.type='vulnerability'""", (ids,))
        check_limit('finding_links', cur.fetchone()['n'])
        cur.execute("""SELECT count(*) AS n FROM findings f WHERE f.scan_id=ANY(%s)
            AND f.type='vulnerability' AND NOT EXISTS (
                SELECT 1 FROM finding_packages fp JOIN packages p USING(scan_id,package_id)
                WHERE fp.scan_id=f.scan_id AND fp.finding_id=f.finding_id
                  AND fp.role='affected' AND p.relationship <> 'root')""", (ids,))
        check_limit('unlinked_findings', cur.fetchone()['n'])


_responses = {200: {'description': 'Stored observations, including explicitly incomplete comparisons',
                   'content': {'application/json': {'schema': contract_schema('compare-response.schema.json')}}}}
for _status in (404, 409, 422, 500, 503):
    _responses[_status] = {'description': 'Comparison error (422 also includes standard request validation)',
        'content': {'application/json': {'schema': contract_schema('compare-error.schema.json')}}}
_responses[422]['content']['application/json']['schema'] = {'anyOf': [
    _responses[422]['content']['application/json']['schema'],
    {'type': 'object', 'required': ['detail'], 'properties': {'detail': {'type': 'array', 'items': {'type': 'object'}}}}]}


@router.get('/scans/{target_scan_id}/compare', responses=_responses, tags=['scan comparison'])
def get_scan_comparison(target_scan_id: UUID, base: UUID = Query(...)):
    try:
        if base == target_scan_id:
            raise ComparisonError('same_scan', 422, [base])
        with connect() as conn:
            with conn.transaction():
                conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                preflight(conn, base, target_scan_id)
                before = load_scan_material(conn, base, comparison=True)
                after = load_scan_material(conn, target_scan_id, comparison=True)
        return compare_scans(before, after)
    except ComparisonError as exc:
        if exc.status == 500:
            log.exception('Invalid stored scan comparison input')
        raise HTTPException(exc.status, exc.detail) from None
    except psycopg.Error:
        log.exception('Scan comparison database lookup failed')
        raise HTTPException(503, ComparisonError('database_unavailable', 503).detail) from None
    except (KeyError, TypeError, ValueError):
        log.exception('Malformed stored scan comparison input')
        raise HTTPException(500, ComparisonError('comparison_invariant_failed').detail) from None
