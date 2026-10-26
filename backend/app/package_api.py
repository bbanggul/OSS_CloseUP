"""Package group API. No scan writes or new priority calculations on reads."""
import logging
from typing import Literal
from uuid import UUID
import psycopg
from fastapi import APIRouter, HTTPException, Query
from psycopg.rows import dict_row
from .db import connect
from .priority_view import load_priority
from .package_view import build_view, filter_groups, public_group

router = APIRouter()
log = logging.getLogger(__name__)


def read_view(scan_id, snapshot_id=None):
    try:
        with connect() as conn:
            with conn.transaction():
                conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute('SELECT scan_id,status,attempt_count,worker_id,tool_status FROM scan_runs WHERE scan_id=%s', (scan_id,))
                    scan = cur.fetchone()
                    if scan is None:
                        raise HTTPException(404, 'scan_not_found')
                    cur.execute('SELECT package_id,ecosystem,name,installed_version,lockfile_path,relationship,licenses,purl,repository_url,repository_full_name FROM packages WHERE scan_id=%s ORDER BY package_id', (scan_id,))
                    packages = cur.fetchall()
                    cur.execute("SELECT * FROM findings WHERE scan_id=%s AND type='vulnerability' ORDER BY finding_id", (scan_id,))
                    findings = cur.fetchall()
                    cur.execute('SELECT * FROM finding_packages WHERE scan_id=%s ORDER BY finding_id,package_id', (scan_id,))
                    links = cur.fetchall()
                state, result = load_priority(conn, scan_id, scan['tool_status'])
    except psycopg.Error:
        log.exception('Package group lookup failed')
        raise HTTPException(503, 'database_unavailable') from None
    view = build_view(scan, packages, findings, links, state, result)
    if snapshot_id is not None and snapshot_id != view['meta']['snapshot_id']:
        raise HTTPException(409, {'code': 'snapshot_changed', 'snapshot_id': view['meta']['snapshot_id']})
    return view


def page_response(view, items, limit, offset):
    meta = view['meta']
    ready = meta['result_state'] in ('ready', 'partial')
    page = items[offset:offset + limit]
    if not ready:
        reason = meta['result_state']
    elif page:
        reason = None
    elif meta['zero_findings_confirmed']:
        reason = 'no_vulnerabilities'
    elif meta['result_state'] == 'partial' and meta['unique_finding_count'] == 0:
        reason = 'partial_no_findings'
    elif not items:
        reason = 'no_matches'
    else:
        reason = 'page_out_of_range'
    return {**meta, 'total': len(items) if ready else None, 'limit': limit, 'offset': offset,
            'empty_reason': reason, 'items': page}


@router.get('/scans/{scan_id}/vulnerable-packages')
def get_vulnerable_packages(scan_id: UUID, limit: int = Query(100, ge=1, le=500),
        offset: int = Query(0, ge=0), q: str = Query('', max_length=200),
        priority: Literal['P0', 'P1', 'P2', 'P3'] | None = None,
        severity: Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] | None = None,
        relationship: Literal['direct', 'indirect', 'unknown'] | None = None,
        snapshot_id: str | None = Query(None, max_length=80)):
    view = read_view(scan_id, snapshot_id)
    rows = filter_groups(view['items'], q=q, priority=priority, severity=severity, relationship=relationship)
    return page_response(view, [public_group(g) for g in rows], limit, offset)


@router.get('/scans/{scan_id}/vulnerable-packages/{package_group_id}')
def get_vulnerable_package(scan_id: UUID, package_group_id: str,
        snapshot_id: str | None = Query(None, max_length=80)):
    view = read_view(scan_id, snapshot_id)
    if view['meta']['result_state'] not in ('ready', 'partial'):
        raise HTTPException(409, {'code': 'results_not_ready', 'result_state': view['meta']['result_state']})
    group = next((g for g in view['items'] if g['package_group_id'] == package_group_id), None)
    if group is None:
        raise HTTPException(404, 'package_group_not_found')
    return {**view['meta'], 'item': public_group(group, detail=True)}


@router.get('/scans/{scan_id}/unlinked-vulnerabilities')
def get_unlinked_vulnerabilities(scan_id: UUID, limit: int = Query(100, ge=1, le=500),
        offset: int = Query(0, ge=0), snapshot_id: str | None = Query(None, max_length=80)):
    view = read_view(scan_id, snapshot_id)
    rows = [{**view['findings'][fid], 'installation_links': view['links'][fid],
             'unlinked_reason': 'no_affected_non_root_installation', 'global_rank': None}
            for fid in view['unlinked_ids']]
    return page_response(view, rows, limit, offset)


@router.get('/scans/{scan_id}/findings/{finding_ref}')
def get_canonical_finding(scan_id: UUID, finding_ref: str,
        snapshot_id: str | None = Query(None, max_length=80)):
    view = read_view(scan_id, snapshot_id)
    if view['meta']['result_state'] not in ('ready', 'partial'):
        raise HTTPException(409, {'code': 'results_not_ready', 'result_state': view['meta']['result_state']})
    direct, aliases = [], []
    for fid, row in view['findings'].items():
        normalized = (row.get('evidence') or {}).get('normalized') or {}
        if finding_ref in (fid, normalized.get('finding_id')):
            direct.append(fid)
        basis = normalized.get('merge_basis') or {}
        if basis.get('kind') == 'explicit_ghsa_identity' and finding_ref in basis.get('source_finding_ids', []):
            aliases.append(fid)
    matches = sorted(set(direct or aliases))
    if not matches:
        raise HTTPException(404, 'finding_not_found')
    if len(matches) != 1:
        raise HTTPException(409, 'ambiguous_finding_alias')
    fid = matches[0]
    return {**view['meta'], 'requested_finding_id': finding_ref, 'canonical_finding_id': fid,
            'resolution': 'direct' if direct else 'merged',
            'item': {**view['findings'][fid], 'installation_links': view['links'][fid]}}
