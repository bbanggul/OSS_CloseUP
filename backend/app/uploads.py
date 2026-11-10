"""Local MVP upload contract: npm lockfile v2/v3, one project, no npm install."""
import hashlib
import json
import logging
import os
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
from fastapi import APIRouter, File, HTTPException, UploadFile, Query, Form
from psycopg.rows import dict_row
from pydantic import BaseModel, Field, field_validator

from .db import connect
from .priority_view import load_priority, present_findings

router = APIRouter()
log = logging.getLogger(__name__)
PACKAGE_LIMIT = 1024 * 1024
LOCK_LIMIT = 10 * 1024 * 1024
BODY_LIMIT = PACKAGE_LIMIT + LOCK_LIMIT + 256 * 1024


class UploadBodyLimit:
    """Bound the entire multipart body before parsing, even without Content-Length."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['method'] != 'POST' or scope['path'].rstrip('/') != '/scans':
            return await self.app(scope, receive, send)
        from starlette.responses import JSONResponse
        body = bytearray()
        while True:
            msg = await receive()
            if msg['type'] == 'http.disconnect':
                return
            chunk = msg.get('body', b'')
            if len(body) + len(chunk) > BODY_LIMIT:
                return await JSONResponse(status_code=413, content={'detail': '업로드 전체 크기 제한을 초과했습니다.'})(scope, receive, send)
            body.extend(chunk)
            if not msg.get('more_body', False):
                break
        sent = False
        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
            return await receive()
        await self.app(scope, replay, send)


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(value)


def read_json(upload, expected, limit):
    if upload.filename != expected:
        raise HTTPException(422, f'파일명은 {expected}이어야 합니다.')
    data = upload.file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f'{expected}: 최대 {limit // (1024 * 1024)} MiB입니다.')
    try:
        obj = json.loads(data.decode('utf-8-sig'), object_pairs_hook=no_duplicate_keys, parse_constant=reject_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise HTTPException(422, f'{expected}: 유효한 UTF-8 JSON이 필요합니다.') from None
    if not isinstance(obj, dict):
        raise HTTPException(422, f'{expected}: JSON 객체가 필요합니다.')
    return data, obj


def validate_pair(package, lock):
    if type(lock.get('lockfileVersion')) is not int or lock['lockfileVersion'] not in (2, 3):
        raise HTTPException(422, '현재 package-lock.json v2/v3만 지원합니다.')
    packages = lock.get('packages')
    if not isinstance(packages, dict) or not isinstance(packages.get(''), dict):
        raise HTTPException(422, 'lock 파일에 packages와 루트 항목이 필요합니다.')
    root = packages['']
    if any('workspaces' in x for x in (package, root)):
        raise HTTPException(422, '현재 단일 프로젝트만 지원합니다(workspaces 미지원).')
    for path, entry in packages.items():
        if not isinstance(entry, dict):
            raise HTTPException(422, 'lock 패키지 항목은 객체여야 합니다.')
        if entry.get('link') or (path and not path.startswith('node_modules/')):
            raise HTTPException(422, 'workspace 및 로컬 링크 패키지는 지원하지 않습니다.')
    for key in ('name', 'version'):
        values = [x[key] for x in (package, lock, root) if key in x]
        if any(not isinstance(v, str) or not v.strip() for v in values) or len(set(values)) > 1:
            raise HTTPException(422, f'두 파일의 {key} 값이 올바르지 않거나 일치하지 않습니다.')
    for key in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
        for obj in (package, root):
            deps = obj.get(key, {})
            if not isinstance(deps, dict) or any(not isinstance(v, str) for v in deps.values()):
                raise HTTPException(422, f'{key}는 문자열 값의 객체여야 합니다.')
            if any(v.startswith(('file:', 'link:', 'workspace:')) for v in deps.values()):
                raise HTTPException(422, '로컬 파일·workspace 의존성은 지원하지 않습니다.')
        if package.get(key, {}) != root.get(key, {}):
            raise HTTPException(422, f'package.json과 lock 루트의 {key}가 다릅니다. lock 파일을 갱신해 주세요.')
    return package.get('name') or lock.get('name') or 'uploaded-project'


@router.post('/scans', status_code=202)
def create_scan(package_json: UploadFile = File(...), package_lock: UploadFile = File(...), project_id: UUID | None = Form(None)):
    package_bytes, package = read_json(package_json, 'package.json', PACKAGE_LIMIT)
    lock_bytes, lock = read_json(package_lock, 'package-lock.json', LOCK_LIMIT)
    name = validate_pair(package, lock)
    existing_project = project_id is not None
    if existing_project:
        try:
            with connect() as conn:
                if conn.execute('SELECT project_id FROM projects WHERE project_id=%s', (project_id,)).fetchone() is None:
                    raise HTTPException(404, '프로젝트를 찾을 수 없습니다.')
        except psycopg.Error:
            raise HTTPException(503, 'DB 조회에 실패했습니다.') from None
    project_id, scan_id = project_id or uuid4(), uuid4()
    storage = Path(os.environ.get('SCAN_STORAGE_ROOT', '/work/uploads'))
    directory = storage / str(scan_id)
    inputs = [('package_json', 'package.json', package_bytes), ('package_lock', 'package-lock.json', lock_bytes)]
    hashes = [hashlib.sha256(item[2]).hexdigest() for item in inputs]
    created = False
    try:
        directory.mkdir(parents=True, mode=0o755)
        created = True
        for _, filename, data in inputs:
            path = directory / filename
            path.write_bytes(data)
            path.chmod(0o644)  # worker UID differs; shared volume is worker-read-only
        with connect() as conn:
            if not existing_project:
                conn.execute('INSERT INTO projects (project_id, name, package_json_sha256, package_lock_sha256) VALUES (%s,%s,%s,%s)', (project_id, name, *hashes))
            conn.execute("INSERT INTO scan_runs (scan_id, project_id, status, input_package_json_sha256, input_package_lock_sha256) VALUES (%s,%s,'queued',%s,%s)", (scan_id, project_id, *hashes))
            for (kind, filename, data), digest in zip(inputs, hashes):
                conn.execute('INSERT INTO scan_artifacts (scan_id, kind, storage_key, sha256, size_bytes, media_type) VALUES (%s,%s,%s,%s,%s,%s)', (scan_id, kind, f'{scan_id}/{filename}', digest, len(data), 'application/json'))
    except (OSError, psycopg.Error):
        # Retain any files after a DB error: a lost COMMIT acknowledgement may
        # mean the transaction succeeded. Deleting then would strand a queued scan.
        # Reconcile unreferenced directories offline; never expose errors/secrets.
        log.exception('Upload persistence failed; scan_id=%s; files_created=%s', scan_id, created)
        raise HTTPException(503, '저장에 실패했습니다. 서버 로그를 확인해 주세요.') from None
    return {'project_id': str(project_id), 'scan_id': str(scan_id), 'status': 'queued', 'status_url': f'/scans/{scan_id}'}


@router.get('/scans/{scan_id}')
def get_scan(scan_id: UUID):
    try:
        with connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute('SELECT scan_id, project_id, display_name, status, created_at, started_at, finished_at, tool_status FROM scan_runs WHERE scan_id=%s', (scan_id,))
                row = cur.fetchone()
    except psycopg.Error:
        log.exception('Scan lookup failed')
        raise HTTPException(503, 'DB 조회에 실패했습니다.') from None
    if row is None:
        raise HTTPException(404, '검사를 찾을 수 없습니다.')
    return row


@router.get('/scans/{scan_id}/packages')
def get_packages(scan_id: UUID, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    try:
        with connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute('SELECT tool_status FROM scan_runs WHERE scan_id=%s', (scan_id,))
                scan = cur.fetchone()
                if scan is None:
                    raise HTTPException(404, '검사를 찾을 수 없습니다.')
                cur.execute('SELECT count(*) AS total FROM packages WHERE scan_id=%s', (scan_id,))
                total = cur.fetchone()['total']
                cur.execute("""SELECT package_id,name,installed_version,lockfile_path,relationship,
                    is_direct,purl,licenses,evidence FROM packages WHERE scan_id=%s
                    ORDER BY lockfile_path LIMIT %s OFFSET %s""", (scan_id, limit, offset))
                items = cur.fetchall()
    except psycopg.Error:
        log.exception('Package lookup failed')
        raise HTTPException(503, 'DB 조회에 실패했습니다.') from None
    return {'scan_id':str(scan_id),'total':total,'limit':limit,'offset':offset,
            'package_storage':scan['tool_status'].get('package_storage', {'status':'pending'}),'items':items}


@router.get('/scans/{scan_id}/maintenance')
def get_maintenance(scan_id: UUID, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    try:
        with connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute('SELECT tool_status FROM scan_runs WHERE scan_id=%s',(scan_id,))
                scan=cur.fetchone()
                if scan is None: raise HTTPException(404,'검사를 찾을 수 없습니다.')
                cur.execute("SELECT count(*) AS total FROM packages WHERE scan_id=%s AND relationship<>'root'",(scan_id,))
                total=cur.fetchone()['total']
                cur.execute("""SELECT p.package_id,p.name,p.installed_version,p.lockfile_path,
                    ms.repository_url,ms.repository_full_name,ms.archived,ms.deprecated,
                    ms.default_branch,ms.latest_commit_at,ms.latest_release_tag,ms.latest_release_published_at,
                    COALESCE(ms.github_status,'pending') AS github_status,
                    COALESCE(ms.npm_status,'pending') AS npm_status,
                    ms.github_error,ms.npm_error,ms.github_checked_at,ms.npm_checked_at,
                    ms.raw_github_response->'mapping' AS repository_mapping
                    FROM packages p LEFT JOIN maintenance_signals ms
                    ON ms.scan_id=p.scan_id AND ms.package_id=p.package_id
                    WHERE p.scan_id=%s AND p.relationship<>'root'
                    ORDER BY p.lockfile_path LIMIT %s OFFSET %s""",(scan_id,limit,offset))
                items=cur.fetchall()
    except psycopg.Error:
        log.exception('Maintenance lookup failed')
        raise HTTPException(503,'DB 조회에 실패했습니다.') from None
    return {'scan_id':str(scan_id),'total':total,'limit':limit,'offset':offset,
            'collection':scan['tool_status'].get('github',{'status':'pending'}),'items':items}


@router.get('/scans/{scan_id}/findings')
def get_findings(scan_id: UUID, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    try:
        with connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute('SELECT tool_status FROM scan_runs WHERE scan_id=%s',(scan_id,))
                scan=cur.fetchone()
                if scan is None: raise HTTPException(404,'검사를 찾을 수 없습니다.')
                cur.execute('SELECT count(*) AS total FROM findings WHERE scan_id=%s',(scan_id,))
                total=cur.fetchone()['total']
                cur.execute('''SELECT f.*,
                    COALESCE((SELECT jsonb_agg(jsonb_build_object(
                        'package_id',p.package_id,'name',p.name,'installed_version',p.installed_version,
                        'lockfile_path',p.lockfile_path,'relationship',p.relationship,
                        'fixed_version_candidates',fp.fixed_version_candidates,
                        'priority',fp.priority,'fix_information',fp.evidence->>'fix_information','recommended_fixed_version',fp.recommended_fixed_version)
                        ORDER BY p.lockfile_path)
                        FROM finding_packages fp JOIN packages p USING(scan_id,package_id)
                        WHERE fp.scan_id=f.scan_id AND fp.finding_id=f.finding_id),'[]'::jsonb) AS packages,
                    COALESCE((SELECT jsonb_agg(m.alias_group_id ORDER BY m.alias_group_id)
                        FROM advisory_alias_group_members m
                        WHERE m.scan_id=f.scan_id AND m.finding_id=f.finding_id),'[]'::jsonb) AS alias_group_ids
                    FROM findings f WHERE f.scan_id=%s ORDER BY f.finding_key LIMIT %s OFFSET %s''',
                    (scan_id,limit,offset))
                items=cur.fetchall()
            priority_state, priority_result = load_priority(conn, scan_id, scan['tool_status'])
            items = present_findings(items, priority_state, priority_result)
    except psycopg.Error:
        log.exception('Finding lookup failed')
        raise HTTPException(503,'DB 조회에 실패했습니다.') from None
    return {'scan_id':str(scan_id),'total':total,'limit':limit,'offset':offset,
            'normalization':scan['tool_status'].get('normalization',{'status':'pending'}),
            'priority_evaluation':priority_state,'items':items}


@router.get('/projects/{project_id}/scans')
def list_project_scans(project_id: UUID, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    try:
        with connect() as conn:
            conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute('SELECT project_id, name FROM projects WHERE project_id=%s', (project_id,))
                project = cur.fetchone()
                if project is None:
                    raise HTTPException(404, '프로젝트를 찾을 수 없습니다.')
                cur.execute('SELECT count(*) AS total FROM scan_runs WHERE project_id=%s', (project_id,))
                total = cur.fetchone()['total']
                cur.execute("""SELECT scan_id, project_id, display_name, status, created_at, finished_at
                    FROM scan_runs WHERE project_id=%s
                    ORDER BY created_at DESC, scan_id DESC LIMIT %s OFFSET %s""", (project_id, limit, offset))
                items = cur.fetchall()
    except psycopg.Error:
        log.exception('Project history lookup failed')
        raise HTTPException(503, '검사 이력을 불러오지 못했습니다.') from None
    return {'project': project, 'items': items, 'total': total, 'limit': limit, 'offset': offset}


class ScanNameUpdate(BaseModel):
    display_name: str = Field(max_length=80)

    @field_validator('display_name')
    @classmethod
    def clean_name(cls, value):
        if any(ord(char) < 32 for char in value):
            raise ValueError('검사 이름은 한 줄로 입력해 주세요.')
        return value.strip()


@router.patch('/scans/{scan_id}')
def rename_scan(scan_id: UUID, body: ScanNameUpdate):
    try:
        with connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute('UPDATE scan_runs SET display_name=%s WHERE scan_id=%s RETURNING scan_id, display_name',
                            (body.display_name or None, scan_id))
                row = cur.fetchone()
    except psycopg.Error:
        log.exception('Scan rename failed')
        raise HTTPException(503, '검사 이름을 저장하지 못했습니다.') from None
    if row is None:
        raise HTTPException(404, '검사를 찾을 수 없습니다.')
    return row
