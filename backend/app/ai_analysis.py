"""AI 설명 조회 API.

생성은 POST에서만 수행한다. GET은 저장된 설명을 조회하며 유료 호출을 하지 않는다.
- 설명이 없으면 404가 아니라 status='not_generated'로 응답한다. 검사 결과 화면을 막지 않기 위해서다.
- succeeded일 때만 본문(output)을 내보낸다. failed/rejected는 사유 코드만 보여준다.
- 검사 사실(심각도·우선순위·수정 후보)은 여기서 다루지 않는다.
"""
import re
from uuid import UUID

from fastapi import APIRouter, HTTPException
from psycopg import errors
from psycopg.rows import dict_row

from .db import connect

router = APIRouter()

SCAN_SQL = "SELECT scan_id, status FROM scan_runs WHERE scan_id = %s"

REPORT_SQL = """
SELECT analysis_id, scope, finding_id, status, attempt_no, provider, model, prompt_version,
       input_fingerprint, output, validation, error_code, created_at, finished_at
  FROM ai_analyses
 WHERE scan_id = %s AND scope = 'scan_report'
 ORDER BY created_at DESC, attempt_no DESC
 LIMIT 1
"""

FINDINGS_SQL = """
SELECT DISTINCT ON (finding_id)
       analysis_id, scope, finding_id, status, attempt_no, provider, model, prompt_version,
       input_fingerprint, output, validation, error_code, created_at, finished_at
  FROM ai_analyses
 WHERE scan_id = %s AND scope = 'finding'
 ORDER BY finding_id, created_at DESC, attempt_no DESC
"""

# 화면에 그대로 노출해도 되는 실패 사유 안내. 원문 오류 메시지는 내보내지 않는다.
ERROR_MESSAGES = {
    "model_unavailable": "설정한 AI 모델을 찾을 수 없거나 사용할 권한이 없습니다. 백엔드 모델 설정을 확인하세요.",
    "authentication_failed": "AI API 키 인증에 실패했습니다. 백엔드 키 설정을 확인하세요.",
    "permission_denied": "이 프로젝트에 AI API를 사용할 권한이 없습니다.",
    "invalid_request": "AI 요청 설정이 지원되지 않습니다. 백엔드 모델과 요청 형식을 확인하세요.",
    "interrupted": "이전 생성이 중단되었습니다. 다시 생성해 주세요.",
    "rate_limited": "API 사용량 또는 크레딧 한도를 확인한 뒤 다시 시도하세요.",
    "incomplete": "설명이 끝까지 생성되지 않았습니다. 모델 설정을 확인하세요.",
    "refused": "모델이 이 입력에 대한 설명을 반환하지 않았습니다.",
    "timeout": "설명 생성 시간이 초과되었습니다.",
    "provider_error": "설명 생성 서비스에서 오류가 발생했습니다.",
    "validation_failed": "생성된 설명이 검사 결과와 맞지 않아 표시하지 않습니다.",
    "budget_exceeded": "설명 생성 한도를 넘었습니다.",
}


def _load_scan(scan_id: UUID):
    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(SCAN_SQL, (scan_id,))
        return cur.fetchone()


def _load_report(scan_id: UUID):
    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(REPORT_SQL, (scan_id,))
        return cur.fetchone()


def _load_findings(scan_id: UUID):
    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(FINDINGS_SQL, (scan_id,))
        return cur.fetchall()


def _present(row):
    """DB 행을 화면용 응답으로 바꾼다. 본문은 succeeded일 때만 포함한다."""
    if row is None:
        return {"status": "not_generated"}
    body = {
        "status": row["status"],
        "analysis_id": str(row["analysis_id"]),
        "attempt_no": row["attempt_no"],
        "model": row["model"],
        "prompt_version": row["prompt_version"],
        "input_fingerprint": row["input_fingerprint"],
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        "finished_at": row["finished_at"].isoformat() if row["finished_at"] else None,
    }
    if row["status"] == "succeeded":
        body["output"] = row["output"]
        body["validation"] = row["validation"]
    elif row["status"] in {"failed", "rejected"}:
        body["error_code"] = row["error_code"]
        body["message"] = ERROR_MESSAGES.get(row["error_code"], "설명을 만들지 못했습니다.")
    return body


def _require_scan(scan_id: UUID):
    scan = _load_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "검사를 찾을 수 없습니다.")
    return scan


@router.get("/scans/{scan_id}/ai/report")
def ai_report(scan_id: UUID):
    _require_scan(scan_id)
    from .ai_service import stale_report
    row = _load_report(scan_id)
    if stale_report(scan_id, row):
        return {"scan_id": str(scan_id), "status": "stale"}
    return {"scan_id": str(scan_id), **_present(row)}


@router.post("/scans/{scan_id}/ai/report")
def generate_ai_report(scan_id: UUID):
    from .ai_service import generate
    return {"scan_id": str(scan_id), **_present(generate(scan_id))}


@router.get("/scans/{scan_id}/ai/findings/{finding_id}")
def ai_finding(scan_id: UUID, finding_id: UUID):
    from .ai_service import stale_report
    _require_scan(scan_id)
    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT 1 FROM findings WHERE scan_id=%s AND finding_id=%s", (scan_id, finding_id))
        if cur.fetchone() is None:
            raise HTTPException(404, "이 검사에서 해당 취약점을 찾을 수 없습니다.")
        cur.execute("""SELECT * FROM ai_analyses WHERE scan_id=%s AND scope='finding' AND finding_id=%s
                       ORDER BY created_at DESC,attempt_no DESC LIMIT 1""", (scan_id, finding_id))
        row = cur.fetchone()
    body = {"status": "stale"} if stale_report(scan_id, row) else _present(row)
    return {"scan_id": str(scan_id), "finding_id": str(finding_id), **body}


@router.post("/scans/{scan_id}/ai/findings/{finding_id}")
def generate_ai_finding(scan_id: UUID, finding_id: UUID):
    from .ai_service import generate
    return {"scan_id": str(scan_id), "finding_id": str(finding_id), **_present(generate(scan_id, finding_id))}


@router.get("/scans/{scan_id}/ai/findings")
def ai_findings(scan_id: UUID):
    _require_scan(scan_id)
    items = []
    for row in _load_findings(scan_id):
        items.append({"finding_id": str(row["finding_id"]), **_present(row)})
    return {"scan_id": str(scan_id), "total": len(items), "items": items}


# 패키지 단위 설명(패키지 상세 화면). 이름에 @scope/가 들어갈 수 있어 쿼리 문자열로 받는다.
NPM_NAME = re.compile(r'^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$')
VERSION_TEXT = re.compile(r'^[0-9A-Za-z.+-]{1,64}$')
MIGRATION_HINT = "패키지 설명 저장을 위해 DB에 db/oss_closeup_v2_3_ai_package.sql을 적용해야 합니다."


def _package(name: str, version: str):
    if len(name) > 214 or not NPM_NAME.match(name) or not VERSION_TEXT.match(version):
        raise HTTPException(422, "패키지 이름이나 버전 형식이 올바르지 않습니다.")
    return (name, version)


@router.get("/scans/{scan_id}/ai/package")
def ai_package(scan_id: UUID, name: str, version: str):
    from .ai_service import package_key, stale_report
    package = _package(name, version)
    _require_scan(scan_id)
    try:
        with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute("""SELECT * FROM ai_analyses WHERE scan_id=%s AND scope='package' AND package_key=%s
                           ORDER BY created_at DESC,attempt_no DESC LIMIT 1""", (scan_id, package_key(package)))
            row = cur.fetchone()
    except errors.UndefinedColumn:
        raise HTTPException(503, MIGRATION_HINT) from None
    body = {"status": "stale"} if stale_report(scan_id, row) else _present(row)
    return {"scan_id": str(scan_id), "package": {"name": name, "version": version}, **body}


@router.post("/scans/{scan_id}/ai/package")
def generate_ai_package(scan_id: UUID, name: str, version: str):
    from .ai_service import generate
    package = _package(name, version)
    try:
        row = generate(scan_id, package=package)
    except (errors.UndefinedColumn, errors.CheckViolation):
        raise HTTPException(503, MIGRATION_HINT) from None
    return {"scan_id": str(scan_id), "package": {"name": name, "version": version}, **_present(row)}
