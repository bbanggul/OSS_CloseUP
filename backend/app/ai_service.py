"""Manual generation for the local MVP; no automatic paid requests."""
from uuid import UUID

from fastapi import HTTPException
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .db import connect
from .priority_view import load_priority
from .ai_generation import (MAX_ATTEMPTS, MAX_ITEMS, PROMPT_VERSION, GenerationError,
                            allowed_reasons, call_model, config, fingerprint, render_output)


def snapshot_for(conn, scan_id, finding_id=None, package=None):
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT status,tool_status FROM scan_runs WHERE scan_id=%s", (scan_id,))
        scan = cur.fetchone()
        if scan is None:
            raise HTTPException(404, "검사를 찾을 수 없습니다.")
        if scan["status"] not in ("completed", "partial"):
            raise HTTPException(409, "검사가 완료되거나 부분 완료된 뒤 설명을 생성할 수 있습니다.")
        cur.execute("""SELECT DISTINCT ON (tool_name) tool_name, status
                       FROM scan_tool_runs WHERE scan_id=%s
                       ORDER BY tool_name, attempt_no DESC""", (scan_id,))
        tools = cur.fetchall()
        cur.execute("""SELECT f.finding_id::text, f.canonical_id, f.type, f.severity,
                       f.manual_review_required, p.package_id::text, p.name AS package_name,
                       p.relationship, p.installed_version, fp.priority, fp.priority_rule_version,
                       COALESCE(jsonb_array_length(fp.fixed_version_candidates)>0, false) AS has_fixed_candidates
                FROM findings f
                LEFT JOIN finding_packages fp ON fp.scan_id=f.scan_id AND fp.finding_id=f.finding_id
                LEFT JOIN packages p ON p.scan_id=fp.scan_id AND p.package_id=fp.package_id
                WHERE f.scan_id=%s AND (%s::uuid IS NULL OR f.finding_id=%s)
                ORDER BY CASE fp.priority WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 WHEN 'P2' THEN 2
                          WHEN 'P3' THEN 3 WHEN 'INFO' THEN 4 ELSE 5 END,
                         f.finding_id, p.package_id
                LIMIT %s""", (scan_id, finding_id, finding_id, 20001 if finding_id is None else MAX_ITEMS + 1))
        items = cur.fetchall()
    priority_state, priority_result = load_priority(conn, scan_id, scan.get('tool_status', {}))
    links = {(x['finding_id'],x['package_id']): x for x in (priority_result or {}).get('link_results', [])}
    for item in items:
        link = links.get((item['finding_id'],item['package_id']), {})
        item['priority'] = link.get('priority')
        item['priority_rule_version'] = link.get('priority_rule_version')
    if finding_id is None:
        if len(items) > 20000:
            raise HTTPException(413, "전체 보고서의 처리 한도(패키지 연결 20,000개)를 초과했습니다.")
        from .ai_narrative import snapshot_for_report
        return snapshot_for_report(conn, scan_id, scan, tools, items, priority_state, priority_result, package)
    if not items:
        raise HTTPException(404, "이 검사에서 해당 취약점을 찾을 수 없습니다.")
    if len(items) > MAX_ITEMS:
        raise HTTPException(413, "이 취약점의 연결 패키지가 30개를 초과해 별도 검토가 필요합니다.")
    for item in items:
        item["evidence_id"] = item["finding_id"] + ":" + (item["package_id"] or "none")
        item["allowed_reasons"] = allowed_reasons(item)
    return {"priority_evaluation": priority_state, "scan_status": scan["status"], "finding_count": 1, "tools": tools, "items": items,
            "scope_note": "All package links of one selected finding; not the entire scan."}


def package_key(package):
    return f"{package[0]}@{package[1]}" if package else None


def parse_package_key(key):
    name, _, version = (key or '').rpartition('@')
    return (name, version) if name and version else None


def generate(scan_id: UUID, finding_id: UUID | None = None, package: tuple | None = None):
    scope = "finding" if finding_id else "package" if package else "scan_report"
    from .ai_narrative import VERSION
    prompt_version = PROMPT_VERSION if finding_id else VERSION
    key = package_key(package)
    # package_key exists only after db/oss_closeup_v2_3_ai_package.sql; other scopes keep the old SQL.
    key_sql = " AND package_key=%s" if package else ""
    # Session lock survives the commit that makes the running state visible.
    # A dedicated connection is closed at exit, releasing the lock even on error.
    with connect() as conn:
        locked = conn.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                              ("ai-report:" + str(scan_id),)).fetchone()[0]
        if not locked:
            raise HTTPException(409, "이 검사의 AI 설명을 생성 중입니다. 잠시 후 다시 확인하세요.")
        try:
            # A single stable snapshot, including authoritative tool statuses.
            conn.commit()
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            snapshot = snapshot_for(conn, scan_id, finding_id) if finding_id else snapshot_for(conn, scan_id, package=package)
            digest = fingerprint(snapshot)
            if not snapshot["items"]:
                raise HTTPException(409, "저장된 검사 항목이 없어 AI 설명을 생성하지 않습니다. 검사 상태를 확인하세요.")
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("""SELECT * FROM ai_analyses WHERE scan_id=%s AND scope=%s
                               AND finding_id IS NOT DISTINCT FROM %s::uuid AND prompt_version=%s""" + key_sql +
                            " ORDER BY attempt_no DESC LIMIT 1", (scan_id, scope, finding_id, prompt_version, *([key] if package else [])))
                previous = cur.fetchone()
                if previous and previous["status"] == "succeeded" and previous["input_fingerprint"] == digest:
                    return previous
                # Obtaining the lock means an earlier running request no longer owns a connection.
                cur.execute("""UPDATE ai_analyses SET status='failed', error_code='interrupted',
                               started_at=COALESCE(started_at,created_at), finished_at=clock_timestamp()
                               WHERE scan_id=%s AND scope=%s AND finding_id IS NOT DISTINCT FROM %s::uuid
                               AND status IN ('pending','running')""" + key_sql, (scan_id, scope, finding_id, *([key] if package else [])))
                attempt = previous["attempt_no"] + 1 if previous else 1
                if attempt > MAX_ATTEMPTS:
                    raise HTTPException(429, "이 설명에서 생성 시도 3회를 사용했습니다. 서버 기록을 확인하세요.")
                try:
                    key, model = config()
                except GenerationError:
                    raise HTTPException(503, "백엔드의 OPENAI_API_KEY와 OPENAI_MODEL을 먼저 설정하세요.") from None
                # Validate input size before recording/issuing a paid request.
                from .ai_generation import model_payload
                try:
                    model_payload(snapshot, model)
                except GenerationError:
                    raise HTTPException(413, "설명 입력 크기를 초과했습니다.") from None
                columns = "scan_id,scope,finding_id,status,attempt_no,provider,model,prompt_version,input_fingerprint,input_snapshot,started_at"
                values = "%s,%s,%s,'running',%s,'openai',%s,%s,%s,%s,now()"
                params = [scan_id, scope, finding_id, attempt, model, prompt_version, digest, Jsonb(snapshot)]
                if package:
                    columns += ",package_key"
                    values += ",%s"
                    params.append(key)
                cur.execute(f"INSERT INTO ai_analyses({columns}) VALUES ({values}) RETURNING analysis_id", tuple(params))
                analysis_id = cur.fetchone()["analysis_id"]
            conn.commit()
            usage = {}
            output = None
            validation = {}
            code = None
            try:
                selected, usage = call_model(snapshot, key, model)
                output = render_output(snapshot, selected)
                validation = {"evidence_ids": True, "order": True, "allowed_reasons": True,
                              "renderer": "reviewed Korean sentences; no unrestricted model prose"}
                if snapshot.get("layout") == "package-v1":
                    validation = {"evidence_ids": True, "order": True, "forbidden_terms": True,
                                  "renderer": "server-written package facts; model writes plain-language risk sentences only"}
                status = "succeeded"
            except GenerationError as exc:
                code = exc.code
                status = "rejected" if code == "validation_failed" else "failed"
            except Exception:
                # Never persist a provider exception that might include credentials or request data.
                code, status = "provider_error", "failed"
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("""UPDATE ai_analyses SET status=%s,output=%s,validation=%s,error_code=%s,
                               usage=%s,finished_at=clock_timestamp() WHERE analysis_id=%s RETURNING *""",
                            (status, Jsonb(output) if output is not None else None, Jsonb(validation), code,
                             Jsonb(usage), analysis_id))
                result = cur.fetchone()
            conn.commit()
            return result
        finally:
            conn.rollback()
            conn.execute("SELECT pg_advisory_unlock(hashtextextended(%s, 0))", ("ai-report:" + str(scan_id),))


def stale_report(scan_id, row):
    """Do not label old generated explanations as current after facts change."""
    if not row or row["status"] != "succeeded":
        return False
    from .ai_narrative import VERSION
    if row.get("scope") in ("scan_report", "package") and row["prompt_version"] != VERSION:
        return True
    if row["prompt_version"] == "scan-evidence-v1":
        return True
    if row["prompt_version"] not in (PROMPT_VERSION, VERSION):
        return False
    with connect() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        try:
            if row.get("scope") == "package":
                current = snapshot_for(conn, scan_id, package=parse_package_key(row.get("package_key")))
            else:
                current = snapshot_for(conn, scan_id, row.get("finding_id"))
            return fingerprint(current) != row["input_fingerprint"]
        except HTTPException as exc:
            if exc.status_code == 409:
                return True
            raise
