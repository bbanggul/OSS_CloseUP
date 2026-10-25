\set ON_ERROR_STOP on
-- v2.3: 패키지 단위 AI 설명(패키지 상세 화면). v2.1 위에 추가로 적용한다.
-- 기존 DB:   docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < db/oss_closeup_v2_3_ai_package.sql
-- 이미 적용된 DB에 다시 실행하면 오류로 멈추고 전체가 롤백된다(중복 적용 방지).
BEGIN;

-- 대상 패키지는 '이름@설치 버전'으로 식별한다(같은 이름·버전이 여러 경로에 설치돼도 한 설명).
ALTER TABLE ai_analyses ADD COLUMN package_key TEXT;

ALTER TABLE ai_analyses DROP CONSTRAINT ai_analyses_scope_check;
ALTER TABLE ai_analyses ADD CONSTRAINT ai_analyses_scope_check
    CHECK (scope IN ('scan_report', 'finding', 'package'));
ALTER TABLE ai_analyses ADD CONSTRAINT ai_package_target
    CHECK ((scope = 'package') = (package_key IS NOT NULL AND btrim(package_key) <> ''));

DROP INDEX idx_ai_attempt_unique;
CREATE UNIQUE INDEX idx_ai_attempt_unique ON ai_analyses (
    scan_id, scope, COALESCE(finding_id, '00000000-0000-0000-0000-000000000000'::uuid),
    COALESCE(package_key, ''), prompt_version, attempt_no
);
CREATE INDEX idx_ai_package_latest ON ai_analyses (scan_id, package_key, created_at DESC) WHERE scope = 'package';

COMMENT ON COLUMN ai_analyses.package_key IS 'scope=package only: "<name>@<installed_version>".';

COMMIT;
