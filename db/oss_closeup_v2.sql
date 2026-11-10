\set ON_ERROR_STOP on
-- v2 draft: fresh database installation only; NOT a v1 upgrade migration.
-- Existing tables cause an error and roll back the whole transaction.
-- Finding keys must be stable normalizer keys for explicitly matched advisories,
-- never transitive alias-group identifiers. Package-specific values live on finding_packages.
BEGIN;
-- OSS Close-UP 검사 결과 저장 스키마 (v1)
-- PostgreSQL 16 기준. gen_random_uuid()는 PG13+ 코어 내장이므로 pgcrypto 불필요.

CREATE TABLE projects (
    project_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    package_json_sha256 TEXT,
    package_lock_sha256 TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retention_until TIMESTAMPTZ
);

CREATE TABLE scan_runs (
    display_name VARCHAR(80),
    scan_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'partial', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    input_package_json_sha256 TEXT,
    input_package_lock_sha256 TEXT,
    tool_status JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT
);

CREATE TABLE packages (
    package_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scan_runs(scan_id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL DEFAULT 'npm',
    name TEXT NOT NULL,
    installed_version TEXT,
    lockfile_path TEXT NOT NULL,
    relationship TEXT NOT NULL DEFAULT 'unknown' CHECK (relationship IN ('root', 'direct', 'indirect', 'unknown')),
    is_direct BOOLEAN GENERATED ALWAYS AS (relationship = 'direct') STORED,
    purl TEXT,
    repository_url TEXT,
    repository_full_name TEXT,
    licenses TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, lockfile_path),
    UNIQUE (scan_id, package_id)
);

CREATE TABLE findings (
    finding_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scan_runs(scan_id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK (type IN ('vulnerability', 'license', 'maintenance')),
    canonical_id TEXT,
    identifiers JSONB NOT NULL DEFAULT '[]'::jsonb,
    title TEXT,
    description TEXT,
    severity TEXT CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
    severity_by_tool JSONB NOT NULL DEFAULT '{}'::jsonb,
    severity_conflict BOOLEAN NOT NULL DEFAULT false,
    source_tools TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    fixed_version_candidates JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommended_fixed_version TEXT,
    priority TEXT CHECK (priority IN ('P0', 'P1', 'P2', 'P3', 'INFO')),
    manual_review_required BOOLEAN NOT NULL DEFAULT false,
    manual_review_reason TEXT,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT maintenance_signal_allowed CHECK (
        type <> 'maintenance'
        OR (evidence->>'signal' IN ('archived', 'deprecated')) IS TRUE
    ),
    UNIQUE (scan_id, finding_id)
);

CREATE TABLE finding_packages (
    scan_id UUID NOT NULL,
    finding_id UUID NOT NULL,
    package_id UUID NOT NULL,
    role TEXT NOT NULL DEFAULT 'affected' CHECK (role IN ('affected', 'entry_point', 'dependency')),
    PRIMARY KEY (finding_id, package_id),
    FOREIGN KEY (scan_id, finding_id) REFERENCES findings(scan_id, finding_id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id, package_id) REFERENCES packages(scan_id, package_id) ON DELETE CASCADE
);

CREATE TABLE advisory_alias_groups (
    alias_group_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scan_runs(scan_id) ON DELETE CASCADE,
    group_key TEXT NOT NULL,
    package_name TEXT,
    package_version TEXT,
    identifiers JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, group_key),
    UNIQUE (scan_id, alias_group_id)
);

CREATE TABLE advisory_alias_group_members (
    scan_id UUID NOT NULL,
    alias_group_id UUID NOT NULL,
    finding_id UUID NOT NULL,
    PRIMARY KEY (alias_group_id, finding_id),
    FOREIGN KEY (scan_id, alias_group_id) REFERENCES advisory_alias_groups(scan_id, alias_group_id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id, finding_id) REFERENCES findings(scan_id, finding_id) ON DELETE CASCADE
);

CREATE TABLE maintenance_signals (
    maintenance_signal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scan_runs(scan_id) ON DELETE CASCADE,
    package_id UUID NOT NULL,
    repository_url TEXT,
    repository_full_name TEXT,
    default_branch TEXT,
    latest_commit_at TIMESTAMPTZ,
    latest_release_tag TEXT,
    latest_release_published_at TIMESTAMPTZ,
    archived BOOLEAN,
    deprecated BOOLEAN,
    raw_github_response JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw_npm_response JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, package_id),
    FOREIGN KEY (scan_id, package_id) REFERENCES packages(scan_id, package_id) ON DELETE CASCADE
);

CREATE VIEW v_maintenance_display AS
SELECT
    ms.scan_id,
    ms.package_id,
    p.name AS package_name,
    ms.repository_full_name,
    ms.latest_commit_at,
    (now()::date - ms.latest_commit_at::date) AS commit_age_days,
    ms.archived,
    ms.deprecated
FROM maintenance_signals ms
JOIN packages p
  ON p.scan_id = ms.scan_id
 AND p.package_id = ms.package_id;

CREATE INDEX idx_scan_runs_project_id ON scan_runs(project_id);
CREATE INDEX idx_scan_runs_queued ON scan_runs(created_at) WHERE status = 'queued';
CREATE INDEX idx_packages_scan_id ON packages(scan_id);
CREATE INDEX idx_packages_name_version ON packages(name, installed_version);
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_type ON findings(type);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_manual_review ON findings(manual_review_required) WHERE manual_review_required;
CREATE INDEX idx_findings_canonical_id ON findings(canonical_id);
CREATE INDEX idx_finding_packages_package_id ON finding_packages(package_id);
CREATE INDEX idx_maintenance_signals_scan_id ON maintenance_signals(scan_id);
CREATE INDEX idx_maintenance_signals_package_id ON maintenance_signals(package_id);

-- v2 additions. This file is one atomic fresh-install script.
ALTER TABLE findings
    ADD COLUMN finding_key TEXT NOT NULL CHECK (btrim(finding_key) <> ''),
    ADD CONSTRAINT findings_scan_key_unique UNIQUE (scan_id, finding_key),
    ADD CONSTRAINT findings_identifiers_array CHECK (jsonb_typeof(identifiers) = 'array'),
    ADD CONSTRAINT findings_evidence_object CHECK (jsonb_typeof(evidence) = 'object'),
    ADD CONSTRAINT findings_severity_object CHECK (jsonb_typeof(severity_by_tool) = 'object'),
    DROP COLUMN fixed_version_candidates,
    DROP COLUMN recommended_fixed_version,
    DROP COLUMN priority;

ALTER TABLE finding_packages
    ADD COLUMN fixed_version_candidates JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(fixed_version_candidates) = 'array'),
    ADD COLUMN recommended_fixed_version TEXT,
    ADD COLUMN priority TEXT CHECK (priority IN ('P0', 'P1', 'P2', 'P3', 'INFO')),
    ADD COLUMN priority_rule_version TEXT,
    ADD COLUMN evidence JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(evidence) = 'object');
-- Each fixed-version candidate should contain source_tool, identifier, raw_value
-- and parsed_version (nullable). Never turn an unverified candidate into a recommendation.

ALTER TABLE scan_runs
    ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    ADD COLUMN heartbeat_at TIMESTAMPTZ,
    ADD COLUMN worker_id TEXT,
    ADD CONSTRAINT scan_tool_status_object CHECK (jsonb_typeof(tool_status) = 'object'),
    ADD CONSTRAINT scan_time_order CHECK (
        (started_at IS NULL OR started_at >= created_at) AND
        (finished_at IS NULL OR (started_at IS NOT NULL AND finished_at >= started_at))
    );
-- tool_status is an optional API summary; scan_tool_runs is authoritative.
-- A worker must claim queued rows atomically (e.g. FOR UPDATE SKIP LOCKED).
-- heartbeat/attempt_count alone do not implement claiming or stale-worker fencing.

ALTER TABLE packages ADD CONSTRAINT packages_evidence_object
    CHECK (jsonb_typeof(evidence) = 'object');
ALTER TABLE advisory_alias_groups
    ADD CONSTRAINT alias_identifiers_array CHECK (jsonb_typeof(identifiers) = 'array'),
    ADD CONSTRAINT alias_evidence_object CHECK (jsonb_typeof(evidence) = 'object');

CREATE TABLE scan_tool_runs (
    tool_run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scan_runs(scan_id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL CHECK (btrim(tool_name) <> ''),
    attempt_no INTEGER NOT NULL DEFAULT 1 CHECK (attempt_no > 0),
    tool_version TEXT,
    database_version TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'completed', 'failed', 'timeout', 'skipped')),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    exit_code INTEGER,
    error_message TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
    UNIQUE (scan_id, tool_name, attempt_no),
    UNIQUE (scan_id, tool_run_id),
    CHECK (finished_at IS NULL OR (started_at IS NOT NULL AND finished_at >= started_at))
);
-- Tool-specific exit codes must be interpreted by the adapter; nonzero is not always failure.

CREATE TABLE scan_artifacts (
    artifact_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scan_runs(scan_id) ON DELETE CASCADE,
    tool_run_id UUID,
    kind TEXT NOT NULL CHECK (kind IN ('package_json', 'package_lock', 'raw_result', 'sbom', 'log')),
    storage_key TEXT NOT NULL CHECK (btrim(storage_key) <> ''),
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    media_type TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retention_until TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    UNIQUE (scan_id, storage_key),
    FOREIGN KEY (scan_id, tool_run_id) REFERENCES scan_tool_runs(scan_id, tool_run_id)
);
CREATE UNIQUE INDEX idx_scan_artifacts_input ON scan_artifacts(scan_id, kind)
    WHERE kind IN ('package_json', 'package_lock');
-- storage_key is a server-generated relative key in shared storage, never a user path/secret URL.
-- Deleting DB rows does not remove physical files: cleanup must be implemented separately.

CREATE TABLE dependencies (
    scan_id UUID NOT NULL REFERENCES scan_runs(scan_id) ON DELETE CASCADE,
    parent_package_id UUID NOT NULL,
    child_package_id UUID NOT NULL,
    dependency_kind TEXT NOT NULL DEFAULT 'runtime'
        CHECK (dependency_kind IN ('runtime', 'dev', 'optional', 'peer', 'unknown')),
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(evidence) = 'object'),
    PRIMARY KEY (scan_id, parent_package_id, child_package_id, dependency_kind),
    FOREIGN KEY (scan_id, parent_package_id) REFERENCES packages(scan_id, package_id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id, child_package_id) REFERENCES packages(scan_id, package_id) ON DELETE CASCADE,
    CHECK (parent_package_id <> child_package_id)
);
-- Store the project root as relationship='root', lockfile_path=''.
-- Graph traversal must handle cycles; depth is path-dependent and is not an edge property.

ALTER TABLE maintenance_signals
    ADD COLUMN github_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (github_status IN ('pending', 'success', 'failed', 'unmapped', 'unsupported', 'skipped')),
    ADD COLUMN npm_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (npm_status IN ('pending', 'success', 'failed', 'not_found', 'skipped')),
    ADD COLUMN github_error TEXT,
    ADD COLUMN npm_error TEXT,
    ADD COLUMN github_checked_at TIMESTAMPTZ,
    ADD COLUMN npm_checked_at TIMESTAMPTZ,
    ADD CONSTRAINT maintenance_github_object CHECK (jsonb_typeof(raw_github_response) = 'object'),
    ADD CONSTRAINT maintenance_npm_object CHECK (jsonb_typeof(raw_npm_response) = 'object');
-- NULL archived/deprecated means unknown, not false. Commit age is display-only.

CREATE INDEX idx_tool_runs_scan_status ON scan_tool_runs(scan_id, status);
CREATE INDEX idx_dependencies_child ON dependencies(scan_id, child_package_id);
CREATE INDEX idx_scan_runs_heartbeat ON scan_runs(heartbeat_at) WHERE status = 'running';
CREATE INDEX idx_finding_packages_priority ON finding_packages(scan_id, priority);

COMMENT ON COLUMN findings.finding_key IS
    'Stable normalizer advisory key within scan; direct verified correspondence only. Alias group is not a merge key.';
COMMENT ON COLUMN finding_packages.priority IS
    'Package-specific priority; NULL until agreed rule is applied. Never changes Finding severity.';
COMMENT ON TABLE scan_tool_runs IS 'Authoritative tool execution history; scan_runs.tool_status is a derived summary.';

COMMIT;
