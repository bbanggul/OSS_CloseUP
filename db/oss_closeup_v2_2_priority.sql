\set ON_ERROR_STOP on
BEGIN;
CREATE TABLE IF NOT EXISTS priority_evaluations (
    evaluation_id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scan_runs(scan_id) ON DELETE CASCADE,
    attempt_id UUID NOT NULL,
    worker_id TEXT NOT NULL,
    attempt_count INTEGER NOT NULL,
    source_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running','completed','invalid_input','failed')),
    evidence_snapshot JSONB NOT NULL,
    result JSONB,
    error JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    finished_at TIMESTAMPTZ,
    CHECK ((status='completed') = (result IS NOT NULL))
);
-- Additive migration for existing installations; re-running is safe.
ALTER TABLE priority_evaluations ADD COLUMN IF NOT EXISTS attempted_payload JSONB;
CREATE INDEX IF NOT EXISTS priority_evaluations_scan ON priority_evaluations(scan_id,created_at DESC);
COMMIT;
