-- Required for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- THOS audit / state schema — Phase 1
-- Extend this in later phases (add tables per new tool/feature)

CREATE TABLE IF NOT EXISTS hunts (
    hunt_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunter_name     TEXT,
    hypothesis_id   TEXT,
    hypothesis_text TEXT,
    status          TEXT NOT NULL DEFAULT 'started',  -- started|running|completed|failed
    last_stage      TEXT,
    current_stage   TEXT,
    failure_stage   TEXT,
    failure_reason  TEXT,
    outcome         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS hunt_steps (
    step_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_id     UUID REFERENCES hunts(hunt_id) ON DELETE CASCADE,
    node_name   TEXT NOT NULL,       -- e.g. query_generator, siem_fetch, reasoning
    input       JSONB,
    output      JSONB,
    status      TEXT NOT NULL DEFAULT 'ok',  -- ok|error
    error_msg   TEXT,
    duration_ms INTEGER,
    agent_name  TEXT,
    model_tier  TEXT,
    model_name  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tool_errors (
    error_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool_name   TEXT NOT NULL,
    hunt_id     UUID,
    error_msg   TEXT,
    payload     JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS reports (
    report_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_id     UUID REFERENCES hunts(hunt_id) ON DELETE CASCADE,
    file_path   TEXT NOT NULL,
    summary     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS platform_audit_logs (
    log_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    level        TEXT NOT NULL DEFAULT 'INFO',
    service      TEXT NOT NULL,
    category     TEXT NOT NULL,
    actor        TEXT,
    action       TEXT NOT NULL,
    resource     TEXT,
    status_code  INTEGER,
    duration_ms  INTEGER,
    message      TEXT NOT NULL,
    context      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_platform_audit_logs_created_at
    ON platform_audit_logs (created_at DESC);

CREATE TABLE IF NOT EXISTS forensic_cases (
    case_id         UUID PRIMARY KEY,
    case_title      TEXT NOT NULL,
    examiner        TEXT NOT NULL,
    evidence_path   TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'queued', -- queued|running|completed|failed
    current_stage   TEXT,
    report_path     TEXT,
    summary         TEXT,
    error_msg       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS forensic_steps (
    step_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id       UUID NOT NULL REFERENCES forensic_cases(case_id) ON DELETE CASCADE,
    stage         TEXT NOT NULL,
    agent_name    TEXT NOT NULL,
    activity      TEXT,
    status        TEXT NOT NULL DEFAULT 'ok',
    duration_ms   INTEGER,
    model_tier    TEXT,
    model_name    TEXT,
    output        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scheduled_sigma_detections (
    run_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schedule_id     TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    rule_title      TEXT,
    rule_source     TEXT,
    level           TEXT,
    siem_type       TEXT NOT NULL,
    status          TEXT NOT NULL, -- detected|no_match|failed
    events_matched  INTEGER NOT NULL DEFAULT 0,
    matched_events  JSONB NOT NULL DEFAULT '[]'::jsonb,
    analysis        JSONB NOT NULL DEFAULT '{}'::jsonb,
    compiled_query  TEXT,
    query_backend   TEXT,
    error_msg       TEXT,
    case_id          UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Agentic transformation foundations: a durable human-review queue and
-- analyst feedback records. Both are append-only audit-friendly data.
CREATE TABLE IF NOT EXISTS hunt_approvals (
    approval_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_id UUID REFERENCES hunts(hunt_id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending', -- pending|approved|rejected
    reason TEXT,
    approval_type TEXT NOT NULL DEFAULT 'hunt_review', -- hunt_review|detection_rule
    artifact_hash TEXT, -- exact SHA-256 for detection_rule approvals
    decided_by TEXT,
    decided_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS finding_feedback (
    feedback_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_id UUID REFERENCES hunts(hunt_id) ON DELETE CASCADE,
    finding_ref TEXT,
    rating TEXT NOT NULL, -- up|down|corrected
    correction TEXT,
    analyst_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cases (
    case_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_id UUID REFERENCES hunts(hunt_id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', -- open|in_progress|resolved|closed
    priority TEXT NOT NULL DEFAULT 'medium', -- low|medium|high|critical
    assigned_to TEXT,
    summary TEXT,
    sla_due_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS case_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    actor TEXT,
    event_type TEXT NOT NULL,
    note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE scheduled_sigma_detections
    ADD COLUMN IF NOT EXISTS case_id UUID REFERENCES cases(case_id) ON DELETE SET NULL;
