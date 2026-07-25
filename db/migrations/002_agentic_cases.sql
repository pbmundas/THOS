-- Apply this once to an existing THOS Postgres volume.
ALTER TABLE hunts ADD COLUMN IF NOT EXISTS last_stage TEXT;
ALTER TABLE hunts ADD COLUMN IF NOT EXISTS current_stage TEXT;
ALTER TABLE hunts ADD COLUMN IF NOT EXISTS failure_stage TEXT;
ALTER TABLE hunts ADD COLUMN IF NOT EXISTS failure_reason TEXT;
ALTER TABLE hunts ADD COLUMN IF NOT EXISTS outcome JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE hunt_steps ADD COLUMN IF NOT EXISTS agent_name TEXT;
ALTER TABLE hunt_steps ADD COLUMN IF NOT EXISTS model_tier TEXT;
ALTER TABLE hunt_steps ADD COLUMN IF NOT EXISTS model_name TEXT;
CREATE TABLE IF NOT EXISTS scheduled_sigma_detections (
    run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), schedule_id TEXT NOT NULL,
    rule_id TEXT NOT NULL, rule_title TEXT, rule_source TEXT, level TEXT,
    siem_type TEXT NOT NULL, status TEXT NOT NULL, events_matched INTEGER NOT NULL DEFAULT 0,
    matched_events JSONB NOT NULL DEFAULT '[]'::jsonb,
    analysis JSONB NOT NULL DEFAULT '{}'::jsonb, compiled_query TEXT,
    query_backend TEXT, error_msg TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE scheduled_sigma_detections ADD COLUMN IF NOT EXISTS compiled_query TEXT;
ALTER TABLE scheduled_sigma_detections ADD COLUMN IF NOT EXISTS query_backend TEXT;
CREATE TABLE IF NOT EXISTS hunt_approvals (
    approval_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_id UUID REFERENCES hunts(hunt_id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending',
    reason TEXT,
    approval_type TEXT NOT NULL DEFAULT 'hunt_review',
    artifact_hash TEXT,
    decided_by TEXT,
    decided_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE hunt_approvals ADD COLUMN IF NOT EXISTS approval_type TEXT NOT NULL DEFAULT 'hunt_review';
ALTER TABLE hunt_approvals ADD COLUMN IF NOT EXISTS artifact_hash TEXT;
CREATE TABLE IF NOT EXISTS finding_feedback (
    feedback_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_id UUID REFERENCES hunts(hunt_id) ON DELETE CASCADE,
    finding_ref TEXT, rating TEXT NOT NULL, correction TEXT, analyst_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS cases (
    case_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_id UUID REFERENCES hunts(hunt_id) ON DELETE SET NULL,
    title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
    priority TEXT NOT NULL DEFAULT 'medium', assigned_to TEXT, summary TEXT,
    sla_due_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS case_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    actor TEXT, event_type TEXT NOT NULL, note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE scheduled_sigma_detections ADD COLUMN IF NOT EXISTS case_id UUID REFERENCES cases(case_id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS forensic_cases (
    case_id UUID PRIMARY KEY,
    case_title TEXT NOT NULL,
    examiner TEXT NOT NULL,
    evidence_path TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    current_stage TEXT,
    report_path TEXT,
    summary TEXT,
    error_msg TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS forensic_steps (
    step_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES forensic_cases(case_id) ON DELETE CASCADE,
    stage TEXT NOT NULL,
    agent_name TEXT NOT NULL,
    activity TEXT,
    status TEXT NOT NULL DEFAULT 'ok',
    duration_ms INTEGER,
    model_tier TEXT,
    model_name TEXT,
    output JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
