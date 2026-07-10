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