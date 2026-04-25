-- +goose Up
PRAGMA foreign_keys = ON;

CREATE TABLE schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE engagements (
  id          TEXT PRIMARY KEY,
  description TEXT,
  created_at  TEXT NOT NULL
);

CREATE TABLE runs (
  id              TEXT PRIMARY KEY,
  engagement_id   TEXT NOT NULL REFERENCES engagements(id),
  seed            INTEGER NOT NULL,
  max_dest        TEXT NOT NULL CHECK (max_dest IN ('low','medium','high')),
  selector_json   TEXT NOT NULL,
  plan_json       TEXT NOT NULL,
  phase           TEXT NOT NULL CHECK (phase IN
                    ('planned','executing','waiting','querying',
                     'scoring','cleanup','reported','failed')),
  authorized_by   TEXT NOT NULL,
  app_user        TEXT,
  started_at      TEXT,
  finished_at     TEXT
);

CREATE TABLE hosts (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  inventory_json TEXT NOT NULL
);

CREATE TABLE executions (
  id              TEXT PRIMARY KEY,
  run_id          TEXT NOT NULL REFERENCES runs(id),
  host_id         TEXT NOT NULL REFERENCES hosts(id),
  test_id         TEXT NOT NULL,
  test_source     TEXT NOT NULL,
  test_yaml_sha256 TEXT NOT NULL,
  attack_technique TEXT,
  attack_tactic   TEXT,
  destructiveness TEXT NOT NULL CHECK (destructiveness IN ('low','medium','high')),
  runner          TEXT NOT NULL,
  started_at      TEXT NOT NULL,
  finished_at     TEXT,
  exit_code       INTEGER,
  duration_ms     INTEGER,
  stdout_path     TEXT,
  stdout_inline   TEXT,
  stderr_path     TEXT,
  stderr_inline   TEXT,
  cleanup_state   TEXT NOT NULL DEFAULT 'pending'
                    CHECK (cleanup_state IN
                      ('pending','succeeded','failed','no_cleanup_defined')),
  cleanup_verify_state TEXT NOT NULL DEFAULT 'pending'
                    CHECK (cleanup_verify_state IN
                      ('pending','succeeded','failed','not_defined','warned_atomic')),
  detection_state TEXT NOT NULL DEFAULT 'pending'
                    CHECK (detection_state IN
                      ('pending','caught','missed','uncertain','no_expectation'))
);

CREATE TABLE expected_detections (
  id              TEXT PRIMARY KEY,
  execution_id    TEXT NOT NULL REFERENCES executions(id),
  expectation_json TEXT NOT NULL,
  wait_seconds    INTEGER NOT NULL,
  state           TEXT NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending','caught','missed','uncertain')),
  detector_name   TEXT,
  reason          TEXT
);

CREATE TABLE detection_hits (
  id              TEXT PRIMARY KEY,
  expected_id     TEXT NOT NULL REFERENCES expected_detections(id),
  hit_id          TEXT NOT NULL,
  hit_at          TEXT NOT NULL,
  raw_json        TEXT NOT NULL,
  UNIQUE (expected_id, hit_id)
);

CREATE TABLE audit_log (
  seq             INTEGER PRIMARY KEY AUTOINCREMENT,
  ts              TEXT NOT NULL,
  actor_json      TEXT NOT NULL,
  engagement_id   TEXT,
  run_id          TEXT,
  event           TEXT NOT NULL,
  payload_json    TEXT NOT NULL,
  prev_hash       TEXT NOT NULL,
  hash            TEXT NOT NULL,
  signature       TEXT NOT NULL
);

CREATE INDEX idx_executions_run    ON executions(run_id);
CREATE INDEX idx_executions_host   ON executions(host_id);
CREATE INDEX idx_executions_tech   ON executions(attack_technique);
CREATE INDEX idx_expected_exec     ON expected_detections(execution_id);
CREATE INDEX idx_audit_run         ON audit_log(run_id);

-- +goose Down
DROP INDEX IF EXISTS idx_audit_run;
DROP INDEX IF EXISTS idx_expected_exec;
DROP INDEX IF EXISTS idx_executions_tech;
DROP INDEX IF EXISTS idx_executions_host;
DROP INDEX IF EXISTS idx_executions_run;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS detection_hits;
DROP TABLE IF EXISTS expected_detections;
DROP TABLE IF EXISTS executions;
DROP TABLE IF EXISTS hosts;
DROP TABLE IF EXISTS runs;
DROP TABLE IF EXISTS engagements;
DROP TABLE IF EXISTS schema_meta;
