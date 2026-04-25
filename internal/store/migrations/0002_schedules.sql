-- +goose Up

CREATE TABLE schedules (
  id              TEXT PRIMARY KEY,            -- "s-" + ulid
  name            TEXT NOT NULL UNIQUE,
  cron_expr       TEXT NOT NULL,
  engagement_id   TEXT NOT NULL REFERENCES engagements(id),
  pack_name       TEXT NOT NULL,
  max_dest        TEXT NOT NULL CHECK (max_dest IN ('low','medium','high')),
  selector_json   TEXT NOT NULL DEFAULT '{}',
  alerts_json     TEXT NOT NULL DEFAULT '[]',  -- list of alert sink configs
  enabled         INTEGER NOT NULL DEFAULT 1,
  authorized_by   TEXT NOT NULL,               -- pre-authorization recorded once at add time
  last_run_at     TEXT,
  last_run_id     TEXT,
  created_at      TEXT NOT NULL
);

CREATE INDEX idx_schedules_engagement ON schedules(engagement_id);

-- +goose Down
DROP INDEX IF EXISTS idx_schedules_engagement;
DROP TABLE IF EXISTS schedules;
