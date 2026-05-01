-- +goose Up

ALTER TABLE schedules ADD COLUMN app_user TEXT;

-- +goose Down
-- SQLite cannot drop columns without a table rebuild. The forward column is
-- nullable and unused by older code paths, so down is a no-op for v1.
