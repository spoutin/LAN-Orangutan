-- +goose Up
ALTER TABLE scan_history ADD COLUMN scan_type TEXT NOT NULL DEFAULT 'sweep';
ALTER TABLE scan_history ADD COLUMN status TEXT NOT NULL DEFAULT 'success';

UPDATE scan_history SET status = CASE WHEN success = 1 THEN 'success' ELSE 'failed' END;

-- +goose Down
ALTER TABLE scan_history DROP COLUMN status;
ALTER TABLE scan_history DROP COLUMN scan_type;
