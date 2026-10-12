-- +goose Up
ALTER TABLE scan_history ADD COLUMN devices_found TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE scan_history DROP COLUMN devices_found;
