-- +goose Up
ALTER TABLE devices ADD COLUMN ansible_managed BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down
ALTER TABLE devices DROP COLUMN ansible_managed;
