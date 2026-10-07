-- +goose Up
ALTER TABLE devices ADD COLUMN detected_ssh_port INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN ssh_override TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN ssh_override_port INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE devices DROP COLUMN detected_ssh_port;
ALTER TABLE devices DROP COLUMN ssh_override;
ALTER TABLE devices DROP COLUMN ssh_override_port;
