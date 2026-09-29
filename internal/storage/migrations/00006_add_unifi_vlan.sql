-- +goose Up
ALTER TABLE devices ADD COLUMN vlan INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE devices DROP COLUMN vlan;
