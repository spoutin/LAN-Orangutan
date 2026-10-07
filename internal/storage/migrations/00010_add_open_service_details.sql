-- +goose Up
ALTER TABLE device_open_ports ADD COLUMN services TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE device_open_ports DROP COLUMN services;
