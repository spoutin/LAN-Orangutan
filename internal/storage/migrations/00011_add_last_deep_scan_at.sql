-- +goose Up
ALTER TABLE device_open_ports ADD COLUMN last_deep_scan_at TIMESTAMP;

-- +goose Down
ALTER TABLE device_open_ports DROP COLUMN last_deep_scan_at;
