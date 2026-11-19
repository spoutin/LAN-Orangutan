-- +goose Up
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
CREATE INDEX IF NOT EXISTS idx_devices_linked_mac ON devices(linked_mac);
CREATE INDEX IF NOT EXISTS idx_devices_is_online ON devices(is_online);
CREATE INDEX IF NOT EXISTS idx_presence_ip_created ON device_presence_history(ip, created_at);
CREATE INDEX IF NOT EXISTS idx_presence_mac_created ON device_presence_history(mac, created_at);
CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(timestamp);

-- +goose Down
DROP INDEX IF EXISTS idx_scan_history_timestamp;
DROP INDEX IF EXISTS idx_presence_mac_created;
DROP INDEX IF EXISTS idx_presence_ip_created;
DROP INDEX IF EXISTS idx_devices_is_online;
DROP INDEX IF EXISTS idx_devices_linked_mac;
DROP INDEX IF EXISTS idx_devices_mac;
