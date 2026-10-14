-- +goose Up
CREATE TABLE IF NOT EXISTS traffic_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    rx_bytes INTEGER NOT NULL DEFAULT 0,
    tx_bytes INTEGER NOT NULL DEFAULT 0,
    rx_rate INTEGER NOT NULL DEFAULT 0,
    tx_rate INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_traffic_samples_mac_time ON traffic_samples(mac, timestamp);

CREATE TABLE IF NOT EXISTS traffic_hourly (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    bucket_time DATETIME NOT NULL,
    rx_bytes_delta INTEGER NOT NULL DEFAULT 0,
    tx_bytes_delta INTEGER NOT NULL DEFAULT 0,
    avg_rx_rate INTEGER NOT NULL DEFAULT 0,
    avg_tx_rate INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_traffic_hourly_mac_time ON traffic_hourly(mac, bucket_time);

ALTER TABLE devices ADD COLUMN traffic_source TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN rx_rate_bps INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN tx_rate_bps INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE devices DROP COLUMN tx_rate_bps;
ALTER TABLE devices DROP COLUMN rx_rate_bps;
ALTER TABLE devices DROP COLUMN traffic_source;
DROP TABLE IF EXISTS traffic_hourly;
DROP TABLE IF EXISTS traffic_samples;
