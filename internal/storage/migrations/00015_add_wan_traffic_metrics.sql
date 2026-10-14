-- +goose Up
ALTER TABLE devices ADD COLUMN wan_rx_rate_bps INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN wan_tx_rate_bps INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN wan_rx_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN wan_tx_bytes INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE devices DROP COLUMN wan_tx_bytes;
ALTER TABLE devices DROP COLUMN wan_rx_bytes;
ALTER TABLE devices DROP COLUMN wan_tx_rate_bps;
ALTER TABLE devices DROP COLUMN wan_rx_rate_bps;
