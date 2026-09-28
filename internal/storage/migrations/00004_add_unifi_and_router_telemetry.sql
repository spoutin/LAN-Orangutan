-- +goose Up
-- SQL in this section is executed when the migration is applied.
ALTER TABLE devices ADD COLUMN ssid TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN ap_name TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN radio_band TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN channel INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN wifi_standard TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN signal INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN signal_quality INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN rx_rate INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN tx_rate INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN rx_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN tx_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN association_uptime INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN unifi_model TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN router_source TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN router_interface TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN lease_expires TIMESTAMP NULL;
ALTER TABLE devices ADD COLUMN lease_lifetime INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN router_notes TEXT NOT NULL DEFAULT '';

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.
ALTER TABLE devices DROP COLUMN router_notes;
ALTER TABLE devices DROP COLUMN lease_lifetime;
ALTER TABLE devices DROP COLUMN lease_expires;
ALTER TABLE devices DROP COLUMN router_interface;
ALTER TABLE devices DROP COLUMN router_source;
ALTER TABLE devices DROP COLUMN unifi_model;
ALTER TABLE devices DROP COLUMN association_uptime;
ALTER TABLE devices DROP COLUMN tx_bytes;
ALTER TABLE devices DROP COLUMN rx_bytes;
ALTER TABLE devices DROP COLUMN tx_rate;
ALTER TABLE devices DROP COLUMN rx_rate;
ALTER TABLE devices DROP COLUMN signal_quality;
ALTER TABLE devices DROP COLUMN signal;
ALTER TABLE devices DROP COLUMN wifi_standard;
ALTER TABLE devices DROP COLUMN channel;
ALTER TABLE devices DROP COLUMN radio_band;
ALTER TABLE devices DROP COLUMN ap_name;
ALTER TABLE devices DROP COLUMN ssid;
