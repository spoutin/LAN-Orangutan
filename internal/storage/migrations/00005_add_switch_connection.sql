-- +goose Up
ALTER TABLE devices ADD COLUMN switch_name TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN switch_host TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN switch_port TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN switch_vlan INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN switch_link_state TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN switch_link_speed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN switch_duplex TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN switch_poe_watts REAL;
ALTER TABLE devices ADD COLUMN switch_updated_at TIMESTAMP;

-- +goose Down
ALTER TABLE devices DROP COLUMN switch_updated_at;
ALTER TABLE devices DROP COLUMN switch_poe_watts;
ALTER TABLE devices DROP COLUMN switch_duplex;
ALTER TABLE devices DROP COLUMN switch_link_speed;
ALTER TABLE devices DROP COLUMN switch_link_state;
ALTER TABLE devices DROP COLUMN switch_vlan;
ALTER TABLE devices DROP COLUMN switch_port;
ALTER TABLE devices DROP COLUMN switch_host;
ALTER TABLE devices DROP COLUMN switch_name;
