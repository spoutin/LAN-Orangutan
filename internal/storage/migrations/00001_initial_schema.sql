-- +goose Up
-- SQL in this section is executed when the migration is applied.

CREATE TABLE devices (
    ip TEXT PRIMARY KEY,
    mac TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    vendor TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT '',
    web_ui INTEGER NOT NULL DEFAULT 0,
    risks TEXT NOT NULL DEFAULT '[]',
    label TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    "group" TEXT NOT NULL DEFAULT '',
    custom_hostname TEXT NOT NULL DEFAULT '',
    custom_web_url TEXT NOT NULL DEFAULT '',
    custom_type TEXT NOT NULL DEFAULT '',
    web_port INTEGER NOT NULL DEFAULT 0,
    web_scheme TEXT NOT NULL DEFAULT '',
    probed INTEGER NOT NULL DEFAULT 0,
    assignment TEXT NOT NULL DEFAULT '',
    network_name TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    response_time REAL,
    address_history TEXT NOT NULL DEFAULT '[]',
    is_online INTEGER NOT NULL DEFAULT 1,
    missed_sweeps INTEGER NOT NULL DEFAULT 0,
    last_presence_change TIMESTAMP NOT NULL
);

CREATE TABLE scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    devices_online INTEGER NOT NULL DEFAULT 0,
    devices_joined INTEGER NOT NULL DEFAULT 0,
    devices_returned INTEGER NOT NULL DEFAULT 0,
    devices_left INTEGER NOT NULL DEFAULT 0,
    duration REAL NOT NULL DEFAULT 0.0,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE device_presence_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    mac TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    event TEXT NOT NULL,
    duration REAL NOT NULL DEFAULT 0.0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scan_state (
    network TEXT PRIMARY KEY,
    last_scan TIMESTAMP NOT NULL,
    last_duration REAL NOT NULL DEFAULT 0.0
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.

DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS scan_state;
DROP TABLE IF EXISTS device_presence_history;
DROP TABLE IF EXISTS scan_history;
DROP TABLE IF EXISTS devices;
