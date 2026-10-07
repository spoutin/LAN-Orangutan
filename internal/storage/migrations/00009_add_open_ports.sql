-- +goose Up
CREATE TABLE device_open_ports (
    ip TEXT PRIMARY KEY,
    ports TEXT NOT NULL DEFAULT '[]'
);

-- +goose Down
DROP TABLE device_open_ports;
