-- +goose Up
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP
);

ALTER TABLE devices ADD COLUMN custom_os_version TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN custom_os_family TEXT NOT NULL DEFAULT '';

-- +goose Down
DROP TABLE IF EXISTS api_tokens;
ALTER TABLE devices DROP COLUMN custom_os_version;
ALTER TABLE devices DROP COLUMN custom_os_family;
