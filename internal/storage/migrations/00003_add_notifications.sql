-- +goose Up
-- SQL in this section is executed when the migration is applied.
CREATE TABLE network_notifications (
    network_cidr TEXT PRIMARY KEY,
    slack_webhook TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1
);

ALTER TABLE devices ADD COLUMN notify_on_seen INTEGER NOT NULL DEFAULT 0;

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.
ALTER TABLE devices DROP COLUMN notify_on_seen;
DROP TABLE IF EXISTS network_notifications;
