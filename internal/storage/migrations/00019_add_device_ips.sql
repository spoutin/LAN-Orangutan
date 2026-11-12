-- +goose Up
-- SQL in this section is executed when the migration is applied.

ALTER TABLE devices ADD COLUMN ips TEXT NOT NULL DEFAULT '[]';

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.

ALTER TABLE devices DROP COLUMN ips;
