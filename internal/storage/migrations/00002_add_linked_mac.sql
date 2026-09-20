-- +goose Up
-- SQL in this section is executed when the migration is applied.
ALTER TABLE devices ADD COLUMN linked_mac TEXT NOT NULL DEFAULT '';

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.
ALTER TABLE devices DROP COLUMN linked_mac;
