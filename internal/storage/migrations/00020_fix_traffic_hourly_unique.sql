-- +goose Up
-- Remove duplicate hourly rollup rows before adding the unique constraint.
DELETE FROM traffic_hourly
WHERE id NOT IN (
    SELECT MIN(id)
    FROM traffic_hourly
    GROUP BY mac, bucket_time, source
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_hourly_unique
ON traffic_hourly(mac, bucket_time, source);

-- +goose Down
DROP INDEX IF EXISTS idx_traffic_hourly_unique;
