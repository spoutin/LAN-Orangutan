package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// RecordTrafficSamples records high-resolution traffic samples and updates device current throughput.
func (s *Storage) RecordTrafficSamples(samples []types.TrafficSample) error {
	if len(samples) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmtSample, err := tx.Prepare(`
		INSERT INTO traffic_samples (mac, timestamp, rx_bytes, tx_bytes, rx_rate, tx_rate, source)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmtSample.Close()

	stmtUpdateDeviceLink, err := tx.Prepare(`
		UPDATE devices SET
			traffic_source = ?,
			rx_rate_bps = ?,
			tx_rate_bps = ?,
			rx_bytes = CASE WHEN ? > 0 THEN ? ELSE rx_bytes END,
			tx_bytes = CASE WHEN ? > 0 THEN ? ELSE tx_bytes END
		WHERE LOWER(mac) = LOWER(?)
	`)
	if err != nil {
		return err
	}
	defer stmtUpdateDeviceLink.Close()

	stmtUpdateDeviceWAN, err := tx.Prepare(`
		UPDATE devices SET
			traffic_source = CASE
				WHEN traffic_source = '' OR traffic_source = 'opnsense' OR traffic_source = 'openwrt' THEN ?
				ELSE traffic_source
			END,
			wan_rx_rate_bps = ?,
			wan_tx_rate_bps = ?,
			wan_rx_bytes = CASE WHEN ? > 0 THEN ? ELSE wan_rx_bytes END,
			wan_tx_bytes = CASE WHEN ? > 0 THEN ? ELSE wan_tx_bytes END
		WHERE LOWER(mac) = LOWER(?)
	`)
	if err != nil {
		return err
	}
	defer stmtUpdateDeviceWAN.Close()

	for _, sample := range samples {
		normMAC := strings.ToLower(strings.TrimSpace(sample.MAC))
		if normMAC == "" {
			continue
		}
		ts := sample.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		tsStr := ts.UTC().Format("2006-01-02 15:04:05")
		_, err := stmtSample.Exec(normMAC, tsStr, sample.RxBytes, sample.TxBytes, sample.RxRate, sample.TxRate, sample.Source)
		if err != nil {
			return fmt.Errorf("failed to insert traffic sample: %w", err)
		}

		if sample.Source == "opnsense" || sample.Source == "openwrt" {
			_, err = stmtUpdateDeviceWAN.Exec(sample.Source, sample.RxRate, sample.TxRate, sample.RxBytes, sample.RxBytes, sample.TxBytes, sample.TxBytes, normMAC)
		} else {
			_, err = stmtUpdateDeviceLink.Exec(sample.Source, sample.RxRate, sample.TxRate, sample.RxBytes, sample.RxBytes, sample.TxBytes, sample.TxBytes, normMAC)
		}
		if err != nil {
			return fmt.Errorf("failed to update device traffic rates: %w", err)
		}
	}

	return tx.Commit()
}

// GetDeviceTrafficSeries returns historical traffic points and current summary for a device MAC.
func (s *Storage) GetDeviceTrafficSeries(mac string, timeRange string) (*types.DeviceTrafficResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	normMAC := strings.ToLower(strings.TrimSpace(mac))
	if normMAC == "" {
		return nil, fmt.Errorf("empty mac address")
	}

	resp := &types.DeviceTrafficResponse{
		MAC:    normMAC,
		Range:  timeRange,
		Series: make([]types.TrafficSeriesPoint, 0),
	}

	var ip, hostname, trafficSource sql.NullString
	var rxBytes, txBytes, rxRateBps, txRateBps sql.NullInt64
	var wanRxRateBps, wanTxRateBps, wanRxBytes, wanTxBytes sql.NullInt64
	err := s.db.QueryRow(`
		SELECT ip, hostname, traffic_source, rx_bytes, tx_bytes, rx_rate_bps, tx_rate_bps,
		       wan_rx_rate_bps, wan_tx_rate_bps, wan_rx_bytes, wan_tx_bytes
		FROM devices
		WHERE LOWER(mac) = LOWER(?)
		LIMIT 1
	`, normMAC).Scan(&ip, &hostname, &trafficSource, &rxBytes, &txBytes, &rxRateBps, &txRateBps,
		&wanRxRateBps, &wanTxRateBps, &wanRxBytes, &wanTxBytes)
	if err == nil {
		resp.IP = ip.String
		resp.Hostname = hostname.String
		resp.Source = trafficSource.String
		resp.Current.RxBytesTotal = rxBytes.Int64
		resp.Current.TxBytesTotal = txBytes.Int64
		resp.Current.RxRateBytesSec = rxRateBps.Int64
		resp.Current.TxRateBytesSec = txRateBps.Int64
		resp.Current.WanRxRateBytesSec = wanRxRateBps.Int64
		resp.Current.WanTxRateBytesSec = wanTxRateBps.Int64
		resp.Current.WanRxBytesTotal = wanRxBytes.Int64
		resp.Current.WanTxBytesTotal = wanTxBytes.Int64
		resp.Current.LastUpdated = time.Now().UTC()
	}

	now := time.Now().UTC()
	switch timeRange {
	case "1h":
		since := now.Add(-1 * time.Hour).Format("2006-01-02 15:04:05")
		rows, err := s.db.Query(`
			SELECT timestamp, rx_rate, tx_rate, rx_bytes, tx_bytes, source
			FROM traffic_samples
			WHERE LOWER(mac) = LOWER(?) AND timestamp >= ?
			ORDER BY timestamp ASC, id ASC
		`, normMAC, since)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var pt types.TrafficSeriesPoint
			var src string
			if err := rows.Scan(&pt.Timestamp, &pt.RxRate, &pt.TxRate, &pt.RxBytes, &pt.TxBytes, &src); err == nil {
				pt.Timestamp = pt.Timestamp.UTC()
				resp.Series = append(resp.Series, pt)
				if resp.Source == "" {
					resp.Source = src
				}
			}
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	case "7d":
		since := now.Add(-7 * 24 * time.Hour).Format("2006-01-02 15:04:05")
		rows, err := s.db.Query(`
			SELECT bucket_time, avg_rx_rate, avg_tx_rate, rx_bytes_delta, tx_bytes_delta, source
			FROM traffic_hourly
			WHERE LOWER(mac) = LOWER(?) AND bucket_time >= ?
			ORDER BY bucket_time ASC, id ASC
		`, normMAC, since)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var pt types.TrafficSeriesPoint
			var src string
			if err := rows.Scan(&pt.Timestamp, &pt.RxRate, &pt.TxRate, &pt.RxBytes, &pt.TxBytes, &src); err == nil {
				pt.Timestamp = pt.Timestamp.UTC()
				resp.Series = append(resp.Series, pt)
				if resp.Source == "" {
					resp.Source = src
				}
			}
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	default: // "24h"
		resp.Range = "24h"
		since := now.Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
		rows, err := s.db.Query(`
			SELECT timestamp, rx_rate, tx_rate, rx_bytes, tx_bytes, source
			FROM traffic_samples
			WHERE LOWER(mac) = LOWER(?) AND timestamp >= ?
			ORDER BY timestamp ASC, id ASC
		`, normMAC, since)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var pt types.TrafficSeriesPoint
			var src string
			if err := rows.Scan(&pt.Timestamp, &pt.RxRate, &pt.TxRate, &pt.RxBytes, &pt.TxBytes, &src); err == nil {
				pt.Timestamp = pt.Timestamp.UTC()
				resp.Series = append(resp.Series, pt)
				if resp.Source == "" {
					resp.Source = src
				}
			}
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// RollupAndPruneTraffic rolls up completed hours from traffic_samples into traffic_hourly and prunes stale records.
func (s *Storage) RollupAndPruneTraffic(sampleRetentionHours int, hourlyRetentionDays int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// 1. Roll up completed hourly intervals into traffic_hourly
	_, err = tx.Exec(`
		INSERT OR IGNORE INTO traffic_hourly (mac, bucket_time, rx_bytes_delta, tx_bytes_delta, avg_rx_rate, avg_tx_rate, source)
		SELECT 
			mac, 
			strftime('%Y-%m-%d %H:00:00', timestamp) AS bucket,
			MAX(rx_bytes) - MIN(rx_bytes) AS rx_delta,
			MAX(tx_bytes) - MIN(tx_bytes) AS tx_delta,
			CAST(AVG(rx_rate) AS INTEGER) AS avg_rx,
			CAST(AVG(tx_rate) AS INTEGER) AS avg_tx,
			source
		FROM traffic_samples
		WHERE timestamp < strftime('%Y-%m-%d %H:00:00', 'now')
		GROUP BY mac, bucket, source
	`)
	if err != nil {
		return 0, fmt.Errorf("failed to rollup hourly traffic: %w", err)
	}

	var totalPruned int64

	// 2. Prune old raw samples
	if sampleRetentionHours <= 0 {
		sampleRetentionHours = 24
	}
	res, err := tx.Exec(`
		DELETE FROM traffic_samples 
		WHERE timestamp < datetime('now', '-' || ? || ' hours')
	`, sampleRetentionHours)
	if err != nil {
		return 0, fmt.Errorf("failed to prune traffic_samples: %w", err)
	}
	if pruned, err := res.RowsAffected(); err == nil {
		totalPruned += pruned
	}

	// 3. Prune old hourly rollups
	if hourlyRetentionDays <= 0 {
		hourlyRetentionDays = 7
	}
	res, err = tx.Exec(`
		DELETE FROM traffic_hourly 
		WHERE bucket_time < datetime('now', '-' || ? || ' days')
	`, hourlyRetentionDays)
	if err != nil {
		return 0, fmt.Errorf("failed to prune traffic_hourly: %w", err)
	}
	if pruned, err := res.RowsAffected(); err == nil {
		totalPruned += pruned
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return totalPruned, nil
}
