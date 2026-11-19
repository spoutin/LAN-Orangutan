package storage

import (
	"database/sql"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// RecordScanHistory records execution history metrics of a scan job
func (s *Storage) RecordScanHistory(network string, success bool, errStr string, startedAt time.Time, duration float64, devices []types.ScanDeviceRecord) error {
	status := "success"
	if !success {
		status = "failed"
	}
	return s.RecordScanHistoryWithDetails(network, "sweep", status, errStr, startedAt, duration, devices)
}

// RecordScanHistoryWithDetails records execution history metrics of a scan job with scan_type and status
func (s *Storage) RecordScanHistoryWithDetails(network string, scanType string, status string, errStr string, startedAt time.Time, duration float64, devices []types.ScanDeviceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if scanType == "" {
		scanType = "sweep"
	}
	if status == "" {
		status = "success"
	}

	_, ipNet, parseErr := net.ParseCIDR(network)

	var joined, returned, left int
	if parseErr == nil {
		rows, err := s.db.Query(`
			SELECT ip, event
			FROM device_presence_history
			WHERE created_at >= ?
		`, startedAt)
		if err != nil {
			return err
		}
		for rows.Next() {
			var ipStr, event string
			if err := rows.Scan(&ipStr, &event); err == nil {
				if ip := net.ParseIP(ipStr); ip != nil && ipNet.Contains(ip) {
					switch event {
					case "join":
						joined++
					case "return":
						returned++
					case "leave":
						left++
					}
				}
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	} else {
		rows, err := s.db.Query(`
			SELECT event, COUNT(*)
			FROM device_presence_history
			WHERE created_at >= ?
			GROUP BY event
		`, startedAt)
		if err != nil {
			return err
		}
		for rows.Next() {
			var event string
			var count int
			if err := rows.Scan(&event, &count); err == nil {
				switch event {
				case "join":
					joined = count
				case "return":
					returned = count
				case "leave":
					left = count
				}
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}

	var online int
	if parseErr == nil {
		rows, err := s.db.Query("SELECT ip FROM devices WHERE is_online = 1")
		if err != nil {
			return err
		}
		for rows.Next() {
			var ipStr string
			if err := rows.Scan(&ipStr); err == nil {
				if ip := net.ParseIP(ipStr); ip != nil && ipNet.Contains(ip) {
					online++
				}
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	} else {
		_ = s.db.QueryRow("SELECT COUNT(*) FROM devices WHERE is_online = 1").Scan(&online)
	}

	successVal := 1
	if status == "failed" {
		successVal = 0
	}

	if devices == nil {
		devices = []types.ScanDeviceRecord{}
	}
	devBytes, _ := json.Marshal(devices)
	devJSON := string(devBytes)

	_, err := s.db.Exec(`
		INSERT INTO scan_history (network, scan_type, success, status, error, devices_online, devices_joined, devices_returned, devices_left, duration, timestamp, devices_found)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, network, scanType, successVal, status, errStr, online, joined, returned, left, duration, time.Now(), devJSON)
	return err
}

// GetScanHistory returns the chronological scan history records, newest first
func (s *Storage) GetScanHistory() ([]types.ScanHistoryRecord, error) {
	return s.GetScanHistoryFiltered("", "", "")
}

// GetScanHistoryFiltered returns filtered scan history records
func (s *Storage) GetScanHistoryFiltered(dateStr string, scanType string, query string) ([]types.ScanHistoryRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var conditions []string
	var args []interface{}

	if dateStr != "" {
		conditions = append(conditions, "SUBSTR(timestamp, 1, 10) = ?")
		args = append(args, dateStr)
	}

	if scanType != "" && scanType != "all" {
		conditions = append(conditions, "scan_type = ?")
		args = append(args, scanType)
	}

	if query != "" {
		conditions = append(conditions, "(network LIKE ? OR error LIKE ? OR devices_found LIKE ?)")
		searchTerm := "%" + query + "%"
		args = append(args, searchTerm, searchTerm, searchTerm)
	}

	baseQuery := `
		SELECT id, network, scan_type, success, status, error, devices_online, devices_joined, devices_returned, devices_left, duration, timestamp, devices_found
		FROM scan_history
	`
	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
	}
	baseQuery += " ORDER BY timestamp DESC LIMIT 200"

	rows, err := s.db.Query(baseQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []types.ScanHistoryRecord
	for rows.Next() {
		var r types.ScanHistoryRecord
		var successVal int
		var devicesFoundJSON string
		err := rows.Scan(&r.ID, &r.Network, &r.ScanType, &successVal, &r.Status, &r.Error, &r.DevicesOnline, &r.DevicesJoined, &r.DevicesReturned, &r.DevicesLeft, &r.Duration, &r.Timestamp, &devicesFoundJSON)
		if err == nil {
			r.Success = successVal != 0
			if devicesFoundJSON != "" {
				_ = json.Unmarshal([]byte(devicesFoundJSON), &r.DevicesFound)
			}
			if r.DevicesFound == nil {
				r.DevicesFound = []types.ScanDeviceRecord{}
			}
			result = append(result, r)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// GetPresenceEvents returns the chronological presence events, newest first
func (s *Storage) GetPresenceEvents() ([]types.PresenceEventRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, ip, mac, hostname, event, duration, created_at
		FROM device_presence_history
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []types.PresenceEventRecord
	for rows.Next() {
		var r types.PresenceEventRecord
		err := rows.Scan(&r.ID, &r.IP, &r.MAC, &r.Hostname, &r.Event, &r.Duration, &r.CreatedAt)
		if err == nil {
			result = append(result, r)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// GetPresenceEventsByMAC returns the chronological presence events for a specific MAC address, newest first
func (s *Storage) GetPresenceEventsByMAC(mac string) ([]types.PresenceEventRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	normMAC := NormalizeMAC(mac)
	rows, err := s.db.Query(`
		SELECT id, ip, mac, hostname, event, duration, created_at
		FROM device_presence_history
		WHERE LOWER(REPLACE(mac, '-', ':')) = ?
		ORDER BY created_at DESC
	`, normMAC)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []types.PresenceEventRecord
	for rows.Next() {
		var r types.PresenceEventRecord
		err := rows.Scan(&r.ID, &r.IP, &r.MAC, &r.Hostname, &r.Event, &r.Duration, &r.CreatedAt)
		if err == nil {
			result = append(result, r)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// GetPresenceEventsFiltered returns chronological presence events, optionally filtered by mac/ip or search keyword
func (s *Storage) GetPresenceEventsFiltered(mac, ip, q string) ([]types.PresenceEventRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var query string
	var args []interface{}

	if q != "" {
		query = `
			SELECT id, ip, mac, hostname, event, duration, created_at
			FROM device_presence_history
			WHERE ip LIKE ? OR mac LIKE ? OR hostname LIKE ?
			ORDER BY created_at DESC
		`
		term := "%" + q + "%"
		args = append(args, term, term, term)
	} else if mac != "" || ip != "" {
		normMAC := NormalizeMAC(mac)
		// Resolve parent MAC to unify logs for linked family
		var parentMAC string
		if normMAC != "" {
			_ = s.db.QueryRow("SELECT COALESCE(NULLIF(linked_mac, ''), mac) FROM devices WHERE LOWER(REPLACE(mac, '-', ':')) = ? AND mac <> '' LIMIT 1", normMAC).Scan(&parentMAC)
		} else {
			_ = s.db.QueryRow("SELECT COALESCE(NULLIF(linked_mac, ''), mac) FROM devices WHERE ip = ? LIMIT 1", ip).Scan(&parentMAC)
		}

		if parentMAC != "" {
			normParent := NormalizeMAC(parentMAC)
			query = `
				SELECT id, ip, mac, hostname, event, duration, created_at
				FROM device_presence_history
				WHERE (mac <> '' AND (LOWER(REPLACE(mac, '-', ':')) = ? OR LOWER(REPLACE(mac, '-', ':')) IN (SELECT LOWER(REPLACE(mac, '-', ':')) FROM devices WHERE LOWER(REPLACE(linked_mac, '-', ':')) = ?))) OR ip = ?
				ORDER BY created_at DESC
			`
			args = append(args, normParent, normParent, ip)
		} else {
			query = `
				SELECT id, ip, mac, hostname, event, duration, created_at
				FROM device_presence_history
				WHERE (mac <> '' AND LOWER(REPLACE(mac, '-', ':')) = ?) OR ip = ?
				ORDER BY created_at DESC
			`
			args = append(args, normMAC, ip)
		}
	} else {
		query = `
			SELECT id, ip, mac, hostname, event, duration, created_at
			FROM device_presence_history
			ORDER BY created_at DESC
		`
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}

	var result []types.PresenceEventRecord
	for rows.Next() {
		var r types.PresenceEventRecord
		err := rows.Scan(&r.ID, &r.IP, &r.MAC, &r.Hostname, &r.Event, &r.Duration, &r.CreatedAt)
		if err == nil {
			r.NetworkName = s.resolveNetworkNameLocked(r.IP)
			result = append(result, r)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	if len(result) == 0 && q == "" && (mac != "" || ip != "") {
		// Attempt to locate device in the devices table to auto-heal blank legacy logs
		var devIP, devMAC, devHostname string
		var isOnlineVal int
		var firstSeen, lastSeen time.Time

		var row *sql.Row
		if mac != "" {
			row = s.db.QueryRow(`
				SELECT ip, mac, hostname, is_online, first_seen, last_seen
				FROM devices
				WHERE mac <> '' AND LOWER(REPLACE(mac, '-', ':')) = ?
				LIMIT 1
			`, NormalizeMAC(mac))
		} else {
			row = s.db.QueryRow(`
				SELECT ip, mac, hostname, is_online, first_seen, last_seen
				FROM devices
				WHERE ip = ?
				LIMIT 1
			`, ip)
		}

		err := row.Scan(&devIP, &devMAC, &devHostname, &isOnlineVal, &firstSeen, &lastSeen)
		if err == nil && !firstSeen.IsZero() {
			if isOnlineVal == 1 {
				result = append(result, types.PresenceEventRecord{
					ID:          -1, // synthetic ID
					IP:          devIP,
					MAC:         devMAC,
					Hostname:    devHostname,
					Event:       "join",
					Duration:    0.0,
					CreatedAt:   firstSeen,
					NetworkName: s.resolveNetworkNameLocked(devIP),
				})
			} else {
				duration := lastSeen.Sub(firstSeen).Seconds()
				if duration < 0 {
					duration = 0
				}
				result = append(result, types.PresenceEventRecord{
					ID:          -2, // synthetic ID
					IP:          devIP,
					MAC:         devMAC,
					Hostname:    devHostname,
					Event:       "leave",
					Duration:    duration,
					CreatedAt:   lastSeen,
					NetworkName: s.resolveNetworkNameLocked(devIP),
				}, types.PresenceEventRecord{
					ID:          -1, // synthetic ID
					IP:          devIP,
					MAC:         devMAC,
					Hostname:    devHostname,
					Event:       "join",
					Duration:    0.0,
					CreatedAt:   firstSeen,
					NetworkName: s.resolveNetworkNameLocked(devIP),
				})
			}
		}
	}

	return result, nil
}
