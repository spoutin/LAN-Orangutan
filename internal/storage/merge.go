package storage

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// MergeDevices merges discovered devices with existing data
func (s *Storage) MergeDevices(discovered []types.Device) ([]types.Device, []types.Device, error) {
	newDevs, seenDevs, _, err := s.MergeDevicesWithMoves(discovered)
	return newDevs, seenDevs, err
}

// MergeDevicesWithMoves merges discovered devices and tracks devices that moved IPs/networks
func (s *Storage) MergeDevicesWithMoves(discovered []types.Device) ([]types.Device, []types.Device, []types.DeviceMoveEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback()

	activeIPs := make(map[string]bool)
	for _, d := range discovered {
		if d.IP != "" {
			activeIPs[d.IP] = true
		}
	}

	var newDevices []types.Device
	var seenDevices []types.Device
	var movedDevices []types.DeviceMoveEvent

	now := time.Now()
	for _, d := range discovered {
		// Check if this IP is already known in the database (either as primary IP or attached IP)
		row := tx.QueryRow(`SELECT `+deviceSelectColumns+`, is_online, last_presence_change
			FROM devices WHERE ip = ? OR instr(ips, '"' || ? || '"') > 0
			LIMIT 1
		`, d.IP, d.IP)

		existingPtr, isOnlineVal, lastPresenceChange, err := s.scanDeviceWithPresence(row)
		if err == nil {
			existing := *existingPtr

			// If d has a different MAC than existing, and existing was holding d.IP only as an attachment,
			// this is DHCP churn / IP reassignment: prune d.IP from existing and let d be added!
			if d.MAC != "" && existing.MAC != "" && NormalizeMAC(existing.MAC) != NormalizeMAC(d.MAC) && existing.IP != d.IP {
				updatedAtts := make([]types.IPAttachment, 0, len(existing.IPs))
				for _, a := range existing.IPs {
					if a.IP != d.IP {
						updatedAtts = append(updatedAtts, a)
					}
				}
				upJSON, _ := json.Marshal(updatedAtts)
				if _, err := tx.Exec("UPDATE devices SET ips = ? WHERE ip = ?", string(upJSON), existing.IP); err != nil {
					return nil, nil, nil, err
				}
				// Fall through to add d as a new device
				dev := d
				dev.NetworkName = s.resolveNetworkNameLocked(d.IP)
				isCompletelyNew, _, err := s.addNewDeviceLocked(tx, &dev, now, activeIPs)
				if err != nil {
					return nil, nil, nil, err
				}
				if isCompletelyNew {
					newDevices = append(newDevices, dev)
				}
				continue
			}

			if existing.IP != d.IP {
				// d.IP is an attached secondary IP of existing:
				// If existing.MAC != "" and d.MAC != "" and existing.MAC != d.MAC, it was handled above.
				// Otherwise (same MAC or no MAC on d): keep existing device row, update its attachment for d.IP,
				// migrate any stray history/open ports, and ensure no separate row for d.IP exists.
				if _, err := tx.Exec("UPDATE device_presence_history SET ip = ? WHERE ip = ?", existing.IP, d.IP); err != nil {
					return nil, nil, nil, err
				}
				if _, err := tx.Exec("UPDATE OR IGNORE device_open_ports SET ip = ? WHERE ip = ?", existing.IP, d.IP); err != nil {
					return nil, nil, nil, err
				}
				if _, err := tx.Exec("DELETE FROM device_open_ports WHERE ip = ?", d.IP); err != nil {
					return nil, nil, nil, err
				}
				if _, err := tx.Exec("DELETE FROM devices WHERE ip = ?", d.IP); err != nil {
					return nil, nil, nil, err
				}
			}
			if !existing.Probed && d.AnsibleManaged {
				existing.AnsibleManaged = true
				if _, err := tx.Exec("UPDATE devices SET ansible_managed = 1 WHERE ip = ?", existing.IP); err != nil {
					return nil, nil, nil, err
				}
			}
			s.attachIPWithTime(&existing, d.IP, d.NetworkName, now)
			s.syncAttachments(&existing)

			if d.MAC != "" {
				existing.MAC = d.MAC
			}
			if existing.MAC != "" {
				_, old, err := s.findByMACLocked(tx, existing.MAC, existing.IP)
				if err != nil {
					return nil, nil, nil, err
				}
				if old != nil {
					s.attachIP(old, existing.IP, existing.NetworkName)
					s.mergeDuplicateDevice(old, &existing, now)
					s.syncAttachments(old)
					if _, err := tx.Exec("UPDATE device_presence_history SET ip = ? WHERE ip = ?", old.IP, existing.IP); err != nil {
						return nil, nil, nil, err
					}
					if _, err := tx.Exec("UPDATE OR IGNORE device_open_ports SET ip = ? WHERE ip = ?", old.IP, existing.IP); err != nil {
						return nil, nil, nil, err
					}
					if _, err := tx.Exec("DELETE FROM device_open_ports WHERE ip = ?", existing.IP); err != nil {
						return nil, nil, nil, err
					}
					if _, err := tx.Exec("DELETE FROM devices WHERE ip = ?", existing.IP); err != nil {
						return nil, nil, nil, err
					}
					existing = *old
				}
			}
			if d.Hostname != "" {
				existing.Hostname = d.Hostname
			}
			if d.Vendor != "" {
				existing.Vendor = d.Vendor
			}
			if d.Type != "" {
				existing.Type = d.Type
			}
			if d.ResponseTime != nil {
				existing.ResponseTime = d.ResponseTime
			}
			if d.Probed {
				existing.WebUI = d.WebUI
				existing.WebPort = d.WebPort
				existing.WebScheme = d.WebScheme
				existing.Risks = d.Risks
				existing.Probed = true
			}
			existing.LastSeen = now
			existing.NetworkName = s.resolveNetworkNameLocked(existing.IP)

			if isOnlineVal == 0 {
				offlineDur := now.Sub(lastPresenceChange).Seconds()
				if offlineDur < 0 {
					offlineDur = 0
				}
				_, err = tx.Exec(`
					INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
					VALUES (?, ?, ?, 'return', ?, ?)
				`, existing.IP, existing.MAC, existing.Hostname, offlineDur, now)
				if err != nil {
					return nil, nil, nil, err
				}
				isOnlineVal = 1
				lastPresenceChange = now

				if existing.NotifyOnSeen {
					seenDevices = append(seenDevices, existing)
				}
			} else {
				_, err = tx.Exec("UPDATE devices SET missed_sweeps = 0 WHERE ip = ?", existing.IP)
				if err != nil {
					return nil, nil, nil, err
				}
			}

			s.syncAttachments(&existing)
			risksJSON, _ := json.Marshal(existing.Risks)
			historyJSON, _ := json.Marshal(existing.AddressHistory)
			ipsJSON, _ := json.Marshal(existing.IPs)

			_, err = tx.Exec(`
				UPDATE devices SET
					ip = ?, mac = ?, hostname = ?, vendor = ?, type = ?, web_ui = ?, risks = ?,
					label = ?, notes = ?, "group" = ?, custom_hostname = ?, custom_web_url = ?,
					custom_type = ?, web_port = ?, web_scheme = ?, probed = ?, assignment = ?,
					network_name = ?, first_seen = ?, last_seen = ?, response_time = ?,
					address_history = ?, is_online = ?, last_presence_change = ?,
					ips = ?
				WHERE ip = ?
			`, existing.IP, existing.MAC, existing.Hostname, existing.Vendor, existing.Type, boolToInt(existing.WebUI), string(risksJSON),
				existing.Label, existing.Notes, existing.Group, existing.CustomHostname, existing.CustomWebURL,
				existing.CustomType, existing.WebPort, existing.WebScheme, boolToInt(existing.Probed), existing.Assignment,
				existing.NetworkName, existing.FirstSeen, existing.LastSeen, existing.ResponseTime,
				string(historyJSON), isOnlineVal, lastPresenceChange,
				string(ipsJSON),
				existing.IP)
			if err != nil {
				return nil, nil, nil, err
			}
		} else {
			dev := d
			dev.NetworkName = s.resolveNetworkNameLocked(d.IP)

			// Check if this MAC already existed (to track move events)
			var oldRecord *types.Device
			if dev.MAC != "" {
				_, oldFound, _ := s.findByMACLocked(tx, dev.MAC, dev.IP)
				if oldFound != nil {
					oldRecord = oldFound
				}
			}

			isCompletelyNew, relocated, err := s.addNewDeviceLocked(tx, &dev, now, activeIPs)
			if err != nil {
				return nil, nil, nil, err
			}
			if isCompletelyNew {
				newDevices = append(newDevices, dev)
			} else if relocated && oldRecord != nil && oldRecord.IP != dev.IP {
				// Record moved event if device changed IP
				movedDevices = append(movedDevices, types.DeviceMoveEvent{
					MAC:            dev.MAC,
					Hostname:       dev.Hostname,
					Label:          dev.Label,
					OldIP:          oldRecord.IP,
					OldNetworkName: oldRecord.NetworkName,
					NewIP:          dev.IP,
					NewNetworkName: dev.NetworkName,
					MovedAt:        now,
				})
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, nil, err
	}
	return newDevices, seenDevices, movedDevices, nil
}

// MergeSupplemental folds in devices from secondary sources
func (s *Storage) MergeSupplemental(discovered []types.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now()
	for _, d := range discovered {
		if parsed := net.ParseIP(d.IP); parsed != nil && parsed.To4() == nil && parsed.IsLinkLocalUnicast() {
			continue
		}

		row := tx.QueryRow(`SELECT `+deviceSelectColumns+`, is_online, last_presence_change
			FROM devices WHERE ip = ?
		`, d.IP)

		existingPtr, isOnlineVal, lastPresenceChange, err := s.scanDeviceWithPresence(row)
		if err == nil {
			existing := *existingPtr

			if existing.MAC == "" && d.MAC != "" {
				existing.MAC = d.MAC
			}
			if existing.Hostname == "" && d.Hostname != "" {
				existing.Hostname = d.Hostname
			}
			if existing.Vendor == "" && d.Vendor != "" {
				existing.Vendor = d.Vendor
			}
			if existing.Type == "" && d.Type != "" {
				existing.Type = d.Type
			}
			existing.LastSeen = now
			existing.NetworkName = s.resolveNetworkNameLocked(d.IP)

			if isOnlineVal == 0 {
				offlineDur := now.Sub(lastPresenceChange).Seconds()
				if offlineDur < 0 {
					offlineDur = 0
				}
				_, err = tx.Exec(`
					INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
					VALUES (?, ?, ?, 'return', ?, ?)
				`, existing.IP, existing.MAC, existing.Hostname, offlineDur, now)
				if err != nil {
					return err
				}
				isOnlineVal = 1
				lastPresenceChange = now
			} else {
				_, err = tx.Exec("UPDATE devices SET missed_sweeps = 0 WHERE ip = ?", existing.IP)
				if err != nil {
					return err
				}
			}

			risksJSON, _ := json.Marshal(existing.Risks)
			historyJSON, _ := json.Marshal(existing.AddressHistory)

			_, err = tx.Exec(`
				UPDATE devices SET
					mac = ?, hostname = ?, vendor = ?, type = ?, web_ui = ?, risks = ?,
					label = ?, notes = ?, "group" = ?, custom_hostname = ?, custom_web_url = ?,
					custom_type = ?, web_port = ?, web_scheme = ?, probed = ?, assignment = ?,
					network_name = ?, first_seen = ?, last_seen = ?, response_time = ?,
					address_history = ?, is_online = ?, last_presence_change = ?
				WHERE ip = ?
			`, existing.MAC, existing.Hostname, existing.Vendor, existing.Type, boolToInt(existing.WebUI), string(risksJSON),
				existing.Label, existing.Notes, existing.Group, existing.CustomHostname, existing.CustomWebURL,
				existing.CustomType, existing.WebPort, existing.WebScheme, boolToInt(existing.Probed), existing.Assignment,
				existing.NetworkName, existing.FirstSeen, existing.LastSeen, existing.ResponseTime,
				string(historyJSON), isOnlineVal, lastPresenceChange, existing.IP)
			if err != nil {
				return err
			}
		} else {
			dev := d
			dev.NetworkName = s.resolveNetworkNameLocked(d.IP)
			if _, _, err := s.addNewDeviceLocked(tx, &dev, now, nil); err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

// MergeIPv6Neighbors folds IPv6 neighbour-discovery results
func (s *Storage) MergeIPv6Neighbors(discovered []types.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now()
	changed := false
	for _, d := range discovered {
		parsed := net.ParseIP(d.IP)
		if parsed == nil || parsed.To4() != nil || parsed.IsLinkLocalUnicast() || d.MAC == "" {
			continue
		}

		existing, err := s.findAnyByMACLocked(tx, d.MAC)
		if err != nil {
			return err
		}

		if existing != nil {
			if existing.Hostname == "" && d.Hostname != "" {
				existing.Hostname = d.Hostname
			}
			if existing.Vendor == "" && d.Vendor != "" {
				existing.Vendor = d.Vendor
			}
			if existing.Type == "" && d.Type != "" {
				existing.Type = d.Type
			}
			existing.LastSeen = now
			existing.NetworkName = s.resolveNetworkNameLocked(existing.IP)

			// Get the database row to see if it's currently online
			var isOnlineVal int
			var lastPresenceChange time.Time
			err := tx.QueryRow("SELECT is_online, last_presence_change FROM devices WHERE ip = ?", existing.IP).Scan(&isOnlineVal, &lastPresenceChange)
			if err == nil {
				if isOnlineVal == 0 {
					offlineDur := now.Sub(lastPresenceChange).Seconds()
					if offlineDur < 0 {
						offlineDur = 0
					}
					_, err = tx.Exec(`
						INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
						VALUES (?, ?, ?, 'return', ?, ?)
					`, existing.IP, existing.MAC, existing.Hostname, offlineDur, now)
					if err != nil {
						return err
					}
					isOnlineVal = 1
					lastPresenceChange = now
				} else {
					_, err = tx.Exec("UPDATE devices SET missed_sweeps = 0 WHERE ip = ?", existing.IP)
					if err != nil {
						return err
					}
				}
			} else {
				isOnlineVal = 0
				if existing.IsOnline(s.GetScanInterval()) {
					isOnlineVal = 1
				}
				lastPresenceChange = now
			}

			risksJSON, _ := json.Marshal(existing.Risks)
			historyJSON, _ := json.Marshal(existing.AddressHistory)

			_, err = tx.Exec(`
				UPDATE devices SET
					mac = ?, hostname = ?, vendor = ?, type = ?, web_ui = ?, risks = ?,
					label = ?, notes = ?, "group" = ?, custom_hostname = ?, custom_web_url = ?,
					custom_type = ?, web_port = ?, web_scheme = ?, probed = ?, assignment = ?,
					network_name = ?, first_seen = ?, last_seen = ?, response_time = ?,
					address_history = ?, is_online = ?, last_presence_change = ?
				WHERE ip = ?
			`, existing.MAC, existing.Hostname, existing.Vendor, existing.Type, boolToInt(existing.WebUI), string(risksJSON),
				existing.Label, existing.Notes, existing.Group, existing.CustomHostname, existing.CustomWebURL,
				existing.CustomType, existing.WebPort, existing.WebScheme, boolToInt(existing.Probed), existing.Assignment,
				existing.NetworkName, existing.FirstSeen, existing.LastSeen, existing.ResponseTime,
				string(historyJSON), isOnlineVal, lastPresenceChange, existing.IP)
			if err != nil {
				return err
			}
			changed = true
			continue
		}

		if !isRandomizedMAC(d.MAC) {
			dev := d
			dev.NetworkName = s.resolveNetworkNameLocked(d.IP)
			if _, _, err := s.addNewDeviceLocked(tx, &dev, now, nil); err != nil {
				return err
			}
			changed = true
		}
	}

	if changed {
		return tx.Commit()
	}
	return nil
}

// ProcessMissingDevices checks and flags online devices not seen in the current sweep
func (s *Storage) ProcessMissingDevices(scannedNetworks []string, activeIPs []string, scanIntervals ...time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	now := time.Now()

	activeMap := make(map[string]bool)
	for _, ip := range activeIPs {
		activeMap[ip] = true
	}

	var nets []*net.IPNet
	for _, netStr := range scannedNetworks {
		_, ipNet, err := net.ParseCIDR(netStr)
		if err == nil {
			nets = append(nets, ipNet)
		}
	}

	rows, err := tx.Query(`
		SELECT ip, mac, hostname, last_seen, missed_sweeps, last_presence_change
		FROM devices
		WHERE is_online = 1
	`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type missingDevice struct {
		ip                 string
		mac                string
		hostname           string
		lastSeen           time.Time
		missedSweeps       int
		lastPresenceChange time.Time
	}

	var candidates []missingDevice
	for rows.Next() {
		var md missingDevice
		if err := rows.Scan(&md.ip, &md.mac, &md.hostname, &md.lastSeen, &md.missedSweeps, &md.lastPresenceChange); err == nil {
			if !activeMap[md.ip] {
				ip := net.ParseIP(md.ip)
				if ip != nil {
					belongs := false
					for _, ipNet := range nets {
						if ipNet.Contains(ip) {
							belongs = true
							break
						}
					}
					if belongs {
						candidates = append(candidates, md)
					}
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	interval := 5 * time.Minute
	if len(scanIntervals) > 0 && scanIntervals[0] > 0 {
		interval = scanIntervals[0]
	}
	expiryThreshold := 3 * interval

	leftCount := 0
	for _, md := range candidates {
		newMissed := md.missedSweeps + 1
		expired := newMissed >= 3 || now.Sub(md.lastSeen) >= expiryThreshold

		if expired {
			sessionDur := md.lastSeen.Sub(md.lastPresenceChange).Seconds()
			if sessionDur < 0 {
				sessionDur = 0
			}

			_, err = tx.Exec(`
				INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
				VALUES (?, ?, ?, 'leave', ?, ?)
			`, md.ip, md.mac, md.hostname, sessionDur, now)
			if err != nil {
				return 0, err
			}

			_, err = tx.Exec(`
				UPDATE devices
				SET is_online = 0, missed_sweeps = 0, last_presence_change = ?
				WHERE ip = ?
			`, now, md.ip)
			if err != nil {
				return 0, err
			}

			leftCount++
		} else {
			_, err = tx.Exec(`
				UPDATE devices
				SET missed_sweeps = ?
				WHERE ip = ?
			`, newMissed, md.ip)
			if err != nil {
				return 0, err
			}
		}
	}

	// Also check secondary attachments across all devices for any IP belonging to the scanned networks
	attRows, err := tx.Query(`SELECT ip, mac, hostname, COALESCE(address_history, '[]'), COALESCE(ips, '[]') FROM devices WHERE instr(ips, '[') > 0`)
	if err != nil {
		return 0, err
	}

	type devAttachmentUpdate struct {
		oldPrimaryIP   string
		newPrimaryIP   string
		newNetworkName string
		mac            string
		hostname       string
		addressHistory []types.AddressChange
		ips            []types.IPAttachment
	}
	var updates []devAttachmentUpdate

	for attRows.Next() {
		var pIP, mac, hostname, ahJSON, ipsJSON string
		if sErr := attRows.Scan(&pIP, &mac, &hostname, &ahJSON, &ipsJSON); sErr != nil {
			attRows.Close()
			return 0, sErr
		}
		var ah []types.AddressChange
		var atts []types.IPAttachment
		_ = json.Unmarshal([]byte(ahJSON), &ah)
		_ = json.Unmarshal([]byte(ipsJSON), &atts)

		changed := false
		surviving := make([]types.IPAttachment, 0, len(atts))

		for _, att := range atts {
			if att.IP == "" {
				continue
			}
			// Only check attachments in the scanned networks
			attIP := net.ParseIP(att.IP)
			if attIP == nil {
				surviving = append(surviving, att)
				continue
			}
			belongs := false
			for _, ipNet := range nets {
				if ipNet.Contains(attIP) {
					belongs = true
					break
				}
			}

			if !belongs {
				// Not part of this sweep: keep as is
				surviving = append(surviving, att)
				continue
			}

			if activeMap[att.IP] {
				// Active in this sweep!
				att.MissedSweeps = 0
				att.IsActive = true
				att.LastSeen = now
				surviving = append(surviving, att)
				changed = true
			} else {
				// Missed this sweep
				att.MissedSweeps++
				if att.MissedSweeps >= 2 {
					// Prune after 2 missed sweeps! Retire to address history if not already recorded
					changed = true
					alreadyInHistory := false
					for _, h := range ah {
						if h.IP == att.IP {
							alreadyInHistory = true
							break
						}
					}
					if !alreadyInHistory {
						ah = appendAddressChange(ah, att.IP, now)
					}
					// Dropped from surviving attachments
				} else {
					att.IsActive = false
					surviving = append(surviving, att)
					changed = true
				}
			}
		}

		if changed {
			// If the primary IP was pruned, promote the most active remaining IP
			newPrimaryIP := pIP
			newNetworkName := ""
			if len(surviving) > 0 {
				primaryFound := false
				for _, a := range surviving {
					if a.IP == pIP {
						primaryFound = true
						break
					}
				}
				if !primaryFound {
					// Promote best surviving attachment
					newPrimaryIP = surviving[0].IP
					newNetworkName = surviving[0].NetworkName
					if newNetworkName == "" {
						newNetworkName = s.resolveNetworkNameLocked(newPrimaryIP)
					}
				}
			}

			updates = append(updates, devAttachmentUpdate{
				oldPrimaryIP:   pIP,
				newPrimaryIP:   newPrimaryIP,
				newNetworkName: newNetworkName,
				mac:            mac,
				hostname:       hostname,
				addressHistory: ah,
				ips:            surviving,
			})
		}
	}
	if err := attRows.Err(); err != nil {
		attRows.Close()
		return 0, err
	}
	attRows.Close()

	for _, u := range updates {
		if u.newPrimaryIP != u.oldPrimaryIP {
			// Primary changed: update devices table primary key and related tables
			if _, err := tx.Exec(`UPDATE devices SET ip = ?, network_name = ? WHERE ip = ?`, u.newPrimaryIP, u.newNetworkName, u.oldPrimaryIP); err != nil {
				return 0, fmt.Errorf("failed to promote primary IP %s -> %s: %w", u.oldPrimaryIP, u.newPrimaryIP, err)
			}
			if _, err := tx.Exec(`UPDATE device_presence_history SET ip = ? WHERE ip = ?`, u.newPrimaryIP, u.oldPrimaryIP); err != nil {
				return 0, fmt.Errorf("failed to migrate presence history %s -> %s: %w", u.oldPrimaryIP, u.newPrimaryIP, err)
			}
			if _, err := tx.Exec(`UPDATE OR IGNORE device_open_ports SET ip = ? WHERE ip = ?`, u.newPrimaryIP, u.oldPrimaryIP); err != nil {
				return 0, fmt.Errorf("failed to migrate open ports %s -> %s: %w", u.oldPrimaryIP, u.newPrimaryIP, err)
			}
			if _, err := tx.Exec(`DELETE FROM device_open_ports WHERE ip = ?`, u.oldPrimaryIP); err != nil {
				return 0, fmt.Errorf("failed to clean old open ports for %s: %w", u.oldPrimaryIP, err)
			}
		}

		newIPSJSON, err := json.Marshal(u.ips)
		if err != nil {
			return 0, err
		}
		if u.addressHistory == nil {
			u.addressHistory = []types.AddressChange{}
		}
		newAHJSON, err := json.Marshal(u.addressHistory)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`UPDATE devices SET ips = ?, address_history = ? WHERE ip = ?`, string(newIPSJSON), string(newAHJSON), u.newPrimaryIP); err != nil {
			return 0, fmt.Errorf("failed to update attachments for %s: %w", u.newPrimaryIP, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return leftCount, nil
}

// MergeRouterDHCP merges DHCP leases and static reservations
func (s *Storage) MergeRouterDHCP(leases []types.Device, reservations []types.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now()
	scanInterval := s.GetScanInterval()

	assignments := make(map[string]string)
	for _, r := range reservations {
		if r.IP != "" {
			assignments[r.IP] = "Static"
		}
	}
	for _, l := range leases {
		if l.IP != "" {
			if _, exists := assignments[l.IP]; !exists {
				assignments[l.IP] = "Dynamic"
			}
		}
	}

	rows, err := tx.Query(`SELECT ` + deviceSelectColumns + ` FROM devices`)
	if err != nil {
		return err
	}
	var storedDevices []*types.Device
	for rows.Next() {
		d, err := s.scanDevice(rows)
		if err == nil {
			storedDevices = append(storedDevices, d)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	type presenceState struct {
		isOnline           int
		lastPresenceChange time.Time
	}
	presenceMap := make(map[string]presenceState, len(storedDevices))
	pRows, err := tx.Query(`SELECT ip, is_online, last_presence_change FROM devices`)
	if err != nil {
		return err
	}
	for pRows.Next() {
		var ip string
		var ps presenceState
		if err := pRows.Scan(&ip, &ps.isOnline, &ps.lastPresenceChange); err != nil {
			pRows.Close()
			return err
		}
		presenceMap[ip] = ps
	}
	if err := pRows.Err(); err != nil {
		pRows.Close()
		return err
	}
	pRows.Close()

	for _, dev := range storedDevices {
		if assign, ok := assignments[dev.IP]; ok {
			dev.Assignment = assign
		} else {
			dev.Assignment = "Discovered"
		}
		dev.NetworkName = s.resolveNetworkNameLocked(dev.IP)

		risksJSON, _ := json.Marshal(dev.Risks)
		historyJSON, _ := json.Marshal(dev.AddressHistory)
		isOnline := 0
		if dev.IsOnline(scanInterval) {
			isOnline = 1
		}

		ps := presenceMap[dev.IP]
		if ps.isOnline == 1 && isOnline == 0 {
			onlineDur := now.Sub(ps.lastPresenceChange).Seconds()
			if onlineDur < 0 {
				onlineDur = 0
			}
			if _, err := tx.Exec(`
				INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
				VALUES (?, ?, ?, 'leave', ?, ?)
			`, dev.IP, dev.MAC, dev.Hostname, onlineDur, now); err != nil {
				return err
			}
			_, err = tx.Exec(`
				UPDATE devices SET
					assignment = ?, network_name = ?, risks = ?, address_history = ?, is_online = ?, last_presence_change = ?
				WHERE ip = ?
			`, dev.Assignment, dev.NetworkName, string(risksJSON), string(historyJSON), isOnline, now, dev.IP)
		} else if ps.isOnline == 0 && isOnline == 1 {
			offlineDur := now.Sub(ps.lastPresenceChange).Seconds()
			if offlineDur < 0 {
				offlineDur = 0
			}
			if _, err := tx.Exec(`
				INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
				VALUES (?, ?, ?, 'return', ?, ?)
			`, dev.IP, dev.MAC, dev.Hostname, offlineDur, now); err != nil {
				return err
			}
			_, err = tx.Exec(`
				UPDATE devices SET
					assignment = ?, network_name = ?, risks = ?, address_history = ?, is_online = ?, last_presence_change = ?
				WHERE ip = ?
			`, dev.Assignment, dev.NetworkName, string(risksJSON), string(historyJSON), isOnline, now, dev.IP)
		} else {
			_, err = tx.Exec(`
				UPDATE devices SET
					assignment = ?, network_name = ?, risks = ?, address_history = ?, is_online = ?
				WHERE ip = ?
			`, dev.Assignment, dev.NetworkName, string(risksJSON), string(historyJSON), isOnline, dev.IP)
		}
		if err != nil {
			return err
		}
	}

	allDHCP := make([]types.Device, 0, len(reservations)+len(leases))
	allDHCP = append(allDHCP, reservations...)
	allDHCP = append(allDHCP, leases...)

	offlineWindow := 3 * scanInterval
	if offlineWindow < time.Hour {
		offlineWindow = time.Hour
	}
	offlineAt := now.Add(-(offlineWindow + 5*time.Minute))

	for _, d := range allDHCP {
		if d.IP == "" {
			continue
		}

		row := tx.QueryRow(`SELECT `+deviceSelectColumns+` FROM devices WHERE ip = ?`, d.IP)
		existing, err := s.scanDevice(row)
		if err == nil {
			if existing.MAC == "" && d.MAC != "" {
				existing.MAC = d.MAC
			}
			if d.Hostname != "" {
				existing.Hostname = d.Hostname
			}
			if existing.Vendor == "" && d.Vendor != "" {
				existing.Vendor = d.Vendor
			}
			if existing.Type == "" && d.Type != "" {
				existing.Type = d.Type
			}
			existing.Assignment = assignments[d.IP]
			existing.NetworkName = s.resolveNetworkNameLocked(d.IP)
			if d.RouterSource != "" {
				existing.RouterSource = d.RouterSource
			}
			if d.RouterInterface != "" {
				existing.RouterInterface = d.RouterInterface
			}
			if !d.LeaseExpires.IsZero() {
				existing.LeaseExpires = d.LeaseExpires
			}
			if d.LeaseLifetime != 0 {
				existing.LeaseLifetime = d.LeaseLifetime
			}
			if d.RouterNotes != "" {
				existing.RouterNotes = d.RouterNotes
			}

			risksJSON, _ := json.Marshal(existing.Risks)
			historyJSON, _ := json.Marshal(existing.AddressHistory)
			isOnline := 0
			if existing.IsOnline(scanInterval) {
				isOnline = 1
			}

			var leaseExpiresVal interface{}
			if !existing.LeaseExpires.IsZero() {
				leaseExpiresVal = existing.LeaseExpires
			}

			_, err = tx.Exec(`
				UPDATE devices SET
					mac = ?, hostname = ?, vendor = ?, type = ?, web_ui = ?, risks = ?,
					label = ?, notes = ?, "group" = ?, custom_hostname = ?, custom_web_url = ?,
					custom_type = ?, web_port = ?, web_scheme = ?, probed = ?, assignment = ?,
					network_name = ?, first_seen = ?, last_seen = ?, response_time = ?,
					address_history = ?, is_online = ?,
					router_source = ?, router_interface = ?, lease_expires = ?, lease_lifetime = ?, router_notes = ?
				WHERE ip = ?
			`, existing.MAC, existing.Hostname, existing.Vendor, existing.Type, boolToInt(existing.WebUI), string(risksJSON),
				existing.Label, existing.Notes, existing.Group, existing.CustomHostname, existing.CustomWebURL,
				existing.CustomType, existing.WebPort, existing.WebScheme, boolToInt(existing.Probed), existing.Assignment,
				existing.NetworkName, existing.FirstSeen, existing.LastSeen, existing.ResponseTime,
				string(historyJSON), isOnline,
				existing.RouterSource, existing.RouterInterface, leaseExpiresVal, existing.LeaseLifetime, existing.RouterNotes,
				existing.IP)
			if err != nil {
				return err
			}
		} else {
			dev := d
			dev.Assignment = assignments[d.IP]
			dev.NetworkName = s.resolveNetworkNameLocked(d.IP)
			if _, _, err := s.addNewDeviceLocked(tx, &dev, offlineAt, nil); err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

// MergeSwitchConnections stores the latest successful forwarding-table results
// for one switch. An empty successful result clears only that switch's entries.
func (s *Storage) MergeSwitchConnections(connections []SwitchConnection, switchName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
		UPDATE devices SET
			switch_name = '', switch_host = '', switch_port = '', switch_vlan = 0,
			switch_link_state = '', switch_link_speed = 0, switch_duplex = '',
			switch_poe_watts = NULL, switch_updated_at = NULL
		WHERE switch_name = ?
	`, switchName); err != nil {
		return err
	}

	for _, connection := range connections {
		if connection.MAC == "" {
			continue
		}
		var poeWatts interface{}
		if connection.PoEWatts != nil {
			poeWatts = *connection.PoEWatts
		}
		var updatedAt interface{}
		if !connection.UpdatedAt.IsZero() {
			updatedAt = connection.UpdatedAt
		}
		if _, err := tx.Exec(`
			UPDATE devices SET
				switch_name = ?, switch_host = ?, switch_port = ?, switch_vlan = ?,
				switch_link_state = ?, switch_link_speed = ?, switch_duplex = ?,
				switch_poe_watts = ?, switch_updated_at = ?
			WHERE LOWER(REPLACE(mac, '-', ':')) = ?
		`, connection.SwitchName, connection.SwitchHost, connection.Port, connection.VLAN,
			connection.LinkState, connection.LinkSpeed, connection.Duplex, poeWatts, updatedAt,
			NormalizeMAC(connection.MAC)); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// MergeUniFiClients merges UniFi client wireless telemetry into the devices table.
func (s *Storage) MergeUniFiClients(clients []types.Device) ([]types.Device, []types.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	now := time.Now()
	var newDevices []types.Device
	var seenDevices []types.Device

	for _, c := range clients {
		if c.IP == "" && c.MAC == "" {
			continue
		}

		var existing *types.Device
		normMAC := NormalizeMAC(c.MAC)
		if normMAC != "" {
			if c.IP != "" {
				row := tx.QueryRow(`SELECT `+deviceSelectColumns+`
					FROM devices
					WHERE LOWER(REPLACE(mac, '-', ':')) = ? AND ip = ?
					LIMIT 1
				`, normMAC, c.IP)
				if d, err := s.scanDevice(row); err == nil {
					existing = d
				}
			}
			if existing == nil {
				row := tx.QueryRow(`SELECT `+deviceSelectColumns+`
					FROM devices
					WHERE LOWER(REPLACE(mac, '-', ':')) = ?
					LIMIT 1
				`, normMAC)
				if d, err := s.scanDevice(row); err == nil {
					existing = d
				}
			}
		}

		if existing == nil && c.IP != "" {
			row := tx.QueryRow(`SELECT `+deviceSelectColumns+`
				FROM devices
				WHERE ip = ?
				LIMIT 1
			`, c.IP)
			if d, err := s.scanDevice(row); err == nil {
				existing = d
			}
		}

		if existing != nil {
			var isOnlineVal int
			var lastPresenceChange time.Time
			err := tx.QueryRow("SELECT is_online, last_presence_change FROM devices WHERE ip = ?", existing.IP).Scan(&isOnlineVal, &lastPresenceChange)
			if err != nil {
				isOnlineVal = 1
				lastPresenceChange = now
			}

			targetIP := existing.IP
			// If device has a new IP reported by UniFi that is not already occupied, relocate it
			if c.IP != "" && c.IP != existing.IP {
				var count int
				if err := tx.QueryRow("SELECT COUNT(*) FROM devices WHERE ip = ?", c.IP).Scan(&count); err != nil {
					return nil, nil, err
				}
				if count == 0 {
					oldIP := existing.IP
					existing.AddressHistory = appendAddressChange(existing.AddressHistory, oldIP, now)
					historyJSON, _ := json.Marshal(existing.AddressHistory)
					networkName := s.resolveNetworkNameLocked(c.IP)
					existing.NetworkName = networkName
					filteredIPs := make([]types.IPAttachment, 0, len(existing.IPs))
					for _, att := range existing.IPs {
						if att.IP != oldIP {
							filteredIPs = append(filteredIPs, att)
						}
					}
					existing.IPs = filteredIPs
					existing.IP = c.IP
					s.attachIPWithTime(existing, c.IP, networkName, now)
					s.syncAttachments(existing)
					ipsJSON, _ := json.Marshal(existing.IPs)

					if _, err = tx.Exec("UPDATE devices SET ip = ?, address_history = ?, network_name = ?, ips = ? WHERE ip = ?", c.IP, string(historyJSON), networkName, string(ipsJSON), oldIP); err != nil {
						return nil, nil, err
					}
					if _, err = tx.Exec("UPDATE device_presence_history SET ip = ? WHERE ip = ?", c.IP, oldIP); err != nil {
						return nil, nil, err
					}
					if _, err = tx.Exec("UPDATE OR IGNORE device_open_ports SET ip = ? WHERE ip = ?", c.IP, oldIP); err != nil {
						return nil, nil, err
					}
					if _, err = tx.Exec("DELETE FROM device_open_ports WHERE ip = ?", oldIP); err != nil {
						return nil, nil, err
					}
					targetIP = c.IP
				}
			}

			macToSet := existing.MAC
			if macToSet == "" && c.MAC != "" {
				macToSet = c.MAC
			}
			hostnameToSet := existing.Hostname
			if hostnameToSet == "" && c.Hostname != "" {
				hostnameToSet = c.Hostname
			}
			if hostnameToSet == "" && c.UniFiName != "" {
				hostnameToSet = c.UniFiName
			}
			unifiNameToSet := existing.UniFiName
			if c.UniFiName != "" {
				unifiNameToSet = c.UniFiName
			}
			vendorToSet := existing.Vendor
			if vendorToSet == "" && c.Vendor != "" {
				vendorToSet = c.Vendor
			}
			typeToSet := existing.Type
			if typeToSet == "" && c.Type != "" {
				typeToSet = c.Type
			}

			if isOnlineVal == 0 {
				offlineDur := now.Sub(lastPresenceChange).Seconds()
				if offlineDur < 0 {
					offlineDur = 0
				}
				_, err = tx.Exec(`
					INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
					VALUES (?, ?, ?, 'return', ?, ?)
				`, targetIP, macToSet, hostnameToSet, offlineDur, now)
				if err != nil {
					return nil, nil, err
				}
				isOnlineVal = 1
				lastPresenceChange = now

				if existing.NotifyOnSeen {
					seenDev := *existing
					seenDev.IP = targetIP
					seenDev.MAC = macToSet
					seenDev.Hostname = hostnameToSet
					seenDev.Vendor = vendorToSet
					seenDev.Type = typeToSet
					seenDev.SSID = c.SSID
					seenDev.APName = c.APName
					seenDev.RadioBand = c.RadioBand
					seenDev.Channel = c.Channel
					seenDev.WiFiStandard = c.WiFiStandard
					seenDev.Signal = c.Signal
					seenDev.SignalQuality = c.SignalQuality
					seenDev.RxRate = c.RxRate
					seenDev.TxRate = c.TxRate
					seenDev.RxBytes = c.RxBytes
					seenDev.TxBytes = c.TxBytes
					seenDev.AssociationUptime = c.AssociationUptime
					seenDev.UniFiModel = c.UniFiModel
					seenDev.LastSeen = now
					seenDevices = append(seenDevices, seenDev)
				}
			}

			_, err = tx.Exec(`
				UPDATE devices SET
					mac = ?,
					hostname = ?,
					vendor = ?,
					type = ?,
					ssid = ?,
					ap_name = ?,
					radio_band = ?,
					channel = ?,
					wifi_standard = ?,
					signal = ?,
					signal_quality = ?,
					rx_rate = ?,
					tx_rate = ?,
					rx_bytes = ?,
					tx_bytes = ?,
					association_uptime = ?,
					unifi_model = ?,
					vlan = ?,
					unifi_name = ?,
					last_seen = ?,
					is_online = 1,
					missed_sweeps = 0,
					last_presence_change = ?
				WHERE ip = ?
			`, macToSet, hostnameToSet, vendorToSet, typeToSet,
				c.SSID, c.APName, c.RadioBand, c.Channel, c.WiFiStandard,
				c.Signal, c.SignalQuality, c.RxRate, c.TxRate,
				c.RxBytes, c.TxBytes, c.AssociationUptime, c.UniFiModel, c.VLAN, unifiNameToSet,
				now, lastPresenceChange, targetIP)
			if err != nil {
				return nil, nil, err
			}
		} else {
			if c.IP == "" {
				continue
			}
			dev := c
			if dev.Hostname == "" && dev.UniFiName != "" {
				dev.Hostname = dev.UniFiName
			}
			dev.Assignment = "Discovered"
			dev.NetworkName = s.resolveNetworkNameLocked(dev.IP)
			dev.FirstSeen = now
			dev.LastSeen = now
			isNew, _, err := s.addNewDeviceLocked(tx, &dev, now, nil)
			if err != nil {
				return nil, nil, err
			}
			if isNew {
				newDevices = append(newDevices, dev)
			} else if dev.NotifyOnSeen {
				seenDevices = append(seenDevices, dev)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return newDevices, seenDevices, nil
}

// DeduplicateMACs finds duplicate MAC records across devices, merges them into the newest/active record,
// migrates presence history, and deletes the stale records.
func (s *Storage) DeduplicateMACs() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`
		SELECT LOWER(REPLACE(TRIM(mac), '-', ':')) AS norm_mac
		FROM devices
		WHERE TRIM(mac) <> ''
		GROUP BY LOWER(REPLACE(TRIM(mac), '-', ':'))
		HAVING COUNT(*) > 1
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var duplicateMACs []string
	for rows.Next() {
		var mac string
		if err := rows.Scan(&mac); err == nil && mac != "" {
			duplicateMACs = append(duplicateMACs, mac)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	now := time.Now()
	scanInterval := s.GetScanInterval()
	for _, mac := range duplicateMACs {
		for _, wantV4 := range []bool{true, false} {
			devRows, err := tx.Query(`SELECT `+deviceSelectColumns+`
				FROM devices
				WHERE LOWER(REPLACE(TRIM(mac), '-', ':')) = ?
			`, mac)
			if err != nil {
				return err
			}

			var list []*types.Device
			for devRows.Next() {
				d, err := s.scanDevice(devRows)
				if err == nil && isIPv4(d.IP) == wantV4 {
					list = append(list, d)
				}
			}
			if err := devRows.Err(); err != nil {
				devRows.Close()
				return err
			}
			devRows.Close()

			if len(list) <= 1 {
				continue
			}

			// Sort newest/active first: online first, then lowest IP (to pick a stable canonical primary IP like 10.0.0.1 over 10.0.0.5 or 192.168.111.1), then newest LastSeen
			sort.Slice(list, func(i, j int) bool {
				iOnline := list[i].IsOnline(scanInterval)
				jOnline := list[j].IsOnline(scanInterval)
				if iOnline != jOnline {
					return iOnline
				}
				iLong := types.IPToLong(list[i].LowestIP())
				jLong := types.IPToLong(list[j].LowestIP())
				if iLong != jLong {
					return iLong < jLong
				}
				if !list[i].LastSeen.Equal(list[j].LastSeen) {
					return list[i].LastSeen.After(list[j].LastSeen)
				}
				return list[i].FirstSeen.After(list[j].FirstSeen)
			})

			target := list[0]
			for _, old := range list[1:] {
				s.mergeDuplicateDevice(target, old, now)
				// Migrate presence
				if _, err := tx.Exec("UPDATE device_presence_history SET ip = ? WHERE ip = ?", target.IP, old.IP); err != nil {
					return err
				}
				// Migrate open ports
				if _, err := tx.Exec("UPDATE OR IGNORE device_open_ports SET ip = ? WHERE ip = ?", target.IP, old.IP); err != nil {
					return err
				}
				if _, err := tx.Exec("DELETE FROM device_open_ports WHERE ip = ?", old.IP); err != nil {
					return err
				}
				// Delete stale device
				if _, err := tx.Exec("DELETE FROM devices WHERE ip = ?", old.IP); err != nil {
					return err
				}
			}

			// Save updated target
			s.syncAttachments(target)
			risksJSON, _ := json.Marshal(target.Risks)
			historyJSON, _ := json.Marshal(target.AddressHistory)
			ipsJSON, _ := json.Marshal(target.IPs)
			var leaseExpiresVal interface{}
			if !target.LeaseExpires.IsZero() {
				leaseExpiresVal = target.LeaseExpires
			}
			var switchUpdatedAtVal interface{}
			if !target.SwitchUpdatedAt.IsZero() {
				switchUpdatedAtVal = target.SwitchUpdatedAt
			}

			if _, err := tx.Exec(`
				UPDATE devices SET
					hostname = ?, vendor = ?, type = ?, web_ui = ?, risks = ?,
					label = ?, notes = ?, "group" = ?, custom_hostname = ?, custom_web_url = ?,
					custom_type = ?, web_port = ?, web_scheme = ?, probed = ?, detected_ssh_port = ?,
					ssh_override = ?, ssh_override_port = ?, assignment = ?, network_name = ?,
					first_seen = ?, last_seen = ?, response_time = ?, address_history = ?,
					is_online = ?,
					linked_mac = ?, notify_on_seen = ?, ansible_managed = ?,
					os = ?, os_version = ?, os_family = ?, custom_os = ?, custom_os_version = ?, custom_os_family = ?,
					ssid = ?, ap_name = ?, radio_band = ?, channel = ?, wifi_standard = ?, signal = ?, signal_quality = ?,
					rx_rate = ?, tx_rate = ?, rx_bytes = ?, tx_bytes = ?, association_uptime = ?, unifi_model = ?, vlan = ?, unifi_name = ?,
					router_source = ?, router_interface = ?, lease_expires = ?, lease_lifetime = ?, router_notes = ?,
					switch_name = ?, switch_host = ?, switch_port = ?, switch_vlan = ?, switch_link_state = ?, switch_link_speed = ?, switch_duplex = ?, switch_poe_watts = ?, switch_updated_at = ?,
					traffic_source = ?, rx_rate_bps = ?, tx_rate_bps = ?, wan_rx_rate_bps = ?, wan_tx_rate_bps = ?, wan_rx_bytes = ?, wan_tx_bytes = ?,
					ips = ?
				WHERE ip = ?
			`, target.Hostname, target.Vendor, target.Type, boolToInt(target.WebUI), string(risksJSON),
				target.Label, target.Notes, target.Group, target.CustomHostname, target.CustomWebURL,
				target.CustomType, target.WebPort, target.WebScheme, boolToInt(target.Probed), target.DetectedSSHPort,
				target.SSHOverride, target.SSHOverridePort, target.Assignment, target.NetworkName,
				target.FirstSeen, target.LastSeen, target.ResponseTime, string(historyJSON),
				boolToInt(target.IsOnline(scanInterval)),
				target.LinkedMAC, boolToInt(target.NotifyOnSeen), boolToInt(target.AnsibleManaged),
				target.OS, target.OSVersion, target.OSFamily, target.CustomOS, target.CustomOSVersion, target.CustomOSFamily,
				target.SSID, target.APName, target.RadioBand, target.Channel, target.WiFiStandard, target.Signal, target.SignalQuality,
				target.RxRate, target.TxRate, target.RxBytes, target.TxBytes, target.AssociationUptime, target.UniFiModel, target.VLAN, target.UniFiName,
				target.RouterSource, target.RouterInterface, leaseExpiresVal, target.LeaseLifetime, target.RouterNotes,
				target.SwitchName, target.SwitchHost, target.SwitchPort, target.SwitchVLAN, target.SwitchLinkState, target.SwitchLinkSpeed, target.SwitchDuplex, target.SwitchPoEWatts, switchUpdatedAtVal,
				target.TrafficSource, target.RxRateBps, target.TxRateBps, target.WanRxRateBps, target.WanTxRateBps, target.WanRxBytes, target.WanTxBytes,
				string(ipsJSON),
				target.IP); err != nil {
				return err
			}
		}
	}

	// Deduplicate any standalone device rows that are already attached as secondary IPs on another device
	attRows, err := tx.Query(`SELECT ` + deviceSelectColumns + `
		FROM devices
		WHERE ips != '[]' AND ips != ''
	`)
	if err != nil {
		return err
	}
	var multiIPDevices []*types.Device
	for attRows.Next() {
		if d, err := s.scanDevice(attRows); err == nil && len(d.IPs) > 1 {
			multiIPDevices = append(multiIPDevices, d)
		}
	}
	if err := attRows.Err(); err != nil {
		attRows.Close()
		return err
	}
	attRows.Close()

	for _, target := range multiIPDevices {
		targetUpdated := false
		for _, att := range target.IPs {
			if att.IP != "" && att.IP != target.IP {
				row := tx.QueryRow(`SELECT `+deviceSelectColumns+`
					FROM devices WHERE ip = ?
				`, att.IP)
				if duplicate, err := s.scanDevice(row); err == nil && duplicate != nil {
					s.mergeDuplicateDevice(target, duplicate, now)
					if _, err := tx.Exec("UPDATE device_presence_history SET ip = ? WHERE ip = ?", target.IP, duplicate.IP); err != nil {
						return err
					}
					if _, err := tx.Exec("UPDATE OR IGNORE device_open_ports SET ip = ? WHERE ip = ?", target.IP, duplicate.IP); err != nil {
						return err
					}
					if _, err := tx.Exec("DELETE FROM device_open_ports WHERE ip = ?", duplicate.IP); err != nil {
						return err
					}
					if _, err := tx.Exec("DELETE FROM devices WHERE ip = ?", duplicate.IP); err != nil {
						return err
					}
					targetUpdated = true
				}
			}
		}
		if targetUpdated {
			s.syncAttachments(target)
			risksJSON, _ := json.Marshal(target.Risks)
			historyJSON, _ := json.Marshal(target.AddressHistory)
			ipsJSON, _ := json.Marshal(target.IPs)
			var leaseExpiresVal interface{}
			if !target.LeaseExpires.IsZero() {
				leaseExpiresVal = target.LeaseExpires
			}
			var switchUpdatedAtVal interface{}
			if !target.SwitchUpdatedAt.IsZero() {
				switchUpdatedAtVal = target.SwitchUpdatedAt
			}

			if _, err := tx.Exec(`
				UPDATE devices SET
					hostname = ?, vendor = ?, type = ?, web_ui = ?, risks = ?,
					label = ?, notes = ?, "group" = ?, custom_hostname = ?, custom_web_url = ?,
					custom_type = ?, web_port = ?, web_scheme = ?, probed = ?, detected_ssh_port = ?,
					ssh_override = ?, ssh_override_port = ?, assignment = ?, network_name = ?,
					first_seen = ?, last_seen = ?, response_time = ?, address_history = ?,
					linked_mac = ?, notify_on_seen = ?, ansible_managed = ?,
					os = ?, os_version = ?, os_family = ?, custom_os = ?, custom_os_version = ?, custom_os_family = ?,
					ssid = ?, ap_name = ?, radio_band = ?, channel = ?, wifi_standard = ?, signal = ?, signal_quality = ?,
					rx_rate = ?, tx_rate = ?, rx_bytes = ?, tx_bytes = ?, association_uptime = ?, unifi_model = ?, vlan = ?, unifi_name = ?,
					router_source = ?, router_interface = ?, lease_expires = ?, lease_lifetime = ?, router_notes = ?,
					switch_name = ?, switch_host = ?, switch_port = ?, switch_vlan = ?, switch_link_state = ?, switch_link_speed = ?, switch_duplex = ?, switch_poe_watts = ?, switch_updated_at = ?,
					traffic_source = ?, rx_rate_bps = ?, tx_rate_bps = ?, wan_rx_rate_bps = ?, wan_tx_rate_bps = ?, wan_rx_bytes = ?, wan_tx_bytes = ?,
					ips = ?
				WHERE ip = ?
			`, target.Hostname, target.Vendor, target.Type, boolToInt(target.WebUI), string(risksJSON),
				target.Label, target.Notes, target.Group, target.CustomHostname, target.CustomWebURL,
				target.CustomType, target.WebPort, target.WebScheme, boolToInt(target.Probed), target.DetectedSSHPort,
				target.SSHOverride, target.SSHOverridePort, target.Assignment, target.NetworkName,
				target.FirstSeen, target.LastSeen, target.ResponseTime, string(historyJSON),
				target.LinkedMAC, boolToInt(target.NotifyOnSeen), boolToInt(target.AnsibleManaged),
				target.OS, target.OSVersion, target.OSFamily, target.CustomOS, target.CustomOSVersion, target.CustomOSFamily,
				target.SSID, target.APName, target.RadioBand, target.Channel, target.WiFiStandard, target.Signal, target.SignalQuality,
				target.RxRate, target.TxRate, target.RxBytes, target.TxBytes, target.AssociationUptime, target.UniFiModel, target.VLAN, target.UniFiName,
				target.RouterSource, target.RouterInterface, leaseExpiresVal, target.LeaseLifetime, target.RouterNotes,
				target.SwitchName, target.SwitchHost, target.SwitchPort, target.SwitchVLAN, target.SwitchLinkState, target.SwitchLinkSpeed, target.SwitchDuplex, target.SwitchPoEWatts, switchUpdatedAtVal,
				target.TrafficSource, target.RxRateBps, target.TxRateBps, target.WanRxRateBps, target.WanTxRateBps, target.WanRxBytes, target.WanTxBytes,
				string(ipsJSON),
				target.IP); err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

// PruneOldHistory deletes device presence events, scan history, and stale offline devices older than a duration.
func (s *Storage) PruneOldHistory(olderThan time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var totalDeleted int64

	// 1. Prune old device presence events
	res, err := tx.Exec("DELETE FROM device_presence_history WHERE created_at < ?", olderThan)
	if err != nil {
		return 0, err
	}
	rows, _ := res.RowsAffected()
	totalDeleted += rows

	// 2. Prune old execution summaries
	res, err = tx.Exec("DELETE FROM scan_history WHERE timestamp < ?", olderThan)
	if err != nil {
		return 0, err
	}
	rows, _ = res.RowsAffected()
	totalDeleted += rows

	// 3. Prune stale offline devices (not seen in > 1 year) to keep devices table clean
	res, err = tx.Exec("DELETE FROM devices WHERE is_online = 0 AND last_seen < ?", olderThan)
	if err != nil {
		return 0, err
	}
	rows, _ = res.RowsAffected()
	totalDeleted += rows

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return totalDeleted, nil
}
