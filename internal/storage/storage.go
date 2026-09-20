// Package storage handles device persistence and state management
package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
	_ "modernc.org/sqlite"
)

// Storage manages device data persistence using SQLite
type Storage struct {
	devicesFile            string
	stateFile              string
	db                     *sql.DB
	mu                     sync.RWMutex
	networkNames           map[string]string
	scanRunning            int32
	scanInterval           int32
	currentScanningNetwork string
	completedNetworks      []string
}

// New creates a new Storage instance
func New(devicesFile, stateFile string) (*Storage, error) {
	// Ensure directories exist
	if err := os.MkdirAll(filepath.Dir(devicesFile), 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(filepath.Dir(devicesFile), "devices.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Configure DB
	db.SetMaxOpenConns(1) // Keep open connections to 1 since we're using SQLite, prevents locking
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to configure sqlite pragma: %w", err)
	}

	// Run migrations
	if err := MigrateDatabase(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	s := &Storage{
		devicesFile:  devicesFile,
		stateFile:    stateFile,
		db:           db,
		networkNames: make(map[string]string),
	}

	// Run legacy JSON migration
	if err := s.migrateLegacyJSON(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate legacy JSON: %w", err)
	}

	// Run prune ephemeral IPv6 on load
	if err := s.pruneEphemeralIPv6(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to prune ephemeral IPv6: %w", err)
	}

	return s, nil
}

// SetScanRunning sets the active scan status thread-safely
func (s *Storage) SetScanRunning(running bool) {
	if running {
		atomic.StoreInt32(&s.scanRunning, 1)
	} else {
		atomic.StoreInt32(&s.scanRunning, 0)
	}
}

// IsScanRunning reports whether a scan is currently running thread-safely
func (s *Storage) IsScanRunning() bool {
	return atomic.LoadInt32(&s.scanRunning) != 0
}

// SetScanInterval sets the configured scan interval thread-safely
func (s *Storage) SetScanInterval(seconds int) {
	atomic.StoreInt32(&s.scanInterval, int32(seconds))
}

// GetScanInterval returns the configured scan interval thread-safely
func (s *Storage) GetScanInterval() time.Duration {
	secs := atomic.LoadInt32(&s.scanInterval)
	if secs <= 0 {
		return time.Hour // default fallback
	}
	return time.Duration(secs) * time.Second
}

// inSameSubnetLocked checks if two IP addresses reside inside the same configured subnet CIDR.
// Must be called while holding s.mu (Lock or RLock).
func (s *Storage) inSameSubnetLocked(ip1, ip2 string) bool {
	p1 := net.ParseIP(ip1)
	p2 := net.ParseIP(ip2)
	if p1 == nil || p2 == nil {
		return false
	}

	networkNames := s.networkNames

	if len(networkNames) > 0 {
		for cidr := range networkNames {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err == nil {
				if ipNet.Contains(p1) && ipNet.Contains(p2) {
					return true
				}
			}
		}
	} else {
		// Fallback for default home networks (/24)
		v41 := p1.To4()
		v42 := p2.To4()
		if v41 != nil && v42 != nil {
			return v41[0] == v42[0] && v41[1] == v42[1] && v41[2] == v42[2]
		}
	}
	return false
}

// SetCurrentScanningNetwork sets the network CIDR currently being scanned
func (s *Storage) SetCurrentScanningNetwork(cidr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentScanningNetwork = cidr
}

// GetCurrentScanningNetwork returns the network CIDR currently being scanned
func (s *Storage) GetCurrentScanningNetwork() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentScanningNetwork
}

// AddCompletedNetwork adds a network CIDR to the list of completed networks in the current run
func (s *Storage) AddCompletedNetwork(cidr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.completedNetworks {
		if n == cidr {
			return
		}
	}
	s.completedNetworks = append(s.completedNetworks, cidr)
}

// ClearCompletedNetworks empties the list of completed networks
func (s *Storage) ClearCompletedNetworks() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completedNetworks = nil
}

// IsNetworkCompletedInCurrentRun reports whether a network CIDR has completed scanning in the current active run
func (s *Storage) IsNetworkCompletedInCurrentRun(cidr string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, n := range s.completedNetworks {
		if n == cidr {
			return true
		}
	}
	return false
}

// Close closes the SQLite database connection
func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// migrateLegacyJSON migrates devices and scan state from legacy JSON files to SQLite
func (s *Storage) migrateLegacyJSON() error {
	if _, err := os.Stat(s.devicesFile); os.IsNotExist(err) {
		return nil
	}

	// Check if devices table is empty
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM devices").Scan(&count); err != nil {
		return fmt.Errorf("failed to check if devices table is empty: %w", err)
	}
	if count > 0 {
		return nil // Migration already completed previously
	}

	// Begin TX
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction for migration: %w", err)
	}
	defer tx.Rollback()

	// Read and unmarshal s.devicesFile
	devData, err := os.ReadFile(s.devicesFile)
	if err != nil {
		return fmt.Errorf("failed to read devices.json: %w", err)
	}

	var legacyDevices map[string]types.Device
	if len(devData) > 0 {
		if err := json.Unmarshal(devData, &legacyDevices); err != nil {
			return fmt.Errorf("failed to unmarshal legacy devices: %w", err)
		}

		for _, d := range legacyDevices {
			risksJSON, _ := json.Marshal(d.Risks)
			historyJSON, _ := json.Marshal(d.AddressHistory)
			isOnline := 0
			if d.IsOnline() {
				isOnline = 1
			}

			_, err := tx.Exec(`
				INSERT INTO devices (
					ip, mac, hostname, vendor, type, web_ui, risks, label, notes, "group",
					custom_hostname, custom_web_url, custom_type, web_port, web_scheme, probed,
					assignment, network_name, first_seen, last_seen, response_time, address_history,
					is_online, missed_sweeps, last_presence_change
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
			`, d.IP, d.MAC, d.Hostname, d.Vendor, d.Type, boolToInt(d.WebUI), string(risksJSON),
				d.Label, d.Notes, d.Group, d.CustomHostname, d.CustomWebURL, d.CustomType,
				d.WebPort, d.WebScheme, boolToInt(d.Probed), d.Assignment, d.NetworkName,
				d.FirstSeen, d.LastSeen, d.ResponseTime, string(historyJSON), isOnline, d.LastSeen)
			if err != nil {
				return fmt.Errorf("failed to insert migrated device %s: %w", d.IP, err)
			}
		}
	}

	// Read s.stateFile if it exists
	if _, err := os.Stat(s.stateFile); err == nil {
		stateData, err := os.ReadFile(s.stateFile)
		if err == nil && len(stateData) > 0 {
			var state types.ScanState
			if err := json.Unmarshal(stateData, &state); err == nil {
				// Migrate last_scan
				for netw, t := range state.LastScan {
					dur := state.LastDuration[netw]
					_, err = tx.Exec(`
						INSERT INTO scan_state (network, last_scan, last_duration)
						VALUES (?, ?, ?)
						ON CONFLICT(network) DO UPDATE SET last_scan = excluded.last_scan, last_duration = excluded.last_duration
					`, netw, t, dur)
					if err != nil {
						return fmt.Errorf("failed to migrate scan state for %s: %w", netw, err)
					}
				}

				// Migrate continuous_scan settings
				if state.ContinuousScan != nil {
					val := "false"
					if *state.ContinuousScan {
						val = "true"
					}
					_, err = tx.Exec(`
						INSERT INTO settings (key, value)
						VALUES ('continuous_scan', ?)
						ON CONFLICT(key) DO UPDATE SET value = excluded.value
					`, val)
					if err != nil {
						return fmt.Errorf("failed to migrate continuous scan setting: %w", err)
					}
				}
			}
		}
	}

	// Commit TX
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit legacy migration transaction: %w", err)
	}

	// Rename legacy JSON files to .json.bak
	_ = os.Rename(s.devicesFile, s.devicesFile+".bak")
	_ = os.Rename(s.stateFile, s.stateFile+".bak")

	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Storage) scanDevice(scanner interface {
	Scan(dest ...interface{}) error
}) (*types.Device, error) {
	var d types.Device
	var webUIVal, probedVal int
	var risksStr, addressHistoryStr string
	err := scanner.Scan(
		&d.IP, &d.MAC, &d.Hostname, &d.Vendor, &d.Type, &webUIVal, &risksStr, &d.Label, &d.Notes, &d.Group,
		&d.CustomHostname, &d.CustomWebURL, &d.CustomType, &d.WebPort, &d.WebScheme, &probedVal, &d.Assignment,
		&d.NetworkName, &d.FirstSeen, &d.LastSeen, &d.ResponseTime, &addressHistoryStr, &d.LinkedMAC,
	)
	if err != nil {
		return nil, err
	}
	d.WebUI = webUIVal != 0
	d.Probed = probedVal != 0
	_ = json.Unmarshal([]byte(risksStr), &d.Risks)
	_ = json.Unmarshal([]byte(addressHistoryStr), &d.AddressHistory)
	return &d, nil
}

// GetDevices returns all devices
func (s *Storage) GetDevices() map[string]*types.Device {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT 
			d.ip, d.mac, d.hostname, d.vendor, d.type, d.web_ui, d.risks,
			COALESCE(NULLIF(p.label, ''), d.label) AS label,
			COALESCE(NULLIF(p.notes, ''), d.notes) AS notes,
			d."group",
			COALESCE(NULLIF(p.custom_hostname, ''), d.custom_hostname) AS custom_hostname,
			COALESCE(NULLIF(p.custom_web_url, ''), d.custom_web_url) AS custom_web_url,
			COALESCE(NULLIF(p.custom_type, ''), d.custom_type) AS custom_type,
			d.web_port, d.web_scheme, d.probed, d.assignment, d.network_name, d.first_seen, d.last_seen, d.response_time, d.address_history,
			d.linked_mac
		FROM devices d
		LEFT JOIN devices p ON d.linked_mac = p.mac AND d.linked_mac <> ''
	`)
	if err != nil {
		return make(map[string]*types.Device)
	}
	defer rows.Close()

	result := make(map[string]*types.Device)
	for rows.Next() {
		d, err := s.scanDevice(rows)
		if err == nil {
			result[d.IP] = d
		}
	}
	return result
}

// GetDevice returns a single device by IP, or nil if there is none
func (s *Storage) GetDevice(ip string) *types.Device {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT 
			d.ip, d.mac, d.hostname, d.vendor, d.type, d.web_ui, d.risks,
			COALESCE(NULLIF(p.label, ''), d.label) AS label,
			COALESCE(NULLIF(p.notes, ''), d.notes) AS notes,
			d."group",
			COALESCE(NULLIF(p.custom_hostname, ''), d.custom_hostname) AS custom_hostname,
			COALESCE(NULLIF(p.custom_web_url, ''), d.custom_web_url) AS custom_web_url,
			COALESCE(NULLIF(p.custom_type, ''), d.custom_type) AS custom_type,
			d.web_port, d.web_scheme, d.probed, d.assignment, d.network_name, d.first_seen, d.last_seen, d.response_time, d.address_history,
			d.linked_mac
		FROM devices d
		LEFT JOIN devices p ON d.linked_mac = p.mac AND d.linked_mac <> ''
		WHERE d.ip = ?
	`, ip)
	d, err := s.scanDevice(row)
	if err != nil {
		return nil
	}
	return d
}

// GetDeviceLocked returns a device while holding a lock
func (s *Storage) GetDeviceLocked(ip string) *types.Device {
	row := s.db.QueryRow(`
		SELECT 
			d.ip, d.mac, d.hostname, d.vendor, d.type, d.web_ui, d.risks,
			COALESCE(NULLIF(p.label, ''), d.label) AS label,
			COALESCE(NULLIF(p.notes, ''), d.notes) AS notes,
			d."group",
			COALESCE(NULLIF(p.custom_hostname, ''), d.custom_hostname) AS custom_hostname,
			COALESCE(NULLIF(p.custom_web_url, ''), d.custom_web_url) AS custom_web_url,
			COALESCE(NULLIF(p.custom_type, ''), d.custom_type) AS custom_type,
			d.web_port, d.web_scheme, d.probed, d.assignment, d.network_name, d.first_seen, d.last_seen, d.response_time, d.address_history,
			d.linked_mac
		FROM devices d
		LEFT JOIN devices p ON d.linked_mac = p.mac AND d.linked_mac <> ''
		WHERE d.ip = ?
	`, ip)
	d, err := s.scanDevice(row)
	if err != nil {
		return nil
	}
	return d
}

// UpdateDevice updates or creates a device
func (s *Storage) UpdateDevice(device *types.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Preserve existing user data if device exists
	existing := s.GetDeviceLocked(device.IP)
	if existing != nil {
		if device.Label == "" {
			device.Label = existing.Label
		}
		if device.Notes == "" {
			device.Notes = existing.Notes
		}
		if device.Group == "" {
			device.Group = existing.Group
		}
		if device.CustomHostname == "" {
			device.CustomHostname = existing.CustomHostname
		}
		if device.CustomWebURL == "" {
			device.CustomWebURL = existing.CustomWebURL
		}
		if device.CustomType == "" {
			device.CustomType = existing.CustomType
		}
		if device.WebPort == 0 {
			device.WebPort = existing.WebPort
		}
		if device.WebScheme == "" {
			device.WebScheme = existing.WebScheme
		}
		if !device.Probed {
			device.Probed = existing.Probed
		}
		if device.FirstSeen.IsZero() {
			device.FirstSeen = existing.FirstSeen
		}
	}

	if device.FirstSeen.IsZero() {
		device.FirstSeen = time.Now()
	}

	risksJSON, _ := json.Marshal(device.Risks)
	historyJSON, _ := json.Marshal(device.AddressHistory)
	isOnline := 0
	if device.IsOnline() {
		isOnline = 1
	}

	_, err := s.db.Exec(`
		INSERT INTO devices (
			ip, mac, hostname, vendor, type, web_ui, risks, label, notes, "group",
			custom_hostname, custom_web_url, custom_type, web_port, web_scheme, probed,
			assignment, network_name, first_seen, last_seen, response_time, address_history,
			is_online, missed_sweeps, last_presence_change
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
		ON CONFLICT(ip) DO UPDATE SET
			mac = excluded.mac,
			hostname = excluded.hostname,
			vendor = excluded.vendor,
			type = excluded.type,
			web_ui = excluded.web_ui,
			risks = excluded.risks,
			label = excluded.label,
			notes = excluded.notes,
			"group" = excluded."group",
			custom_hostname = excluded.custom_hostname,
			custom_web_url = excluded.custom_web_url,
			custom_type = excluded.custom_type,
			web_port = excluded.web_port,
			web_scheme = excluded.web_scheme,
			probed = excluded.probed,
			assignment = excluded.assignment,
			network_name = excluded.network_name,
			first_seen = excluded.first_seen,
			last_seen = excluded.last_seen,
			response_time = excluded.response_time,
			address_history = excluded.address_history,
			is_online = excluded.is_online
	`, device.IP, device.MAC, device.Hostname, device.Vendor, device.Type, boolToInt(device.WebUI), string(risksJSON),
		device.Label, device.Notes, device.Group, device.CustomHostname, device.CustomWebURL, device.CustomType,
		device.WebPort, device.WebScheme, boolToInt(device.Probed), device.Assignment, device.NetworkName,
		device.FirstSeen, device.LastSeen, device.ResponseTime, string(historyJSON), isOnline, device.LastSeen)
	return err
}

// UpdateDeviceFields updates specific fields of a device
func (s *Storage) UpdateDeviceFields(ip string, label, notes, group, customHostname, customWebURL, customType, linkedMac *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing := s.GetDeviceLocked(ip)
	if existing == nil {
		return fmt.Errorf("device not found: %s", ip)
	}

	// 1. Determine active parent MAC address
	parentMAC := existing.LinkedMAC
	if linkedMac != nil {
		parentMAC = *linkedMac
	}

	// 2. If parentMAC is set and valid, update parent's customizations!
	if parentMAC != "" {
		// Try to find the parent device IP
		var parentIP string
		_ = s.db.QueryRow("SELECT ip FROM devices WHERE mac = ? AND mac <> '' LIMIT 1", parentMAC).Scan(&parentIP)
		
		if parentIP != "" {
			// Forward customizations directly to the parent device!
			parentQuery := `UPDATE devices SET `
			var parentArgs []interface{}
			var parentFields []string

			if label != nil {
				parentFields = append(parentFields, `label = ?`)
				parentArgs = append(parentArgs, *label)
			}
			if notes != nil {
				parentFields = append(parentFields, `notes = ?`)
				parentArgs = append(parentArgs, *notes)
			}
			if group != nil {
				parentFields = append(parentFields, `"group" = ?`)
				parentArgs = append(parentArgs, *group)
			}
			if customHostname != nil {
				parentFields = append(parentFields, `custom_hostname = ?`)
				parentArgs = append(parentArgs, *customHostname)
			}
			if customWebURL != nil {
				parentFields = append(parentFields, `custom_web_url = ?`)
				parentArgs = append(parentArgs, *customWebURL)
			}
			if customType != nil {
				parentFields = append(parentFields, `custom_type = ?`)
				parentArgs = append(parentArgs, *customType)
			}

			if len(parentFields) > 0 {
				parentQuery += joinStrings(parentFields, ", ") + ` WHERE ip = ?`
				parentArgs = append(parentArgs, parentIP)
				_, _ = s.db.Exec(parentQuery, parentArgs...)
			}

			// Clear customizations on the child so it cleanly inherits them from the parent
			childQuery := `UPDATE devices SET label = '', notes = '', "group" = '', custom_hostname = '', custom_web_url = '', custom_type = ''`
			var childArgs []interface{}
			if linkedMac != nil {
				childQuery += `, linked_mac = ?`
				childArgs = append(childArgs, *linkedMac)
			}
			childQuery += ` WHERE ip = ?`
			childArgs = append(childArgs, ip)
			_, err := s.db.Exec(childQuery, childArgs...)
			return err
		}
	}

	// 3. Otherwise, if not linked, update the child directly as normal
	query := `UPDATE devices SET `
	var args []interface{}
	var fields []string

	if label != nil {
		fields = append(fields, `label = ?`)
		args = append(args, *label)
	}
	if notes != nil {
		fields = append(fields, `notes = ?`)
		args = append(args, *notes)
	}
	if group != nil {
		fields = append(fields, `"group" = ?`)
		args = append(args, *group)
	}
	if customHostname != nil {
		fields = append(fields, `custom_hostname = ?`)
		args = append(args, *customHostname)
	}
	if customWebURL != nil {
		fields = append(fields, `custom_web_url = ?`)
		args = append(args, *customWebURL)
	}
	if customType != nil {
		fields = append(fields, `custom_type = ?`)
		args = append(args, *customType)
	}
	if linkedMac != nil {
		fields = append(fields, `linked_mac = ?`)
		args = append(args, *linkedMac)
	}

	if len(fields) == 0 {
		return nil
	}

	query += joinStrings(fields, ", ") + ` WHERE ip = ?`
	args = append(args, ip)

	_, err := s.db.Exec(query, args...)
	return err
}

func joinStrings(elems []string, sep string) string {
	if len(elems) == 0 {
		return ""
	}
	res := elems[0]
	for _, s := range elems[1:] {
		res += sep + s
	}
	return res
}

// DeleteDevice removes a device by IP
func (s *Storage) DeleteDevice(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec("DELETE FROM devices WHERE ip = ?", ip)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("device not found: %s", ip)
	}
	return nil
}

func (s *Storage) findByMACLocked(tx *sql.Tx, mac, excludeIP string) (string, *types.Device, error) {
	if mac == "" {
		return "", nil, nil
	}
	wantV4 := isIPv4(excludeIP)
	rows, err := tx.Query(`
		SELECT ip, mac, hostname, vendor, type, web_ui, risks, label, notes, "group",
		       custom_hostname, custom_web_url, custom_type, web_port, web_scheme, probed,
		       assignment, network_name, first_seen, last_seen, response_time, address_history,
		       linked_mac
		FROM devices
		WHERE mac = ? AND ip != ?
	`, mac, excludeIP)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()

	for rows.Next() {
		d, err := s.scanDevice(rows)
		if err == nil {
			if isIPv4(d.IP) == wantV4 {
				return d.IP, d, nil
			}
		}
	}
	return "", nil, nil
}

func (s *Storage) findAnyByMACLocked(tx *sql.Tx, mac string) (*types.Device, error) {
	if mac == "" {
		return nil, nil
	}
	row := tx.QueryRow(`
		SELECT ip, mac, hostname, vendor, type, web_ui, risks, label, notes, "group",
		       custom_hostname, custom_web_url, custom_type, web_port, web_scheme, probed,
		       assignment, network_name, first_seen, last_seen, response_time, address_history,
		       linked_mac
		FROM devices
		WHERE mac = ?
		LIMIT 1
	`, mac)
	d, err := s.scanDevice(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return d, nil
}

func (s *Storage) addNewDeviceLocked(tx *sql.Tx, d *types.Device, now time.Time, activeIPs map[string]bool) error {
	if d.MAC != "" {
		oldIP, old, err := s.findByMACLocked(tx, d.MAC, d.IP)
		if err != nil {
			return err
		}
		if old != nil {
			// Check if the old IP is also active (using either sweep active list, or DB online state depending on subnet boundary)
			var oldIPActive bool
			if s.inSameSubnetLocked(d.IP, oldIP) {
				// Same subnet: both must be present in the active sweep list to coexist
				oldIPActive = activeIPs != nil && activeIPs[oldIP]
			} else {
				// Different subnets/concurrency: check if the old IP is online in the DB state
				oldIPActive = old.IsOnline(s.GetScanInterval())
			}

			d.Label = old.Label
			d.Notes = old.Notes
			d.Group = old.Group
			d.CustomHostname = old.CustomHostname
			d.CustomWebURL = old.CustomWebURL
			d.CustomType = old.CustomType
			d.WebPort = old.WebPort
			d.WebScheme = old.WebScheme
			d.Probed = old.Probed
			d.FirstSeen = old.FirstSeen
			if d.Type == "" {
				d.Type = old.Type
			}

			if !oldIPActive {
				// Relocation: Old IP is offline, so migrate and delete
				d.AddressHistory = appendAddressChange(old.AddressHistory, oldIP, now)
				_, err = tx.Exec("DELETE FROM devices WHERE ip = ?", oldIP)
				if err != nil {
					return err
				}
			}
		}
	}
	if d.FirstSeen.IsZero() {
		d.FirstSeen = now
	}
	d.LastSeen = now

	risksJSON, _ := json.Marshal(d.Risks)
	historyJSON, _ := json.Marshal(d.AddressHistory)
	isOnline := 0
	if d.IsOnline() {
		isOnline = 1
	}

	_, err := tx.Exec(`
		INSERT INTO devices (
			ip, mac, hostname, vendor, type, web_ui, risks, label, notes, "group",
			custom_hostname, custom_web_url, custom_type, web_port, web_scheme, probed,
			assignment, network_name, first_seen, last_seen, response_time, address_history,
			is_online, missed_sweeps, last_presence_change
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
	`, d.IP, d.MAC, d.Hostname, d.Vendor, d.Type, boolToInt(d.WebUI), string(risksJSON),
		d.Label, d.Notes, d.Group, d.CustomHostname, d.CustomWebURL, d.CustomType,
		d.WebPort, d.WebScheme, boolToInt(d.Probed), d.Assignment, d.NetworkName,
		d.FirstSeen, d.LastSeen, d.ResponseTime, string(historyJSON), isOnline, d.LastSeen)
	if err != nil {
		return err
	}

	// Log an initial 'join' presence event for first-time discovery!
	_, err = tx.Exec(`
		INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
		VALUES (?, ?, ?, 'join', 0.0, ?)
	`, d.IP, d.MAC, d.Hostname, now)
	return err
}

func isIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}

func isRandomizedMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) == 0 {
		return false
	}
	return hw[0]&0x02 != 0
}

func (s *Storage) pruneEphemeralIPv6() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`
		SELECT ip, mac, hostname, vendor, type, web_ui, risks, label, notes, "group",
		       custom_hostname, custom_web_url, custom_type, web_port, web_scheme, probed,
		       assignment, network_name, first_seen, last_seen, response_time, address_history,
		       linked_mac
		FROM devices
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var toDelete []string
	for rows.Next() {
		d, err := s.scanDevice(rows)
		if err == nil {
			parsed := net.ParseIP(d.IP)
			if parsed == nil || parsed.To4() != nil {
				continue // not IPv6
			}
			if d.Label != "" || d.Notes != "" || d.Group != "" {
				continue // curated by the user: never auto-delete
			}
			if parsed.IsLinkLocalUnicast() || (d.MAC != "" && isRandomizedMAC(d.MAC)) {
				toDelete = append(toDelete, d.IP)
			}
		}
	}

	if len(toDelete) > 0 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		for _, ip := range toDelete {
			_, err = tx.Exec("DELETE FROM devices WHERE ip = ?", ip)
			if err != nil {
				return err
			}
		}
		return tx.Commit()
	}
	return nil
}

// GetSetting retrieves a setting value by key
func (s *Storage) GetSetting(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var val string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&val)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return val, nil
}

// SetSetting saves or updates a setting by key
func (s *Storage) SetSetting(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO settings (key, value)
		VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, value)
	return err
}

// MergeDevices merges discovered devices with existing data
func (s *Storage) MergeDevices(discovered []types.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	activeIPs := make(map[string]bool)
	for _, d := range discovered {
		if d.IP != "" {
			activeIPs[d.IP] = true
		}
	}

	now := time.Now()
	for _, d := range discovered {
		row := tx.QueryRow(`
			SELECT ip, mac, hostname, vendor, type, web_ui, risks, label, notes, "group",
			       custom_hostname, custom_web_url, custom_type, web_port, web_scheme, probed,
			       assignment, network_name, first_seen, last_seen, response_time, address_history,
			       is_online, last_presence_change
			FROM devices WHERE ip = ?
		`, d.IP)

		var existing types.Device
		var webUIVal, probedVal int
		var risksStr, addressHistoryStr string
		var isOnlineVal int
		var lastPresenceChange time.Time

		err := row.Scan(
			&existing.IP, &existing.MAC, &existing.Hostname, &existing.Vendor, &existing.Type, &webUIVal, &risksStr, &existing.Label, &existing.Notes, &existing.Group,
			&existing.CustomHostname, &existing.CustomWebURL, &existing.CustomType, &existing.WebPort, &existing.WebScheme, &probedVal, &existing.Assignment,
			&existing.NetworkName, &existing.FirstSeen, &existing.LastSeen, &existing.ResponseTime, &addressHistoryStr,
			&isOnlineVal, &lastPresenceChange,
		)

		if err == nil {
			existing.WebUI = webUIVal != 0
			existing.Probed = probedVal != 0
			_ = json.Unmarshal([]byte(risksStr), &existing.Risks)
			_ = json.Unmarshal([]byte(addressHistoryStr), &existing.AddressHistory)

			if d.MAC != "" {
				existing.MAC = d.MAC
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
			existing.NetworkName = resolveNetworkName(d.IP, s.networkNames)

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
			dev.NetworkName = resolveNetworkName(d.IP, s.networkNames)
			if err := s.addNewDeviceLocked(tx, &dev, now, activeIPs); err != nil {
				return err
			}
		}
	}

	return tx.Commit()
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

		row := tx.QueryRow(`
			SELECT ip, mac, hostname, vendor, type, web_ui, risks, label, notes, "group",
			       custom_hostname, custom_web_url, custom_type, web_port, web_scheme, probed,
			       assignment, network_name, first_seen, last_seen, response_time, address_history,
			       is_online, last_presence_change
			FROM devices WHERE ip = ?
		`, d.IP)

		var existing types.Device
		var webUIVal, probedVal int
		var risksStr, addressHistoryStr string
		var isOnlineVal int
		var lastPresenceChange time.Time

		err := row.Scan(
			&existing.IP, &existing.MAC, &existing.Hostname, &existing.Vendor, &existing.Type, &webUIVal, &risksStr, &existing.Label, &existing.Notes, &existing.Group,
			&existing.CustomHostname, &existing.CustomWebURL, &existing.CustomType, &existing.WebPort, &existing.WebScheme, &probedVal, &existing.Assignment,
			&existing.NetworkName, &existing.FirstSeen, &existing.LastSeen, &existing.ResponseTime, &addressHistoryStr,
			&isOnlineVal, &lastPresenceChange,
		)

		if err == nil {
			existing.WebUI = webUIVal != 0
			existing.Probed = probedVal != 0
			_ = json.Unmarshal([]byte(risksStr), &existing.Risks)
			_ = json.Unmarshal([]byte(addressHistoryStr), &existing.AddressHistory)

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
			existing.NetworkName = resolveNetworkName(d.IP, s.networkNames)

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
			dev.NetworkName = resolveNetworkName(d.IP, s.networkNames)
			if err := s.addNewDeviceLocked(tx, &dev, now, nil); err != nil {
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
			existing.NetworkName = resolveNetworkName(existing.IP, s.networkNames)

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
				if existing.IsOnline() {
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
			dev.NetworkName = resolveNetworkName(d.IP, s.networkNames)
			if err := s.addNewDeviceLocked(tx, &dev, now, nil); err != nil {
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

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return leftCount, nil
}

// RecordScanHistory records execution history metrics of a scan job
func (s *Storage) RecordScanHistory(network string, success bool, errStr string, startedAt time.Time, duration float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var joined, returned, left int
	rows, err := s.db.Query(`
		SELECT event, COUNT(*)
		FROM device_presence_history
		WHERE created_at >= ?
		GROUP BY event
	`, startedAt)
	if err == nil {
		defer rows.Close()
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
	}

	var online int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM devices WHERE is_online = 1").Scan(&online)

	successVal := 0
	if success {
		successVal = 1
	}

	_, err = s.db.Exec(`
		INSERT INTO scan_history (network, success, error, devices_online, devices_joined, devices_returned, devices_left, duration, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, network, successVal, errStr, online, joined, returned, left, duration, time.Now())
	return err
}

const maxAddressHistory = 10

func appendAddressChange(history []types.AddressChange, ip string, at time.Time) []types.AddressChange {
	history = append(history, types.AddressChange{IP: ip, ChangedAt: at})
	if len(history) > maxAddressHistory {
		history = history[len(history)-maxAddressHistory:]
	}
	return history
}

// GetLastScan returns the last scan time for a network
func (s *Storage) GetLastScan(network string) time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var t time.Time
	err := s.db.QueryRow("SELECT last_scan FROM scan_state WHERE network = ?", network).Scan(&t)
	if err != nil {
		return time.Time{}
	}
	return t
}

// GetMostRecentScan returns the time of the most recent scan
func (s *Storage) GetMostRecentScan() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var t time.Time
	err := s.db.QueryRow("SELECT last_scan FROM scan_state ORDER BY last_scan DESC LIMIT 1").Scan(&t)
	if err != nil {
		return time.Time{}
	}
	return t
}

// SetLastScan updates the last scan time for a network
func (s *Storage) SetLastScan(network string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO scan_state (network, last_scan, last_duration)
		VALUES (?, ?, 0.0)
		ON CONFLICT(network) DO UPDATE SET last_scan = excluded.last_scan
	`, network, t)
	return err
}

// GetLastDuration returns how long the previous scan took
func (s *Storage) GetLastDuration(network string) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var d float64
	err := s.db.QueryRow("SELECT last_duration FROM scan_state WHERE network = ?", network).Scan(&d)
	if err != nil {
		return 0.0
	}
	return d
}

// SetLastDuration records how long a scan took
func (s *Storage) SetLastDuration(network string, seconds float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO scan_state (network, last_scan, last_duration)
		VALUES (?, ?, ?)
		ON CONFLICT(network) DO UPDATE SET last_duration = excluded.last_duration
	`, network, time.Time{}, seconds)
	return err
}

// ContinuousScanEnabled reports whether background scanning should run
func (s *Storage) ContinuousScanEnabled(configDefault bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var val string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key = 'continuous_scan'").Scan(&val)
	if err != nil {
		return configDefault
	}
	return val == "true"
}

// SetContinuousScan saves override for background scanning
func (s *Storage) SetContinuousScan(enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	val := "false"
	if enabled {
		val = "true"
	}

	_, err := s.db.Exec(`
		INSERT INTO settings (key, value)
		VALUES ('continuous_scan', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, val)
	return err
}

// GetStats returns device statistics
func (s *Storage) GetStats() types.DeviceStats {
	stats := types.DeviceStats{
		Groups: make(map[string]int),
	}

	devices := s.GetDevices()
	for _, d := range devices {
		stats.Total++
		if d.IsOnline() {
			stats.Online++
		} else {
			stats.Offline++
		}
		if d.Group != "" {
			stats.Groups[d.Group]++
		}
	}

	return stats
}

// SetNetworkNames updates the network names lookup map
func (s *Storage) SetNetworkNames(names map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.networkNames = names
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

	rows, err := tx.Query(`
		SELECT ip, mac, hostname, vendor, type, web_ui, risks, label, notes, "group",
		       custom_hostname, custom_web_url, custom_type, web_port, web_scheme, probed,
		       assignment, network_name, first_seen, last_seen, response_time, address_history
		FROM devices
	`)
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
	rows.Close()

	for _, dev := range storedDevices {
		if assign, ok := assignments[dev.IP]; ok {
			dev.Assignment = assign
		} else {
			dev.Assignment = "Discovered"
		}
		dev.NetworkName = resolveNetworkName(dev.IP, s.networkNames)

		risksJSON, _ := json.Marshal(dev.Risks)
		historyJSON, _ := json.Marshal(dev.AddressHistory)
		isOnline := 0
		if dev.IsOnline() {
			isOnline = 1
		}

		_, err = tx.Exec(`
			UPDATE devices SET
				assignment = ?, network_name = ?, risks = ?, address_history = ?, is_online = ?
			WHERE ip = ?
		`, dev.Assignment, dev.NetworkName, string(risksJSON), string(historyJSON), isOnline, dev.IP)
		if err != nil {
			return err
		}
	}

	allDHCP := append(reservations, leases...)
	for _, d := range allDHCP {
		if d.IP == "" {
			continue
		}

		row := tx.QueryRow(`
			SELECT ip, mac, hostname, vendor, type, web_ui, risks, label, notes, "group",
			       custom_hostname, custom_web_url, custom_type, web_port, web_scheme, probed,
			       assignment, network_name, first_seen, last_seen, response_time, address_history
			FROM devices WHERE ip = ?
		`, d.IP)
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
			existing.NetworkName = resolveNetworkName(d.IP, s.networkNames)

			risksJSON, _ := json.Marshal(existing.Risks)
			historyJSON, _ := json.Marshal(existing.AddressHistory)
			isOnline := 0
			if existing.IsOnline() {
				isOnline = 1
			}

			_, err = tx.Exec(`
				UPDATE devices SET
					mac = ?, hostname = ?, vendor = ?, type = ?, web_ui = ?, risks = ?,
					label = ?, notes = ?, "group" = ?, custom_hostname = ?, custom_web_url = ?,
					custom_type = ?, web_port = ?, web_scheme = ?, probed = ?, assignment = ?,
					network_name = ?, first_seen = ?, last_seen = ?, response_time = ?,
					address_history = ?, is_online = ?
				WHERE ip = ?
			`, existing.MAC, existing.Hostname, existing.Vendor, existing.Type, boolToInt(existing.WebUI), string(risksJSON),
				existing.Label, existing.Notes, existing.Group, existing.CustomHostname, existing.CustomWebURL,
				existing.CustomType, existing.WebPort, existing.WebScheme, boolToInt(existing.Probed), existing.Assignment,
				existing.NetworkName, existing.FirstSeen, existing.LastSeen, existing.ResponseTime,
				string(historyJSON), isOnline, existing.IP)
			if err != nil {
				return err
			}
		} else {
			dev := d
			dev.Assignment = assignments[d.IP]
			dev.NetworkName = resolveNetworkName(d.IP, s.networkNames)
			if err := s.addNewDeviceLocked(tx, &dev, now.Add(-65*time.Minute), nil); err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

func resolveNetworkName(ipStr string, networkNames map[string]string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	for cidr, name := range networkNames {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet.Contains(ip) {
			return name
		}
	}
	return ""
}

// GetNewDevicesCount returns the count of devices discovered since the given time
func (s *Storage) GetNewDevicesCount(since time.Time) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM devices WHERE first_seen > ?", since).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

// GetScanHistory returns the chronological scan history records, newest first
func (s *Storage) GetScanHistory() ([]types.ScanHistoryRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, network, success, error, devices_online, devices_joined, devices_returned, devices_left, duration, timestamp
		FROM scan_history
		ORDER BY timestamp DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []types.ScanHistoryRecord
	for rows.Next() {
		var r types.ScanHistoryRecord
		var successVal int
		err := rows.Scan(&r.ID, &r.Network, &successVal, &r.Error, &r.DevicesOnline, &r.DevicesJoined, &r.DevicesReturned, &r.DevicesLeft, &r.Duration, &r.Timestamp)
		if err == nil {
			r.Success = successVal != 0
			result = append(result, r)
		}
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
	return result, nil
}

// GetPresenceEventsByMAC returns the chronological presence events for a specific MAC address, newest first
func (s *Storage) GetPresenceEventsByMAC(mac string) ([]types.PresenceEventRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, ip, mac, hostname, event, duration, created_at
		FROM device_presence_history
		WHERE mac = ?
		ORDER BY created_at DESC
	`, mac)
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
		// Resolve parent MAC to unify logs for linked family
		var parentMAC string
		if mac != "" {
			_ = s.db.QueryRow("SELECT COALESCE(NULLIF(linked_mac, ''), mac) FROM devices WHERE mac = ? AND mac <> '' LIMIT 1", mac).Scan(&parentMAC)
		} else {
			_ = s.db.QueryRow("SELECT COALESCE(NULLIF(linked_mac, ''), mac) FROM devices WHERE ip = ? LIMIT 1", ip).Scan(&parentMAC)
		}

		if parentMAC != "" {
			query = `
				SELECT id, ip, mac, hostname, event, duration, created_at
				FROM device_presence_history
				WHERE (mac <> '' AND (mac = ? OR mac IN (SELECT mac FROM devices WHERE linked_mac = ?))) OR ip = ?
				ORDER BY created_at DESC
			`
			args = append(args, parentMAC, parentMAC, ip)
		} else {
			query = `
				SELECT id, ip, mac, hostname, event, duration, created_at
				FROM device_presence_history
				WHERE (mac <> '' AND mac = ?) OR ip = ?
				ORDER BY created_at DESC
			`
			args = append(args, mac, ip)
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
	defer rows.Close()

	var result []types.PresenceEventRecord
	for rows.Next() {
		var r types.PresenceEventRecord
		err := rows.Scan(&r.ID, &r.IP, &r.MAC, &r.Hostname, &r.Event, &r.Duration, &r.CreatedAt)
		if err == nil {
			result = append(result, r)
		}
	}

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
				WHERE mac <> '' AND mac = ?
				LIMIT 1
			`, mac)
		} else {
			row = s.db.QueryRow(`
				SELECT ip, mac, hostname, is_online, first_seen, last_seen
				FROM devices
				WHERE ip = ?
				LIMIT 1
			`, ip)
		}

		err := row.Scan(&devIP, &devMAC, &devHostname, &isOnlineVal, &firstSeen, &lastSeen)
		if err == nil {
			// Found device with no explicit transition history!
			// Synthesize automatic history based on is_online status:
			if isOnlineVal == 1 {
				// 1. Synthesize a 'join' event at firstSeen
				result = append(result, types.PresenceEventRecord{
					ID:        -1, // synthetic ID
					IP:        devIP,
					MAC:       devMAC,
					Hostname:  devHostname,
					Event:     "join",
					Duration:  0.0,
					CreatedAt: firstSeen,
				})
			} else {
				// 2. Synthesize 'leave' event (newest, at lastSeen) and 'join' event (oldest, at firstSeen)
				duration := lastSeen.Sub(firstSeen).Seconds()
				if duration < 0 {
					duration = 0
				}
				result = append(result, types.PresenceEventRecord{
					ID:        -2, // synthetic ID
					IP:        devIP,
					MAC:       devMAC,
					Hostname:  devHostname,
					Event:     "leave",
					Duration:  duration,
					CreatedAt: lastSeen,
				}, types.PresenceEventRecord{
					ID:        -1, // synthetic ID
					IP:        devIP,
					MAC:       devMAC,
					Hostname:  devHostname,
					Event:     "join",
					Duration:  0.0,
					CreatedAt: firstSeen,
				})
			}
		}
	}

	return result, nil
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

// ClearDevices removes all devices, or only those belonging to a specific network name.
func (s *Storage) ClearDevices(networkName string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var res sql.Result
	var err error

	if networkName == "" || strings.ToLower(networkName) == "all" {
		res, err = s.db.Exec("DELETE FROM devices")
	} else {
		res, err = s.db.Exec("DELETE FROM devices WHERE LOWER(network_name) = LOWER(?)", networkName)
	}

	if err != nil {
		return 0, err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}

	return affected, nil
}
