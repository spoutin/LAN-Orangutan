// Package storage handles device persistence and state management
package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
	_ "modernc.org/sqlite"
)

const maxAddressHistory = 10

type networkCIDR struct {
	cidr  string
	ipNet *net.IPNet
	name  string
	ones  int
	bits  int
}

// Storage manages device data persistence using SQLite
type Storage struct {
	devicesFile                string
	stateFile                  string
	db                         *sql.DB
	mu                         sync.RWMutex
	networkNames               map[string]string
	networkCIDRs               []networkCIDR
	scanRunning                int32
	scanInterval               int32
	currentScanningNetwork     string
	activeScanningNetworks     map[string]bool
	activeDeepScanningNetworks map[string]bool
	networkScanErrors          map[string]string
	completedNetworks          []string
}

// SwitchConnection is a current switch forwarding-table match for a device MAC.
type SwitchConnection struct {
	MAC        string
	SwitchName string
	SwitchHost string
	Port       string
	VLAN       int
	LinkState  string
	LinkSpeed  int
	Duplex     string
	PoEWatts   *float64
	UpdatedAt  time.Time
	InOctets   uint64
	OutOctets  uint64
	SingleMAC  bool
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
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;"); err != nil {
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

	// Run deduplicate MACs on load
	if err := s.DeduplicateMACs(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to deduplicate MACs: %w", err)
	}

	return s, nil
}

// GetDB returns the underlying sql.DB instance (useful for test assertions or maintenance).
func (s *Storage) GetDB() *sql.DB {
	return s.db
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

// SetNetworkNames updates the network names lookup map and caches parsed CIDRs sorted longest-prefix-first.
func (s *Storage) SetNetworkNames(names map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := make(map[string]string, len(names))
	cidrs := make([]networkCIDR, 0, len(names))
	for k, v := range names {
		cloned[k] = v
		if _, ipNet, err := net.ParseCIDR(k); err == nil {
			ones, bits := ipNet.Mask.Size()
			cidrs = append(cidrs, networkCIDR{
				cidr:  k,
				ipNet: ipNet,
				name:  v,
				ones:  ones,
				bits:  bits,
			})
		}
	}
	sort.Slice(cidrs, func(i, j int) bool {
		if cidrs[i].ones != cidrs[j].ones {
			return cidrs[i].ones > cidrs[j].ones
		}
		if cidrs[i].bits != cidrs[j].bits {
			return cidrs[i].bits > cidrs[j].bits
		}
		return cidrs[i].cidr < cidrs[j].cidr
	})
	s.networkNames = cloned
	s.networkCIDRs = cidrs
}

// resolveNetworkNameLocked resolves the configured network name for an IP address.
// Must be called while holding s.mu (Lock or RLock).
func (s *Storage) resolveNetworkNameLocked(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	for _, entry := range s.networkCIDRs {
		if entry.ipNet.Contains(ip) {
			return entry.name
		}
	}
	return ""
}

// inSameSubnetLocked checks if two IP addresses reside inside the same configured subnet CIDR.
// Must be called while holding s.mu (Lock or RLock).
func (s *Storage) inSameSubnetLocked(ip1, ip2 string) bool {
	p1 := net.ParseIP(ip1)
	p2 := net.ParseIP(ip2)
	if p1 == nil || p2 == nil {
		return false
	}

	if len(s.networkCIDRs) > 0 {
		for _, entry := range s.networkCIDRs {
			if entry.ipNet.Contains(p1) && entry.ipNet.Contains(p2) {
				return true
			}
		}
	} else if len(s.networkNames) == 0 {
		// Fallback for default home networks (/24)
		v41 := p1.To4()
		v42 := p2.To4()
		if v41 != nil && v42 != nil {
			return v41[0] == v42[0] && v41[1] == v42[1] && v41[2] == v42[2]
		}
	}
	return false
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

func (s *Storage) pruneEphemeralIPv6() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT ` + deviceSelectColumns + ` FROM devices`)
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
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

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

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func joinStrings(elems []string, sep string) string {
	return strings.Join(elems, sep)
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

func appendAddressChange(history []types.AddressChange, ip string, at time.Time) []types.AddressChange {
	history = append(history, types.AddressChange{IP: ip, ChangedAt: at})
	if len(history) > maxAddressHistory {
		history = history[len(history)-maxAddressHistory:]
	}
	return history
}

// NormalizeMAC standardizes a MAC address to lowercase colon-separated format.
func NormalizeMAC(mac string) string {
	clean := strings.ToLower(strings.TrimSpace(mac))
	clean = strings.ReplaceAll(clean, "-", ":")
	return clean
}
