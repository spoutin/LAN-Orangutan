// Package storage handles device persistence and state management
package storage

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/291-Group/LAN-Orangutan/internal/types"
)

// Storage manages device data persistence
type Storage struct {
	devicesFile  string
	stateFile    string
	mu           sync.RWMutex
	devices      map[string]*types.Device
	state        *types.ScanState
	networkNames map[string]string
}

// New creates a new Storage instance
func New(devicesFile, stateFile string) (*Storage, error) {
	s := &Storage{
		devicesFile:  devicesFile,
		stateFile:    stateFile,
		devices:      make(map[string]*types.Device),
		state: &types.ScanState{
			LastScan:     make(map[string]time.Time),
			LastDuration: make(map[string]float64),
		},
		networkNames: make(map[string]string),
	}

	// Ensure directories exist
	if err := os.MkdirAll(filepath.Dir(devicesFile), 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Load existing data. Name the file in the error: a damaged file is
	// something the user has to go and look at, and "invalid character 'h'"
	// on its own does not say where to look.
	if err := s.loadDevices(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("could not read the device list at %s: %w", devicesFile, err)
	}
	if err := s.loadState(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("could not read the scan history at %s: %w", stateFile, err)
	}

	// One-time cleanup: drop phantom devices created from noisy IPv6 neighbour
	// data (link-local and privacy addresses) before that path was fixed, so an
	// upgraded install heals down to the real device count. Safe here because
	// New runs before the store is shared with any other goroutine.
	if s.pruneEphemeralIPv6Locked() {
		_ = s.saveDevices()
	}

	return s, nil
}

// loadDevices reads devices from the JSON file
func (s *Storage) loadDevices() error {
	data, err := os.ReadFile(s.devicesFile)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		return nil
	}

	return json.Unmarshal(data, &s.devices)
}

// loadState reads scan state from the JSON file
func (s *Storage) loadState() error {
	data, err := os.ReadFile(s.stateFile)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		return nil
	}

	if err := json.Unmarshal(data, &s.state); err != nil {
		return err
	}

	// State files written before durations were tracked have no such map, so
	// recreate it rather than leave a nil map that cannot be written to.
	if s.state.LastScan == nil {
		s.state.LastScan = make(map[string]time.Time)
	}
	if s.state.LastDuration == nil {
		s.state.LastDuration = make(map[string]float64)
	}
	return nil
}

// saveDevices writes devices to the JSON file atomically
func (s *Storage) saveDevices() error {
	data, err := json.MarshalIndent(s.devices, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal devices: %w", err)
	}

	return atomicWrite(s.devicesFile, data)
}

// saveState writes scan state to the JSON file atomically
func (s *Storage) saveState() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	return atomicWrite(s.stateFile, data)
}

// atomicWrite writes data to a file atomically using a temp file
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tempFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()

	// Clean up temp file on error
	defer func() {
		if tempPath != "" {
			os.Remove(tempPath)
		}
	}()

	if _, err := tempFile.Write(data); err != nil {
		tempFile.Close()
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := tempFile.Sync(); err != nil {
		tempFile.Close()
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	tempPath = "" // Prevent cleanup of renamed file
	return nil
}

// GetDevices returns all devices.
//
// Each device is copied, not shared. A later scan merges results by mutating
// the stored structs in place, so handing out the live pointers would let a
// caller read a field while it is being written. The copies are snapshots the
// caller can read freely.
func (s *Storage) GetDevices() map[string]*types.Device {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]*types.Device, len(s.devices))
	for k, v := range s.devices {
		cp := *v
		result[k] = &cp
	}
	return result
}

// GetDevice returns a single device by IP, or nil if there is none.
//
// The returned device is a copy, for the same reason as GetDevices: the stored
// struct is mutated in place by later scans.
func (s *Storage) GetDevice(ip string) *types.Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.devices[ip]
	if !ok {
		return nil
	}
	cp := *d
	return &cp
}

// UpdateDevice updates or creates a device
func (s *Storage) UpdateDevice(device *types.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Preserve existing user data if device exists
	if existing, ok := s.devices[device.IP]; ok {
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
		if device.FirstSeen.IsZero() {
			device.FirstSeen = existing.FirstSeen
		}
	}

	s.devices[device.IP] = device
	return s.saveDevices()
}

// UpdateDeviceFields updates specific fields of a device
func (s *Storage) UpdateDeviceFields(ip string, label, notes, group, customHostname, customWebURL *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	device, ok := s.devices[ip]
	if !ok {
		return fmt.Errorf("device not found: %s", ip)
	}

	if label != nil {
		device.Label = *label
	}
	if notes != nil {
		device.Notes = *notes
	}
	if group != nil {
		device.Group = *group
	}
	if customHostname != nil {
		device.CustomHostname = *customHostname
	}
	if customWebURL != nil {
		device.CustomWebURL = *customWebURL
	}

	return s.saveDevices()
}

// DeleteDevice removes a device by IP
func (s *Storage) DeleteDevice(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.devices[ip]; !ok {
		return fmt.Errorf("device not found: %s", ip)
	}

	delete(s.devices, ip)
	return s.saveDevices()
}

// MergeDevices merges discovered devices with existing data
func (s *Storage) MergeDevices(discovered []types.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, d := range discovered {
		if existing, ok := s.devices[d.IP]; ok {
			// A primary scan is authoritative. It replaces the probe fields
			// (WebUI and Risks reflect the latest probe, so a fixed risk stops
			// showing), but it does not wipe an identity field it happened to
			// gather less of this time: a scan without sudo has no MAC, and a
			// device that did not resolve this time keeps its known name.
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
			existing.WebUI = d.WebUI
			existing.Risks = d.Risks
			existing.LastSeen = now
			existing.NetworkName = resolveNetworkName(d.IP, s.networkNames)
		} else {
			dev := d
			dev.NetworkName = resolveNetworkName(d.IP, s.networkNames)
			s.addNewDeviceLocked(&dev, now)
		}
	}

	return s.saveDevices()
}

// MergeSupplemental folds in devices from a secondary source, such as mDNS or
// IPv6 neighbor discovery, that carries only part of a device's picture. It
// fills gaps on a known device but never clobbers what the primary scan found,
// and never touches the probe fields, so an mDNS answer with no MAC cannot erase
// a MAC the scan discovered, nor clear a web or risk flag.
func (s *Storage) MergeSupplemental(discovered []types.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, d := range discovered {
		// A link-local IPv6 address is never a device (same reasoning as
		// MergeIPv6Neighbors); skip it so a supplemental source like mDNS cannot
		// create a phantom keyed by fe80::.
		if parsed := net.ParseIP(d.IP); parsed != nil && parsed.To4() == nil && parsed.IsLinkLocalUnicast() {
			continue
		}
		if existing, ok := s.devices[d.IP]; ok {
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
		} else {
			dev := d
			dev.NetworkName = resolveNetworkName(d.IP, s.networkNames)
			s.addNewDeviceLocked(&dev, now)
		}
	}

	return s.saveDevices()
}

// MergeIPv6Neighbors folds IPv6 neighbour-discovery results into the inventory.
// The IPv6 neighbour cache is noisy: it is full of link-local and rotating
// privacy addresses, each often behind a randomised MAC, so a device sighted
// over IPv6 can look brand new every time. Using it to create a device per
// address is what produces hundreds of phantom entries. Instead it ENRICHES a
// device already found by the reliable IPv4/ARP scan, matched by MAC across
// address families. A new device is created only for a routable address whose
// MAC is a real (universally-administered) hardware address not already known --
// a genuine IPv6-only device. Link-local, and randomised-MAC addresses with no
// match, are dropped, so privacy addresses cannot pile up.
func (s *Storage) MergeIPv6Neighbors(discovered []types.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	changed := false
	for _, d := range discovered {
		parsed := net.ParseIP(d.IP)
		if parsed == nil || parsed.To4() != nil || parsed.IsLinkLocalUnicast() || d.MAC == "" {
			continue // not a routable IPv6 address we can attribute
		}

		// Enrich the device we already know by this MAC rather than creating a
		// second entry for its IPv6 address.
		if existing := s.findAnyByMACLocked(d.MAC); existing != nil {
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
			changed = true
			continue
		}

		// No match: create a device only for a real hardware MAC (a genuine
		// IPv6-only device). A randomised MAC with no match is a privacy
		// address, not a device -- skip it so it cannot accumulate.
		if !isRandomizedMAC(d.MAC) {
			dev := d
			dev.NetworkName = resolveNetworkName(d.IP, s.networkNames)
			s.addNewDeviceLocked(&dev, now)
			changed = true
		}
	}

	if changed {
		return s.saveDevices()
	}
	return nil
}

// addNewDeviceLocked stores a device newly seen at its IP. If one with the same
// MAC exists at another IP in the same address family, it moved: its identity
// and user data carry across and the change is recorded. Callers hold s.mu.
func (s *Storage) addNewDeviceLocked(d *types.Device, now time.Time) {
	if d.MAC != "" {
		if oldIP, old := s.findByMACLocked(d.MAC, d.IP); old != nil {
			d.Label = old.Label
			d.Notes = old.Notes
			d.Group = old.Group
			d.CustomHostname = old.CustomHostname
			d.CustomWebURL = old.CustomWebURL
			d.FirstSeen = old.FirstSeen
			if d.Type == "" {
				d.Type = old.Type
			}
			d.AddressHistory = appendAddressChange(old.AddressHistory, oldIP, now)
			delete(s.devices, oldIP)
		}
	}
	if d.FirstSeen.IsZero() {
		d.FirstSeen = now
	}
	d.LastSeen = now
	s.devices[d.IP] = d
}

// findByMACLocked returns the IP and device of a stored device with the given
// MAC at an IP other than excludeIP, or "" and nil if there is none. Callers
// must hold s.mu.
//
// The match is confined to the same address family. A dual-stack device has an
// IPv4 and an IPv6 address at once, and those are not a "move" from one to the
// other: matching across families would wrongly collapse the two into one when
// IPv6 discovery runs alongside an IPv4 scan.
func (s *Storage) findByMACLocked(mac, excludeIP string) (string, *types.Device) {
	wantV4 := isIPv4(excludeIP)
	for ip, dev := range s.devices {
		if ip != excludeIP && dev.MAC == mac && isIPv4(ip) == wantV4 {
			return ip, dev
		}
	}
	return "", nil
}

func isIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}

// findAnyByMACLocked returns any stored device with the given MAC, regardless of
// address family, or nil. Used to attach an IPv6 sighting to the device already
// known from the IPv4 scan. Callers hold s.mu.
func (s *Storage) findAnyByMACLocked(mac string) *types.Device {
	if mac == "" {
		return nil
	}
	for _, dev := range s.devices {
		if dev.MAC == mac {
			return dev
		}
	}
	return nil
}

// isRandomizedMAC reports whether a MAC is locally administered (the
// second-least-significant bit of the first octet is set), which is how phones
// and laptops mark privacy-randomised addresses. Such a MAC cannot reliably
// identify a device across sightings.
func isRandomizedMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) == 0 {
		return false
	}
	return hw[0]&0x02 != 0
}

// pruneEphemeralIPv6Locked removes phantom devices that noisy IPv6 neighbour
// data created before that path was fixed: link-local addresses, and privacy
// (randomised-MAC) IPv6 addresses, which are not real, persistent devices. It
// runs on load so existing installs heal down to the real device count; once
// healed it is a no-op, because no code path creates such entries any more.
//
// It never removes a device the user has curated (a label, notes or a group),
// so a real device that happens to be keyed by such an address keeps its data
// instead of being wiped and re-created on every restart. Returns whether
// anything was removed. Callers hold s.mu.
func (s *Storage) pruneEphemeralIPv6Locked() bool {
	removed := false
	for ip, dev := range s.devices {
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() != nil {
			continue // not IPv6
		}
		if dev.Label != "" || dev.Notes != "" || dev.Group != "" {
			continue // curated by the user: never auto-delete
		}
		if parsed.IsLinkLocalUnicast() || (dev.MAC != "" && isRandomizedMAC(dev.MAC)) {
			delete(s.devices, ip)
			removed = true
		}
	}
	return removed
}

// maxAddressHistory bounds how many previous addresses a device keeps, so the
// history cannot grow without limit on a device that changes IP often.
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
	return s.state.LastScan[network]
}

// GetMostRecentScan returns the time of the most recent scan of any network.
//
// The device list is only as current as the last scan, so the dashboard shows
// this alongside the per-device "last seen" times. Without it, a device last
// seen during a scan hours ago still reads as though it were just checked.
//
// The zero time means nothing has ever been scanned.
func (s *Storage) GetMostRecentScan() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var latest time.Time
	for _, t := range s.state.LastScan {
		if t.After(latest) {
			latest = t
		}
	}
	return latest
}

// SetLastScan updates the last scan time for a network
func (s *Storage) SetLastScan(network string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.LastScan[network] = t
	return s.saveState()
}

// GetLastDuration returns how long the previous scan of a network took, in
// seconds. It returns 0 when the network has not been scanned before.
func (s *Storage) GetLastDuration(network string) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.LastDuration[network]
}

// SetLastDuration records how long a scan of a network took, in seconds.
func (s *Storage) SetLastDuration(network string, seconds float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state.LastDuration == nil {
		s.state.LastDuration = make(map[string]float64)
	}
	s.state.LastDuration[network] = seconds
	return s.saveState()
}

// ContinuousScanEnabled reports whether background scanning should run. It
// honours a runtime override the user set from the UI, and falls back to the
// configured default when no override has been saved.
func (s *Storage) ContinuousScanEnabled(configDefault bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state.ContinuousScan != nil {
		return *s.state.ContinuousScan
	}
	return configDefault
}

// SetContinuousScan saves the user's runtime override for background scanning so
// it survives a restart.
func (s *Storage) SetContinuousScan(enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.ContinuousScan = &enabled
	return s.saveState()
}

// GetStats returns device statistics
func (s *Storage) GetStats() types.DeviceStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := types.DeviceStats{
		Groups: make(map[string]int),
	}

	for _, d := range s.devices {
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

// SetNetworkNames updates the Storage instance's network names lookup map.
func (s *Storage) SetNetworkNames(names map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.networkNames = names
}

// MergeRouterDHCP merges DHCP leases and static reservations from routers into storage.
func (s *Storage) MergeRouterDHCP(leases []types.Device, reservations []types.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// 1. Build a map of IP -> Assignment (Static / Dynamic)
	assignments := make(map[string]string)
	for _, r := range reservations {
		if r.IP != "" {
			assignments[r.IP] = "Static"
		}
	}
	for _, l := range leases {
		if l.IP != "" {
			// Do not overwrite Static with Dynamic
			if _, exists := assignments[l.IP]; !exists {
				assignments[l.IP] = "Dynamic"
			}
		}
	}

	// 2. Set Assignments for all currently stored devices
	for ip, dev := range s.devices {
		if assign, ok := assignments[ip]; ok {
			dev.Assignment = assign
		} else {
			// If not found in any leases/reservations, default to "Discovered"
			dev.Assignment = "Discovered"
		}
		// Refresh NetworkName while we are here
		dev.NetworkName = resolveNetworkName(ip, s.networkNames)
	}

	// 3. For any lease or reservation not currently found by scans, register them!
	allDHCP := append(reservations, leases...)
	for _, d := range allDHCP {
		if d.IP == "" {
			continue
		}

		if existing, ok := s.devices[d.IP]; ok {
			// Enrich missing fields
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
		} else {
			// Brand new device discovered via DHCP!
			dev := d
			dev.Assignment = assignments[d.IP]
			dev.NetworkName = resolveNetworkName(d.IP, s.networkNames)
			
			// We haven't pinged it, so we won't show it as online unless LastSeen is fresh.
			// Setting LastSeen to 65 minutes ago makes sure it registers as offline but keeps history.
			s.addNewDeviceLocked(&dev, now.Add(-65*time.Minute))
		}
	}

	return s.saveDevices()
}

// resolveNetworkName matches an IP against the configured subnet map
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

// GetNewDevicesCount returns the number of devices discovered since the given time.
func (s *Storage) GetNewDevicesCount(since time.Time) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, d := range s.devices {
		if d.FirstSeen.After(since) {
			count++
		}
	}
	return count
}
