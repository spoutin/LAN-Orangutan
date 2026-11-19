package storage

import (
	"sort"
	"sync/atomic"
	"time"
)

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

// SetCurrentScanningNetwork sets the network CIDR currently being scanned
func (s *Storage) SetCurrentScanningNetwork(cidr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentScanningNetwork = cidr
	if s.activeScanningNetworks == nil {
		s.activeScanningNetworks = make(map[string]bool)
	}
	if cidr != "" {
		s.activeScanningNetworks[cidr] = true
	}
}

// SetNetworkScanning marks a network CIDR as actively scanning or finished
func (s *Storage) SetNetworkScanning(cidr string, active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeScanningNetworks == nil {
		s.activeScanningNetworks = make(map[string]bool)
	}
	if active {
		s.activeScanningNetworks[cidr] = true
		s.currentScanningNetwork = cidr
	} else {
		delete(s.activeScanningNetworks, cidr)
		if s.currentScanningNetwork == cidr {
			s.currentScanningNetwork = ""
			for n := range s.activeScanningNetworks {
				s.currentScanningNetwork = n
				break
			}
		}
	}
}

// IsNetworkScanning reports whether a network CIDR is currently being scanned
func (s *Storage) IsNetworkScanning(cidr string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activeScanningNetworks != nil && s.activeScanningNetworks[cidr] {
		return true
	}
	return s.currentScanningNetwork == cidr
}

// GetActiveScanningNetworks returns a list of all network CIDRs currently being scanned
func (s *Storage) GetActiveScanningNetworks() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []string
	for n := range s.activeScanningNetworks {
		list = append(list, n)
	}
	sort.Strings(list)
	return list
}

// ClearScanningNetworks clears all active scanning networks
func (s *Storage) ClearScanningNetworks() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeScanningNetworks = make(map[string]bool)
	s.activeDeepScanningNetworks = make(map[string]bool)
	s.currentScanningNetwork = ""
}

// SetNetworkDeepScanning marks a network CIDR as actively performing Stage 2 deep scans
func (s *Storage) SetNetworkDeepScanning(cidr string, active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeDeepScanningNetworks == nil {
		s.activeDeepScanningNetworks = make(map[string]bool)
	}
	if active {
		s.activeDeepScanningNetworks[cidr] = true
	} else {
		delete(s.activeDeepScanningNetworks, cidr)
	}
}

// IsNetworkDeepScanning reports whether a network CIDR is currently undergoing Stage 2 deep scans
func (s *Storage) IsNetworkDeepScanning(cidr string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activeDeepScanningNetworks == nil {
		return false
	}
	return s.activeDeepScanningNetworks[cidr]
}

// ClearDeepScanningNetworks clears all active deep scanning networks
func (s *Storage) ClearDeepScanningNetworks() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeDeepScanningNetworks = make(map[string]bool)
}

// SetNetworkScanError records a scan error for a network
func (s *Storage) SetNetworkScanError(cidr, err string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.networkScanErrors == nil {
		s.networkScanErrors = make(map[string]string)
	}
	if err != "" {
		s.networkScanErrors[cidr] = err
	} else {
		delete(s.networkScanErrors, cidr)
	}
}

// GetNetworkScanError returns the latest scan error for a network, if any
func (s *Storage) GetNetworkScanError(cidr string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.networkScanErrors == nil {
		return ""
	}
	return s.networkScanErrors[cidr]
}

// ClearNetworkScanError clears any recorded scan error for a network
func (s *Storage) ClearNetworkScanError(cidr string) {
	s.SetNetworkScanError(cidr, "")
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

	res, err := s.db.Exec(`
		UPDATE scan_state SET last_duration = ? WHERE network = ?
	`, seconds, network)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		_, err = s.db.Exec(`
			INSERT INTO scan_state (network, last_scan, last_duration)
			VALUES (?, ?, ?)
			ON CONFLICT(network) DO UPDATE SET last_duration = excluded.last_duration
		`, network, time.Now(), seconds)
		return err
	}
	return nil
}
