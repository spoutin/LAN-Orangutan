package api

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/scanner"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// percentUnknown is reported when a network has never been scanned before and
// there is therefore no timing history to estimate progress from.
const percentUnknown = -1

// scanJob tracks a scan running in the background. Scans of large networks take
// minutes, which is far too long to hold an HTTP request open, so the scan runs
// detached and the UI polls for progress.
type scanJob struct {
	id       string
	networks []string
	cancel   context.CancelFunc

	mu               sync.RWMutex
	status           string // running, done, cancelled or failed
	currentNetwork   string
	networkIndex     int // 1-based; 0 before the first network starts
	deviceCount      int
	startedAt        time.Time
	networkStartedAt time.Time
	// estimatedSeconds is how long the current network took to scan last time,
	// or 0 when it has never been scanned before.
	estimatedSeconds float64
	results          []networkScanSummary
	err              string

	// automatic marks a scan the background scanner started, as opposed to one
	// the user clicked. Set once at creation. The UI uses it to stay quiet for
	// automatic scans instead of popping the progress overlay on its own.
	automatic bool

	// Stage 2 port scanning telemetry
	portScanActive   bool
	portScanTotal    int
	portScanComplete int
	portScanWG       sync.WaitGroup
}

// scanProgress is the snapshot of a job returned to the UI.
type scanProgress struct {
	JobID              string  `json:"job_id"`
	Status             string  `json:"status"`
	CurrentNetwork     string  `json:"current_network,omitempty"`
	CurrentNetworkName string  `json:"current_network_name,omitempty"`
	NetworkIndex       int     `json:"network_index"`
	NetworkCount       int     `json:"network_count"`
	DeviceCount        int     `json:"device_count"`
	NewDeviceCount     int     `json:"new_device_count"`
	Elapsed            float64 `json:"elapsed"`
	// Percent is the estimated completion of the whole job, or -1 when the
	// current network has no timing history and progress cannot be estimated.
	Percent float64 `json:"percent"`
	// Remaining is the estimated number of seconds left, omitted when unknown.
	Remaining *float64             `json:"remaining,omitempty"`
	Networks  []networkScanSummary `json:"networks"`
	Error     string               `json:"error,omitempty"`
	// Automatic is true for a scan the background scanner started. The UI does
	// not show its progress overlay for these, so an automatic scan never pops
	// a dialog with a Cancel button on its own.
	Automatic bool `json:"automatic"`

	// Stage 2 port scanning progress fields
	PortScanActive   bool `json:"port_scan_active"`
	PortScanTotal    int  `json:"port_scan_total"`
	PortScanComplete int  `json:"port_scan_complete"`
}

// snapshot returns the current progress of the job. The estimate is based on
// how long each network took to scan previously, which is real measured data,
// but it is only ever an estimate: nmap cannot report incremental progress for
// a ping sweep, so there is nothing more accurate to use.
func (j *scanJob) snapshot(cfg *config.Config, store *storage.Storage) scanProgress {
	j.mu.RLock()
	defer j.mu.RUnlock()

	p := scanProgress{
		JobID:            j.id,
		Status:           j.status,
		CurrentNetwork:   j.currentNetwork,
		NetworkIndex:     j.networkIndex,
		NetworkCount:     len(j.networks),
		DeviceCount:      j.deviceCount,
		Elapsed:          time.Since(j.startedAt).Seconds(),
		Percent:          percentUnknown,
		Error:            j.err,
		Automatic:        j.automatic,
		PortScanActive:   j.portScanActive,
		PortScanTotal:    j.portScanTotal,
		PortScanComplete: j.portScanComplete,
	}

	if j.currentNetwork != "" && cfg != nil {
		if name, ok := cfg.Scanning.NetworkNames[j.currentNetwork]; ok {
			p.CurrentNetworkName = name
		}
	}

	if store != nil {
		p.NewDeviceCount = store.GetNewDevicesCount(j.startedAt)
	}

	// Copy and enrich results with network names
	p.Networks = make([]networkScanSummary, len(j.results))
	for i, res := range j.results {
		summary := res
		if cfg != nil {
			if name, ok := cfg.Scanning.NetworkNames[res.Network]; ok {
				summary.NetworkName = name
			}
		}
		p.Networks[i] = summary
	}

	// Only a job that ran to completion is 100%. A cancelled or failed job
	// stopped wherever it stopped, so leave its progress unknown rather than
	// reporting it as finished.
	if j.status == "done" {
		p.Percent = 100
		return p
	}
	if j.status != "running" {
		return p
	}

	// Without timing history for the current network there is no honest way to
	// estimate progress, so report it as unknown and let the UI show an
	// indeterminate state rather than invent a number.
	if j.estimatedSeconds <= 0 || j.networkIndex == 0 {
		return p
	}

	// Weight every network equally: finished ones count in full, and the
	// current one counts as its own elapsed fraction. Cap the fraction just
	// below 1 so a network that overruns its estimate does not appear complete
	// while it is still working.
	fraction := time.Since(j.networkStartedAt).Seconds() / j.estimatedSeconds
	if fraction > 0.99 {
		fraction = 0.99
	}
	p.Percent = (float64(j.networkIndex-1) + fraction) / float64(len(j.networks)) * 100

	remaining := (1 - fraction) * j.estimatedSeconds
	p.Remaining = &remaining
	return p
}

// startScanJob begins scanning the given networks in the background. The caller
// must hold h.jobMu. automatic marks a scan the background scanner started, so
// the UI can stay quiet for it.
func (h *Handler) startScanJob(networks []string, automatic bool) *scanJob {
	// Descend from h.scanCtx (the server's shutdown context) rather than
	// context.Background(), so cancelling it at shutdown cancels a running scan.
	ctx, cancel := context.WithCancel(h.scanCtx)

	job := &scanJob{
		id:        fmt.Sprintf("scan-%d", time.Now().UnixNano()),
		networks:  networks,
		cancel:    cancel,
		status:    "running",
		startedAt: time.Now(),
		results:   make([]networkScanSummary, 0, len(networks)),
		automatic: automatic,
	}

	h.scanWG.Add(1)
	go func() {
		defer h.scanWG.Done()
		job.run(ctx, h)
	}()
	return job
}

// run scans each network in turn, recording the outcome of each. A network that
// is rate limited or fails does not abort the job, so one bad interface cannot
// hide results from the others.
func (j *scanJob) run(ctx context.Context, h *Handler) {
	activeIPsMap := make(map[string]bool)

	defer func() {
		dur := time.Since(j.startedAt).Seconds()
		networkName := "All Networks"
		if len(j.networks) == 1 {
			networkName = j.networks[0]
		}

		j.mu.RLock()
		status := j.status
		errStr := j.err
		j.mu.RUnlock()

		success := status == "done"
		_ = h.store.RecordScanHistory(networkName, success, errStr, j.startedAt, dur)
	}()

	for i, cidr := range j.networks {
		if ctx.Err() != nil {
			j.finish("cancelled", "")
			return
		}

		j.beginNetwork(cidr, i+1, h.store.GetLastDuration(cidr))

		summary := networkScanSummary{Network: cidr}

		lastScan := h.store.GetLastScan(cidr)
		if canScan, waitTime := h.scanner.CheckRateLimit(lastScan); !canScan {
			summary.Status = "skipped"
			summary.Error = "rate limited, wait " + waitTime.Round(time.Second).String()
			j.addResult(summary, 0)
			continue
		}

		// scanNetwork applies its own per-network timeout.
		result, err := h.scanNetwork(ctx, cidr)

		if err != nil {
			// A cancelled job surfaces as a scan error, but it is not a failure.
			if ctx.Err() != nil {
				j.finish("cancelled", "")
				return
			}
			summary.Status = "failed"
			summary.Error = err.Error()
			j.addResult(summary, 0)
			continue
		}

		summary.Status = "scanned"
		summary.DeviceCount = result.DeviceCount
		summary.Duration = result.Duration
		j.addResult(summary, result.DeviceCount)

		for _, d := range result.Devices {
			if d.IP != "" {
				activeIPsMap[d.IP] = true
			}
		}

		// Launch asynchronous port scan (Stage 2) on discovered active devices
		if h.cfg.Scanning.EnablePortScan && h.cfg.Scanning.PortScanRange != "" {
			shouldPortScan := false
			if !j.automatic {
				// Keep manual scans immediate
				shouldPortScan = true
			} else {
				// Automatic background scan: quiet-hour 3:00 AM Eastern Time prober
				loc, err := time.LoadLocation("America/New_York")
				if err != nil {
					// Fallback to UTC if America/New_York is not loaded/available
					loc = time.UTC
				}
				nowET := time.Now().In(loc)
				if nowET.Hour() == 3 {
					todayStr := nowET.Format("2006-01-02")
					lastDeepScan, _ := h.store.GetSetting("last_deep_scan_date")
					if lastDeepScan != todayStr {
						shouldPortScan = true
						_ = h.store.SetSetting("last_deep_scan_date", todayStr)
					}
				}
			}

			if shouldPortScan {
				j.portScanWG.Add(1)
				go func(devices []types.Device) {
					defer j.portScanWG.Done()
					j.startPortScan(ctx, h, devices)
				}(result.Devices)
			}
		}
	}

	// Supplemental discovery, once for the whole job: IPv6 neighbors (an IPv6
	// subnet cannot be swept) and mDNS announcements. Both merge as secondary
	// sources so they enrich rather than overwrite. A cancelled job skips them.
	if ctx.Err() == nil {
		if ipv6 := h.scanner.DiscoverIPv6(ctx); len(ipv6) > 0 {
			if err := h.store.MergeIPv6Neighbors(ipv6); err == nil {
				j.addResult(networkScanSummary{Network: "IPv6 neighbors", Status: "scanned", DeviceCount: len(ipv6)}, len(ipv6))
				for _, d := range ipv6 {
					if d.IP != "" {
						activeIPsMap[d.IP] = true
					}
				}
			}
		}
	}
	if ctx.Err() == nil {
		if mdns := h.scanner.DiscoverMDNS(ctx); len(mdns) > 0 {
			if err := h.store.MergeSupplemental(mdns); err == nil {
				j.addResult(networkScanSummary{Network: "mDNS", Status: "scanned", DeviceCount: len(mdns)}, len(mdns))
				for _, d := range mdns {
					if d.IP != "" {
						activeIPsMap[d.IP] = true
					}
				}
			}
		}
	}

	// Router DHCP and static mappings discovery
	if ctx.Err() == nil {
		var allLeases []types.Device
		var allReservations []types.Device
		var routerName string

		// Query OpenWrt if enabled
		if h.cfg.OpenWrt.Enable {
			leases, reservations, err := scanner.FetchOpenWrtDHCP(ctx, h.cfg.OpenWrt)
			if err == nil {
				allLeases = append(allLeases, leases...)
				allReservations = append(allReservations, reservations...)
				routerName = "OpenWrt"
			} else {
				fmt.Printf("Router OpenWrt DHCP fetch error: %v\n", err)
			}
		}

		// Query OPNsense if enabled
		if h.cfg.OPNsense.Enable {
			leases, reservations, arpEntries, err := scanner.FetchOPNsenseDHCP(ctx, h.cfg.OPNsense)
			if err == nil {
				allLeases = append(allLeases, leases...)
				allReservations = append(allReservations, reservations...)
				if len(arpEntries) > 0 {
					_ = h.store.MergeSupplemental(arpEntries)
					for _, d := range arpEntries {
						if d.IP != "" {
							activeIPsMap[d.IP] = true
						}
					}
				}
				if routerName == "" {
					routerName = "OPNsense"
				} else {
					routerName += " & OPNsense"
				}
			} else {
				fmt.Printf("Router OPNsense DHCP fetch error: %v\n", err)
			}
		}

		if len(allLeases) > 0 || len(allReservations) > 0 {
			if err := h.store.MergeRouterDHCP(allLeases, allReservations); err == nil {
				total := len(allLeases) + len(allReservations)
				j.addResult(networkScanSummary{
					Network:     routerName + " DHCP",
					Status:      "scanned",
					DeviceCount: total,
				}, total)
			}
		}
	}

	// Wait for any asynchronous port scanning (Stage 2) to complete before finishing the job
	j.portScanWG.Wait()

	if ctx.Err() == nil {
		var activeIPs []string
		for ip := range activeIPsMap {
			activeIPs = append(activeIPs, ip)
		}
		_, err := h.store.ProcessMissingDevices(j.networks, activeIPs)
		if err != nil {
			fmt.Printf("[DEBUG] ProcessMissingDevices error: %v\n", err)
		}
		j.finish("done", "")
	} else {
		j.finish("cancelled", "")
	}
}

// beginNetwork records that the job has started scanning a network.
func (j *scanJob) beginNetwork(cidr string, index int, estimate float64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.currentNetwork = cidr
	j.networkIndex = index
	j.networkStartedAt = time.Now()
	j.estimatedSeconds = estimate
}

// addResult records the outcome of one network.
func (j *scanJob) addResult(summary networkScanSummary, devices int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.results = append(j.results, summary)
	j.deviceCount += devices
}

// finish marks the job as no longer running.
func (j *scanJob) finish(status, err string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.status = status
	j.err = err
	j.currentNetwork = ""
}

// isRunning reports whether the job is still in progress.
func (j *scanJob) isRunning() bool {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.status == "running"
}

// adopt marks a running job as user-initiated. When someone clicks Scan while
// the background scanner is mid-scan, the manual request attaches to that scan
// (rather than being rejected) and adopts it so the progress overlay follows it
// to completion instead of treating it as a silent automatic scan.
func (j *scanJob) adopt() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.automatic = false
}

// StartBackgroundScanner re-scans the detected networks every interval so the
// device list stays current on its own, without anyone clicking Scan or keeping
// a browser open. It reuses the same job path, the one-scan-at-a-time guard and
// the per-network rate limiting as a manual scan, and stops when ctx is
// cancelled. A non-positive interval disables it. The ticker always runs so the
// user can switch continuous scanning on and off at runtime; runBackgroundScan
// skips the actual scan while the setting is off.
func (h *Handler) StartBackgroundScanner(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}

	go func() {
		// Scan shortly after startup so a freshly started server does not sit
		// empty until the first interval elapses.
		startup := time.NewTimer(5 * time.Second)
		defer startup.Stop()
		select {
		case <-ctx.Done():
			return
		case <-startup.C:
		}
		h.runBackgroundScan()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.runBackgroundScan()
			}
		}
	}()
}

// runBackgroundScan starts one scan of all detected networks, unless a scan is
// already running. The job itself skips any network that was scanned too
// recently, so this never scans a network more often than the rate limit
// allows, however short the interval.
func (h *Handler) runBackgroundScan() {
	// The ticker always runs so the setting can be toggled at runtime; skip the
	// actual scan when continuous scanning is currently switched off.
	if !h.store.ContinuousScanEnabled(h.cfg.Scanning.ContinuousScan) {
		return
	}

	networks, err := h.resolveScanTargets("all")
	if err != nil || len(networks) == 0 {
		return
	}

	h.jobMu.Lock()
	defer h.jobMu.Unlock()

	if h.job != nil && h.job.isRunning() {
		return
	}
	h.job = h.startScanJob(networks, true)
}

// startPortScan runs a targeted high-speed port scan on a list of discovered active devices.
func (j *scanJob) startPortScan(ctx context.Context, h *Handler, devices []types.Device) {
	var activeDevices []types.Device
	for _, d := range devices {
		if d.IP != "" {
			activeDevices = append(activeDevices, d)
		}
	}

	if len(activeDevices) == 0 {
		return
	}

	j.mu.Lock()
	j.portScanActive = true
	j.portScanTotal += len(activeDevices)
	j.mu.Unlock()

	// Use a worker pool to scan devices sequentially (max 1 host at once)
	const concurrency = 1
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, d := range activeDevices {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(device types.Device) {
			defer wg.Done()
			defer func() { <-sem }()

			// Perform targeted port scan
			ports, err := h.scanner.ScanHostPorts(ctx, device.IP, h.cfg.Scanning.PortScanRange)
			if err != nil {
				fmt.Printf("[DEBUG-PORT-SCAN] Failed to scan ports for %s: %v\n", device.IP, err)
			} else {
				// Fetch current device from store to preserve customized fields
				current := h.store.GetDevice(device.IP)
				if current == nil {
					current = &device
				}
				current.OpenPorts = ports

				// Enrich device with open ports (re-classifies types and finds web servers)
				tempDevices := []types.Device{*current}
				scanner.EnrichWithServices(ctx, tempDevices)
				*current = tempDevices[0]
				current.Probed = true

				// Save back to database
				_ = h.store.MergeDevices([]types.Device{*current})
			}

			// Increment completion count
			j.mu.Lock()
			j.portScanComplete++
			if j.portScanComplete >= j.portScanTotal {
				j.portScanActive = false
			}
			j.mu.Unlock()
		}(d)
	}

	wg.Wait()
}
