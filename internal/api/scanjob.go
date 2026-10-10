package api

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/notification"
	"github.com/spoutin/LAN-Orangutan/internal/scanner"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// percentUnknown is reported when a network has never been scanned before and
// there is therefore no timing history to estimate progress from.
const percentUnknown = -1

const (
	scanModeQuick = "quick"
	scanModeDeep  = "deep"
	scanModeBoth  = "both"
)

// scanJob tracks a scan running in the background. Scans of large networks take
// minutes, which is far too long to hold an HTTP request open, so the scan runs
// detached and the UI polls for progress.
type scanJob struct {
	id       string
	networks []string
	cancel   context.CancelFunc
	done     chan struct{}

	mu               sync.RWMutex
	status           string // running, done, cancelled or failed
	currentNetwork   string
	networkIndex     int // 1-based; 0 before the first network starts
	deviceCount      int
	startedAt        time.Time
	networkStartedAt time.Time
	// estimatedSeconds is how long the current network took to scan last time,
	// or 0 when it has never been scanned before.
	estimatedSeconds      float64
	estimatedTotalSeconds float64
	results               []networkScanSummary
	err                   string

	// automatic marks a scan the background scanner started, as opposed to one
	// the user clicked. Set once at creation. The UI uses it to stay quiet for
	// automatic scans instead of popping the progress overlay on its own.
	automatic    bool
	mode         string
	nightlyDeep  bool
	deepNetworks []string
	deepDevices  []types.Device

	// Stage 2 port scanning telemetry
	portScanActive      bool
	portScanTotal       int
	portScanComplete    int
	portScanWG          sync.WaitGroup
	lastPortScanHost    scanHostResult
	portScanStartedAt   time.Time
	deepNetworkProgress []deepNetworkProgress

	accumulatedNew  []string
	accumulatedSeen []string
}

type scanHostResult struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	Network   string `json:"network,omitempty"`
	OpenPorts []int  `json:"open_ports"`
	Error     string `json:"error,omitempty"`
}

type deepNetworkProgress struct {
	Network  string `json:"network"`
	Total    int    `json:"total"`
	Complete int    `json:"complete"`
	Active   int    `json:"active"`
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
	Automatic        bool                  `json:"automatic"`
	Mode             string                `json:"mode"`
	Stage            string                `json:"stage"`
	LastPortScanHost scanHostResult        `json:"last_port_scan_host"`
	DeepNetworks     []deepNetworkProgress `json:"deep_networks"`
	TargetedDeepScan bool                  `json:"targeted_deep_scan"`
	TargetedDeviceIP string                `json:"targeted_device_ip,omitempty"`

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
		Mode:             j.mode,
		LastPortScanHost: j.lastPortScanHost,
		PortScanActive:   j.portScanActive,
		PortScanTotal:    j.portScanTotal,
		PortScanComplete: j.portScanComplete,
		DeepNetworks:     append([]deepNetworkProgress(nil), j.deepNetworkProgress...),
		TargetedDeepScan: len(j.deepDevices) == 1,
	}
	if j.portScanActive || j.mode == scanModeDeep {
		for _, network := range j.deepNetworkProgress {
			if network.Active > 0 {
				p.CurrentNetwork = network.Network
				break
			}
		}
		if p.CurrentNetwork == "" {
			for _, network := range j.deepNetworkProgress {
				if network.Total > network.Complete {
					p.CurrentNetwork = network.Network
					break
				}
			}
		}
	}
	if len(j.deepDevices) == 1 {
		p.TargetedDeviceIP = j.deepDevices[0].IP
	}
	if j.estimatedTotalSeconds > 0 {
		remaining := j.estimatedTotalSeconds - time.Since(j.startedAt).Seconds()
		if remaining < 0 {
			remaining = 0
		}
		p.Remaining = &remaining
	}

	if j.portScanActive || j.mode == scanModeDeep {
		p.Stage = scanModeDeep
		if j.portScanComplete > 0 && !j.portScanStartedAt.IsZero() && j.portScanTotal > j.portScanComplete {
			averagePerHost := time.Since(j.portScanStartedAt).Seconds() / float64(j.portScanComplete)
			remaining := averagePerHost * float64(j.portScanTotal-j.portScanComplete)
			p.Remaining = &remaining
		}
	} else {
		p.Stage = scanModeQuick
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

	return p
}

// startScanJob begins scanning the given networks in the background. The caller
// must hold h.jobMu. automatic marks a scan the background scanner started, so
// the UI can stay quiet for it.
func (h *Handler) startScanJob(networks []string, automatic bool, mode string) *scanJob {
	return h.startScanJobWithDeadline(networks, automatic, mode, time.Time{}, nil, nil)
}

func (h *Handler) startScanJobWithDeadline(networks []string, automatic bool, mode string, deadline time.Time, deepNetworks []string, deepDevices []types.Device) *scanJob {
	// Descend from h.scanCtx (the server's shutdown context) rather than
	// context.Background(), so cancelling it at shutdown cancels a running scan.
	ctx, cancel := context.WithCancel(h.scanCtx)
	if !deadline.IsZero() {
		deadlineCtx, deadlineCancel := context.WithDeadline(ctx, deadline)
		baseCancel := cancel
		ctx = deadlineCtx
		cancel = func() {
			deadlineCancel()
			baseCancel()
		}
	}

	job := &scanJob{
		id:           fmt.Sprintf("scan-%d", time.Now().UnixNano()),
		networks:     networks,
		cancel:       cancel,
		done:         make(chan struct{}),
		status:       "running",
		startedAt:    h.now(),
		results:      make([]networkScanSummary, 0, len(networks)),
		automatic:    automatic,
		mode:         mode,
		nightlyDeep:  !deadline.IsZero(),
		deepNetworks: append([]string(nil), deepNetworks...),
		deepDevices:  append([]types.Device(nil), deepDevices...),
	}
	for _, network := range networks {
		estimate := h.store.GetLastDuration(network)
		if estimate <= 0 {
			estimate = 30
		}
		job.estimatedTotalSeconds += estimate
	}

	h.store.ClearCompletedNetworks()
	h.store.SetCurrentScanningNetwork("")
	if len(deepDevices) != 1 {
		h.store.SetScanRunning(true)
	}

	h.scanWG.Add(1)
	go func() {
		defer h.scanWG.Done()
		defer close(job.done)
		job.run(ctx, h)
	}()
	return job
}

// run scans each network in turn, recording the outcome of each. A network that
// is rate limited or fails does not abort the job, so one bad interface cannot
// hide results from the others.
func (j *scanJob) run(ctx context.Context, h *Handler) {
	activeIPsMap := make(map[string]bool)
	deepTargets := make(map[string][]types.Device)

	defer h.store.SetScanRunning(false)

	defer func() {
		h.store.SetCurrentScanningNetwork("")
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

	if j.mode == scanModeDeep {
		j.runDeepScan(ctx, h)
		if ctx.Err() != nil {
			j.finish("cancelled", "")
		} else {
			j.finish("done", "")
		}
		return
	}

	for i, cidr := range j.networks {
		if ctx.Err() != nil {
			j.finish("cancelled", "")
			return
		}

		j.beginNetwork(cidr, i+1, h.store.GetLastDuration(cidr))
		h.store.SetCurrentScanningNetwork(cidr)

		summary := networkScanSummary{Network: cidr}

		lastScan := h.store.GetLastScan(cidr)
		if canScan, waitTime := h.scanner.CheckRateLimit(lastScan); !canScan {
			summary.Status = "skipped"
			summary.Error = "rate limited, wait " + waitTime.Round(time.Second).String()
			j.addResult(summary, 0)
			h.store.AddCompletedNetwork(cidr)
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
			h.store.AddCompletedNetwork(cidr)
			continue
		}

		summary.Status = "scanned"
		summary.DeviceCount = result.DeviceCount
		summary.Duration = result.Duration
		j.addResult(summary, result.DeviceCount)
		h.store.AddCompletedNetwork(cidr)

		for _, d := range result.Devices {
			if d.IP != "" {
				activeIPsMap[d.IP] = true
			}
		}

		// Stage 2 begins after discovery has covered every requested network, so
		// each result and progress indicator has one unambiguous network context.
		if j.mode == scanModeBoth && h.cfg.Scanning.PortScanRange != "" && (!j.automatic || h.cfg.Scanning.EnablePortScan) {
			shouldPortScan := false
			if !j.automatic {
				// Keep manual scans immediate
				shouldPortScan = true
			} else if !j.nightlyDeep {
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
				deepTargets[cidr] = append(deepTargets[cidr], result.Devices...)
			}
		}
	}

	if j.nightlyDeep && ctx.Err() == nil {
		j.runNightlyDeepScan(ctx, h)
		if ctx.Err() == context.DeadlineExceeded {
			j.finish("cancelled", "nightly deep scan stopped at the 06:00 Eastern cutoff")
			return
		}
	} else if len(deepTargets) > 0 && ctx.Err() == nil {
		j.runDeepQueue(ctx, h, deepTargets)
	} else if ctx.Err() == nil {
		j.runNewDeviceDeepScan(ctx, h)
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

	// UniFi clients discovery
	if ctx.Err() == nil && h.cfg.UniFi.Enable {
		unifiClients, err := scanner.FetchUniFiClients(ctx, h.cfg.UniFi)
		if err == nil {
			newDevs, seenDevs, mergeErr := h.store.MergeUniFiClients(unifiClients)
			if mergeErr != nil {
				fmt.Printf("[DEBUG] UniFi client merge error: %v\n", mergeErr)
			}
			var newIPs, seenIPs []string
			for _, d := range newDevs {
				if d.IP != "" {
					newIPs = append(newIPs, d.IP)
				}
			}
			for _, d := range seenDevs {
				if d.IP != "" {
					seenIPs = append(seenIPs, d.IP)
				}
			}
			if len(newIPs) > 0 || len(seenIPs) > 0 {
				j.accumulate(newIPs, seenIPs)
			}
			for _, d := range unifiClients {
				if d.IP != "" {
					activeIPsMap[d.IP] = true
				}
			}
			j.addResult(networkScanSummary{
				Network:     "UniFi Controller",
				Status:      "scanned",
				DeviceCount: len(unifiClients),
			}, len(unifiClients))
		} else {
			fmt.Printf("UniFi client fetch error: %v\n", err)
		}
	}

	if ctx.Err() == nil && h.cfg.Switches.Enable {
		vlanByMAC := make(map[string]int)
		for _, device := range h.store.GetDevices() {
			if device.MAC != "" {
				vlanByMAC[device.MAC] = device.VLAN
			}
		}
		seenSwitches := make(map[string]struct{}, len(h.cfg.Switches.Names))
		for _, name := range h.cfg.Switches.Names {
			switchCfg, ok := h.cfg.Switches.Configs[name]
			if !ok {
				continue
			}
			if _, seen := seenSwitches[switchCfg.ID]; seen {
				continue
			}
			seenSwitches[switchCfg.ID] = struct{}{}
			if err := switchCfg.Validate(); err != nil {
				fmt.Printf("Switch %s SNMP configuration invalid\n", switchCfg.ID)
				j.addResult(networkScanSummary{Network: switchCfg.ID + " SNMP", Status: "failed", Error: "SNMP configuration invalid"}, 0)
				continue
			}
			connections, err := h.fetchSwitchConnections(ctx, switchCfg, vlanByMAC)
			if err != nil {
				// SNMP failures can include transport details. Keep user-visible
				// summaries and logs credential-safe.
				fmt.Printf("Switch %s SNMP poll failed\n", switchCfg.ID)
				j.addResult(networkScanSummary{Network: switchCfg.ID + " SNMP", Status: "failed", Error: "SNMP polling failed"}, 0)
				continue
			}
			storageConnections := make([]storage.SwitchConnection, len(connections))
			for i, connection := range connections {
				storageConnections[i] = storage.SwitchConnection{
					MAC: connection.MAC, SwitchName: connection.SwitchName, SwitchHost: connection.SwitchHost,
					Port: connection.Port, VLAN: connection.VLAN, LinkState: connection.LinkState,
					LinkSpeed: connection.LinkSpeed, Duplex: connection.Duplex, PoEWatts: connection.PoEWatts,
					UpdatedAt: connection.UpdatedAt,
				}
			}
			if err := h.store.MergeSwitchConnections(storageConnections, switchCfg.ID); err != nil {
				fmt.Printf("Switch %s SNMP merge failed\n", switchCfg.ID)
				j.addResult(networkScanSummary{Network: switchCfg.ID + " SNMP", Status: "failed", Error: "SNMP result storage failed"}, 0)
				continue
			}
			fmt.Printf("Switch %s SNMP resolved %d connections\n", switchCfg.ID, len(connections))
			j.addResult(networkScanSummary{Network: switchCfg.ID + " SNMP", Status: "scanned", DeviceCount: len(connections)}, len(connections))
		}
	}

	if ctx.Err() == nil {
		var activeIPs []string
		for ip := range activeIPsMap {
			activeIPs = append(activeIPs, ip)
		}
		scanInterval := time.Duration(h.cfg.Scanning.ScanInterval) * time.Second
		allNetworks, _ := h.resolveScanTargets("all")
		cycleInterval := scanInterval
		if len(allNetworks) > 1 {
			cycleInterval = time.Duration(len(allNetworks)) * scanInterval
		}
		_, err := h.store.ProcessMissingDevices(j.networks, activeIPs, cycleInterval)
		if err != nil {
			fmt.Printf("[DEBUG] ProcessMissingDevices error: %v\n", err)
		}

		// Dispatch deferred notifications using fully complete, enriched database entries
		j.dispatchDeferredNotifications(h)

		j.finish("done", "")
	} else {
		j.finish("cancelled", "")
	}
}

// runNewDeviceDeepScan immediately profiles only records created by this Stage
// 1 job. Known devices are left for manual or monthly deep scans.
func (j *scanJob) runNewDeviceDeepScan(ctx context.Context, h *Handler) {
	j.mu.RLock()
	newIPs := append([]string(nil), j.accumulatedNew...)
	j.mu.RUnlock()
	if len(newIPs) == 0 {
		return
	}
	targets := make(map[string][]types.Device)
	for _, ip := range newIPs {
		device := h.store.GetDevice(ip)
		if device == nil || !device.IsOnline(time.Duration(h.cfg.Scanning.ScanInterval)*time.Second) {
			continue
		}
		for _, network := range j.networks {
			_, cidr, err := net.ParseCIDR(network)
			if err == nil && cidr.Contains(net.ParseIP(ip)) {
				targets[network] = append(targets[network], *device)
				break
			}
		}
	}
	if len(targets) == 0 {
		return
	}
	// New-device probing is intentionally conservative even outside the nightly window.
	wasNightly := j.nightlyDeep
	j.nightlyDeep = true
	j.runDeepQueue(ctx, h, targets)
	j.nightlyDeep = wasNightly
}

func (j *scanJob) runDeepQueue(ctx context.Context, h *Handler, targetsByNetwork map[string][]types.Device) {
	type deepTarget struct {
		network string
		device  types.Device
	}
	progress := make([]deepNetworkProgress, 0, len(j.networks))
	queue := make([]deepTarget, 0)
	for _, network := range j.networks {
		if targets := targetsByNetwork[network]; len(targets) > 0 {
			progress = append(progress, deepNetworkProgress{Network: network, Total: len(targets)})
			for _, target := range targets {
				queue = append(queue, deepTarget{network: network, device: target})
			}
		}
	}
	if len(progress) == 0 {
		return
	}

	j.mu.Lock()
	j.portScanActive = true
	j.portScanStartedAt = time.Now()
	j.deepNetworkProgress = progress
	for _, network := range progress {
		j.portScanTotal += network.Total
	}
	j.mu.Unlock()

	jobs := make(chan deepTarget)
	var wg sync.WaitGroup
	concurrency := 3
	if j.nightlyDeep {
		concurrency = 1
	}
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				if len(j.deepDevices) != 1 {
					h.store.SetCurrentScanningNetwork(target.network)
				}
				j.scanPortHost(ctx, h, target.network, target.device)
			}
		}()
	}
	for _, target := range queue {
		if ctx.Err() != nil {
			break
		}
		jobs <- target
	}
	close(jobs)
	wg.Wait()

	if len(j.deepDevices) != 1 {
		h.store.SetCurrentScanningNetwork("")
	}

	j.mu.Lock()
	j.portScanActive = false
	j.mu.Unlock()
}

// runNightlyDeepScan builds one shuffled all-network queue. It is separate from
// Stage 1 so staggering discovery does not exclude later networks from Stage 2.
func (j *scanJob) runNightlyDeepScan(ctx context.Context, h *Handler) {
	devices := h.store.GetDevices()
	networks := append([]string(nil), j.deepNetworks...)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(networks), func(i, k int) { networks[i], networks[k] = networks[k], networks[i] })
	targetsByNetwork := make(map[string][]types.Device, len(networks))
	for _, cidr := range networks {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		for _, device := range devices {
			ip := net.ParseIP(device.IP)
			isEligiblePresence := !device.LastSeen.IsZero() && time.Since(device.LastSeen) <= 24*time.Hour
			isEligibleAge := device.LastDeepScanAt.IsZero() || time.Since(device.LastDeepScanAt) >= 30*24*time.Hour
			if ip != nil && network.Contains(ip) && isEligiblePresence && isEligibleAge {
				targetsByNetwork[cidr] = append(targetsByNetwork[cidr], *device)
			}
		}
		rng.Shuffle(len(targetsByNetwork[cidr]), func(i, k int) {
			targetsByNetwork[cidr][i], targetsByNetwork[cidr][k] = targetsByNetwork[cidr][k], targetsByNetwork[cidr][i]
		})
	}
	j.networks = networks
	j.runDeepQueue(ctx, h, targetsByNetwork)
	if ctx.Err() == context.DeadlineExceeded {
		j.notifyNightlyDeepCutoff(h)
	}
}

func (j *scanJob) notifyNightlyDeepCutoff(h *Handler) {
	j.mu.RLock()
	progress := append([]deepNetworkProgress(nil), j.deepNetworkProgress...)
	j.mu.RUnlock()
	for _, network := range progress {
		skipped := network.Total - network.Complete
		if skipped <= 0 {
			continue
		}
		conf, err := h.store.GetNetworkNotification(network.Network)
		if err != nil || conf == nil || !conf.Enabled || conf.SlackWebhook == "" {
			continue
		}
		name := network.Network
		if configured, ok := h.cfg.Scanning.NetworkNames[network.Network]; ok {
			name = configured
		}
		message := notification.FormatDeepScanCutoffSlackMessage(name, network.Network, network.Complete, skipped)
		if err := h.sendSlackNotification(conf.SlackWebhook, message); err != nil {
			fmt.Printf("Nightly deep scan cutoff notification failed for %s: %v\n", network.Network, err)
		}
	}
}

// runDeepScan probes currently online inventory records without rediscovering
// the network. This gives users an explicit Stage 2-only operation.
func (j *scanJob) runDeepScan(ctx context.Context, h *Handler) {
	if len(j.deepDevices) > 0 {
		targets := make(map[string][]types.Device)
		for _, device := range j.deepDevices {
			cidr := findSubnetForIP(device.IP, j.networks)
			if cidr != "" {
				targets[cidr] = append(targets[cidr], device)
			}
		}
		j.runDeepQueue(ctx, h, targets)
		return
	}
	devices := h.store.GetDevices()
	interval := time.Duration(h.cfg.Scanning.ScanInterval) * time.Second
	targetsByNetwork := make(map[string][]types.Device)
	for _, cidr := range j.networks {
		if ctx.Err() != nil {
			return
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			j.addResult(networkScanSummary{Network: cidr, Status: "failed", Error: err.Error()}, 0)
			continue
		}
		var targets []types.Device
		for _, device := range devices {
			ip := net.ParseIP(device.IP)
			if ip != nil && network.Contains(ip) && device.IsOnline(interval) {
				targets = append(targets, *device)
			}
		}
		targetsByNetwork[cidr] = targets
	}
	j.runDeepQueue(ctx, h, targetsByNetwork)
	for i, cidr := range j.networks {
		targets := targetsByNetwork[cidr]
		j.beginNetwork(cidr, i+1, 0)
		j.addResult(networkScanSummary{Network: cidr, Status: "scanned", DeviceCount: len(targets)}, len(targets))
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

// StartBackgroundScanner rotates through detected networks, waiting for one
// automatic scan to complete and then spacing the next one by interval. This
// prevents an all-network sweep from concentrating its connection state at once.
func (h *Handler) StartBackgroundScanner(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}

	go func() {
		startup := time.NewTimer(5 * time.Second)
		defer startup.Stop()
		select {
		case <-ctx.Done():
			return
		case <-startup.C:
		}

		for {
			if !h.store.ContinuousScanEnabled(h.cfg.Scanning.ContinuousScan) {
				if !waitForBackgroundScan(ctx, nil, interval) {
					return
				}
				continue
			}

			networks, err := h.resolveScanTargets("all")
			if err != nil || len(networks) == 0 {
				if !waitForBackgroundScan(ctx, nil, interval) {
					return
				}
				continue
			}
			network, ok := selectOldestScannedNetwork(h.store, networks)
			if !ok {
				continue
			}

			job := h.startBackgroundNetwork(network, networks)
			wasNightlyDeep := job != nil && job.nightlyDeep
			if job != nil && !waitForBackgroundScan(ctx, job.done, interval) {
				return
			}
			if job == nil && !waitForBackgroundScan(ctx, nil, interval) {
				return
			}
			if wasNightlyDeep {
				// The overnight deep scan window has ended. Run an immediate Stage 1
				// discovery sweep across all networks so device presence is fully refreshed.
				allNetworks, err := h.resolveScanTargets("all")
				if err == nil && len(allNetworks) > 0 {
					h.jobMu.Lock()
					if h.job == nil || !h.job.isRunning() {
						sweepJob := h.startScanJob(allNetworks, true, scanModeQuick)
						h.jobMu.Unlock()
						if sweepJob != nil {
							_ = waitForBackgroundScan(ctx, sweepJob.done, 0)
						}
					} else {
						h.jobMu.Unlock()
					}
				}
			}
		}
	}()
}

func (h *Handler) startBackgroundNetwork(network string, allNetworks []string) *scanJob {
	h.jobMu.Lock()
	defer h.jobMu.Unlock()

	if h.job != nil && h.job.isRunning() {
		return nil
	}
	var deadline time.Time
	var deepNetworks []string
	if h.cfg.Scanning.EnablePortScan && h.cfg.Scanning.PortScanRange != "" {
		loc, err := time.LoadLocation("America/New_York")
		if err != nil {
			loc = time.UTC
		}
		now := h.now().In(loc)
		if now.Hour() == 3 {
			date := now.Format("2006-01-02")
			last, _ := h.store.GetSetting("last_deep_scan_date")
			if last != date {
				_ = h.store.SetSetting("last_deep_scan_date", date)
				deadline = time.Date(now.Year(), now.Month(), now.Day(), 6, 0, 0, 0, loc)
				deepNetworks = append([]string(nil), allNetworks...)
			}
		}
	}
	h.job = h.startScanJobWithDeadline([]string{network}, true, scanModeBoth, deadline, deepNetworks, nil)
	return h.job
}

// runBackgroundScan preserves the immediate refresh when continuous scanning is
// enabled from the UI, but starts only the first resolved network. The scheduler
// then continues its normal one-network rotation.
func (h *Handler) runBackgroundScan() {
	if !h.store.ContinuousScanEnabled(h.cfg.Scanning.ContinuousScan) {
		return
	}
	networks, err := h.resolveScanTargets("all")
	if err != nil || len(networks) == 0 {
		return
	}
	network, ok := selectOldestScannedNetwork(h.store, networks)
	if !ok {
		return
	}
	h.startBackgroundNetwork(network, networks)
}

func selectOldestScannedNetwork(store *storage.Storage, networks []string) (string, bool) {
	if len(networks) == 0 {
		return "", false
	}
	oldestNet := networks[0]
	oldestTime := store.GetLastScan(oldestNet)

	for _, n := range networks[1:] {
		t := store.GetLastScan(n)
		if t.IsZero() {
			return n, true
		}
		if oldestTime.IsZero() || t.Before(oldestTime) {
			oldestNet = n
			oldestTime = t
		}
	}
	return oldestNet, true
}

func nextBackgroundNetwork(networks []string, cursor int) (string, int, bool) {
	if len(networks) == 0 {
		return "", 0, false
	}
	if cursor < 0 || cursor >= len(networks) {
		cursor = 0
	}
	return networks[cursor], (cursor + 1) % len(networks), true
}

func waitForBackgroundScan(ctx context.Context, done <-chan struct{}, delay time.Duration) bool {
	if done != nil {
		select {
		case <-ctx.Done():
			return false
		case <-done:
		}
	}
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// startPortScan runs a targeted high-speed port scan on a list of discovered active devices.
func (j *scanJob) startPortScan(ctx context.Context, h *Handler, network string, devices []types.Device) {
	var activeDevices []types.Device
	for _, d := range devices {
		if d.IP != "" {
			activeDevices = append(activeDevices, d)
		}
	}

	if len(activeDevices) == 0 {
		return
	}

	for _, d := range activeDevices {
		if ctx.Err() != nil {
			break
		}
		j.scanPortHost(ctx, h, network, d)
	}
}

func (j *scanJob) scanPortHost(ctx context.Context, h *Handler, network string, device types.Device) {
	j.mu.Lock()
	for i := range j.deepNetworkProgress {
		if j.deepNetworkProgress[i].Network == network {
			j.deepNetworkProgress[i].Active++
			break
		}
	}
	j.mu.Unlock()

	ports, sshPorts, services, err := h.scanner.ScanHostPortsWithTiming(ctx, device.IP, h.cfg.Scanning.PortScanRange, j.nightlyDeep)
	if err != nil {
		fmt.Printf("[DEBUG-PORT-SCAN] Failed to scan ports for %s: %v\n", device.IP, err)
	} else {
		// Fetch current device from store to preserve customized fields
		current := h.store.GetDevice(device.IP)
		if current == nil {
			current = &device
		}
		current.OpenPorts = ports
		current.OpenServices = services
		current.DetectedSSHPort = 0
		if len(sshPorts) > 0 {
			current.DetectedSSHPort = sshPorts[0]
		}
		current.LastSeen = time.Now()

		// Enrich device with open ports (re-classifies types and finds web servers)
		tempDevices := []types.Device{*current}
		scanner.EnrichWithServices(ctx, tempDevices)
		*current = tempDevices[0]
		current.Probed = true

		// Save back to database
		_ = h.store.UpdateDevice(current)
		_ = h.store.UpdateOpenPorts(current.IP, ports, services)
	}

	// Increment completion count
	j.mu.Lock()
	j.portScanComplete++
	for i := range j.deepNetworkProgress {
		if j.deepNetworkProgress[i].Network == network {
			j.deepNetworkProgress[i].Active--
			j.deepNetworkProgress[i].Complete++
			if j.deepNetworkProgress[i].Complete >= j.deepNetworkProgress[i].Total && len(j.deepDevices) != 1 {
				h.store.AddCompletedNetwork(network)
			}
			break
		}
	}
	j.lastPortScanHost = scanHostResult{IP: device.IP, Hostname: device.Hostname, Network: network, OpenPorts: ports}
	if err != nil {
		j.lastPortScanHost.Error = err.Error()
	}
	j.mu.Unlock()
}

// StartBackgroundCleanup runs a daily task to delete history older than a year.
func (h *Handler) StartBackgroundCleanup(ctx context.Context) {
	go func() {
		// Run cleanup shortly after startup
		startup := time.NewTimer(30 * time.Second)
		defer startup.Stop()
		select {
		case <-ctx.Done():
			return
		case <-startup.C:
		}
		h.runCleanup()

		// Run every 24 hours
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.runCleanup()
			}
		}
	}()
}

func (h *Handler) runCleanup() {
	oneYearAgo := time.Now().AddDate(-1, 0, 0)
	deleted, err := h.store.PruneOldHistory(oneYearAgo)
	if err != nil {
		fmt.Printf("[CLEANUP] Failed to prune old history: %v\n", err)
	} else if deleted > 0 {
		fmt.Printf("[CLEANUP] Pruned %d records older than a year\n", deleted)
	}
}

// accumulate appends discovered new and seen device IPs to the scan job
func (j *scanJob) accumulate(newIPs, seenIPs []string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.accumulatedNew = append(j.accumulatedNew, newIPs...)
	j.accumulatedSeen = append(j.accumulatedSeen, seenIPs...)
}

// dispatchDeferredNotifications pulls complete, enriched rows from SQLite and sends the Slack reports
func (j *scanJob) dispatchDeferredNotifications(h *Handler) {
	j.mu.Lock()
	newIPs := j.accumulatedNew
	seenIPs := j.accumulatedSeen
	j.mu.Unlock()

	if len(newIPs) == 0 && len(seenIPs) == 0 {
		return
	}

	newByNetwork := make(map[string][]types.Device)
	seenByNetwork := make(map[string][]types.Device)

	// Pull fully complete, enriched models from storage
	for _, ip := range newIPs {
		d := h.store.GetDevice(ip)
		if d != nil {
			cidr := findSubnetForIP(d.IP, j.networks)
			if cidr != "" {
				newByNetwork[cidr] = append(newByNetwork[cidr], *d)
			}
		}
	}

	for _, ip := range seenIPs {
		d := h.store.GetDevice(ip)
		if d != nil {
			cidr := findSubnetForIP(d.IP, j.networks)
			if cidr != "" {
				seenByNetwork[cidr] = append(seenByNetwork[cidr], *d)
			}
		}
	}

	// Dispatch consolidated notifications for each subnet
	for _, cidr := range j.networks {
		news := newByNetwork[cidr]
		seens := seenByNetwork[cidr]
		if len(news) > 0 || len(seens) > 0 {
			h.dispatchNotifications(cidr, news, seens)
		}
	}
}

// findSubnetForIP returns the network CIDR block that contains the given IP
func findSubnetForIP(ipStr string, subnets []string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	for _, subnetStr := range subnets {
		_, subnet, err := net.ParseCIDR(subnetStr)
		if err == nil && subnet.Contains(ip) {
			return subnetStr
		}
	}
	return ""
}
