package api

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/logging"
	"github.com/spoutin/LAN-Orangutan/internal/network"
	"github.com/spoutin/LAN-Orangutan/internal/scanner"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

const (
	maxTrafficPrevAge           = 24 * time.Hour
	maxTrafficPrevEntries       = 10000
	defaultTrafficSourceTimeout = 10 * time.Second
	defaultTrafficCycleTimeout  = 50 * time.Second
)

type prevOctets struct {
	timestamp time.Time
	rxBytes   int64
	txBytes   int64
}

// TrafficCollector manages periodic polling of switch port octets, UniFi telemetry,
// and OPNsense NetFlow to calculate instantaneous bandwidth and record rolling samples.
type TrafficCollector struct {
	store         *storage.Storage
	cfg           *config.Config
	sourceTimeout time.Duration
	mu            sync.Mutex
	prev          map[string]prevOctets
}

// NewTrafficCollector creates a new TrafficCollector.
func NewTrafficCollector(store *storage.Storage, cfg *config.Config) *TrafficCollector {
	return &TrafficCollector{
		store:         store,
		cfg:           cfg,
		sourceTimeout: defaultTrafficSourceTimeout,
		prev:          make(map[string]prevOctets),
	}
}

func clampUint64ToInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

func (tc *TrafficCollector) withSourceTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := tc.sourceTimeout
	if timeout <= 0 {
		timeout = defaultTrafficSourceTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

func (tc *TrafficCollector) evictOldestPrevLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for key, entry := range tc.prev {
		if first || entry.timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.timestamp
			first = false
		}
	}
	if !first {
		delete(tc.prev, oldestKey)
	}
}

func (tc *TrafficCollector) prunePrev(now time.Time) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	cutoff := now.Add(-maxTrafficPrevAge)
	for key, entry := range tc.prev {
		if entry.timestamp.Before(cutoff) {
			delete(tc.prev, key)
		}
	}
	for len(tc.prev) > maxTrafficPrevEntries {
		tc.evictOldestPrevLocked()
	}
}

// ComputeRate computes the instantaneous rx and tx bytes/sec given previous sample.
func (tc *TrafficCollector) ComputeRate(mac string, rxBytes, txBytes int64, now time.Time) (int64, int64) {
	normMAC := storage.NormalizeMAC(mac)
	if normMAC == "" {
		return 0, 0
	}
	if rxBytes < 0 {
		rxBytes = 0
	}
	if txBytes < 0 {
		txBytes = 0
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()

	prev, exists := tc.prev[normMAC]
	if !exists && len(tc.prev) >= maxTrafficPrevEntries {
		tc.evictOldestPrevLocked()
	}
	tc.prev[normMAC] = prevOctets{
		timestamp: now,
		rxBytes:   rxBytes,
		txBytes:   txBytes,
	}

	if !exists || prev.timestamp.IsZero() {
		return 0, 0
	}

	deltaSec := now.Sub(prev.timestamp).Seconds()
	if deltaSec <= 0.05 {
		return 0, 0
	}

	var rxRate, txRate int64
	rxDelta := rxBytes - prev.rxBytes
	if rxDelta >= 0 {
		rxRate = int64(float64(rxDelta) / deltaSec)
	}

	txDelta := txBytes - prev.txBytes
	if txDelta >= 0 {
		txRate = int64(float64(txDelta) / deltaSec)
	}

	return rxRate, txRate
}

// CollectCycle executes one data collection cycle across Switch, UniFi, OPNsense, and OpenWrt.
func (tc *TrafficCollector) CollectCycle(
	ctx context.Context,
	now time.Time,
	fetchSwitch func(context.Context, config.SwitchConfig, map[string]int) ([]scanner.SwitchConnection, error),
	fetchUniFi func(context.Context, config.UniFiConfig) ([]types.Device, error),
	fetchNetFlow func(context.Context, config.OPNsenseConfig) (map[string]*types.NetFlowDeviceStats, error),
	fetchNlbwmon func(context.Context, config.OpenWrtConfig) (map[string]*types.NetFlowDeviceStats, error),
) ([]types.TrafficSample, error) {
	var samples []types.TrafficSample
	seenMACs := make(map[string]bool)
	tc.prunePrev(now)

	// 1. Cisco Switch (SNMPv3 64-bit Port Octets)
	if tc.cfg.Switches.Enable && len(tc.cfg.Switches.Configs) > 0 && fetchSwitch != nil {
		devices := tc.store.GetDevices()
		vlanByMAC := make(map[string]int, len(devices))
		for _, dev := range devices {
			normMAC := storage.NormalizeMAC(dev.MAC)
			if normMAC == "" {
				continue
			}
			vlan := dev.SwitchVLAN
			if vlan <= 0 {
				vlan = dev.VLAN
			}
			vlanByMAC[normMAC] = vlan
		}

		for _, switchCfg := range tc.cfg.Switches.Configs {
			if ctx.Err() != nil {
				break
			}
			srcCtx, srcCancel := tc.withSourceTimeout(ctx)
			conns, err := fetchSwitch(srcCtx, switchCfg, vlanByMAC)
			srcCancel()
			if err != nil {
				continue
			}
			for _, c := range conns {
				// Only attribute traffic directly if port is dedicated to a single MAC
				if !c.SingleMAC || (c.InOctets == 0 && c.OutOctets == 0) {
					continue
				}
				normMAC := storage.NormalizeMAC(c.MAC)
				if normMAC == "" {
					continue
				}

				// Switch port Out is Device Rx (bytes sent by switch to device)
				// Switch port In is Device Tx (bytes received by switch from device)
				rxBytes := clampUint64ToInt64(c.OutOctets)
				txBytes := clampUint64ToInt64(c.InOctets)
				rxRate, txRate := tc.ComputeRate(normMAC, rxBytes, txBytes, now)

				samples = append(samples, types.TrafficSample{
					MAC:       normMAC,
					Timestamp: now,
					RxBytes:   rxBytes,
					TxBytes:   txBytes,
					RxRate:    rxRate,
					TxRate:    txRate,
					Source:    "switch",
				})
				seenMACs[normMAC] = true
			}
		}
	}

	// 2. UniFi Controller (Station Telemetry for Wireless Devices)
	if tc.cfg.UniFi.Enable && tc.cfg.UniFi.URL != "" && fetchUniFi != nil && ctx.Err() == nil {
		srcCtx, srcCancel := tc.withSourceTimeout(ctx)
		clients, err := fetchUniFi(srcCtx, tc.cfg.UniFi)
		srcCancel()
		if err == nil {
			for _, c := range clients {
				normMAC := storage.NormalizeMAC(c.MAC)
				if normMAC == "" || seenMACs[normMAC] {
					continue
				}
				if c.RxBytes == 0 && c.TxBytes == 0 {
					continue
				}

				rxRate, txRate := tc.ComputeRate(normMAC, c.RxBytes, c.TxBytes, now)
				samples = append(samples, types.TrafficSample{
					MAC:       normMAC,
					Timestamp: now,
					RxBytes:   c.RxBytes,
					TxBytes:   c.TxBytes,
					RxRate:    rxRate,
					TxRate:    txRate,
					Source:    "unifi",
				})
				seenMACs[normMAC] = true
			}
		}
	}

	// 3. OPNsense Firewall (NetFlow / Active States for Routed Traffic)
	// Only collect WAN traffic for devices residing on the firewall's strictly configured networks.
	if tc.cfg.OPNsense.Enable && tc.cfg.OPNsense.URL != "" && len(tc.cfg.OPNsense.Networks) > 0 && fetchNetFlow != nil && ctx.Err() == nil {
		srcCtx, srcCancel := tc.withSourceTimeout(ctx)
		flowStats, err := fetchNetFlow(srcCtx, tc.cfg.OPNsense)
		srcCancel()
		if err != nil {
			logging.GlobalBuffer.Add("warn", fmt.Sprintf("[traffic] OPNsense NetFlow query failed: %v", err))
		} else {
			matchedHosts := 0
			for ip, st := range flowStats {
				dev := tc.store.GetDevice(ip)
				if dev == nil || dev.MAC == "" {
					continue
				}
				if !network.ContainsIP(tc.cfg.OPNsense.Networks, dev.IP) {
					continue
				}
				// Skip if the device resides on an enabled OpenWrt network
				isOnOpenWrt := false
				for _, wrt := range tc.cfg.AllOpenWrts() {
					if wrt.Enable && wrt.TrafficMonitoring && len(wrt.Networks) > 0 && network.ContainsIP(wrt.Networks, dev.IP) {
						isOnOpenWrt = true
						break
					}
				}
				if isOnOpenWrt {
					continue
				}
				normMAC := storage.NormalizeMAC(dev.MAC)
				if normMAC == "" || (st.RxBytes == 0 && st.TxBytes == 0) {
					continue
				}

				wanRateKey := normMAC + ":wan"
				rxRate, txRate := tc.ComputeRate(wanRateKey, st.RxBytes, st.TxBytes, now)
				samples = append(samples, types.TrafficSample{
					MAC:       normMAC,
					Timestamp: now,
					RxBytes:   st.RxBytes,
					TxBytes:   st.TxBytes,
					RxRate:    rxRate,
					TxRate:    txRate,
					Source:    "opnsense",
				})
				matchedHosts++
			}
			logging.GlobalBuffer.Add("info", fmt.Sprintf("[traffic] OPNsense NetFlow: collected flows for %d hosts (%d active in inventory on firewall networks)", len(flowStats), matchedHosts))
		}
	}

	// 4. OpenWrt Firewall (nlbwmon Bandwidth Monitor)
	if fetchNlbwmon != nil && ctx.Err() == nil {
		for _, wrt := range tc.cfg.AllOpenWrts() {
			if ctx.Err() != nil {
				break
			}
			if !wrt.Enable || !wrt.TrafficMonitoring || len(wrt.Networks) == 0 {
				continue
			}
			srcCtx, srcCancel := tc.withSourceTimeout(ctx)
			flowStats, err := fetchNlbwmon(srcCtx, wrt)
			srcCancel()
			if err != nil {
				logging.GlobalBuffer.Add("warn", fmt.Sprintf("[traffic] OpenWrt (%s) nlbwmon query failed: %v", wrt.ID, err))
				continue
			}
			matchedHosts := 0
			for ip, st := range flowStats {
				dev := tc.store.GetDevice(ip)
				if dev == nil || dev.MAC == "" {
					continue
				}
				if !network.ContainsIP(wrt.Networks, dev.IP) {
					continue
				}
				// Skip if the device resides on an enabled OPNsense network
				if tc.cfg.OPNsense.Enable && len(tc.cfg.OPNsense.Networks) > 0 && network.ContainsIP(tc.cfg.OPNsense.Networks, dev.IP) {
					continue
				}
				normMAC := storage.NormalizeMAC(dev.MAC)
				if normMAC == "" || (st.RxBytes == 0 && st.TxBytes == 0) {
					continue
				}
				wanRateKey := normMAC + ":wan"
				rxRate, txRate := tc.ComputeRate(wanRateKey, st.RxBytes, st.TxBytes, now)
				samples = append(samples, types.TrafficSample{
					MAC:       normMAC,
					Timestamp: now,
					RxBytes:   st.RxBytes,
					TxBytes:   st.TxBytes,
					RxRate:    rxRate,
					TxRate:    txRate,
					Source:    "openwrt",
				})
				matchedHosts++
			}
			logging.GlobalBuffer.Add("info", fmt.Sprintf("[traffic] OpenWrt (%s) nlbwmon: collected flows for %d hosts (%d active on firewall networks)", wrt.ID, len(flowStats), matchedHosts))
		}
	}

	if len(samples) > 0 {
		if err := tc.store.RecordTrafficSamples(samples); err != nil {
			return samples, fmt.Errorf("failed to persist traffic samples: %w", err)
		}
	}

	return samples, nil
}

// StartTrafficCollector launches the periodic 60-second telemetry poller and 1-hour rollup pruner.
func (h *Handler) StartTrafficCollector(ctx context.Context) {
	if h.trafficCollector == nil {
		h.trafficCollector = NewTrafficCollector(h.store, h.cfg)
	}

	runCtx, cancel := h.bgContext(ctx)
	h.bgWG.Add(1)
	go func() {
		defer h.bgWG.Done()
		defer cancel()

		// Run initial collection shortly after startup
		initTimer := time.NewTimer(2 * time.Second)
		select {
		case <-runCtx.Done():
			initTimer.Stop()
			return
		case <-initTimer.C:
		}

		h.runTrafficCycle(runCtx)

		ticker := time.NewTicker(60 * time.Second)
		pruneTicker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		defer pruneTicker.Stop()

		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				h.runTrafficCycle(runCtx)
			case <-pruneTicker.C:
				_, _ = h.store.RollupAndPruneTraffic(24, 7)
			}
		}
	}()
}

func (h *Handler) runTrafficCycle(ctx context.Context) {
	cycleCtx, cancel := context.WithTimeout(ctx, defaultTrafficCycleTimeout)
	defer cancel()

	_, _ = h.trafficCollector.CollectCycle(
		cycleCtx,
		time.Now(),
		h.fetchSwitchConnections,
		h.fetchUniFiClients,
		h.fetchOPNsenseNetFlow,
		h.fetchOpenWrtNlbwmon,
	)
}
