package api

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/logging"
	"github.com/spoutin/LAN-Orangutan/internal/network"
	"github.com/spoutin/LAN-Orangutan/internal/scanner"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

type prevOctets struct {
	timestamp time.Time
	rxBytes   int64
	txBytes   int64
}

// TrafficCollector manages periodic polling of switch port octets, UniFi telemetry,
// and OPNsense NetFlow to calculate instantaneous bandwidth and record rolling samples.
type TrafficCollector struct {
	store *storage.Storage
	cfg   *config.Config
	mu    sync.Mutex
	prev  map[string]prevOctets
}

// NewTrafficCollector creates a new TrafficCollector.
func NewTrafficCollector(store *storage.Storage, cfg *config.Config) *TrafficCollector {
	return &TrafficCollector{
		store: store,
		cfg:   cfg,
		prev:  make(map[string]prevOctets),
	}
}

// ComputeRate computes the instantaneous rx and tx bytes/sec given previous sample.
func (tc *TrafficCollector) ComputeRate(mac string, rxBytes, txBytes int64, now time.Time) (int64, int64) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	normMAC := strings.ToLower(strings.TrimSpace(mac))
	prev, exists := tc.prev[normMAC]
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

	// 1. Cisco Switch (SNMPv3 64-bit Port Octets)
	if tc.cfg.Switches.Enable && len(tc.cfg.Switches.Configs) > 0 && fetchSwitch != nil {
		devices := tc.store.GetDevices()
		vlanByMAC := make(map[string]int, len(devices))
		for _, dev := range devices {
			if dev.MAC != "" && dev.SwitchVLAN > 0 {
				vlanByMAC[strings.ToLower(dev.MAC)] = dev.SwitchVLAN
			}
		}

		for _, switchCfg := range tc.cfg.Switches.Configs {
			if ctx.Err() != nil {
				break
			}
			conns, err := fetchSwitch(ctx, switchCfg, vlanByMAC)
			if err != nil {
				continue
			}
			for _, c := range conns {
				// Only attribute traffic directly if port is dedicated to a single MAC
				if !c.SingleMAC || (c.InOctets == 0 && c.OutOctets == 0) {
					continue
				}
				normMAC := strings.ToLower(strings.TrimSpace(c.MAC))
				if normMAC == "" {
					continue
				}

				// Switch port Out is Device Rx (bytes sent by switch to device)
				// Switch port In is Device Tx (bytes received by switch from device)
				rxBytes := int64(c.OutOctets)
				txBytes := int64(c.InOctets)
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
		clients, err := fetchUniFi(ctx, tc.cfg.UniFi)
		if err == nil {
			for _, c := range clients {
				normMAC := strings.ToLower(strings.TrimSpace(c.MAC))
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
		flowStats, err := fetchNetFlow(ctx, tc.cfg.OPNsense)
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
				normMAC := strings.ToLower(strings.TrimSpace(dev.MAC))
				if st.RxBytes == 0 && st.TxBytes == 0 {
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
			if !wrt.Enable || !wrt.Nlbwmon || len(wrt.Networks) == 0 {
				continue
			}
			flowStats, err := fetchNlbwmon(ctx, wrt)
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
				normMAC := strings.ToLower(strings.TrimSpace(dev.MAC))
				if st.RxBytes == 0 && st.TxBytes == 0 {
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

	go func() {
		// Run initial collection shortly after startup
		initTimer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			initTimer.Stop()
			return
		case <-initTimer.C:
		}

		h.runTrafficCycle(ctx)

		ticker := time.NewTicker(60 * time.Second)
		pruneTicker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		defer pruneTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.runTrafficCycle(ctx)
			case <-pruneTicker.C:
				_, _ = h.store.RollupAndPruneTraffic(24, 7)
			}
		}
	}()
}

func (h *Handler) runTrafficCycle(ctx context.Context) {
	cycleCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	_, _ = h.trafficCollector.CollectCycle(
		cycleCtx,
		time.Now(),
		h.fetchSwitchConnections,
		h.fetchUniFiClients,
		h.fetchOPNsenseNetFlow,
		scanner.FetchOpenWrtNlbwmon,
	)
}
