package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/scanner"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

func TestTrafficCollector_ComputeRate(t *testing.T) {
	tc := NewTrafficCollector(nil, nil)
	t0 := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	mac := "00:11:22:33:44:55"

	// 1. Initial call sets baseline, returns 0 rate
	rxRate, txRate := tc.ComputeRate(mac, 1000000, 500000, t0)
	if rxRate != 0 || txRate != 0 {
		t.Fatalf("expected initial rate 0/0, got %d/%d", rxRate, txRate)
	}

	// 2. Call 60 seconds later with +600,000 bytes Rx and +120,000 bytes Tx
	t1 := t0.Add(60 * time.Second)
	rxRate, txRate = tc.ComputeRate(mac, 1600000, 620000, t1)
	if rxRate != 10000 { // 600000 / 60 = 10000
		t.Errorf("expected rxRate 10000, got %d", rxRate)
	}
	if txRate != 2000 { // 120000 / 60 = 2000
		t.Errorf("expected txRate 2000, got %d", txRate)
	}

	// 3. Counter reset (e.g. switch reboot, current < prev)
	t2 := t1.Add(60 * time.Second)
	rxRate, txRate = tc.ComputeRate(mac, 50000, 10000, t2)
	if rxRate != 0 || txRate != 0 {
		t.Errorf("expected 0/0 on counter reset, got %d/%d", rxRate, txRate)
	}
}

func TestTrafficCollector_CollectCycle(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	defer store.Close()

	// Seed devices
	devWired := types.Device{IP: "10.0.0.10", MAC: "aa:bb:cc:11:22:01", Hostname: "wired-pc"}
	devWireless := types.Device{IP: "10.0.0.20", MAC: "aa:bb:cc:11:22:02", Hostname: "phone"}
	devRouted := types.Device{IP: "10.0.0.30", MAC: "aa:bb:cc:11:22:03", Hostname: "iot-device"}
	if err := store.UpdateDevice(&devWired); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateDevice(&devWireless); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateDevice(&devRouted); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Switches: config.SwitchesConfig{
			Enable: true,
			Configs: map[string]config.SwitchConfig{
				"switchy": {ID: "switchy", Host: "10.0.0.2"},
			},
		},
		UniFi: config.UniFiConfig{
			Enable: true,
			URL:    "https://unifi.local",
		},
		OPNsense: config.OPNsenseConfig{
			Enable:   true,
			URL:      "https://opnsense.local",
			Networks: []string{"10.0.0.0/24"},
		},
	}

	tc := NewTrafficCollector(store, cfg)
	t0 := time.Now()

	// Mock switch fetch
	fetchSwitch := func(_ context.Context, _ config.SwitchConfig, _ map[string]int) ([]scanner.SwitchConnection, error) {
		return []scanner.SwitchConnection{
			{
				MAC:       "aa:bb:cc:11:22:01",
				Port:      "gi1/1",
				InOctets:  500000,
				OutOctets: 2000000,
				SingleMAC: true,
			},
		}, nil
	}

	// Mock UniFi fetch
	fetchUniFi := func(_ context.Context, _ config.UniFiConfig) ([]types.Device, error) {
		return []types.Device{
			{
				MAC:     "aa:bb:cc:11:22:02",
				RxBytes: 800000,
				TxBytes: 150000,
			},
		}, nil
	}

	// Mock OPNsense fetch
	fetchNetFlow := func(_ context.Context, _ config.OPNsenseConfig) (map[string]*types.NetFlowDeviceStats, error) {
		return map[string]*types.NetFlowDeviceStats{
			"10.0.0.30": {
				IP:      "10.0.0.30",
				RxBytes: 400000,
				TxBytes: 90000,
			},
		}, nil
	}

	// Cycle 1: Baseline
	samples1, err := tc.CollectCycle(context.Background(), t0, fetchSwitch, fetchUniFi, fetchNetFlow, nil)
	if err != nil {
		t.Fatalf("CollectCycle 1 failed: %v", err)
	}
	if len(samples1) != 3 {
		t.Fatalf("expected 3 samples, got %d", len(samples1))
	}

	// Cycle 2: 60 seconds later
	t1 := t0.Add(60 * time.Second)
	fetchSwitch2 := func(_ context.Context, _ config.SwitchConfig, _ map[string]int) ([]scanner.SwitchConnection, error) {
		return []scanner.SwitchConnection{
			{
				MAC:       "aa:bb:cc:11:22:01",
				Port:      "gi1/1",
				InOctets:  500000 + 120000,  // +2000 B/s Tx
				OutOctets: 2000000 + 600000, // +10000 B/s Rx
				SingleMAC: true,
			},
		}, nil
	}

	samples2, err := tc.CollectCycle(context.Background(), t1, fetchSwitch2, fetchUniFi, fetchNetFlow, nil)
	if err != nil {
		t.Fatalf("CollectCycle 2 failed: %v", err)
	}

	byMAC := make(map[string]types.TrafficSample)
	for _, s := range samples2 {
		byMAC[s.MAC] = s
	}

	sWired := byMAC["aa:bb:cc:11:22:01"]
	if sWired.Source != "switch" {
		t.Errorf("expected source 'switch', got %s", sWired.Source)
	}
	if sWired.RxRate != 10000 || sWired.TxRate != 2000 {
		t.Errorf("expected wired rates 10000/2000, got %d/%d", sWired.RxRate, sWired.TxRate)
	}

	// Verify query from store
	series, err := store.GetDeviceTrafficSeries("aa:bb:cc:11:22:01", "1h")
	if err != nil {
		t.Fatalf("GetDeviceTrafficSeries failed: %v", err)
	}
	if len(series.Series) != 2 {
		t.Errorf("expected 2 series points in store, got %d", len(series.Series))
	}
}

func TestDeviceTrafficAPI(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	defer store.Close()

	dev := types.Device{
		IP:            "10.0.0.55",
		MAC:           "00:11:22:33:44:55",
		Hostname:      "my-desktop",
		TrafficSource: "switch",
		RxRateBps:     12000,
		TxRateBps:     3000,
		RxBytes:       5000000,
		TxBytes:       1000000,
	}
	if err := store.UpdateDevice(&dev); err != nil {
		t.Fatal(err)
	}

	// Insert samples
	now := time.Now()
	_ = store.RecordTrafficSamples([]types.TrafficSample{
		{
			MAC:       "00:11:22:33:44:55",
			Timestamp: now.Add(-10 * time.Minute),
			RxBytes:   4000000,
			TxBytes:   800000,
			RxRate:    10000,
			TxRate:    2000,
			Source:    "switch",
		},
		{
			MAC:       "00:11:22:33:44:55",
			Timestamp: now,
			RxBytes:   5000000,
			TxBytes:   1000000,
			RxRate:    12000,
			TxRate:    3000,
			Source:    "switch",
		},
	})

	cfg := config.Default()
	h := NewHandler(store, cfg)

	// 1. Query by MAC
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/devices/00:11:22:33:44:55/traffic?range=1h", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp types.APIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected success=true, got error: %s", resp.Error)
	}

	// 2. Query by IP
	recIP := httptest.NewRecorder()
	reqIP := httptest.NewRequest("GET", "/api/devices/10.0.0.55/traffic?range=24h", nil)
	h.ServeHTTP(recIP, reqIP)
	if recIP.Code != http.StatusOK {
		t.Fatalf("expected status 200 by IP, got %d: %s", recIP.Code, recIP.Body.String())
	}

	// 3. Verify WAN stats sanitization for devices outside OPNsense networks
	cfg.OPNsense.Networks = []string{"192.168.1.0/24"} // does not include 10.0.0.55
	recSanitized := httptest.NewRecorder()
	reqSanitized := httptest.NewRequest("GET", "/api/devices/00:11:22:33:44:55/traffic?range=1h", nil)
	h.ServeHTTP(recSanitized, reqSanitized)
	var respSanitized struct {
		Success bool                        `json:"success"`
		Data    types.DeviceTrafficResponse `json:"data"`
	}
	if err := json.Unmarshal(recSanitized.Body.Bytes(), &respSanitized); err != nil {
		t.Fatalf("failed to decode sanitized response: %v", err)
	}
	if respSanitized.Data.Current.WanRxRateBytesSec != 0 || respSanitized.Data.Current.WanTxRateBytesSec != 0 {
		t.Errorf("expected 0 WAN rates for device outside OPNsense network, got %d/%d",
			respSanitized.Data.Current.WanRxRateBytesSec, respSanitized.Data.Current.WanTxRateBytesSec)
	}
}

func TestTrafficCollector_DualLinkAndWANTraffic(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	defer store.Close()

	dev := types.Device{IP: "10.0.0.50", MAC: "aa:bb:cc:55:66:77", Hostname: "dual-host"}
	if err := store.UpdateDevice(&dev); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Switches: config.SwitchesConfig{
			Enable: true,
			Configs: map[string]config.SwitchConfig{
				"switchy": {ID: "switchy", Host: "10.0.0.2"},
			},
		},
		OPNsense: config.OPNsenseConfig{
			Enable:   true,
			URL:      "https://opnsense.local",
			Networks: []string{"10.0.0.0/24"},
		},
	}
	tc := NewTrafficCollector(store, cfg)
	t0 := time.Now()

	fetchSwitch := func(_ context.Context, _ config.SwitchConfig, _ map[string]int) ([]scanner.SwitchConnection, error) {
		return []scanner.SwitchConnection{
			{
				MAC:       "aa:bb:cc:55:66:77",
				Port:      "gi1/5",
				InOctets:  1000000,
				OutOctets: 5000000,
				SingleMAC: true,
			},
		}, nil
	}
	fetchNetFlow := func(_ context.Context, _ config.OPNsenseConfig) (map[string]*types.NetFlowDeviceStats, error) {
		return map[string]*types.NetFlowDeviceStats{
			"10.0.0.50": {
				IP:      "10.0.0.50",
				RxBytes: 2000000,
				TxBytes: 300000,
			},
		}, nil
	}

	// Baseline
	_, err = tc.CollectCycle(context.Background(), t0, fetchSwitch, nil, fetchNetFlow, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Second sample 60s later
	t1 := t0.Add(60 * time.Second)
	fetchSwitch2 := func(_ context.Context, _ config.SwitchConfig, _ map[string]int) ([]scanner.SwitchConnection, error) {
		return []scanner.SwitchConnection{
			{
				MAC:       "aa:bb:cc:55:66:77",
				Port:      "gi1/5",
				InOctets:  1000000 + 60000,  // +1000 B/s Tx
				OutOctets: 5000000 + 300000, // +5000 B/s Rx
				SingleMAC: true,
			},
		}, nil
	}
	fetchNetFlow2 := func(_ context.Context, _ config.OPNsenseConfig) (map[string]*types.NetFlowDeviceStats, error) {
		return map[string]*types.NetFlowDeviceStats{
			"10.0.0.50": {
				IP:      "10.0.0.50",
				RxBytes: 2000000 + 120000, // +2000 B/s WAN Rx
				TxBytes: 300000 + 30000,   // +500 B/s WAN Tx
			},
		}, nil
	}

	_, err = tc.CollectCycle(context.Background(), t1, fetchSwitch2, nil, fetchNetFlow2, nil)
	if err != nil {
		t.Fatal(err)
	}

	storedDev := store.GetDevice("10.0.0.50")
	if storedDev == nil {
		t.Fatal("device not found in store")
	}

	// Verify both Link and WAN metrics exist on the device
	if storedDev.TrafficSource != "switch" {
		t.Errorf("expected TrafficSource 'switch', got %s", storedDev.TrafficSource)
	}
	if storedDev.RxRateBps != 5000 || storedDev.TxRateBps != 1000 {
		t.Errorf("expected link rates 5000/1000, got %d/%d", storedDev.RxRateBps, storedDev.TxRateBps)
	}
	if storedDev.WanRxRateBps != 2000 || storedDev.WanTxRateBps != 500 {
		t.Errorf("expected WAN rates 2000/500, got %d/%d", storedDev.WanRxRateBps, storedDev.WanTxRateBps)
	}
	if storedDev.WanRxBytes != 2120000 || storedDev.WanTxBytes != 330000 {
		t.Errorf("expected WAN bytes 2120000/330000, got %d/%d", storedDev.WanRxBytes, storedDev.WanTxBytes)
	}
}

func TestTrafficCollector_OPNsenseNetworkFiltering(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	defer store.Close()

	devInside := types.Device{IP: "10.0.0.50", MAC: "aa:bb:cc:00:11:01", Hostname: "inside-dev"}
	devOutside := types.Device{IP: "192.168.1.99", MAC: "aa:bb:cc:00:11:02", Hostname: "outside-dev"}
	if err := store.UpdateDevice(&devInside); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateDevice(&devOutside); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		OPNsense: config.OPNsenseConfig{
			Enable:   true,
			URL:      "https://opnsense.local",
			Networks: []string{"10.0.0.0/24"},
		},
	}
	tc := NewTrafficCollector(store, cfg)
	now := time.Now()

	fetchNetFlow := func(_ context.Context, _ config.OPNsenseConfig) (map[string]*types.NetFlowDeviceStats, error) {
		return map[string]*types.NetFlowDeviceStats{
			"10.0.0.50": {
				IP:      "10.0.0.50",
				RxBytes: 1500000,
				TxBytes: 250000,
			},
			"192.168.1.99": {
				IP:      "192.168.1.99",
				RxBytes: 3000000,
				TxBytes: 500000,
			},
		}, nil
	}

	samples, err := tc.CollectCycle(context.Background(), now, nil, nil, fetchNetFlow, nil)
	if err != nil {
		t.Fatalf("CollectCycle failed: %v", err)
	}

	// Only devInside should be collected
	if len(samples) != 1 {
		t.Fatalf("expected 1 sample, got %d: %+v", len(samples), samples)
	}
	if samples[0].MAC != "aa:bb:cc:00:11:01" {
		t.Errorf("sample MAC = %q, want aa:bb:cc:00:11:01", samples[0].MAC)
	}

	storedInside := store.GetDevice("10.0.0.50")
	if storedInside == nil || storedInside.WanRxBytes != 1500000 {
		t.Errorf("inside device WAN rx bytes = %v, want 1500000", storedInside)
	}

	storedOutside := store.GetDevice("192.168.1.99")
	if storedOutside == nil {
		t.Fatal("outside device not found")
	}
	if storedOutside.WanRxBytes != 0 || storedOutside.WanTxBytes != 0 || storedOutside.WanRxRateBps != 0 || storedOutside.WanTxRateBps != 0 {
		t.Errorf("outside device should have 0 WAN stats, got RxBytes=%d TxBytes=%d", storedOutside.WanRxBytes, storedOutside.WanTxBytes)
	}

	// Test with no OPNsense networks configured: zero devices should be tracked
	cfg.OPNsense.Networks = nil
	tc2 := NewTrafficCollector(store, cfg)
	samples2, err := tc2.CollectCycle(context.Background(), now.Add(time.Minute), nil, nil, fetchNetFlow, nil)
	if err != nil {
		t.Fatalf("CollectCycle with empty networks failed: %v", err)
	}
	if len(samples2) != 0 {
		t.Errorf("expected 0 samples when OPNsense.Networks is empty, got %d", len(samples2))
	}
}

func TestTrafficCollector_OpenWrtNlbwmon(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	defer store.Close()

	devInside := types.Device{IP: "10.5.5.10", MAC: "aa:bb:cc:55:00:01", Hostname: "inside-wrt"}
	devOutside := types.Device{IP: "192.168.1.50", MAC: "aa:bb:cc:55:00:02", Hostname: "outside-wrt"}
	if err := store.UpdateDevice(&devInside); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateDevice(&devOutside); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.OpenWrt = config.OpenWrtConfig{
		ID:                "wrt-main",
		Enable:            true,
		TrafficMonitoring: true,
		Networks:          []string{"10.5.5.0/24"},
	}
	tc := NewTrafficCollector(store, cfg)
	t0 := time.Now()

	fetchNlbwmon := func(_ context.Context, _ config.OpenWrtConfig) (map[string]*types.NetFlowDeviceStats, error) {
		return map[string]*types.NetFlowDeviceStats{
			"10.5.5.10": {
				IP:      "10.5.5.10",
				RxBytes: 1000000,
				TxBytes: 200000,
			},
			"192.168.1.50": {
				IP:      "192.168.1.50",
				RxBytes: 5000000,
				TxBytes: 800000,
			},
		}, nil
	}

	// 1. Initial cycle: Baseline
	samples1, err := tc.CollectCycle(context.Background(), t0, nil, nil, nil, fetchNlbwmon)
	if err != nil {
		t.Fatalf("CollectCycle baseline failed: %v", err)
	}

	// Only devInside should be collected (devOutside is outside 10.5.5.0/24)
	if len(samples1) != 1 {
		t.Fatalf("expected 1 sample, got %d: %+v", len(samples1), samples1)
	}
	if samples1[0].MAC != "aa:bb:cc:55:00:01" {
		t.Errorf("sample MAC = %q, want aa:bb:cc:55:00:01", samples1[0].MAC)
	}
	if samples1[0].Source != "openwrt" {
		t.Errorf("sample Source = %q, want openwrt", samples1[0].Source)
	}

	// 2. Second cycle 60s later: Rate calculation verification
	t1 := t0.Add(60 * time.Second)
	fetchNlbwmon2 := func(_ context.Context, _ config.OpenWrtConfig) (map[string]*types.NetFlowDeviceStats, error) {
		return map[string]*types.NetFlowDeviceStats{
			"10.5.5.10": {
				IP:      "10.5.5.10",
				RxBytes: 1000000 + 120000, // +2000 B/s Rx
				TxBytes: 200000 + 30000,   // +500 B/s Tx
			},
			"192.168.1.50": {
				IP:      "192.168.1.50",
				RxBytes: 6000000,
				TxBytes: 900000,
			},
		}, nil
	}

	samples2, err := tc.CollectCycle(context.Background(), t1, nil, nil, nil, fetchNlbwmon2)
	if err != nil {
		t.Fatalf("CollectCycle cycle 2 failed: %v", err)
	}
	if len(samples2) != 1 {
		t.Fatalf("expected 1 sample in cycle 2, got %d", len(samples2))
	}
	s := samples2[0]
	if s.Source != "openwrt" {
		t.Errorf("expected source 'openwrt', got %s", s.Source)
	}
	if s.RxRate != 2000 || s.TxRate != 500 {
		t.Errorf("expected WAN rates 2000/500, got %d/%d", s.RxRate, s.TxRate)
	}

	// Verify store state
	storedInside := store.GetDevice("10.5.5.10")
	if storedInside == nil {
		t.Fatal("inside device not found in store")
	}
	if storedInside.WanRxBytes != 1120000 || storedInside.WanTxBytes != 230000 {
		t.Errorf("expected WAN bytes 1120000/230000, got %d/%d", storedInside.WanRxBytes, storedInside.WanTxBytes)
	}
	if storedInside.WanRxRateBps != 2000 || storedInside.WanTxRateBps != 500 {
		t.Errorf("expected WAN rate 2000/500, got %d/%d", storedInside.WanRxRateBps, storedInside.WanTxRateBps)
	}

	storedOutside := store.GetDevice("192.168.1.50")
	if storedOutside == nil {
		t.Fatal("outside device not found in store")
	}
	if storedOutside.WanRxBytes != 0 || storedOutside.WanTxBytes != 0 || storedOutside.WanRxRateBps != 0 || storedOutside.WanTxRateBps != 0 {
		t.Errorf("outside device should have 0 WAN stats, got RxBytes=%d TxBytes=%d", storedOutside.WanRxBytes, storedOutside.WanTxBytes)
	}

	// 3. When TrafficMonitoring: false, no collection occurs
	cfg.OpenWrt.TrafficMonitoring = false
	samples3, err := tc.CollectCycle(context.Background(), t1.Add(60*time.Second), nil, nil, nil, fetchNlbwmon2)
	if err != nil {
		t.Fatalf("CollectCycle with TrafficMonitoring: false failed: %v", err)
	}
	if len(samples3) != 0 {
		t.Errorf("expected 0 samples when TrafficMonitoring is false, got %d", len(samples3))
	}
}

func TestTrafficCollector_FirewallSubnetMutualExclusion(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	defer store.Close()

	devOpn := types.Device{IP: "10.0.0.50", MAC: "aa:bb:cc:00:00:01", Hostname: "opn-host"}
	devWrt := types.Device{IP: "10.5.5.50", MAC: "aa:bb:cc:00:00:02", Hostname: "wrt-host"}
	if err := store.UpdateDevice(&devOpn); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateDevice(&devWrt); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.OPNsense = config.OPNsenseConfig{
		Enable:   true,
		URL:      "https://opnsense.local",
		Networks: []string{"10.0.0.0/24"},
	}
	cfg.OpenWrt = config.OpenWrtConfig{
		ID:                "wrt",
		Enable:            true,
		TrafficMonitoring: true,
		URL:               "https://10.5.5.1",
		Networks:          []string{"10.5.5.0/24"},
	}

	tc := NewTrafficCollector(store, cfg)
	now := time.Now()

	// Both routers report flows for BOTH IPs (simulating cross-chatter)
	fetchNetFlow := func(_ context.Context, _ config.OPNsenseConfig) (map[string]*types.NetFlowDeviceStats, error) {
		return map[string]*types.NetFlowDeviceStats{
			"10.0.0.50": {IP: "10.0.0.50", RxBytes: 1000, TxBytes: 500},
			"10.5.5.50": {IP: "10.5.5.50", RxBytes: 9999, TxBytes: 9999}, // should be rejected by OPNsense collector
		}, nil
	}
	fetchNlbwmon := func(_ context.Context, _ config.OpenWrtConfig) (map[string]*types.NetFlowDeviceStats, error) {
		return map[string]*types.NetFlowDeviceStats{
			"10.0.0.50": {IP: "10.0.0.50", RxBytes: 8888, TxBytes: 8888}, // should be rejected by OpenWrt collector
			"10.5.5.50": {IP: "10.5.5.50", RxBytes: 2000, TxBytes: 1000},
		}, nil
	}

	samples, err := tc.CollectCycle(context.Background(), now, nil, nil, fetchNetFlow, fetchNlbwmon)
	if err != nil {
		t.Fatalf("CollectCycle failed: %v", err)
	}

	if len(samples) != 2 {
		t.Fatalf("expected exactly 2 samples, got %d: %+v", len(samples), samples)
	}

	for _, s := range samples {
		if s.MAC == "aa:bb:cc:00:00:01" {
			if s.Source != "opnsense" || s.RxBytes != 1000 {
				t.Errorf("expected opnsense source with 1000 bytes for opn host, got %+v", s)
			}
		} else if s.MAC == "aa:bb:cc:00:00:02" {
			if s.Source != "openwrt" || s.RxBytes != 2000 {
				t.Errorf("expected openwrt source with 2000 bytes for wrt host, got %+v", s)
			}
		}
	}
}
