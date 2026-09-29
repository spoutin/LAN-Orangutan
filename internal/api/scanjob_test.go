package api

import (
	"context"
	"errors"
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

func TestScanJob_SwitchesPollSequentiallyAndPropagateKnownVLAN(t *testing.T) {
	store := newScanJobTestStore(t)
	if err := store.UpdateDevice(&types.Device{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", VLAN: 30}); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	cfg := switchTestConfig("edge-a", "edge-b")
	h := NewHandler(store, cfg)
	var calls []string
	h.fetchSwitchConnections = func(_ context.Context, switchCfg config.SwitchConfig, vlanByMAC map[string]int) ([]scanner.SwitchConnection, error) {
		calls = append(calls, switchCfg.ID)
		if got := vlanByMAC["AA:BB:CC:DD:EE:01"]; got != 30 {
			t.Fatalf("vlanByMAC for known device = %d, want 30", got)
		}
		return []scanner.SwitchConnection{{MAC: "aa:bb:cc:dd:ee:01", SwitchName: switchCfg.ID, SwitchHost: switchCfg.Host, Port: "gi1/10", VLAN: 30}}, nil
	}

	job := runSwitchScanJob(t, h)
	if got, want := calls, []string{"edge-a", "edge-b"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("switch calls = %v, want %v", got, want)
	}
	for _, name := range []string{"edge-a", "edge-b"} {
		summary := switchSummary(t, job, name+" SNMP")
		if summary.Status != "scanned" || summary.DeviceCount != 1 {
			t.Errorf("%s summary = %+v, want scanned with one connection", name, summary)
		}
	}
	if device := store.GetDevice("192.168.1.10"); device == nil || device.SwitchName != "edge-b" || device.SwitchPort != "gi1/10" {
		t.Errorf("stored switch telemetry = %+v, want edge-b gi1/10", device)
	}
}

func TestScanJob_SwitchesResolveUnknownVLANInventoryMACThroughBridgeFDB(t *testing.T) {
	store := newScanJobTestStore(t)
	if err := store.UpdateDevice(&types.Device{IP: "192.168.1.11", MAC: "AA:BB:CC:DD:EE:02"}); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	cfg := switchTestConfig("edge-a")
	h := NewHandler(store, cfg)
	h.fetchSwitchConnections = func(_ context.Context, switchCfg config.SwitchConfig, vlanByMAC map[string]int) ([]scanner.SwitchConnection, error) {
		vlan, ok := vlanByMAC["AA:BB:CC:DD:EE:02"]
		if !ok || vlan != 0 {
			t.Fatalf("vlanByMAC = %v, want unknown-VLAN inventory MAC", vlanByMAC)
		}
		// This represents the resolver's unambiguous standard BRIDGE FDB match.
		return []scanner.SwitchConnection{{MAC: "aa:bb:cc:dd:ee:02", SwitchName: switchCfg.ID, SwitchHost: switchCfg.Host, Port: "gi1/11", VLAN: 0}}, nil
	}

	job := runSwitchScanJob(t, h)
	if summary := switchSummary(t, job, "edge-a SNMP"); summary.Status != "scanned" || summary.DeviceCount != 1 {
		t.Errorf("switch summary = %+v, want one resolved connection", summary)
	}
	if device := store.GetDevice("192.168.1.11"); device == nil || device.SwitchPort != "gi1/11" || device.SwitchVLAN != 0 {
		t.Errorf("stored switch telemetry = %+v, want standard BRIDGE FDB result", device)
	}
}

func TestScanJob_SwitchesIgnoreDuplicateConfiguredNames(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := switchTestConfig("switchy", "switchy", "core")
	h := NewHandler(store, cfg)
	var calls []string
	h.fetchSwitchConnections = func(_ context.Context, switchCfg config.SwitchConfig, _ map[string]int) ([]scanner.SwitchConnection, error) {
		calls = append(calls, switchCfg.ID)
		return nil, nil
	}

	job := runSwitchScanJob(t, h)
	if got, want := calls, []string{"switchy", "core"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("switch calls = %v, want %v", got, want)
	}
	if got := countSwitchSummaries(job, "switchy SNMP"); got != 1 {
		t.Errorf("switchy summary count = %d, want 1", got)
	}
	if got := countSwitchSummaries(job, "core SNMP"); got != 1 {
		t.Errorf("core summary count = %d, want 1", got)
	}
}

func TestScanJob_SwitchesIgnoreAliasesWithSameID(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := switchTestConfig("primary", "alias")
	cfg.Switches.Configs["primary"] = validSwitchConfig("switchy", "switchy.example.test")
	cfg.Switches.Configs["alias"] = validSwitchConfig("switchy", "switchy.example.test")
	h := NewHandler(store, cfg)
	calls := 0
	h.fetchSwitchConnections = func(_ context.Context, switchCfg config.SwitchConfig, _ map[string]int) ([]scanner.SwitchConnection, error) {
		calls++
		if switchCfg.ID != "switchy" {
			t.Fatalf("fetched switch ID = %q, want switchy", switchCfg.ID)
		}
		return nil, nil
	}

	job := runSwitchScanJob(t, h)
	if calls != 1 {
		t.Errorf("switch fetch calls = %d, want 1", calls)
	}
	if got := countSwitchSummaries(job, "switchy SNMP"); got != 1 {
		t.Errorf("switchy summary count = %d, want 1", got)
	}
}

func TestScanJob_SwitchFailureIsIsolated(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := switchTestConfig("unreachable", "edge-b")
	h := NewHandler(store, cfg)
	var calls []string
	h.fetchSwitchConnections = func(_ context.Context, switchCfg config.SwitchConfig, _ map[string]int) ([]scanner.SwitchConnection, error) {
		calls = append(calls, switchCfg.ID)
		if switchCfg.ID == "unreachable" {
			return nil, errors.New("authentication password leaked")
		}
		return nil, nil
	}

	job := runSwitchScanJob(t, h)
	if got, want := calls, []string{"unreachable", "edge-b"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("switch calls = %v, want %v", got, want)
	}
	failed := switchSummary(t, job, "unreachable SNMP")
	if failed.Status != "failed" || failed.Error == "" || failed.Error == "authentication password leaked" {
		t.Errorf("failed summary = %+v, want sanitized error", failed)
	}
	if success := switchSummary(t, job, "edge-b SNMP"); success.Status != "scanned" {
		t.Errorf("edge-b summary = %+v, want scanned", success)
	}
}

func TestScanJob_InvalidSwitchIsIsolated(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := switchTestConfig("invalid", "edge-b")
	cfg.Switches.Configs["invalid"] = config.SwitchConfig{ID: "invalid"}
	h := NewHandler(store, cfg)
	var calls []string
	h.fetchSwitchConnections = func(_ context.Context, switchCfg config.SwitchConfig, _ map[string]int) ([]scanner.SwitchConnection, error) {
		calls = append(calls, switchCfg.ID)
		return nil, nil
	}

	job := runSwitchScanJob(t, h)
	if len(calls) != 1 || calls[0] != "edge-b" {
		t.Fatalf("switch calls = %v, want only edge-b", calls)
	}
	if failed := switchSummary(t, job, "invalid SNMP"); failed.Status != "failed" {
		t.Errorf("invalid switch summary = %+v, want failed", failed)
	}
	if got := countSwitchSummaries(job, "invalid SNMP"); got != 1 {
		t.Errorf("invalid switch summary count = %d, want 1", got)
	}
	if success := switchSummary(t, job, "edge-b SNMP"); success.Status != "scanned" {
		t.Errorf("edge-b summary = %+v, want scanned", success)
	}
}

func TestScanJob_SwitchesDisabledDoesNotPoll(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := switchTestConfig("edge-a")
	cfg.Switches.Enable = false
	h := NewHandler(store, cfg)
	calls := 0
	h.fetchSwitchConnections = func(context.Context, config.SwitchConfig, map[string]int) ([]scanner.SwitchConnection, error) {
		calls++
		return nil, nil
	}

	job := runSwitchScanJob(t, h)
	if calls != 0 {
		t.Errorf("switch fetch calls = %d, want 0", calls)
	}
	for _, result := range job.results {
		if result.Network == "edge-a SNMP" {
			t.Errorf("disabled switch should not create a summary: %+v", result)
		}
	}
}

func newScanJobTestStore(t *testing.T) *storage.Storage {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "devices.json"), filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	return store
}

func switchTestConfig(names ...string) *config.Config {
	cfg := config.Default()
	cfg.OpenWrt.Enable = false
	cfg.OPNsense.Enable = false
	cfg.UniFi.Enable = false
	cfg.Switches.Enable = true
	cfg.Switches.Names = names
	cfg.Switches.Configs = make(map[string]config.SwitchConfig, len(names))
	for _, name := range names {
		cfg.Switches.Configs[name] = validSwitchConfig(name, name+".example.test")
	}
	return cfg
}

func validSwitchConfig(id, host string) config.SwitchConfig {
	return config.SwitchConfig{ID: id, Host: host, Port: 161, Version: 3, Username: "monitor", SecurityLevel: "authPriv", AuthProtocol: "SHA", AuthPassword: "auth-secret", PrivacyProtocol: "AES", PrivacyPassword: "privacy-secret", TimeoutSeconds: 5}
}

func runSwitchScanJob(t *testing.T, h *Handler) *scanJob {
	t.Helper()
	job := &scanJob{id: "switch-test", startedAt: time.Now(), status: "running"}
	job.run(context.Background(), h)
	return job
}

func switchSummary(t *testing.T, job *scanJob, network string) networkScanSummary {
	t.Helper()
	job.mu.RLock()
	defer job.mu.RUnlock()
	for _, result := range job.results {
		if result.Network == network {
			return result
		}
	}
	t.Fatalf("missing %s summary in %+v", network, job.results)
	return networkScanSummary{}
}

func countSwitchSummaries(job *scanJob, network string) int {
	job.mu.RLock()
	defer job.mu.RUnlock()
	count := 0
	for _, result := range job.results {
		if result.Network == network {
			count++
		}
	}
	return count
}

func TestScanJob_UniFiIntegration(t *testing.T) {
	// Mock UniFi OS Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/proxy/network/api/s/default/stat/device":
			_, _ = w.Write([]byte(`{
				"meta": {"rc": "ok"},
				"data": [
					{"mac": "00:11:22:33:44:00", "name": "Office AP", "model": "U6-Pro"}
				]
			}`))
		case "/proxy/network/api/s/default/stat/sta":
			_, _ = w.Write([]byte(`{
				"meta": {"rc": "ok"},
				"data": [
					{
						"mac": "aa:bb:cc:dd:ee:01",
						"vlan": 42,
						"ip": "192.168.1.150",
						"hostname": "test-workstation",
						"essid": "Corp-WiFi",
						"ap_mac": "00:11:22:33:44:00",
						"radio": "na",
						"channel": 44,
						"radio_proto": "ax",
						"signal": -55,
						"rx_rate": 1201000,
						"tx_rate": 1201000,
						"rx_bytes": 100000,
						"tx_bytes": 50000,
						"uptime": 1800,
						"model": "Workstation"
					}
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	store, err := storage.New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	cfg := config.Default()
	cfg.UniFi.Enable = true
	cfg.UniFi.URL = server.URL
	cfg.UniFi.Site = "default"
	cfg.UniFi.APIKey = "test-token"
	cfg.OpenWrt.Enable = false
	cfg.OPNsense.Enable = false
	cfg.Switches.Enable = true
	cfg.Switches.Names = []string{"edge"}
	cfg.Switches.Configs["edge"] = validSwitchConfig("edge", "edge.example.test")

	h := NewHandler(store, cfg)
	fetches := 0
	h.fetchSwitchConnections = func(_ context.Context, switchCfg config.SwitchConfig, vlanByMAC map[string]int) ([]scanner.SwitchConnection, error) {
		fetches++
		if switchCfg.ID != "edge" {
			t.Fatalf("switch ID = %q, want edge", switchCfg.ID)
		}
		if got := vlanByMAC["aa:bb:cc:dd:ee:01"]; got != 42 {
			t.Fatalf("UniFi VLAN passed to switch fetcher = %d, want 42", got)
		}
		return nil, nil
	}

	job := &scanJob{
		id:        "test-job-1",
		networks:  []string{},
		startedAt: time.Now(),
		status:    "running",
	}

	job.run(context.Background(), h)

	// Verify device merged into storage
	dev := store.GetDevice("192.168.1.150")
	if dev == nil {
		t.Fatalf("expected device 192.168.1.150 to be merged, got nil")
	}
	if dev.SSID != "Corp-WiFi" {
		t.Errorf("dev.SSID = %q, want %q", dev.SSID, "Corp-WiFi")
	}
	if dev.VLAN != 42 {
		t.Errorf("dev.VLAN = %d, want 42", dev.VLAN)
	}
	if fetches != 1 {
		t.Errorf("switch fetches = %d, want 1", fetches)
	}
	if dev.APName != "Office AP" {
		t.Errorf("dev.APName = %q, want %q", dev.APName, "Office AP")
	}
	if dev.Signal != -55 {
		t.Errorf("dev.Signal = %d, want %d", dev.Signal, -55)
	}
	if dev.AssociationUptime != 1800 {
		t.Errorf("dev.AssociationUptime = %d, want %d", dev.AssociationUptime, 1800)
	}
	if dev.Assignment != "Discovered" {
		t.Errorf("dev.Assignment = %q, want %q", dev.Assignment, "Discovered")
	}

	// Verify scan results recorded
	job.mu.RLock()
	results := job.results
	job.mu.RUnlock()

	foundUniFi := false
	for _, res := range results {
		if res.Network == "UniFi Controller" {
			foundUniFi = true
			if res.Status != "scanned" {
				t.Errorf("UniFi summary status = %q, want %q", res.Status, "scanned")
			}
			if res.DeviceCount != 1 {
				t.Errorf("UniFi summary DeviceCount = %d, want 1", res.DeviceCount)
			}
		}
	}
	if !foundUniFi {
		t.Errorf("expected UniFi Controller summary in job results, got: %+v", results)
	}

	// Verify deferred notifications accumulated new device
	job.mu.RLock()
	accumNew := job.accumulatedNew
	job.mu.RUnlock()
	if len(accumNew) != 1 || accumNew[0] != "192.168.1.150" {
		t.Errorf("expected accumulatedNew to contain 192.168.1.150, got %v", accumNew)
	}
}

func TestScanJob_UniFiErrorGraceful(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	dir := t.TempDir()
	store, err := storage.New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	cfg := config.Default()
	cfg.UniFi.Enable = true
	cfg.UniFi.URL = server.URL
	cfg.UniFi.Site = "default"
	cfg.UniFi.APIKey = "test-token"
	cfg.OpenWrt.Enable = false
	cfg.OPNsense.Enable = false

	h := NewHandler(store, cfg)

	job := &scanJob{
		id:        "test-job-err",
		networks:  []string{},
		startedAt: time.Now(),
		status:    "running",
	}

	// Should not panic or crash
	job.run(context.Background(), h)

	job.mu.RLock()
	status := job.status
	job.mu.RUnlock()

	if status != "done" {
		t.Errorf("job status = %q, want %q", status, "done")
	}
}

func TestScanJob_UniFiSeenNotification(t *testing.T) {
	// Mock UniFi OS Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/proxy/network/api/s/default/stat/device":
			_, _ = w.Write([]byte(`{"meta": {"rc": "ok"}, "data": []}`))
		case "/proxy/network/api/s/default/stat/sta":
			_, _ = w.Write([]byte(`{
				"meta": {"rc": "ok"},
				"data": [
					{
						"mac": "aa:bb:cc:dd:ee:99",
						"ip": "192.168.1.99",
						"hostname": "returning-device",
						"essid": "Corp-WiFi"
					}
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	store, err := storage.New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	// Pre-insert device as offline with NotifyOnSeen: true
	existingDev := &types.Device{
		IP:           "192.168.1.99",
		MAC:          "AA:BB:CC:DD:EE:99",
		Hostname:     "returning-device",
		NotifyOnSeen: true,
	}
	if err := store.UpdateDevice(existingDev); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	// Force it offline in DB
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	_, err = store.GetDB().Exec("UPDATE devices SET is_online = 0, last_presence_change = ? WHERE ip = ?", twoHoursAgo, "192.168.1.99")
	if err != nil {
		t.Fatalf("force offline: %v", err)
	}

	cfg := config.Default()
	cfg.UniFi.Enable = true
	cfg.UniFi.URL = server.URL
	cfg.UniFi.Site = "default"
	cfg.UniFi.APIKey = "test-token"
	cfg.OpenWrt.Enable = false
	cfg.OPNsense.Enable = false

	h := NewHandler(store, cfg)

	job := &scanJob{
		id:        "test-job-seen",
		networks:  []string{},
		startedAt: time.Now(),
		status:    "running",
	}

	job.run(context.Background(), h)

	job.mu.RLock()
	accumSeen := job.accumulatedSeen
	job.mu.RUnlock()

	if len(accumSeen) != 1 || accumSeen[0] != "192.168.1.99" {
		t.Errorf("expected accumulatedSeen to contain 192.168.1.99, got %v", accumSeen)
	}
}
