package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
)

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

	h := NewHandler(store, cfg)

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

