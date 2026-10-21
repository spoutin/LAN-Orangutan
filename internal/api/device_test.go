package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/logging"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

func TestDeviceDeepScanStartsOnlyRequestedDevice(t *testing.T) {
	store := newScanJobTestStore(t)
	device := &types.Device{IP: "192.168.1.25", Hostname: "nas"}
	if err := store.UpdateDevice(device); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	cfg := config.Default()
	cfg.Scanning.Networks = []string{"192.168.1.0/24"}
	cfg.Scanning.OnlyConfiguredNetworks = true
	h := NewHandler(store, cfg)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/devices/192.168.1.25/deep-scan", nil)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("deep scan status = %d: %s", rec.Code, rec.Body.String())
	}
	h.jobMu.Lock()
	job := h.job
	h.jobMu.Unlock()
	if job == nil || len(job.deepDevices) != 1 || job.deepDevices[0].IP != device.IP {
		t.Fatalf("deep scan targets = %+v, want only %s", job, device.IP)
	}
	if store.IsScanRunning() {
		t.Fatal("targeted deep scan must not mark general network scan running in store")
	}
	job.cancel()
	<-job.done
}

func TestUpdateDevice_CustomOS(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	dev := types.Device{
		IP:  "192.168.1.150",
		MAC: "aa:bb:cc:dd:ee:55",
	}
	if err := store.UpdateDevice(&dev); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	h := NewHandler(store, config.Default())
	customOS := "OpenWrt 23.05"
	reqBody, _ := json.Marshal(map[string]interface{}{
		"custom_os": customOS,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/devices/192.168.1.150", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	updated := store.GetDevice("192.168.1.150")
	if updated == nil || updated.CustomOS != "OpenWrt 23.05" {
		t.Fatalf("updated device CustomOS = %q, want OpenWrt 23.05", updated.CustomOS)
	}
}

func TestDevice_PUT_UpdateEndpoint(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	dev := types.Device{
		IP:        "192.168.1.100",
		MAC:       "aa:bb:cc:dd:ee:01",
		Hostname:  "test-device",
		Vendor:    "TestVendor",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
	if err := store.UpdateDevice(&dev); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	cfg := config.Default()
	h := NewHandler(store, cfg)

	// Send PUT /api/devices/192.168.1.100
	customHost := "custom-test-box"
	label := "My Office TV"
	customType := "TV"
	notes := "Sidebar notes here"
	customURL := "http://192.168.1.100:8080"
	reqBody, _ := json.Marshal(map[string]interface{}{
		"label":           label,
		"custom_hostname": customHost,
		"custom_type":     customType,
		"notes":           notes,
		"custom_web_url":  customURL,
		"ansible_managed": true,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/devices/192.168.1.100", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/devices/192.168.1.100 status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// Verify updated fields in storage
	updated := store.GetDevice("192.168.1.100")
	if updated == nil {
		t.Fatalf("device 192.168.1.100 not found in store")
	}
	if updated.Label != label {
		t.Errorf("Label = %q, want %q", updated.Label, label)
	}
	if updated.CustomHostname != customHost {
		t.Errorf("CustomHostname = %q, want %q", updated.CustomHostname, customHost)
	}
	if updated.CustomType != customType {
		t.Errorf("CustomType = %q, want %q", updated.CustomType, customType)
	}
	if updated.Notes != notes {
		t.Errorf("Notes = %q, want %q", updated.Notes, notes)
	}
	if updated.CustomWebURL != customURL {
		t.Errorf("CustomWebURL = %q, want %q", updated.CustomWebURL, customURL)
	}
	if !updated.AnsibleManaged {
		t.Errorf("AnsibleManaged = false, want true")
	}
}

func TestLogs_APIEndpoint(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	cfg := config.Default()
	h := NewHandler(store, cfg)

	logging.GlobalBuffer.Add("info", "test normal info log")
	logging.GlobalBuffer.Add("error", "service scan failed for 10.5.5.143: connection refused")

	req := httptest.NewRequest(http.MethodGet, "/api/logs?q=10.5.5.143", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp struct {
		Success bool               `json:"success"`
		Data    []logging.LogEntry `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Success {
		t.Fatal("expected success: true")
	}
	if len(resp.Data) == 0 {
		t.Fatal("expected at least 1 log entry matching 10.5.5.143")
	}
	if !strings.Contains(resp.Data[0].Message, "10.5.5.143") {
		t.Errorf("expected message containing 10.5.5.143, got %q", resp.Data[0].Message)
	}
}
