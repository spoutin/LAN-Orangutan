package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
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

func TestDevice_POST_FactsEndpoint(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	dev := types.Device{
		IP:  "192.168.1.100",
		MAC: "aa:bb:cc:dd:ee:01",
	}
	if err := store.UpdateDevice(&dev); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	h := NewHandler(store, config.Default())

	// 1. Post facts with valid MAC format
	reqBody, _ := json.Marshal(map[string]interface{}{
		"os":         "Ubuntu",
		"os_version": "24.04.1 LTS",
		"os_family":  "Linux",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/devices/aa-bb-cc-dd-ee-01/facts", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/devices/{mac}/facts status = %d: %s", rec.Code, rec.Body.String())
	}

	updated := store.GetDevice("192.168.1.100")
	if updated == nil {
		t.Fatal("device not found after update")
	}
	if updated.CustomOS != "Ubuntu" || updated.CustomOSVersion != "24.04.1 LTS" || updated.CustomOSFamily != "Linux" {
		t.Errorf("CustomOS fields = %q / %q / %q, want Ubuntu / 24.04.1 LTS / Linux",
			updated.CustomOS, updated.CustomOSVersion, updated.CustomOSFamily)
	}

	// 2. Post facts for non-existent MAC
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/devices/00:00:00:00:00:00/facts", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown MAC, got %d", rec.Code)
	}

	// 3. Post facts by IP address for routed L3 host without MAC, including MAC in body
	routedDev := types.Device{
		IP:  "10.10.10.50",
		MAC: "",
	}
	if err := store.UpdateDevice(&routedDev); err != nil {
		t.Fatalf("UpdateDevice routed: %v", err)
	}

	routedBody, _ := json.Marshal(map[string]interface{}{
		"os":         "Red Hat Enterprise Linux",
		"os_version": "9.4",
		"os_family":  "Linux",
		"mac":        "00:50:56:a1:b2:c3", // VMware MAC
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/devices/10.10.10.50/facts", bytes.NewReader(routedBody))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/devices/{ip}/facts status = %d: %s", rec.Code, rec.Body.String())
	}

	updatedRouted := store.GetDevice("10.10.10.50")
	if updatedRouted == nil {
		t.Fatal("routed device not found")
	}
	if updatedRouted.CustomOS != "Red Hat Enterprise Linux" || updatedRouted.CustomOSVersion != "9.4" || updatedRouted.CustomOSFamily != "Linux" {
		t.Errorf("routed CustomOS = %q / %q / %q, want RHEL / 9.4 / Linux",
			updatedRouted.CustomOS, updatedRouted.CustomOSVersion, updatedRouted.CustomOSFamily)
	}
	if updatedRouted.MAC != "00:50:56:a1:b2:c3" {
		t.Errorf("routed MAC = %q, want 00:50:56:a1:b2:c3", updatedRouted.MAC)
	}
	if updatedRouted.Vendor != "VMware, Inc." && updatedRouted.Vendor != "VMware" {
		t.Logf("routed Vendor = %q", updatedRouted.Vendor)
	}

	// 4. Update MAC and custom OS fields via PUT /api/devices/{ip}
	putBody, _ := json.Marshal(map[string]interface{}{
		"mac":               "00:1c:42:11:22:33", // Parallels MAC
		"custom_os":         "Debian",
		"custom_os_version": "12.5",
		"custom_os_family":  "Linux",
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/api/devices/10.10.10.50", bytes.NewReader(putBody))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/devices/{ip} status = %d: %s", rec.Code, rec.Body.String())
	}

	updatedPut := store.GetDevice("10.10.10.50")
	if updatedPut == nil {
		t.Fatal("device not found after PUT")
	}
	if updatedPut.MAC != "00:1c:42:11:22:33" {
		t.Errorf("PUT updated MAC = %q, want 00:1c:42:11:22:33", updatedPut.MAC)
	}
	if updatedPut.CustomOS != "Debian" || updatedPut.CustomOSVersion != "12.5" || updatedPut.CustomOSFamily != "Linux" {
		t.Errorf("PUT CustomOS = %q / %q / %q, want Debian / 12.5 / Linux",
			updatedPut.CustomOS, updatedPut.CustomOSVersion, updatedPut.CustomOSFamily)
	}
}

func TestAPITokensEndpoints(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	h := NewHandler(store, config.Default())

	// 1. Create a token
	createBody, _ := json.Marshal(map[string]string{
		"name": "Ansible CI",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/tokens status = %d: %s", rec.Code, rec.Body.String())
	}

	var createResp struct {
		Success bool `json:"success"`
		Data    struct {
			ID          int64  `json:"id"`
			Name        string `json:"name"`
			TokenPrefix string `json:"token_prefix"`
			Token       string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("unmarshal createResp: %v", err)
	}
	if !strings.HasPrefix(createResp.Data.Token, "ora_") {
		t.Errorf("expected token to start with ora_, got %q", createResp.Data.Token)
	}
	if createResp.Data.Name != "Ansible CI" {
		t.Errorf("expected name Ansible CI, got %q", createResp.Data.Name)
	}

	// 2. List tokens
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/tokens", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/tokens status = %d: %s", rec.Code, rec.Body.String())
	}

	var listResp struct {
		Success bool `json:"success"`
		Data    []struct {
			ID          int64  `json:"id"`
			Name        string `json:"name"`
			TokenPrefix string `json:"token_prefix"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal listResp: %v", err)
	}
	if len(listResp.Data) != 1 || listResp.Data[0].ID != createResp.Data.ID {
		t.Fatalf("expected 1 token with ID %d, got %+v", createResp.Data.ID, listResp.Data)
	}

	// 3. Delete token
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/tokens/"+strconv.FormatInt(createResp.Data.ID, 10), nil)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /api/tokens status = %d: %s", rec.Code, rec.Body.String())
	}

	// Verify list is empty
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/tokens", nil)
	h.ServeHTTP(rec, req)
	_ = json.Unmarshal(rec.Body.Bytes(), &listResp)
	if len(listResp.Data) != 0 {
		t.Fatalf("expected 0 tokens, got %d", len(listResp.Data))
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
