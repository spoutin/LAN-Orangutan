package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
)

func TestScanProgressReportsLastDeepScanHost(t *testing.T) {
	job := &scanJob{
		status:           "running",
		startedAt:        time.Now().Add(-10 * time.Second),
		networks:         []string{"192.168.1.0/24"},
		mode:             scanModeDeep,
		portScanActive:   true,
		portScanTotal:    4,
		portScanComplete: 2,
		lastPortScanHost: scanHostResult{IP: "192.168.1.25", Hostname: "nas", OpenPorts: []int{22, 443}},
	}

	progress := job.snapshot(config.Default(), nil)
	if progress.Stage != "deep" {
		t.Errorf("Stage = %q, want deep", progress.Stage)
	}
	if progress.LastPortScanHost.IP != "192.168.1.25" || len(progress.LastPortScanHost.OpenPorts) != 2 {
		t.Errorf("LastPortScanHost = %+v, want completed NAS scan", progress.LastPortScanHost)
	}
}

func TestScanProgressUsesTotalJobETA(t *testing.T) {
	job := &scanJob{
		status:                "running",
		startedAt:             time.Now().Add(-10 * time.Second),
		networks:              []string{"192.168.1.0/24", "10.0.0.0/24"},
		mode:                  scanModeQuick,
		networkIndex:          1,
		networkStartedAt:      time.Now().Add(-10 * time.Second),
		estimatedTotalSeconds: 90,
	}

	progress := job.snapshot(config.Default(), nil)
	if progress.Remaining == nil {
		t.Fatal("Remaining = nil, want total job estimate")
	}
	if *progress.Remaining < 78 || *progress.Remaining > 82 {
		t.Errorf("Remaining = %.1f, want about 80 seconds for the full job", *progress.Remaining)
	}
}

func TestScanStartRejectsUnknownMode(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "devices.json"), filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	h := NewHandler(store, config.Default())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/scan/start?network=all&mode=invalid", nil)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/scan/start invalid mode status = %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}
