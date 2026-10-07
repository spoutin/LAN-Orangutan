package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
)

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
