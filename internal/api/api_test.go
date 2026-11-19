package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/logging"
	"github.com/spoutin/LAN-Orangutan/internal/remotescan"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

func TestCSRFProtectionRejectsContentTypeBypass(t *testing.T) {
	store := newScanJobTestStore(t)
	h := newTestHandler(t, store, config.Default())

	cases := []struct {
		name           string
		contentType    string
		xRequestedWith string
		wantCode       int
	}{
		{"text/plain smuggling application/json", "text/plain; charset=application/json", "", http.StatusForbidden},
		{"text/plain alone", "text/plain", "", http.StatusForbidden},
		{"empty headers", "", "", http.StatusForbidden},
		{"form urlencoded", "application/x-www-form-urlencoded", "", http.StatusForbidden},
		{"valid application/json", "application/json", "", http.StatusOK},
		{"valid application/json with charset", "Application/JSON; charset=utf-8", "", http.StatusOK},
		{"valid X-Requested-With", "text/plain", "XMLHttpRequest", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/devices/clear", strings.NewReader(`{}`))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			if tc.xRequestedWith != "" {
				req.Header.Set("X-Requested-With", tc.xRequestedWith)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantCode, rec.Body.String())
			}
		})
	}
}

func TestHandleScanRequiresPOST(t *testing.T) {
	store := newScanJobTestStore(t)
	h := newTestHandler(t, store, config.Default())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/scan?network=192.168.1.0/24", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/scan status = %d, want 405: %s", rec.Code, rec.Body.String())
	}

	// POST without CSRF headers must be blocked.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/scan?network=192.168.1.0/24", nil)
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("POST /api/scan without CSRF headers status = %d, want 403", rec2.Code)
	}
}

func TestDevicesCSVNeutralizesFormulaPrefixes(t *testing.T) {
	store := newScanJobTestStore(t)
	now := time.Now()
	evil := types.Device{
		IP:        "192.168.1.50",
		MAC:       "aa:bb:cc:dd:ee:01",
		Hostname:  "=CMD|'/C calc'!A0",
		Vendor:    "\t=1+1",
		Label:     "+SUM(1,1)",
		Notes:     "-2+3",
		Group:     "@evil",
		FirstSeen: now,
		LastSeen:  now,
	}
	normal := types.Device{
		IP:        "192.168.1.51",
		MAC:       "aa:bb:cc:dd:ee:02",
		Hostname:  "my-nas",
		Vendor:    "Synology",
		Label:     "Main NAS",
		Notes:     "rack-1",
		Group:     "servers",
		FirstSeen: now,
		LastSeen:  now,
	}
	if err := store.UpdateDevice(&evil); err != nil {
		t.Fatalf("UpdateDevice evil: %v", err)
	}
	if err := store.UpdateDevice(&normal); err != nil {
		t.Fatalf("UpdateDevice normal: %v", err)
	}

	h := newTestHandler(t, store, config.Default())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/devices?format=csv", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("CSV export status = %d, want 200", rec.Code)
	}

	rows, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("CSV row count = %d, want 3 (header + 2 devices)", len(rows))
	}

	evilRow := rows[1]
	if evilRow[2] != "'=CMD|'/C calc'!A0" {
		t.Errorf("Hostname cell = %q, want formula-neutralized", evilRow[2])
	}
	if evilRow[3] != "'\t=1+1" {
		t.Errorf("Vendor cell = %q, want formula-neutralized", evilRow[3])
	}
	if evilRow[4] != "'+SUM(1,1)" {
		t.Errorf("Label cell = %q, want formula-neutralized", evilRow[4])
	}
	if evilRow[5] != "'-2+3" {
		t.Errorf("Notes cell = %q, want formula-neutralized", evilRow[5])
	}
	if evilRow[6] != "'@evil" {
		t.Errorf("Group cell = %q, want formula-neutralized", evilRow[6])
	}

	normalRow := rows[2]
	if normalRow[2] != "my-nas" || normalRow[5] != "rack-1" {
		t.Errorf("normal row unexpectedly altered: %+v", normalRow)
	}
}

func TestMaxBytesReaderRejectsOversizedJSON(t *testing.T) {
	store := newScanJobTestStore(t)
	h := newTestHandler(t, store, config.Default())

	hugeNotes := strings.Repeat("a", 2*1024*1024)
	payload := `{"ip":"192.168.1.10","notes":"` + hugeNotes + `"}`

	req := httptest.NewRequest(http.MethodPost, "/api/device", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized JSON status = %d, want 413: %s", rec.Code, rec.Body.String())
	}
}

func TestLogsLimitClamped(t *testing.T) {
	orig := logging.GlobalBuffer
	testBuf := logging.NewBuffer(1500)
	logging.GlobalBuffer = testBuf
	defer func() {
		logging.GlobalBuffer = orig
	}()

	for i := 0; i < 1200; i++ {
		testBuf.Add("info", "log entry")
	}

	store := newScanJobTestStore(t)
	h := newTestHandler(t, store, config.Default())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/logs?limit=999999", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/logs status = %d, want 200", rec.Code)
	}

	var resp struct {
		Success bool               `json:"success"`
		Data    []logging.LogEntry `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode /api/logs response: %v", err)
	}
	if len(resp.Data) != maxLogsLimit {
		t.Errorf("/api/logs returned %d entries for limit=999999, want clamped %d", len(resp.Data), maxLogsLimit)
	}
}

func TestNotificationsTestRejectsSSRFAndSanitizesErrors(t *testing.T) {
	store := newScanJobTestStore(t)
	h := newTestHandler(t, store, config.Default())

	called := false
	h.sendSlackNotification = func(url, text string) error {
		called = true
		return errors.New("dial tcp 10.0.0.99:443: connect: connection refused")
	}

	for _, badURL := range []string{
		"http://127.0.0.1:8080/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://localhost/hook",
		"file:///etc/passwd",
	} {
		called = false
		body, _ := json.Marshal(map[string]string{"slack_webhook": badURL})
		req := httptest.NewRequest(http.MethodPost, "/api/settings/notifications/test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("webhook %q test status = %d, want 400: %s", badURL, rec.Code, rec.Body.String())
		}
		if called {
			t.Errorf("sendSlackNotification was called for blocked URL %q", badURL)
		}

		// Saving blocked webhook URL must also be rejected.
		saveBody, _ := json.Marshal(map[string]interface{}{
			"network_cidr":  "192.168.1.0/24",
			"slack_webhook": badURL,
			"enabled":       true,
		})
		saveReq := httptest.NewRequest(http.MethodPost, "/api/settings/notifications", bytes.NewReader(saveBody))
		saveReq.Header.Set("Content-Type", "application/json")
		saveRec := httptest.NewRecorder()
		h.ServeHTTP(saveRec, saveReq)
		if saveRec.Code != http.StatusBadRequest {
			t.Errorf("save webhook %q status = %d, want 400: %s", badURL, saveRec.Code, saveRec.Body.String())
		}
	}

	// Transport errors from valid webhook hosts must not leak internal dial/IP details.
	called = false
	body, _ := json.Marshal(map[string]string{"slack_webhook": "https://hooks.slack.com/services/T00/B00/XXX"})
	req := httptest.NewRequest(http.MethodPost, "/api/settings/notifications/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected sendSlackNotification to be called for valid webhook URL")
	}
	if rec.Code < 400 {
		t.Fatalf("expected error status on transport failure, got %d", rec.Code)
	}
	respStr := rec.Body.String()
	if strings.Contains(respStr, "10.0.0.99") || strings.Contains(respStr, "connection refused") {
		t.Errorf("response leaked raw transport error details: %s", respStr)
	}
}

type slowScanMockRunner struct {
	delay time.Duration
}

func (r *slowScanMockRunner) HasRemoteScannerForTarget(string) bool { return true }
func (r *slowScanMockRunner) GetGatewayForTarget(string) string     { return "mock" }
func (r *slowScanMockRunner) CanRunPrivileged(string) bool          { return false }
func (r *slowScanMockRunner) Close() error                          { return nil }
func (r *slowScanMockRunner) RunScan(ctx context.Context, target string, args []string) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(r.delay):
		return []byte(`<nmaprun><host><status state="up"/><address addr="10.5.5.1" addrtype="ipv4"/></host></nmaprun>`), nil
	}
}

var _ remotescan.Runner = (*slowScanMockRunner)(nil)

func TestHandleScan_ExtendsWriteDeadlineBeyondServerWriteTimeout(t *testing.T) {
	store := newScanJobTestStore(t)
	defer store.Close()

	h := newTestHandler(t, store, config.Default())
	defer h.Close()
	h.scanner.SetRemoteRunner(&slowScanMockRunner{delay: 150 * time.Millisecond})

	srv := &http.Server{
		Handler:      h,
		WriteTimeout: 50 * time.Millisecond,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/api/scan?network=10.5.5.0/24", ln.Addr().String()), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/scan failed due to server WriteTimeout: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/scan status = %d, want 200", resp.StatusCode)
	}
}

func TestServeHTTP_CSRFMethodsAndNotFound(t *testing.T) {
	store := newScanJobTestStore(t)
	h := newTestHandler(t, store, config.Default())

	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/device?ip=10.0.0.1", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s without CSRF headers status = %d, want 403", method, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/does-not-exist", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown endpoint status = %d, want 404", rec.Code)
	}
}

func TestHandleDevicesJSONAndClear(t *testing.T) {
	store := newScanJobTestStore(t)
	now := time.Now()
	_ = store.UpdateDevice(&types.Device{IP: "10.1.0.1", MAC: "00:11:22:33:01:01", Hostname: "core-gw", NetworkName: "Core", FirstSeen: now, LastSeen: now})
	_ = store.UpdateDevice(&types.Device{IP: "10.2.0.1", MAC: "00:11:22:33:02:01", Hostname: "iot-cam", NetworkName: "IoT", FirstSeen: now, LastSeen: now})

	h := newTestHandler(t, store, config.Default())

	// GET /api/devices JSON
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/devices", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/devices status = %d, want 200", rec.Code)
	}
	var devResp struct {
		Success bool                     `json:"success"`
		Data    map[string]*types.Device `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &devResp); err != nil {
		t.Fatalf("decode /api/devices: %v", err)
	}
	if !devResp.Success || len(devResp.Data) != 2 {
		t.Fatalf("unexpected /api/devices response: %+v", devResp)
	}

	// POST /api/devices -> 405
	postReq := httptest.NewRequest(http.MethodPost, "/api/devices", strings.NewReader(`{}`))
	postReq.Header.Set("Content-Type", "application/json")
	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/devices status = %d, want 405", postRec.Code)
	}

	// GET /api/devices/clear -> 405
	clearGetRec := httptest.NewRecorder()
	h.ServeHTTP(clearGetRec, httptest.NewRequest(http.MethodGet, "/api/devices/clear", nil))
	if clearGetRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/devices/clear status = %d, want 405", clearGetRec.Code)
	}

	// POST /api/devices/clear specific network
	clearReq := httptest.NewRequest(http.MethodPost, "/api/devices/clear", strings.NewReader(`{"network":"Core"}`))
	clearReq.Header.Set("Content-Type", "application/json")
	clearRec := httptest.NewRecorder()
	h.ServeHTTP(clearRec, clearReq)
	if clearRec.Code != http.StatusOK {
		t.Fatalf("POST /api/devices/clear status = %d, want 200: %s", clearRec.Code, clearRec.Body.String())
	}
	if store.GetDevice("10.1.0.1") != nil || store.GetDevice("10.2.0.1") == nil {
		t.Fatal("POST /api/devices/clear(Core) did not remove only Core device")
	}
}

func TestHandleStatsStatusAndNotificationSettings(t *testing.T) {
	store := newScanJobTestStore(t)
	now := time.Now()
	_ = store.UpdateDevice(&types.Device{IP: "10.0.0.10", MAC: "00:11:22:33:44:10", Group: "Servers", FirstSeen: now, LastSeen: now})

	cfg := config.Default()
	cfg.Server.Port = 8088
	cfg.Server.BindAddress = "127.0.0.1"
	h := newTestHandler(t, store, cfg)
	h.sendSlackNotification = func(url, text string) error {
		return nil
	}

	// /api/stats
	statsRec := httptest.NewRecorder()
	h.ServeHTTP(statsRec, httptest.NewRequest(http.MethodGet, "/api/stats", nil))
	if statsRec.Code != http.StatusOK {
		t.Fatalf("GET /api/stats = %d, want 200", statsRec.Code)
	}
	var statsResp struct {
		Success bool              `json:"success"`
		Data    types.DeviceStats `json:"data"`
	}
	if err := json.Unmarshal(statsRec.Body.Bytes(), &statsResp); err != nil {
		t.Fatalf("decode /api/stats: %v", err)
	}
	if statsResp.Data.Total != 1 || statsResp.Data.Online != 1 || statsResp.Data.Groups["Servers"] != 1 {
		t.Fatalf("unexpected /api/stats: %+v", statsResp.Data)
	}

	// /api/status
	statusRec := httptest.NewRecorder()
	h.ServeHTTP(statusRec, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if statusRec.Code != http.StatusOK {
		t.Fatalf("GET /api/status = %d, want 200", statusRec.Code)
	}
	var statusResp struct {
		Success bool                   `json:"success"`
		Data    map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(statusRec.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("decode /api/status: %v", err)
	}
	if statusResp.Data["server"] != "running" {
		t.Fatalf("unexpected /api/status: %+v", statusResp.Data)
	}

	// POST /api/settings/notifications & GET /api/settings/notifications
	saveReq := httptest.NewRequest(http.MethodPost, "/api/settings/notifications", strings.NewReader(`{"network_cidr":"10.0.0.0/24","slack_webhook":"https://hooks.slack.com/services/T00/B00/OK","enabled":true}`))
	saveReq.Header.Set("Content-Type", "application/json")
	saveRec := httptest.NewRecorder()
	h.ServeHTTP(saveRec, saveReq)
	if saveRec.Code != http.StatusOK {
		t.Fatalf("POST /api/settings/notifications = %d, want 200: %s", saveRec.Code, saveRec.Body.String())
	}

	getNotifRec := httptest.NewRecorder()
	h.ServeHTTP(getNotifRec, httptest.NewRequest(http.MethodGet, "/api/settings/notifications", nil))
	if getNotifRec.Code != http.StatusOK {
		t.Fatalf("GET /api/settings/notifications = %d, want 200", getNotifRec.Code)
	}
	var notifResp struct {
		Success bool                        `json:"success"`
		Data    []types.NetworkNotification `json:"data"`
	}
	if err := json.Unmarshal(getNotifRec.Body.Bytes(), &notifResp); err != nil {
		t.Fatalf("decode /api/settings/notifications: %v", err)
	}
	if len(notifResp.Data) != 1 || notifResp.Data[0].NetworkCIDR != "10.0.0.0/24" || !notifResp.Data[0].Enabled {
		t.Fatalf("unexpected notifications list: %+v", notifResp.Data)
	}

	// POST /api/settings/notifications/test success & missing webhook
	testReq := httptest.NewRequest(http.MethodPost, "/api/settings/notifications/test", strings.NewReader(`{"slack_webhook":"https://hooks.slack.com/services/T00/B00/OK"}`))
	testReq.Header.Set("Content-Type", "application/json")
	testRec := httptest.NewRecorder()
	h.ServeHTTP(testRec, testReq)
	if testRec.Code != http.StatusOK {
		t.Fatalf("POST /api/settings/notifications/test = %d, want 200: %s", testRec.Code, testRec.Body.String())
	}

	badTestReq := httptest.NewRequest(http.MethodPost, "/api/settings/notifications/test", strings.NewReader(`{}`))
	badTestReq.Header.Set("Content-Type", "application/json")
	badTestRec := httptest.NewRecorder()
	h.ServeHTTP(badTestRec, badTestReq)
	if badTestRec.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/settings/notifications/test empty = %d, want 400", badTestRec.Code)
	}
}

type controllableScanRunner struct {
	started chan struct{}
	release chan struct{}
}

func (r *controllableScanRunner) HasRemoteScannerForTarget(string) bool { return true }
func (r *controllableScanRunner) GetGatewayForTarget(string) string     { return "mockgw" }
func (r *controllableScanRunner) CanRunPrivileged(string) bool          { return false }
func (r *controllableScanRunner) Close() error                          { return nil }
func (r *controllableScanRunner) RunScan(ctx context.Context, target string, args []string) ([]byte, error) {
	if r.started != nil {
		select {
		case r.started <- struct{}{}:
		default:
		}
	}
	if r.release != nil {
		select {
		case <-r.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return []byte(`<nmaprun><host><status state="up"/><address addr="10.5.5.1" addrtype="ipv4"/></host></nmaprun>`), nil
}

func TestHandleScanEndpointsAndJobLifecycle(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := config.Default()
	cfg.Scanning.MinScanInterval = 60
	cfg.Scanning.Networks = []string{"10.5.5.0/24"}
	cfg.Scanning.OnlyConfiguredNetworks = true
	h := newTestHandler(t, store, cfg)
	h.scanner.SetRemoteRunner(&controllableScanRunner{})

	// 1. POST /api/scan validation & rate limit & network=all
	for _, tc := range []struct {
		url      string
		wantCode int
	}{
		{"/api/scan", http.StatusBadRequest},
		{"/api/scan?network=not-a-cidr", http.StatusBadRequest},
		{"/api/scan?network=all", http.StatusOK},
		{"/api/scan?network=10.5.5.0/24", http.StatusTooManyRequests}, // just scanned via network=all
	} {
		req := httptest.NewRequest(http.MethodPost, tc.url, nil)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.wantCode {
			t.Fatalf("POST %s = %d, want %d: %s", tc.url, rec.Code, tc.wantCode, rec.Body.String())
		}
	}

	// 2. Idle /api/scan/progress and /api/scan/cancel
	progRec := httptest.NewRecorder()
	h.ServeHTTP(progRec, httptest.NewRequest(http.MethodGet, "/api/scan/progress", nil))
	if progRec.Code != http.StatusOK || !strings.Contains(progRec.Body.String(), `"status":"idle"`) {
		t.Fatalf("idle /api/scan/progress = %d %s", progRec.Code, progRec.Body.String())
	}

	cancelIdleReq := httptest.NewRequest(http.MethodPost, "/api/scan/cancel", nil)
	cancelIdleReq.Header.Set("Content-Type", "application/json")
	cancelIdleRec := httptest.NewRecorder()
	h.ServeHTTP(cancelIdleRec, cancelIdleReq)
	if cancelIdleRec.Code != http.StatusConflict {
		t.Fatalf("POST /api/scan/cancel when idle = %d, want 409", cancelIdleRec.Code)
	}

	// 3. Start scan job, inspect running progress, adopt, and cancel
	_ = store.SetLastScan("10.5.5.0/24", time.Now().Add(-5*time.Minute))
	runner := &controllableScanRunner{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	h.scanner.SetRemoteRunner(runner)

	startReq := httptest.NewRequest(http.MethodPost, "/api/scan/start?network=10.5.5.0/24&mode=quick", nil)
	startReq.Header.Set("Content-Type", "application/json")
	startRec := httptest.NewRecorder()
	h.ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("POST /api/scan/start = %d, want 200: %s", startRec.Code, startRec.Body.String())
	}

	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("scan job did not invoke runner")
	}

	progRunningRec := httptest.NewRecorder()
	h.ServeHTTP(progRunningRec, httptest.NewRequest(http.MethodGet, "/api/scan/progress", nil))
	if progRunningRec.Code != http.StatusOK || !strings.Contains(progRunningRec.Body.String(), `"status":"running"`) {
		t.Fatalf("running /api/scan/progress = %d %s", progRunningRec.Code, progRunningRec.Body.String())
	}

	cancelReq := httptest.NewRequest(http.MethodPost, "/api/scan/cancel", nil)
	cancelReq.Header.Set("Content-Type", "application/json")
	cancelRec := httptest.NewRecorder()
	h.ServeHTTP(cancelRec, cancelReq)
	if cancelRec.Code != http.StatusOK {
		t.Fatalf("POST /api/scan/cancel = %d, want 200: %s", cancelRec.Code, cancelRec.Body.String())
	}
	h.WaitForScans()

	// 4. GET and POST /api/scan/continuous
	contGetRec := httptest.NewRecorder()
	h.ServeHTTP(contGetRec, httptest.NewRequest(http.MethodGet, "/api/scan/continuous", nil))
	if contGetRec.Code != http.StatusOK {
		t.Fatalf("GET /api/scan/continuous = %d, want 200", contGetRec.Code)
	}

	contPostReq := httptest.NewRequest(http.MethodPost, "/api/scan/continuous", strings.NewReader(`{"enabled":false}`))
	contPostReq.Header.Set("Content-Type", "application/json")
	contPostRec := httptest.NewRecorder()
	h.ServeHTTP(contPostRec, contPostReq)
	if contPostRec.Code != http.StatusOK || !strings.Contains(contPostRec.Body.String(), `"enabled":false`) {
		t.Fatalf("POST /api/scan/continuous = %d %s", contPostRec.Code, contPostRec.Body.String())
	}
}

func TestServeHTTP_RoutingAndNoURLMutation(t *testing.T) {
	store := newScanJobTestStore(t)
	now := time.Now()
	_ = store.UpdateDevice(&types.Device{
		IP:        "192.168.1.55",
		MAC:       "aa:bb:cc:dd:ee:55",
		Hostname:  "app-host",
		FirstSeen: now,
		LastSeen:  now,
	})
	cfg := config.Default()
	cfg.Scanning.Networks = []string{"192.168.1.0/24"}
	cfg.Scanning.OnlyConfiguredNetworks = true
	h := newTestHandler(t, store, cfg)

	// 1. GET /api/devices/{ip} must not mutate r.URL.RawQuery
	getReq := httptest.NewRequest(http.MethodGet, "/api/devices/192.168.1.55", nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /api/devices/192.168.1.55 = %d, want 200: %s", getRec.Code, getRec.Body.String())
	}
	if getReq.URL.RawQuery != "" || getReq.URL.Path != "/api/devices/192.168.1.55" {
		t.Fatalf("ServeHTTP mutated request URL: path=%q rawQuery=%q", getReq.URL.Path, getReq.URL.RawQuery)
	}

	// 2. POST /api/devices/{ip}/deep-scan must not mutate r.URL.Path
	dsReq := httptest.NewRequest(http.MethodPost, "/api/devices/192.168.1.55/deep-scan", nil)
	dsReq.Header.Set("Content-Type", "application/json")
	dsRec := httptest.NewRecorder()
	h.ServeHTTP(dsRec, dsReq)
	if dsRec.Code != http.StatusOK {
		t.Fatalf("POST /api/devices/192.168.1.55/deep-scan = %d, want 200: %s", dsRec.Code, dsRec.Body.String())
	}
	if dsReq.URL.Path != "/api/devices/192.168.1.55/deep-scan" {
		t.Fatalf("ServeHTTP mutated deep-scan URL.Path to %q", dsReq.URL.Path)
	}
	h.jobMu.Lock()
	job := h.job
	h.jobMu.Unlock()
	if job != nil {
		job.cancel()
		<-job.done
	}

	// 3. Method-not-allowed returns 405 JSON on method-restricted paths (including trailing slash)
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/devices/clear"},
		{http.MethodGet, "/api/devices/192.168.1.55/deep-scan"},
		{http.MethodGet, "/api/devices/192.168.1.55/facts"},
		{http.MethodPost, "/api/devices/192.168.1.55/traffic"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		if tc.method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s = %d, want 405: %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
		var errResp types.APIResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil || errResp.Success {
			t.Fatalf("%s %s did not return JSON error response: %s", tc.method, tc.path, rec.Body.String())
		}
	}

	// 4. Trailing slash compatibility without mutating caller's request URL
	slashReq := httptest.NewRequest(http.MethodGet, "/api/devices/", nil)
	slashRec := httptest.NewRecorder()
	h.ServeHTTP(slashRec, slashReq)
	if slashRec.Code != http.StatusOK {
		t.Fatalf("GET /api/devices/ = %d, want 200", slashRec.Code)
	}
	if slashReq.URL.Path != "/api/devices/" {
		t.Fatalf("ServeHTTP mutated trailing-slash request path to %q", slashReq.URL.Path)
	}
}

func TestExecuteNetworkSweep_SharedByHandleScan(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := config.Default()
	cfg.Scanning.MinScanInterval = 60
	cfg.Scanning.Networks = []string{"10.5.5.0/24"}
	cfg.Scanning.OnlyConfiguredNetworks = true
	h := newTestHandler(t, store, cfg)
	h.scanner.SetRemoteRunner(&slowScanMockRunner{delay: 25 * time.Millisecond})

	req := httptest.NewRequest(http.MethodPost, "/api/scan?network=10.5.5.0/24", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/scan = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	if got := store.GetLastDuration("10.5.5.0/24"); got <= 0 {
		t.Fatalf("GetLastDuration(10.5.5.0/24) = %v, want > 0 from shared executeNetworkSweep", got)
	}
	if store.GetDevice("10.5.5.1") == nil {
		t.Fatal("expected discovered device 10.5.5.1 to be merged into store")
	}
}
