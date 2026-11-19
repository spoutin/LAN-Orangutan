package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/remotescan"
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
	h := newTestHandler(t, store, cfg)
	var calls []string
	h.fetchSwitchConnections = func(_ context.Context, switchCfg config.SwitchConfig, vlanByMAC map[string]int) ([]scanner.SwitchConnection, error) {
		calls = append(calls, switchCfg.ID)
		if got := vlanByMAC["aa:bb:cc:dd:ee:01"]; got != 30 {
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

func TestSelectOldestScannedNetwork(t *testing.T) {
	store := newScanJobTestStore(t)
	networks := []string{"192.168.1.0/24", "10.20.0.0/24", "172.16.0.0/24"}

	// Unscanned network is picked first
	_ = store.SetLastScan("192.168.1.0/24", time.Now().Add(-10*time.Minute))
	_ = store.SetLastScan("10.20.0.0/24", time.Now().Add(-20*time.Minute))
	// "172.16.0.0/24" has zero LastScan

	selected, ok := selectOldestScannedNetwork(store, networks)
	if !ok || selected != "172.16.0.0/24" {
		t.Fatalf("selected = %q, want unscanned 172.16.0.0/24", selected)
	}

	// Once all are scanned, oldest timestamp is selected
	_ = store.SetLastScan("172.16.0.0/24", time.Now().Add(-5*time.Minute))
	selected, ok = selectOldestScannedNetwork(store, networks)
	if !ok || selected != "10.20.0.0/24" {
		t.Fatalf("selected = %q, want oldest 10.20.0.0/24", selected)
	}
}

func TestSelectOldestScannedNetworksPerGateway(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := config.Default()
	h := newTestHandler(t, store, cfg)

	runner := &testConcurrencyTrackingRemoteRunner{}
	h.scanner.SetRemoteRunner(runner)

	networks := []string{
		"10.0.0.0/24", "10.0.1.0/24", // opnsense
		"10.5.5.0/24", "10.5.6.0/24", // openwrt
		"172.16.0.0/24", // local
	}

	// opnsense: 10.0.0.0/24 is 30m old, 10.0.1.0/24 is 10m old -> pick 10.0.0.0/24
	_ = store.SetLastScan("10.0.0.0/24", time.Now().Add(-30*time.Minute))
	_ = store.SetLastScan("10.0.1.0/24", time.Now().Add(-10*time.Minute))

	// openwrt: 10.5.5.0/24 is 5m old, 10.5.6.0/24 is never scanned -> pick 10.5.6.0/24
	_ = store.SetLastScan("10.5.5.0/24", time.Now().Add(-5*time.Minute))

	// local: 172.16.0.0/24 is 1h old -> pick 172.16.0.0/24
	_ = store.SetLastScan("172.16.0.0/24", time.Now().Add(-60*time.Minute))

	selected := selectOldestScannedNetworksPerGateway(h, networks)
	if len(selected) != 3 {
		t.Fatalf("expected 3 selected networks (1 per gateway), got %d: %v", len(selected), selected)
	}

	has := func(needle string) bool {
		for _, n := range selected {
			if n == needle {
				return true
			}
		}
		return false
	}

	if !has("10.0.0.0/24") {
		t.Errorf("expected opnsense oldest '10.0.0.0/24' to be selected: %v", selected)
	}
	if !has("10.5.6.0/24") {
		t.Errorf("expected openwrt unscanned '10.5.6.0/24' to be selected: %v", selected)
	}
	if !has("172.16.0.0/24") {
		t.Errorf("expected local '172.16.0.0/24' to be selected: %v", selected)
	}
}

func TestStartBackgroundScanner_SchedulesAllNetworksTogether(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.0.0.0/24", "10.0.1.0/24", "10.5.5.0/24"}
	cfg.Scanning.OnlyConfiguredNetworks = true
	cfg.Scanning.ContinuousScan = true
	h := newTestHandler(t, store, cfg)

	networks, err := h.resolveScanTargets("all")
	if err != nil {
		t.Fatalf("resolveScanTargets: %v", err)
	}

	job := h.startBackgroundNetworks(networks, networks)
	if job == nil {
		t.Fatal("expected background job to be created")
	}
	if len(job.networks) != 3 {
		t.Fatalf("expected all 3 networks scheduled together, got %d: %v", len(job.networks), job.networks)
	}
	job.cancel()
	<-job.done
}

func TestWaitForBackgroundScanWaitsForCompletionBeforeDelay(t *testing.T) {
	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	finished := make(chan bool, 1)
	go func() {
		finished <- waitForBackgroundScan(ctx, done, 20*time.Millisecond)
	}()

	select {
	case <-finished:
		t.Fatal("waitForBackgroundScan returned before the scan completed")
	case <-time.After(10 * time.Millisecond):
	}

	close(done)
	select {
	case ok := <-finished:
		if !ok {
			t.Fatal("waitForBackgroundScan returned false after a completed scan")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("waitForBackgroundScan did not finish after completion and delay")
	}
}

func TestWaitForBackgroundScanStopsWhenCancelled(t *testing.T) {
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitForBackgroundScan(ctx, done, time.Hour) {
		t.Fatal("waitForBackgroundScan returned true after cancellation")
	}
}

func TestStartBackgroundNetworkMakesOneNightlyDeepJobForAllNetworks(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := config.Default()
	cfg.Scanning.EnablePortScan = true
	cfg.Scanning.PortScanRange = "1-10"
	h := newTestHandler(t, store, cfg)
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return time.Date(2026, time.October, 8, 3, 10, 0, 0, loc) }

	networks := []string{"192.168.1.0/24", "10.20.0.0/24"}
	job := h.startBackgroundNetwork(networks[0], networks)
	if job == nil || !job.nightlyDeep {
		t.Fatal("expected first 03:00 background scan to start a nightly deep job")
	}
	if len(job.deepNetworks) != len(networks) {
		t.Fatalf("deep networks = %v, want %v", job.deepNetworks, networks)
	}
	if _, err := store.GetSetting("last_deep_scan_date"); err != nil {
		t.Fatalf("last_deep_scan_date was not recorded: %v", err)
	}
	job.cancel()
	<-job.done

	second := h.startBackgroundNetwork(networks[1], networks)
	if second == nil {
		t.Fatal("expected a second background job")
	}
	if second.nightlyDeep {
		t.Fatal("expected nightly deep job to run only once per day")
	}
	second.cancel()
	<-second.done
}

func TestNightlyDeepCutoffNotifiesOnlyAffectedNetworks(t *testing.T) {
	store := newScanJobTestStore(t)
	if err := store.SaveNetworkNotification("192.168.1.0/24", "https://example.test/affected", true); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveNetworkNotification("10.20.0.0/24", "https://example.test/complete", true); err != nil {
		t.Fatal(err)
	}
	h := newTestHandler(t, store, config.Default())
	var messages []string
	h.sendSlackNotification = func(webhook, text string) error {
		messages = append(messages, webhook+"\n"+text)
		return nil
	}
	job := &scanJob{deepNetworkProgress: []deepNetworkProgress{
		{Network: "192.168.1.0/24", Total: 5, Complete: 3},
		{Network: "10.20.0.0/24", Total: 2, Complete: 2},
	}}
	job.notifyNightlyDeepCutoff(h)
	if len(messages) != 1 {
		t.Fatalf("notification count = %d, want 1: %v", len(messages), messages)
	}
	if !strings.Contains(messages[0], "affected") || !strings.Contains(messages[0], "3 completed") || !strings.Contains(messages[0], "2 skipped") {
		t.Errorf("notification = %q", messages[0])
	}
}

func TestNightlyDeepScanIncludesDevicesSeenWithin24h(t *testing.T) {
	store := newScanJobTestStore(t)
	device := &types.Device{
		IP:       "192.168.1.50",
		Hostname: "device-2h-old",
		LastSeen: time.Now().Add(-2 * time.Hour), // 2 hours old (outside 15m window, but inside 24h)
	}
	if err := store.UpdateDevice(device); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Scanning.Networks = []string{"192.168.1.0/24"}
	h := newTestHandler(t, store, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so runDeepQueue does not actually execute nmap

	job := &scanJob{
		deepNetworks: []string{"192.168.1.0/24"},
		networks:     []string{"192.168.1.0/24"},
	}
	job.runNightlyDeepScan(ctx, h)

	job.mu.RLock()
	defer job.mu.RUnlock()
	if len(job.deepNetworkProgress) == 0 || job.deepNetworkProgress[0].Total != 1 {
		t.Fatalf("deepNetworkProgress = %+v, want 1 target queued for 2h-old device", job.deepNetworkProgress)
	}
}

func TestScanPortHostUpdatesPresence(t *testing.T) {
	store := newScanJobTestStore(t)
	past := time.Now().Add(-2 * time.Hour)
	device := types.Device{
		IP:       "192.168.1.55",
		Hostname: "printer",
		LastSeen: past,
	}
	if err := store.UpdateDevice(&device); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Scanning.PortScanRange = "80"
	h := newTestHandler(t, store, cfg)
	h.scanner.SetRemoteRunner(&testControlledRemoteRunner{
		fn: func(ctx context.Context, target string, args []string) ([]byte, error) {
			return []byte(`<nmaprun><host><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>`), nil
		},
	})

	job := &scanJob{
		deepNetworkProgress: []deepNetworkProgress{
			{Network: "192.168.1.0/24", Total: 1},
		},
	}
	job.scanPortHost(context.Background(), h, "192.168.1.0/24", device)

	stored := store.GetDevice("192.168.1.55")
	if stored == nil {
		t.Fatal("device not found in store")
	}
	if !stored.LastSeen.After(past) {
		t.Fatalf("stored LastSeen = %v, expected updated after %v", stored.LastSeen, past)
	}
}

func TestScanPortHost_SavesDetectedOS(t *testing.T) {
	store := newScanJobTestStore(t)
	device := types.Device{
		IP:       "192.168.1.55",
		Hostname: "my-ubuntu",
		CustomOS: "Custom Admin Override",
	}
	if err := store.UpdateDevice(&device); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Scanning.PortScanRange = "22"
	h := newTestHandler(t, store, cfg)
	h.scanner.SetRemoteRunner(&testControlledRemoteRunner{
		fn: func(ctx context.Context, target string, args []string) ([]byte, error) {
			return []byte(`<?xml version="1.0"?>
<nmaprun><host>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.10" extrainfo="Ubuntu Linux; protocol 2.0"/>
    </port>
  </ports>
  <os>
    <osmatch name="Linux 5.4 - 5.15" accuracy="95">
      <osclass vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="95"/>
    </osmatch>
  </os>
</host></nmaprun>`), nil
		},
	})

	job := &scanJob{
		deepNetworkProgress: []deepNetworkProgress{
			{Network: "192.168.1.0/24", Total: 1},
		},
	}
	_, err := job.scanPortHost(context.Background(), h, "192.168.1.0/24", device)
	if err != nil {
		t.Fatalf("scanPortHost: %v", err)
	}

	stored := store.GetDevice("192.168.1.55")
	if stored == nil {
		t.Fatal("device not found in store")
	}
	if stored.OS != "Ubuntu Linux" {
		t.Errorf("stored OS = %q, want Ubuntu Linux", stored.OS)
	}
	if stored.OSVersion != "22.04" {
		t.Errorf("stored OSVersion = %q, want 22.04", stored.OSVersion)
	}
	if stored.OSFamily != "Linux" {
		t.Errorf("stored OSFamily = %q, want Linux", stored.OSFamily)
	}
	if stored.CustomOS != "Custom Admin Override" {
		t.Errorf("stored CustomOS = %q, want preserved Custom Admin Override", stored.CustomOS)
	}
}

func TestSingleDeviceScan_DoesNotAlertSlackOrTriggerFalseRecovery(t *testing.T) {
	store := newScanJobTestStore(t)
	_ = store.SaveNetworkNotification("10.5.5.0/24", "https://example.test/slack-openwrt", true)

	// Pre-seed the gateway returned by the mock sweep so the sweep does not
	// treat it as a newly discovered device and emit a sweep report.
	_ = store.UpdateDevice(&types.Device{
		IP:        "10.5.5.1",
		Hostname:  "openwrt",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	})

	device := types.Device{
		IP:       "10.5.5.143",
		Hostname: "iot-device",
		LastSeen: time.Now(),
	}
	_ = store.UpdateDevice(&device)

	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.5.5.0/24"}
	cfg.Scanning.PortScanRange = "22,80"
	h := newTestHandler(t, store, cfg)
	defer h.Close()

	var mu sync.Mutex
	var slackMessages []string
	h.sendSlackNotification = func(webhook, text string) error {
		mu.Lock()
		slackMessages = append(slackMessages, text)
		mu.Unlock()
		return nil
	}

	// Mock runner where port scan on 10.5.5.143 fails, but network sweep on 10.5.5.0/24 succeeds
	h.scanner.SetRemoteRunner(&testControlledRemoteRunner{
		fn: func(ctx context.Context, target string, args []string) ([]byte, error) {
			if target == "10.5.5.143" {
				return nil, fmt.Errorf("connection refused")
			}
			return []byte(`<nmaprun><host><status state="up"/><address addr="10.5.5.1" addrtype="ipv4"/></host></nmaprun>`), nil
		},
	})

	// 1. Run single device service scan that fails
	job := &scanJob{
		deepNetworkProgress: []deepNetworkProgress{
			{Network: "10.5.5.0/24", Total: 1},
		},
	}
	job.scanPortHost(context.Background(), h, "10.5.5.0/24", device)

	// Single device failure should NOT send Slack notifications!
	h.WaitForScans()
	mu.Lock()
	if len(slackMessages) != 0 {
		mu.Unlock()
		t.Fatalf("expected 0 Slack alerts for single device failure, got %d: %v", len(slackMessages), slackMessages)
	}
	mu.Unlock()

	// 2. Run a normal network discovery sweep on 10.5.5.0/24
	sweepJob := h.startScanJob([]string{"10.5.5.0/24"}, false, scanModeQuick)
	<-sweepJob.done
	h.WaitForScans()

	// Successful sweep should NOT trigger a false recovery message!
	mu.Lock()
	defer mu.Unlock()
	if len(slackMessages) != 0 {
		t.Fatalf("expected 0 Slack alerts (no false recovery), got %d: %v", len(slackMessages), slackMessages)
	}
}

func TestSingleDeviceScan_LogsSingleDeviceCompletion(t *testing.T) {
	store := newScanJobTestStore(t)
	device := types.Device{
		IP:       "10.5.5.142",
		Hostname: "proxmox",
		LastSeen: time.Now(),
	}
	_ = store.UpdateDevice(&device)

	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.5.5.0/24"}
	cfg.Scanning.PortScanRange = "22"
	h := newTestHandler(t, store, cfg)

	h.scanner.SetRemoteRunner(&testControlledRemoteRunner{
		fn: func(ctx context.Context, target string, args []string) ([]byte, error) {
			return []byte(`<nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host></nmaprun>`), nil
		},
	})

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	job := &scanJob{
		networks:    []string{"10.5.5.0/24"},
		deepDevices: []types.Device{device},
	}
	targets := map[string][]types.Device{"10.5.5.0/24": {device}}
	job.runDeepQueue(context.Background(), h, targets)

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "completed single-device service scan on 10.5.5.142") {
		t.Errorf("expected log to contain 'completed single-device service scan on 10.5.5.142', got:\n%s", logOutput)
	}
	if strings.Contains(logOutput, "completed service scan queue on 10.5.5.0/24") {
		t.Errorf("did not expect log to say 'completed service scan queue on 10.5.5.0/24'")
	}
}

func TestDeepScan_TracksFailedAndWarningStatus(t *testing.T) {
	store := newScanJobTestStore(t)
	dev1 := types.Device{IP: "10.5.5.10", Hostname: "host1", LastSeen: time.Now()}
	dev2 := types.Device{IP: "10.5.5.20", Hostname: "host2", LastSeen: time.Now()}
	_ = store.UpdateDevice(&dev1)
	_ = store.UpdateDevice(&dev2)

	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.5.5.0/24"}
	cfg.Scanning.PortScanRange = "22"
	h := newTestHandler(t, store, cfg)

	// Case 1: All hosts fail (e.g. fatal scanner error)
	h.scanner.SetRemoteRunner(&testControlledRemoteRunner{
		fn: func(ctx context.Context, target string, args []string) ([]byte, error) {
			return nil, fmt.Errorf("nsock_pool_dtls_init called with no OpenSSL DTLS support")
		},
	})

	job1 := &scanJob{
		networks: []string{"10.5.5.0/24"},
	}
	job1.runDeepQueue(context.Background(), h, map[string][]types.Device{"10.5.5.0/24": {dev1, dev2}})

	history, err := store.GetScanHistory()
	if err != nil {
		t.Fatalf("get history: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(history))
	}
	if history[0].Status != "failed" {
		t.Errorf("expected status 'failed', got %q", history[0].Status)
	}
	if history[0].ScanType != "deep" {
		t.Errorf("expected scan_type 'deep', got %q", history[0].ScanType)
	}
	if !strings.Contains(history[0].Error, "DTLS support") {
		t.Errorf("expected error to mention DTLS support, got: %s", history[0].Error)
	}

	// Case 2: Partial failure (one host passes, one host fails)
	h.scanner.SetRemoteRunner(&testControlledRemoteRunner{
		fn: func(ctx context.Context, target string, args []string) ([]byte, error) {
			if target == "10.5.5.10" {
				return []byte(`<nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host></nmaprun>`), nil
			}
			return nil, fmt.Errorf("connection timed out")
		},
	})

	job2 := &scanJob{
		networks: []string{"10.5.5.0/24"},
	}
	job2.runDeepQueue(context.Background(), h, map[string][]types.Device{"10.5.5.0/24": {dev1, dev2}})

	history, _ = store.GetScanHistory()
	if len(history) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(history))
	}
	// history[0] is newest
	if history[0].Status != "warning" {
		t.Errorf("expected status 'warning', got %q", history[0].Status)
	}
	if history[0].ScanType != "deep" {
		t.Errorf("expected scan_type 'deep', got %q", history[0].ScanType)
	}
	if !strings.Contains(history[0].Error, "1 of 2 host service scans failed") {
		t.Errorf("expected error summary to mention 1 of 2 failed, got: %s", history[0].Error)
	}

	// Test API endpoint with filter ?type=deep
	req := httptest.NewRequest(http.MethodGet, "/api/scans/history?type=deep", nil)
	w := httptest.NewRecorder()
	h.handleScansHistory(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("handleScansHistory returned %d", w.Code)
	}
	var resp struct {
		Success bool                      `json:"success"`
		Data    []types.ScanHistoryRecord `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Data) != 2 {
		t.Errorf("expected 2 deep records from API, got %d", len(resp.Data))
	}
}

type testRemoteRunnerFailure struct {
	gateway string
	target  string
	err     error
}

func (r *testRemoteRunnerFailure) HasRemoteScannerForTarget(target string) bool {
	return target == r.target
}
func (r *testRemoteRunnerFailure) GetGatewayForTarget(target string) string {
	return r.gateway
}
func (r *testRemoteRunnerFailure) CanRunPrivileged(target string) bool {
	return false
}
func (r *testRemoteRunnerFailure) RunScan(ctx context.Context, target string, args []string) ([]byte, error) {
	return nil, &remotescan.RemoteScannerError{
		Gateway:       r.gateway,
		Target:        target,
		Err:           r.err,
		IsMissingNmap: true,
	}
}

func TestRemoteScannerFailureNotifiesSlackAndSkips(t *testing.T) {
	store := newScanJobTestStore(t)
	_ = store.SaveNetworkNotification("10.0.0.0/24", "https://example.test/slack-opnsense", true)

	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.0.0.0/24"}
	cfg.Scanning.OnlyConfiguredNetworks = true
	h := newTestHandler(t, store, cfg)

	var slackMessages []string
	h.sendSlackNotification = func(webhook, text string) error {
		slackMessages = append(slackMessages, text)
		return nil
	}

	h.scanner.SetRemoteRunner(&testRemoteRunnerFailure{
		gateway: "opnsense (10.0.0.1)",
		target:  "10.0.0.0/24",
		err:     fmt.Errorf("nmap: not found"),
	})

	job := h.startScanJob([]string{"10.0.0.0/24"}, false, scanModeQuick)
	<-job.done

	job.mu.RLock()
	defer job.mu.RUnlock()
	if len(job.results) == 0 {
		t.Fatal("expected job results")
	}
	if job.results[0].Status != "failed" {
		t.Fatalf("expected status=failed, got %s", job.results[0].Status)
	}

	if len(slackMessages) != 1 {
		t.Fatalf("expected 1 Slack notification, got %d: %v", len(slackMessages), slackMessages)
	}
	if !strings.Contains(slackMessages[0], "Remote Scanner Failure") || !strings.Contains(slackMessages[0], "opnsense (10.0.0.1)") {
		t.Fatalf("unexpected Slack message: %s", slackMessages[0])
	}

	// A second failure within the hour must be debounced
	job2 := h.startScanJob([]string{"10.0.0.0/24"}, false, scanModeQuick)
	<-job2.done
	if len(slackMessages) != 1 {
		t.Fatalf("expected still 1 Slack notification after debounced second failure, got %d", len(slackMessages))
	}
}

type testSwitchableRemoteRunner struct {
	gateway string
	target  string
	fail    bool
	err     error
}

func (r *testSwitchableRemoteRunner) HasRemoteScannerForTarget(target string) bool {
	return target == r.target
}
func (r *testSwitchableRemoteRunner) GetGatewayForTarget(target string) string {
	return r.gateway
}
func (r *testSwitchableRemoteRunner) CanRunPrivileged(target string) bool {
	return false
}
func (r *testSwitchableRemoteRunner) RunScan(ctx context.Context, target string, args []string) ([]byte, error) {
	if r.fail {
		return nil, &remotescan.RemoteScannerError{
			Gateway:       r.gateway,
			Target:        target,
			Err:           r.err,
			IsMissingNmap: true,
		}
	}
	return []byte(`<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>`), nil
}
func (r *testSwitchableRemoteRunner) Close() error { return nil }

func TestRemoteScannerAlertOnceAndRecoveryNotification(t *testing.T) {
	store := newScanJobTestStore(t)
	_ = store.SaveNetworkNotification("10.0.0.0/24", "https://example.test/slack-opnsense", true)
	// Pre-seed the gateway returned by testSwitchableRemoteRunner so recovery
	// does not also emit a new-device sweep report.
	_ = store.UpdateDevice(&types.Device{
		IP:        "10.0.0.1",
		Hostname:  "opnsense",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	})

	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.0.0.0/24"}
	cfg.Scanning.OnlyConfiguredNetworks = true
	h := newTestHandler(t, store, cfg)
	defer h.Close()

	var mu sync.Mutex
	var slackMessages []string
	h.sendSlackNotification = func(webhook, text string) error {
		mu.Lock()
		slackMessages = append(slackMessages, text)
		mu.Unlock()
		return nil
	}

	runner := &testSwitchableRemoteRunner{
		gateway: "opnsense (10.0.0.1)",
		target:  "10.0.0.0/24",
		fail:    true,
		err:     fmt.Errorf("nmap: not found"),
	}
	h.scanner.SetRemoteRunner(runner)
	ctx := context.Background()

	// 1. First failure -> 1 failure Slack alert
	_, _ = h.scanNetwork(ctx, "10.0.0.0/24")
	mu.Lock()
	if len(slackMessages) != 1 {
		t.Fatalf("expected 1 Slack notification, got %d: %v", len(slackMessages), slackMessages)
	}
	if !strings.Contains(slackMessages[0], "Remote Scanner Failure") {
		t.Fatalf("unexpected message: %s", slackMessages[0])
	}
	mu.Unlock()

	// 2. Second failure while still down -> 0 new alerts (suppressed, no repeat spam)
	_, _ = h.scanNetwork(ctx, "10.0.0.0/24")
	mu.Lock()
	if len(slackMessages) != 1 {
		t.Fatalf("expected still 1 notification after second failure, got %d", len(slackMessages))
	}
	mu.Unlock()

	// 3. Scanner recovers -> 1 recovery Slack alert
	runner.fail = false
	_, err := h.scanNetwork(ctx, "10.0.0.0/24")
	if err != nil {
		t.Fatalf("scanNetwork: %v", err)
	}
	mu.Lock()
	if len(slackMessages) != 2 {
		t.Fatalf("expected 2 Slack notifications after recovery, got %d: %v", len(slackMessages), slackMessages)
	}
	if !strings.Contains(slackMessages[1], "Remote Scanner Recovered") || !strings.Contains(slackMessages[1], "opnsense (10.0.0.1)") {
		t.Fatalf("unexpected recovery message: %s", slackMessages[1])
	}
	mu.Unlock()

	// 4. Continued success -> 0 new alerts
	_, _ = h.scanNetwork(ctx, "10.0.0.0/24")
	mu.Lock()
	if len(slackMessages) != 2 {
		t.Fatalf("expected still 2 Slack notifications after continued success, got %d", len(slackMessages))
	}
	mu.Unlock()

	// 5. Subsequent failure -> 1 new failure alert
	runner.fail = true
	_, _ = h.scanNetwork(ctx, "10.0.0.0/24")
	mu.Lock()
	if len(slackMessages) != 3 {
		t.Fatalf("expected 3 Slack notifications after new failure, got %d: %v", len(slackMessages), slackMessages)
	}
	if !strings.Contains(slackMessages[2], "Remote Scanner Failure") {
		t.Fatalf("unexpected message: %s", slackMessages[2])
	}
	mu.Unlock()
}

func TestScanJob_RecordsAndClearsNetworkScanError(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.0.0.0/24"}
	cfg.Scanning.OnlyConfiguredNetworks = true
	h := newTestHandler(t, store, cfg)
	runner := &testSwitchableRemoteRunner{
		gateway: "opnsense (10.0.0.1)",
		target:  "10.0.0.0/24",
		fail:    true,
		err:     fmt.Errorf("dial tcp: connection refused"),
	}
	h.scanner.SetRemoteRunner(runner)
	ctx := context.Background()

	// Initial state: no error
	if got := store.GetNetworkScanError("10.0.0.0/24"); got != "" {
		t.Fatalf("expected empty error initially, got %q", got)
	}

	// 1. Scan fails -> records error in store
	_, _ = h.scanNetwork(ctx, "10.0.0.0/24")
	if got := store.GetNetworkScanError("10.0.0.0/24"); !strings.Contains(got, "connection refused") {
		t.Fatalf("expected error containing 'connection refused', got %q", got)
	}

	// 2. Scan recovers -> clears error in store
	runner.fail = false
	_, err := h.scanNetwork(ctx, "10.0.0.0/24")
	if err != nil {
		t.Fatalf("scanNetwork: %v", err)
	}
	if got := store.GetNetworkScanError("10.0.0.0/24"); got != "" {
		t.Fatalf("expected empty error after recovery, got %q", got)
	}
}

type testMultiSubnetRunner struct {
	failMap map[string]error
}

func (r *testMultiSubnetRunner) HasRemoteScannerForTarget(target string) bool {
	return true
}
func (r *testMultiSubnetRunner) GetGatewayForTarget(target string) string {
	return "gw (" + target + ")"
}
func (r *testMultiSubnetRunner) CanRunPrivileged(target string) bool {
	return false
}
func (r *testMultiSubnetRunner) RunScan(ctx context.Context, target string, args []string) ([]byte, error) {
	if err, fail := r.failMap[target]; fail {
		return nil, &remotescan.RemoteScannerError{
			Gateway: "gw (" + target + ")",
			Target:  target,
			Err:     err,
		}
	}
	return []byte(`<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><address addr="00:11:22:33:44:55" addrtype="mac"/><hostnames><hostname name="box.internal" type="PTR"/></hostnames></host></nmaprun>`), nil
}
func (r *testMultiSubnetRunner) Close() error { return nil }

func TestScanJob_RecordsPerNetworkScanHistoryOnSuccessAndFailure(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.0.0.0/24", "10.5.5.0/24"}
	cfg.Scanning.OnlyConfiguredNetworks = true
	cfg.Scanning.PortScanRange = ""
	cfg.Scanning.EnablePortScan = false
	h := newTestHandler(t, store, cfg)

	// Pre-seed 10.0.0.1 so new device deep scan doesn't run
	_, _, _ = store.MergeDevices([]types.Device{{
		IP:        "10.0.0.1",
		Hostname:  "router",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}})

	// mock runner: 10.5.5.0/24 fails with SSH timeout
	runner := &testMultiSubnetRunner{
		failMap: map[string]error{
			"10.5.5.0/24": fmt.Errorf("SSH dial timeout"),
		},
	}
	h.scanner.SetRemoteRunner(runner)

	job := h.startScanJob(cfg.Scanning.Networks, false, scanModeQuick)
	<-job.done

	history, err := store.GetScanHistory()
	if err != nil {
		t.Fatalf("GetScanHistory: %v", err)
	}

	// Should have 2 records: one for 10.0.0.0/24 and one for 10.5.5.0/24
	if len(history) != 2 {
		t.Fatalf("expected 2 history records, got %d: %+v", len(history), history)
	}

	var rec10, rec55 *types.ScanHistoryRecord
	for i := range history {
		if history[i].Network == "10.0.0.0/24" {
			rec10 = &history[i]
		} else if history[i].Network == "10.5.5.0/24" {
			rec55 = &history[i]
		}
	}

	if rec10 == nil {
		t.Fatal("missing record for 10.0.0.0/24")
	}
	if !rec10.Success {
		t.Errorf("expected 10.0.0.0/24 success = true, got error %q", rec10.Error)
	}

	if rec55 == nil {
		t.Fatal("missing record for 10.5.5.0/24")
	}
	if rec55.Success {
		t.Errorf("expected 10.5.5.0/24 success = false")
	}
	if !strings.Contains(rec55.Error, "SSH dial timeout") {
		t.Errorf("expected 10.5.5.0/24 error to contain 'SSH dial timeout', got %q", rec55.Error)
	}
}

func TestNotifyFailure_FallbackWebhook(t *testing.T) {
	store := newScanJobTestStore(t)
	// Only 10.0.0.0/24 has a webhook configured
	_ = store.SaveNetworkNotification("10.0.0.0/24", "https://example.test/primary-slack", true)

	cfg := config.Default()
	h := newTestHandler(t, store, cfg)
	h.scanner.SetRemoteRunner(&testSwitchableRemoteRunner{
		gateway: "openwrt (10.5.5.1)",
		target:  "10.5.5.0/24",
	})

	var sentWebhooks []string
	var sentMessages []string
	h.sendSlackNotification = func(webhook, text string) error {
		sentWebhooks = append(sentWebhooks, webhook)
		sentMessages = append(sentMessages, text)
		return nil
	}

	// 1. Failure on 10.5.5.0/24 (which has no dedicated webhook)
	h.notifyRemoteScannerFailure("10.5.5.0/24", "10.5.5.0/24", fmt.Errorf("connection refused"))
	if len(sentWebhooks) != 1 {
		t.Fatalf("expected 1 alert sent via fallback, got %d", len(sentWebhooks))
	}
	if sentWebhooks[0] != "https://example.test/primary-slack" {
		t.Errorf("expected fallback webhook 'https://example.test/primary-slack', got %q", sentWebhooks[0])
	}
	if !strings.Contains(sentMessages[0], "openwrt (10.5.5.1)") {
		t.Errorf("expected message to mention gateway, got %q", sentMessages[0])
	}

	// 2. Recovery on 10.5.5.0/24
	h.notifyRemoteScannerSuccess("10.5.5.0/24", "10.5.5.0/24")
	if len(sentWebhooks) != 2 {
		t.Fatalf("expected recovery alert sent via fallback, got %d", len(sentWebhooks))
	}
	if sentWebhooks[1] != "https://example.test/primary-slack" {
		t.Errorf("expected recovery webhook 'https://example.test/primary-slack', got %q", sentWebhooks[1])
	}
}

func TestScanJob_MultiOpenWrtRouters(t *testing.T) {
	cfg := config.Default()
	cfg.OpenWrts.Names = []string{"core", "branch"}
	cfg.OpenWrts.Configs = map[string]config.OpenWrtConfig{
		"core": {
			ID:     "core",
			Enable: true,
			URL:    "https://10.5.5.1",
		},
		"branch": {
			ID:     "branch",
			Enable: true,
			URL:    "https://10.6.6.1",
		},
	}

	all := cfg.AllOpenWrts()
	if len(all) != 2 {
		t.Fatalf("expected 2 OpenWrts, got %d", len(all))
	}
}

func TestPrioritizeDeepScanDevices(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	devices := []types.Device{
		{IP: "10.0.0.3", LastDeepScanAt: t2},          // scanned recently
		{IP: "10.0.0.1", LastDeepScanAt: time.Time{}}, // never scanned
		{IP: "10.0.0.4", LastDeepScanAt: t1},          // scanned older
		{IP: "10.0.0.2", LastDeepScanAt: time.Time{}}, // never scanned
	}

	sorted := prioritizeDeepScanDevices(devices)
	wantIPs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.4", "10.0.0.3"}
	for i, dev := range sorted {
		if dev.IP != wantIPs[i] {
			t.Fatalf("at index %d got IP %s, want %s (sorted: %+v)", i, dev.IP, wantIPs[i], sorted)
		}
	}
}

type testConcurrencyTrackingRemoteRunner struct {
	mu             sync.Mutex
	activePerGW    map[string]int
	maxPerGW       map[string]int
	activeGlobal   int
	maxGlobal      int
	expectedGlobal int
	allEntered     chan struct{}
	enteredOnce    sync.Once
}

func (r *testConcurrencyTrackingRemoteRunner) HasRemoteScannerForTarget(target string) bool {
	return strings.HasPrefix(target, "10.0.") || strings.HasPrefix(target, "10.5.")
}

func (r *testConcurrencyTrackingRemoteRunner) GetGatewayForTarget(target string) string {
	if strings.HasPrefix(target, "10.0.") {
		return "opnsense"
	}
	if strings.HasPrefix(target, "10.5.") {
		return "openwrt"
	}
	return "local"
}

func (r *testConcurrencyTrackingRemoteRunner) CanRunPrivileged(target string) bool {
	return false
}

func (r *testConcurrencyTrackingRemoteRunner) RunScan(ctx context.Context, target string, args []string) ([]byte, error) {
	gw := r.GetGatewayForTarget(target)
	r.mu.Lock()
	if r.activePerGW == nil {
		r.activePerGW = make(map[string]int)
		r.maxPerGW = make(map[string]int)
	}
	r.activePerGW[gw]++
	if r.activePerGW[gw] > r.maxPerGW[gw] {
		r.maxPerGW[gw] = r.activePerGW[gw]
	}
	r.activeGlobal++
	if r.activeGlobal > r.maxGlobal {
		r.maxGlobal = r.activeGlobal
	}
	if r.expectedGlobal > 0 && r.allEntered != nil && r.activeGlobal >= r.expectedGlobal {
		r.enteredOnce.Do(func() { close(r.allEntered) })
	}
	allEntered := r.allEntered
	r.mu.Unlock()

	if allEntered != nil {
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-allEntered:
		case <-ctx.Done():
		case <-timer.C:
		}
		timer.Stop()
	}

	r.mu.Lock()
	r.activePerGW[gw]--
	r.activeGlobal--
	r.mu.Unlock()

	return []byte(`<nmaprun></nmaprun>`), nil
}

func (r *testConcurrencyTrackingRemoteRunner) Close() error { return nil }

func TestScanJob_Stage1AllSubnetsParallelSweep(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.0.0.0/24", "10.0.1.0/24", "10.5.5.0/24", "10.5.6.0/24"}
	cfg.Scanning.OnlyConfiguredNetworks = true
	cfg.Scanning.MinScanInterval = 1
	h := newTestHandler(t, store, cfg)

	runner := &testConcurrencyTrackingRemoteRunner{
		expectedGlobal: 4,
		allEntered:     make(chan struct{}),
	}
	h.scanner.SetRemoteRunner(runner)

	job := h.startScanJob(cfg.Scanning.Networks, false, scanModeQuick)
	<-job.done

	runner.mu.Lock()
	defer runner.mu.Unlock()

	if runner.maxGlobal != 4 {
		t.Fatalf("expected all 4 subnets sweeping in parallel, got maxGlobal = %d", runner.maxGlobal)
	}

	job.mu.RLock()
	defer job.mu.RUnlock()
	subnetsDone := 0
	for _, res := range job.results {
		if strings.HasPrefix(res.Network, "10.") {
			subnetsDone++
		}
	}
	if subnetsDone != 4 {
		t.Fatalf("expected 4 subnets completed, got %d", subnetsDone)
	}
}

type testDeepScanConcurrencyRemoteRunner struct {
	mu                    sync.Mutex
	activeHostsPerGW      map[string]int
	maxHostsPerGW         map[string]int
	activeSubnetsPerGW    map[string]map[string]int
	maxActiveSubnetsPerGW map[string]int
	maxGlobalHosts        int
	activeGlobalHosts     int
	expectedGlobalHosts   int
	allEntered            chan struct{}
	enteredOnce           sync.Once
}

func (r *testDeepScanConcurrencyRemoteRunner) HasRemoteScannerForTarget(target string) bool {
	return strings.HasPrefix(target, "10.0.") || strings.HasPrefix(target, "10.5.")
}

func (r *testDeepScanConcurrencyRemoteRunner) GetGatewayForTarget(target string) string {
	if strings.HasPrefix(target, "10.0.") {
		return "opnsense"
	}
	if strings.HasPrefix(target, "10.5.") {
		return "openwrt"
	}
	return "local"
}

func (r *testDeepScanConcurrencyRemoteRunner) CanRunPrivileged(target string) bool {
	return false
}

func (r *testDeepScanConcurrencyRemoteRunner) RunScan(ctx context.Context, target string, args []string) ([]byte, error) {
	if strings.Contains(target, "/") {
		// Stage 1 ping sweep
		return []byte(`<nmaprun></nmaprun>`), nil
	}
	// Stage 2 host port scan
	gw := r.GetGatewayForTarget(target)
	subnet := "10.0.0.0/24"
	if strings.HasPrefix(target, "10.0.1.") {
		subnet = "10.0.1.0/24"
	} else if strings.HasPrefix(target, "10.5.5.") {
		subnet = "10.5.5.0/24"
	} else if strings.HasPrefix(target, "10.5.6.") {
		subnet = "10.5.6.0/24"
	}

	r.mu.Lock()
	if r.activeHostsPerGW == nil {
		r.activeHostsPerGW = make(map[string]int)
		r.maxHostsPerGW = make(map[string]int)
		r.activeSubnetsPerGW = make(map[string]map[string]int)
		r.maxActiveSubnetsPerGW = make(map[string]int)
	}
	if r.activeSubnetsPerGW[gw] == nil {
		r.activeSubnetsPerGW[gw] = make(map[string]int)
	}

	r.activeHostsPerGW[gw]++
	if r.activeHostsPerGW[gw] > r.maxHostsPerGW[gw] {
		r.maxHostsPerGW[gw] = r.activeHostsPerGW[gw]
	}
	r.activeSubnetsPerGW[gw][subnet]++
	activeSubnets := 0
	for _, count := range r.activeSubnetsPerGW[gw] {
		if count > 0 {
			activeSubnets++
		}
	}
	if activeSubnets > r.maxActiveSubnetsPerGW[gw] {
		r.maxActiveSubnetsPerGW[gw] = activeSubnets
	}

	r.activeGlobalHosts++
	if r.activeGlobalHosts > r.maxGlobalHosts {
		r.maxGlobalHosts = r.activeGlobalHosts
	}
	if r.expectedGlobalHosts > 0 && r.allEntered != nil && r.activeGlobalHosts >= r.expectedGlobalHosts {
		r.enteredOnce.Do(func() { close(r.allEntered) })
	}
	allEntered := r.allEntered
	r.mu.Unlock()

	if allEntered != nil {
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-allEntered:
		case <-ctx.Done():
		case <-timer.C:
		}
		timer.Stop()
	}

	r.mu.Lock()
	r.activeHostsPerGW[gw]--
	r.activeSubnetsPerGW[gw][subnet]--
	r.activeGlobalHosts--
	r.mu.Unlock()

	return []byte(`<nmaprun><host><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>`), nil
}

func (r *testDeepScanConcurrencyRemoteRunner) Close() error { return nil }

func TestScanJob_Stage2PerGatewayDeepScan(t *testing.T) {
	store := newScanJobTestStore(t)
	// Seed 8 online devices across 2 subnets on opnsense and 2 subnets on openwrt
	for _, ip := range []string{
		"10.0.0.10", "10.0.0.11",
		"10.0.1.10", "10.0.1.11",
		"10.5.5.10", "10.5.5.11",
		"10.5.6.10", "10.5.6.11",
	} {
		_ = store.UpdateDevice(&types.Device{
			IP:       ip,
			MAC:      "aa:bb:cc:dd:ee:ff",
			LastSeen: time.Now(),
		})
	}

	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.0.0.0/24", "10.0.1.0/24", "10.5.5.0/24", "10.5.6.0/24"}
	cfg.Scanning.PortScanRange = "80"
	cfg.Scanning.EnablePortScan = true
	h := newTestHandler(t, store, cfg)

	runner := &testDeepScanConcurrencyRemoteRunner{
		expectedGlobalHosts: 4,
		allEntered:          make(chan struct{}),
	}
	h.scanner.SetRemoteRunner(runner)

	job := h.startScanJob(cfg.Scanning.Networks, false, scanModeDeep)
	<-job.done

	runner.mu.Lock()
	defer runner.mu.Unlock()

	// 1 subnet at a time per gateway!
	if runner.maxActiveSubnetsPerGW["opnsense"] != 1 {
		t.Fatalf("expected opnsense max concurrent subnets = 1, got %d", runner.maxActiveSubnetsPerGW["opnsense"])
	}
	if runner.maxActiveSubnetsPerGW["openwrt"] != 1 {
		t.Fatalf("expected openwrt max concurrent subnets = 1, got %d", runner.maxActiveSubnetsPerGW["openwrt"])
	}

	// 2 hosts per gateway!
	if runner.maxHostsPerGW["opnsense"] != 2 {
		t.Fatalf("expected opnsense max concurrent hosts = 2, got %d", runner.maxHostsPerGW["opnsense"])
	}
	if runner.maxHostsPerGW["openwrt"] != 2 {
		t.Fatalf("expected openwrt max concurrent hosts = 2, got %d", runner.maxHostsPerGW["openwrt"])
	}

	// Global concurrency reaches 4 (2 on opnsense + 2 on openwrt)
	if runner.maxGlobalHosts != 4 {
		t.Fatalf("expected global concurrent hosts = 4 (2 per gateway), got %d", runner.maxGlobalHosts)
	}
}

type testControlledRemoteRunner struct {
	fn func(ctx context.Context, target string, args []string) ([]byte, error)
}

func (r *testControlledRemoteRunner) HasRemoteScannerForTarget(target string) bool {
	return true
}

func (r *testControlledRemoteRunner) GetGatewayForTarget(target string) string {
	if strings.HasPrefix(target, "10.0.") {
		return "opnsense"
	}
	if strings.HasPrefix(target, "10.5.") {
		return "openwrt"
	}
	return "local"
}

func (r *testControlledRemoteRunner) CanRunPrivileged(target string) bool {
	return false
}

func (r *testControlledRemoteRunner) RunScan(ctx context.Context, target string, args []string) ([]byte, error) {
	if r.fn != nil {
		return r.fn(ctx, target, args)
	}
	return nil, nil
}

func (r *testControlledRemoteRunner) Close() error { return nil }

func TestScanJob_Stage2PerSubnetDeepScanningLifecycle(t *testing.T) {
	store := newScanJobTestStore(t)
	// Seed 1 device on opnsense (fast) and 1 device on openwrt (slow)
	_ = store.UpdateDevice(&types.Device{
		IP:       "10.0.0.10",
		MAC:      "aa:bb:cc:dd:ee:01",
		LastSeen: time.Now(),
	})
	_ = store.UpdateDevice(&types.Device{
		IP:       "10.5.5.10",
		MAC:      "aa:bb:cc:dd:ee:02",
		LastSeen: time.Now(),
	})

	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.0.0.0/24", "10.5.5.0/24"}
	cfg.Scanning.PortScanRange = "80"
	cfg.Scanning.EnablePortScan = true
	h := newTestHandler(t, store, cfg)

	opnDone := make(chan struct{})
	unblockOpenwrt := make(chan struct{})
	openwrtRunning := make(chan struct{})

	runner := &testControlledRemoteRunner{
		fn: func(ctx context.Context, target string, args []string) ([]byte, error) {
			if strings.Contains(target, "10.0.0.10") {
				// Fast opnsense completes immediately
				defer close(opnDone)
				return []byte(`<nmaprun><host><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>`), nil
			}
			if strings.Contains(target, "10.5.5.10") {
				close(openwrtRunning)
				<-unblockOpenwrt
				return []byte(`<nmaprun><host><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>`), nil
			}
			return nil, fmt.Errorf("unexpected target %s", target)
		},
	}
	h.scanner.SetRemoteRunner(runner)

	job := h.startScanJob(cfg.Scanning.Networks, false, scanModeDeep)

	// Wait until openwrt is running and opnsense has completed
	<-openwrtRunning
	<-opnDone

	// Wait until opnsense (10.0.0.0/24) has finished its subnet deep scan queue
	deadline := time.Now().Add(5 * time.Second)
	for store.IsNetworkDeepScanning("10.0.0.0/24") && time.Now().Before(deadline) {
		runtime.Gosched()
	}

	// At this point, opnsense deep scan is complete, so 10.0.0.0/24 should NOT be deep scanning!
	// But 10.5.5.0/24 is still waiting, so it SHOULD be deep scanning!
	if store.IsNetworkDeepScanning("10.0.0.0/24") {
		t.Error("expected 10.0.0.0/24 deep scanning to be false after its subnet finished")
	}
	if !store.IsNetworkDeepScanning("10.5.5.0/24") {
		t.Error("expected 10.5.5.0/24 deep scanning to be true while still running")
	}

	close(unblockOpenwrt)
	<-job.done

	if store.IsNetworkDeepScanning("10.5.5.0/24") {
		t.Error("expected 10.5.5.0/24 deep scanning to be false after completion")
	}
}

type testBlockingRemoteRunner struct {
	started      chan string
	continueChan chan struct{}
}

func (r *testBlockingRemoteRunner) HasRemoteScannerForTarget(target string) bool {
	return true
}

func (r *testBlockingRemoteRunner) GetGatewayForTarget(target string) string {
	if strings.HasPrefix(target, "10.0.") {
		return "opnsense"
	}
	return "openwrt"
}

func (r *testBlockingRemoteRunner) CanRunPrivileged(target string) bool {
	return false
}

func (r *testBlockingRemoteRunner) RunScan(ctx context.Context, target string, args []string) ([]byte, error) {
	r.started <- target
	<-r.continueChan
	return []byte(`<nmaprun></nmaprun>`), nil
}

func (r *testBlockingRemoteRunner) Close() error { return nil }

func TestScanJob_SnapshotReportsActiveNetworksDuringParallelSweep(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.0.0.0/24", "10.5.5.0/24"}
	cfg.Scanning.OnlyConfiguredNetworks = true
	h := newTestHandler(t, store, cfg)

	startedSweep := make(chan string, 2)
	continueSweep := make(chan struct{})

	h.scanner.SetRemoteRunner(&testBlockingRemoteRunner{
		started:      startedSweep,
		continueChan: continueSweep,
	})

	job := h.startScanJob(cfg.Scanning.Networks, false, scanModeQuick)
	// Wait until both networks have started their sweep
	<-startedSweep
	<-startedSweep

	// Both networks must be active in snapshot and storage!
	snap := job.snapshot(cfg, store)
	if len(snap.ActiveNetworks) != 2 {
		t.Fatalf("expected 2 active_networks in snapshot, got %d: %v", len(snap.ActiveNetworks), snap.ActiveNetworks)
	}
	if !strings.Contains(snap.CurrentNetwork, "10.0.0.0/24") || !strings.Contains(snap.CurrentNetwork, "10.5.5.0/24") {
		t.Fatalf("expected CurrentNetwork to list both active networks, got: %s", snap.CurrentNetwork)
	}

	if !store.IsNetworkScanning("10.0.0.0/24") || !store.IsNetworkScanning("10.5.5.0/24") {
		t.Fatalf("expected both networks IsNetworkScanning=true in storage")
	}

	// Release sweeps
	close(continueSweep)
	<-job.done

	// When job completes, storage active networks must be cleared
	if store.IsNetworkScanning("10.0.0.0/24") || store.IsNetworkScanning("10.5.5.0/24") {
		t.Fatalf("expected networks cleared from active scanning after job done")
	}
}

func TestScanJob_TelemetryExcludesSupplementalFromNetworkCountAndDeduplicatesDevices(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.0.0.0/24", "10.0.1.0/24"}
	cfg.Scanning.OnlyConfiguredNetworks = true

	job := &scanJob{
		id:             "test-job",
		networks:       cfg.Scanning.Networks,
		startedAt:      time.Now(),
		status:         "running",
		activeNetworks: make(map[string]string),
	}

	// Subnet 1 finds 10.0.0.1 and 10.0.0.2
	job.recordDiscoveredIPs([]string{"10.0.0.1", "10.0.0.2"})
	job.addResult(networkScanSummary{
		Network:     "10.0.0.0/24",
		Status:      "scanned",
		DeviceCount: 2,
	})

	// Subnet 2 finds 10.0.1.1
	job.recordDiscoveredIPs([]string{"10.0.1.1"})
	job.addResult(networkScanSummary{
		Network:     "10.0.1.0/24",
		Status:      "scanned",
		DeviceCount: 1,
	})

	// Supplemental source: DHCP finds 10.0.0.1 (existing) and 10.0.1.1 (existing)
	job.recordDiscoveredIPs([]string{"10.0.0.1", "10.0.1.1"})
	job.addResult(networkScanSummary{
		Network:        "OPNsense DHCP",
		Status:         "scanned",
		DeviceCount:    2,
		IsSupplemental: true,
	})

	// Supplemental source: switch SNMP reports 2 switch connections (MAC mapping)
	job.addResult(networkScanSummary{
		Network:        "switchy SNMP",
		Status:         "scanned",
		DeviceCount:    2,
		IsSupplemental: true,
	})

	snap := job.snapshot(cfg, store)

	// NetworkCount should be 2 (only the actual subnets)
	if snap.NetworkCount != 2 {
		t.Errorf("NetworkCount = %d, want 2", snap.NetworkCount)
	}

	// ScannedNetworkCount should be 2 (both subnets scanned, excluding supplemental)
	if snap.ScannedNetworkCount != 2 {
		t.Errorf("ScannedNetworkCount = %d, want 2", snap.ScannedNetworkCount)
	}

	// DeviceCount should be 3 (10.0.0.1, 10.0.0.2, 10.0.1.1 deduplicated, NOT 2+1+2+2=7!)
	if snap.DeviceCount != 3 {
		t.Errorf("DeviceCount = %d, want 3", snap.DeviceCount)
	}
}

func TestScanJob_BriefRateLimitWaitsAndProceeds(t *testing.T) {
	store := newScanJobTestStore(t)
	// Network was scanned 29.95s ago, with minInterval=30s, wait is ~50ms
	_ = store.SetLastScan("10.0.0.0/24", time.Now().Add(-29950*time.Millisecond))

	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.0.0.0/24"}
	cfg.Scanning.OnlyConfiguredNetworks = true
	h := newTestHandler(t, store, cfg)

	scanned := false
	runner := &testControlledRemoteRunner{
		fn: func(ctx context.Context, target string, args []string) ([]byte, error) {
			scanned = true
			return []byte(`<nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/><status state="up"/></host></nmaprun>`), nil
		},
	}
	h.scanner.SetRemoteRunner(runner)

	job := h.startScanJob(cfg.Scanning.Networks, false, scanModeQuick)
	<-job.done

	if !scanned {
		t.Fatal("expected network to be scanned after brief wait, but it was skipped")
	}

	snap := job.snapshot(cfg, store)
	if snap.ScannedNetworkCount != 1 {
		t.Fatalf("ScannedNetworkCount = %d, want 1", snap.ScannedNetworkCount)
	}
	if len(snap.Networks) == 0 || snap.Networks[0].Status != "scanned" {
		t.Fatalf("expected network status = scanned, got: %+v", snap.Networks)
	}
}

func TestScanJob_RouterAPIFailureAlertAndRecovery(t *testing.T) {
	store := newScanJobTestStore(t)
	_ = store.SaveNetworkNotification("10.5.5.0/24", "https://example.test/slack-openwrt", true)

	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.5.5.0/24"}
	cfg.Scanning.OnlyConfiguredNetworks = true
	cfg.OpenWrt.Enable = true
	cfg.OpenWrt.ID = "openwrt"
	cfg.OpenWrt.Networks = []string{"10.5.5.0/24"}
	cfg.OpenWrt.URL = "http://127.0.0.1:1"
	h := newTestHandler(t, store, cfg)

	var mu sync.Mutex
	var slackMessages []string
	h.sendSlackNotification = func(webhook, text string) error {
		mu.Lock()
		slackMessages = append(slackMessages, text)
		mu.Unlock()
		return nil
	}

	h.notifyRouterAPIFailure("OpenWrt", "openwrt", cfg.OpenWrt.Networks, fmt.Errorf("401 Unauthorized"))
	mu.Lock()
	if len(slackMessages) != 1 || !strings.Contains(slackMessages[0], "Router API Failure") {
		t.Fatalf("expected 1 Router API Failure message, got: %v", slackMessages)
	}
	mu.Unlock()

	// Second failure -> suppressed (no repeat spam)
	h.notifyRouterAPIFailure("OpenWrt", "openwrt", cfg.OpenWrt.Networks, fmt.Errorf("401 Unauthorized"))
	mu.Lock()
	if len(slackMessages) != 1 {
		t.Fatalf("expected failure alert to be debounced, got %d messages", len(slackMessages))
	}
	mu.Unlock()

	// Recovery -> 1 recovery alert
	h.notifyRouterAPISuccess("OpenWrt", "openwrt", cfg.OpenWrt.Networks)
	mu.Lock()
	if len(slackMessages) != 2 || !strings.Contains(slackMessages[1], "Router API Recovered") {
		t.Fatalf("expected recovery alert, got: %v", slackMessages)
	}
	mu.Unlock()
}

func TestScanJob_SwitchesResolveUnknownVLANInventoryMACThroughBridgeFDB(t *testing.T) {
	store := newScanJobTestStore(t)
	if err := store.UpdateDevice(&types.Device{IP: "192.168.1.11", MAC: "AA:BB:CC:DD:EE:02"}); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	cfg := switchTestConfig("edge-a")
	h := newTestHandler(t, store, cfg)
	h.fetchSwitchConnections = func(_ context.Context, switchCfg config.SwitchConfig, vlanByMAC map[string]int) ([]scanner.SwitchConnection, error) {
		vlan, ok := vlanByMAC["aa:bb:cc:dd:ee:02"]
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
	h := newTestHandler(t, store, cfg)
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
	h := newTestHandler(t, store, cfg)
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
	h := newTestHandler(t, store, cfg)
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
	h := newTestHandler(t, store, cfg)
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
	h := newTestHandler(t, store, cfg)
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
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func newTestHandler(t *testing.T, store *storage.Storage, cfg *config.Config) *Handler {
	t.Helper()
	h := NewHandler(store, cfg)
	h.discoverIPv6 = func(context.Context) []types.Device { return nil }
	h.discoverMDNS = func(context.Context) []types.Device { return nil }
	h.fetchOpenWrtDHCP = func(context.Context, config.OpenWrtConfig) ([]types.Device, []types.Device, error) {
		return nil, nil, nil
	}
	h.fetchOPNsenseDHCP = func(context.Context, config.OPNsenseConfig) ([]types.Device, []types.Device, []types.Device, error) {
		return nil, nil, nil, nil
	}
	h.fetchOpenWrtNlbwmon = func(context.Context, config.OpenWrtConfig) (map[string]*types.NetFlowDeviceStats, error) {
		return nil, nil
	}
	h.fetchUniFiClients = func(context.Context, config.UniFiConfig) ([]types.Device, error) { return nil, nil }
	h.fetchSwitchConnections = func(context.Context, config.SwitchConfig, map[string]int) ([]scanner.SwitchConnection, error) {
		return nil, nil
	}
	h.fetchOPNsenseNetFlow = func(context.Context, config.OPNsenseConfig) (map[string]*types.NetFlowDeviceStats, error) {
		return nil, nil
	}
	h.enrichWithServices = func(context.Context, []types.Device) {}
	h.sendSlackNotification = func(string, string) error { return nil }
	h.scanner.SetHooks(scanner.Hooks{
		LookPath: func(file string) (string, error) {
			return "", fmt.Errorf("%s disabled in test", file)
		},
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return nil, fmt.Errorf("command %s disabled in test", name)
		},
		GetInterface:   func(context.Context, string) string { return "eth0" },
		ReverseDNS:     func(context.Context, string, string) string { return "" },
		NetBIOSName:    func(context.Context, string) string { return "" },
		EnrichServices: func(context.Context, []types.Device) {},
		QueryMDNS:      func(context.Context) [][]byte { return nil },
		IPv6Interfaces: func() []string { return nil },
		RunIPv6Command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return nil, fmt.Errorf("ipv6 command %s disabled in test", name)
		},
	})
	t.Cleanup(func() { _ = h.Close() })
	return h
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

	store := newScanJobTestStore(t)

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

	h := newTestHandler(t, store, cfg)
	h.fetchUniFiClients = scanner.FetchUniFiClients
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

	store := newScanJobTestStore(t)

	cfg := config.Default()
	cfg.UniFi.Enable = true
	cfg.UniFi.URL = server.URL
	cfg.UniFi.Site = "default"
	cfg.UniFi.APIKey = "test-token"
	cfg.OpenWrt.Enable = false
	cfg.OPNsense.Enable = false

	h := newTestHandler(t, store, cfg)
	h.fetchUniFiClients = scanner.FetchUniFiClients

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

	store := newScanJobTestStore(t)

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
	_, err := store.GetDB().Exec("UPDATE devices SET is_online = 0, last_presence_change = ? WHERE ip = ?", twoHoursAgo, "192.168.1.99")
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

	h := newTestHandler(t, store, cfg)
	h.fetchUniFiClients = scanner.FetchUniFiClients

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

func TestScanJob_SnapshotConcurrentWithNightlyAndNewDeviceDeepScan(t *testing.T) {
	store := newScanJobTestStore(t)
	defer store.Close()

	now := time.Now()
	for _, ip := range []string{"192.168.1.10", "10.20.0.10", "10.30.0.10"} {
		if err := store.UpdateDevice(&types.Device{
			IP:       ip,
			MAC:      "aa:bb:cc:00:00:" + ip[len(ip)-2:],
			LastSeen: now,
		}); err != nil {
			t.Fatalf("UpdateDevice %s: %v", ip, err)
		}
	}

	cfg := config.Default()
	cfg.Scanning.Networks = []string{"192.168.1.0/24", "10.20.0.0/24", "10.30.0.0/24"}
	cfg.Scanning.PortScanRange = "22"
	h := newTestHandler(t, store, cfg)
	defer h.Close()

	h.scanner.SetRemoteRunner(&testControlledRemoteRunner{
		fn: func(ctx context.Context, target string, args []string) ([]byte, error) {
			return []byte(`<nmaprun></nmaprun>`), nil
		},
	})

	// 1. Concurrent snapshot() during runNightlyDeepScan() and runNewDeviceDeepScan().
	job := &scanJob{
		id:             "race-deep",
		status:         "running",
		startedAt:      now,
		networks:       []string{"192.168.1.0/24", "10.20.0.0/24", "10.30.0.0/24"},
		deepNetworks:   []string{"192.168.1.0/24", "10.20.0.0/24", "10.30.0.0/24"},
		accumulatedNew: []string{"192.168.1.10", "10.20.0.10"},
	}

	stopSnap := make(chan struct{})
	var snapWG sync.WaitGroup
	snapWG.Add(1)
	go func() {
		defer snapWG.Done()
		for {
			select {
			case <-stopSnap:
				return
			default:
				_ = job.snapshot(cfg, store)
			}
		}
	}()

	var deepWG sync.WaitGroup
	deepWG.Add(2)
	go func() {
		defer deepWG.Done()
		job.runNightlyDeepScan(context.Background(), h)
	}()
	go func() {
		defer deepWG.Done()
		job.runNewDeviceDeepScan(context.Background(), h)
	}()
	deepWG.Wait()
	close(stopSnap)
	snapWG.Wait()

	// 2. Parallel Stage 1 beginNetwork calls should track per-network timing rather
	// than clobbering a single scalar networkIndex and jumping Percent immediately.
	parallelJob := &scanJob{
		id:        "parallel-stage1",
		status:    "running",
		startedAt: time.Now(),
		networks:  []string{"192.168.1.0/24", "10.20.0.0/24", "10.30.0.0/24"},
	}
	var stageWG sync.WaitGroup
	for i, cidr := range parallelJob.networks {
		stageWG.Add(1)
		go func(c string, idx int) {
			defer stageWG.Done()
			parallelJob.beginNetwork(c, idx, 60)
		}(cidr, i+1)
	}
	stageWG.Wait()

	snap := parallelJob.snapshot(cfg, store)
	if snap.Percent > 25 {
		t.Fatalf("parallel beginNetwork jumped Percent to %.2f immediately at t=0; want <= 25", snap.Percent)
	}
}

func TestScanJob_DispatchDeferredNotificationsConcurrentWithAccumulate(t *testing.T) {
	store := newScanJobTestStore(t)
	defer store.Close()

	cfg := config.Default()
	cfg.Scanning.Networks = []string{"192.168.1.0/24"}
	h := newTestHandler(t, store, cfg)
	defer h.Close()

	_ = store.SaveNetworkNotification("192.168.1.0/24", "https://example.test/slack", true)
	h.sendSlackNotification = func(webhook, text string) error { return nil }

	if err := store.UpdateDevice(&types.Device{
		IP:        "192.168.1.50",
		MAC:       "aa:bb:cc:dd:ee:50",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	job := &scanJob{
		id:        "race-notify",
		status:    "running",
		startedAt: time.Now().Add(-time.Second),
		networks:  []string{"192.168.1.0/24"},
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			job.accumulate([]string{"192.168.1.50"}, []string{"192.168.1.50"})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			job.dispatchDeferredNotifications(h)
		}
	}()
	wg.Wait()
	h.WaitForScans()
}

func TestHandler_LifecycleCloseDrainsBackgroundGoroutines(t *testing.T) {
	store := newScanJobTestStore(t)
	defer store.Close()

	_ = store.SaveNetworkNotification("192.168.1.0/24", "https://example.test/slack", true)

	cfg := config.Default()
	cfg.Scanning.ScanInterval = 1
	h := newTestHandler(t, store, cfg)

	slackStarted := make(chan struct{})
	releaseSlack := make(chan struct{})
	var slackFinished sync.WaitGroup
	slackFinished.Add(1)
	var slackDone atomicBoolFlag
	h.sendSlackNotification = func(webhook, text string) error {
		close(slackStarted)
		<-releaseSlack
		slackDone.Set(true)
		slackFinished.Done()
		return nil
	}

	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()
	h.SetScanContext(bgCtx)
	h.StartBackgroundScanner(bgCtx, time.Hour)
	h.StartBackgroundCleanup(bgCtx)
	h.StartTrafficCollector(bgCtx)

	// Trigger async Slack notification via dispatchNotificationsWithMoves
	h.dispatchNotifications("192.168.1.0/24", []types.Device{{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:10"}}, nil)

	select {
	case <-slackStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for async Slack notification goroutine to start")
	}

	// Cancel context and start Close() in a goroutine; Close() must wait until the
	// in-flight Slack goroutine and background loops drain cleanly.
	bgCancel()
	closeReturned := make(chan error, 1)
	go func() {
		closeReturned <- h.Close()
	}()

	select {
	case err := <-closeReturned:
		t.Fatalf("Handler.Close() returned (%v) before async Slack goroutine finished", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseSlack)
	select {
	case err := <-closeReturned:
		if err != nil {
			t.Fatalf("Handler.Close() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Handler.Close() did not return after background goroutines unblocked")
	}

	if !slackDone.Get() {
		t.Fatal("expected async Slack goroutine to finish before Handler.Close() returned")
	}
	slackFinished.Wait()
}

type atomicBoolFlag struct {
	mu  sync.Mutex
	val bool
}

func (f *atomicBoolFlag) Set(v bool) {
	f.mu.Lock()
	f.val = v
	f.mu.Unlock()
}

func (f *atomicBoolFlag) Get() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.val
}

func TestScanJob_CleanupUsesStandardLogger(t *testing.T) {
	store := newScanJobTestStore(t)
	defer store.Close()

	// Insert an old offline device so runCleanup prunes it and logs a message.
	twoYearsAgo := time.Now().AddDate(-2, 0, 0)
	if err := store.UpdateDevice(&types.Device{
		IP:       "192.168.1.99",
		MAC:      "aa:bb:cc:dd:ee:99",
		LastSeen: twoYearsAgo,
	}); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	h := newTestHandler(t, store, config.Default())
	defer h.Close()

	var buf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOut)

	h.runCleanup()

	if !strings.Contains(buf.String(), "[CLEANUP] Pruned") {
		t.Fatalf("expected runCleanup to log via standard log.Printf (so /api/logs receives it), got log buffer: %q", buf.String())
	}
}

func TestEnrichGatewayMACs(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := config.Default()
	cfg.RemoteScanners = config.RemoteScannersConfig{
		Enable: true,
		Names:  []string{"opnsense"},
		Configs: map[string]config.RemoteScannerConfig{
			"opnsense": {ID: "opnsense", Host: "10.0.0.1", Networks: []string{"10.0.0.0/24"}},
		},
	}
	h := newTestHandler(t, store, cfg)

	now := time.Now()
	_ = store.UpdateDevice(&types.Device{
		IP:        "10.0.0.1",
		MAC:       "00:0d:b9:11:22:33",
		Vendor:    "PC Engines",
		FirstSeen: now,
		LastSeen:  now,
	})
	_ = store.UpdateDevice(&types.Device{
		IP:        "10.0.0.2",
		MAC:       "aa:bb:cc:00:00:02",
		Vendor:    "Ubiquiti",
		FirstSeen: now,
		LastSeen:  now,
	})

	devices := []types.Device{
		{IP: "10.0.0.1"}, // matches gwHost, empty MAC -> enriched
		{IP: "10.0.0.2"}, // matches stored IP fallback -> enriched
		{IP: "10.0.0.3", MAC: "11:22:33:44:55:66"}, // already has MAC -> untouched
		{IP: "10.0.0.4"}, // unknown -> stays empty
	}
	h.enrichGatewayMACs("10.0.0.0/24", devices)

	if devices[0].MAC != "00:0d:b9:11:22:33" || devices[0].Vendor != "PC Engines" {
		t.Errorf("gwHost device not enriched: %+v", devices[0])
	}
	if devices[1].MAC != "aa:bb:cc:00:00:02" || devices[1].Vendor != "Ubiquiti" {
		t.Errorf("stored IP fallback device not enriched: %+v", devices[1])
	}
	if devices[2].MAC != "11:22:33:44:55:66" {
		t.Errorf("existing MAC overwritten: %+v", devices[2])
	}
	if devices[3].MAC != "" {
		t.Errorf("unknown device got unexpected MAC: %+v", devices[3])
	}
}

func TestDispatchDeferredNotifications(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := config.Default()
	h := newTestHandler(t, store, cfg)

	_ = store.SaveNetworkNotification("10.10.0.0/24", "https://hooks.slack.com/services/T00/B00/ONE", true)
	var sent []string
	var sentMu sync.Mutex
	h.sendSlackNotification = func(webhookURL, text string) error {
		sentMu.Lock()
		sent = append(sent, text)
		sentMu.Unlock()
		return nil
	}

	startedAt := time.Now().Add(-1 * time.Minute)
	_ = store.UpdateDevice(&types.Device{
		IP:        "10.10.0.10",
		MAC:       "00:11:22:33:10:10",
		Hostname:  "fresh-host",
		FirstSeen: startedAt.Add(10 * time.Second),
		LastSeen:  startedAt.Add(10 * time.Second),
	})
	_ = store.UpdateDevice(&types.Device{
		IP:        "10.10.0.11",
		MAC:       "00:11:22:33:10:11",
		Hostname:  "preexisting-host",
		FirstSeen: startedAt.Add(-1 * time.Hour),
		LastSeen:  startedAt.Add(15 * time.Second),
	})
	_ = store.UpdateDevice(&types.Device{
		IP:           "10.10.0.12",
		MAC:          "00:11:22:33:10:12",
		Hostname:     "tracked-host",
		NotifyOnSeen: true,
		FirstSeen:    startedAt.Add(-2 * time.Hour),
		LastSeen:     startedAt.Add(20 * time.Second),
	})

	job := &scanJob{
		networks:        []string{"10.10.0.0/24"},
		startedAt:       startedAt,
		accumulatedNew:  []string{"10.10.0.10", "10.10.0.11"},
		accumulatedSeen: []string{"10.10.0.12"},
	}
	job.dispatchDeferredNotifications(h)
	h.WaitForScans()

	sentMu.Lock()
	defer sentMu.Unlock()
	if len(sent) != 1 {
		t.Fatalf("expected 1 Slack notification, got %d: %v", len(sent), sent)
	}
	if !strings.Contains(sent[0], "fresh-host") {
		t.Errorf("expected fresh-host in notification: %s", sent[0])
	}
	if strings.Contains(sent[0], "preexisting-host") {
		t.Errorf("preexisting-host should have been filtered from new devices: %s", sent[0])
	}
	if !strings.Contains(sent[0], "tracked-host") {
		t.Errorf("expected tracked-host in notification: %s", sent[0])
	}
}

func TestRunNewDeviceDeepScan(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := config.Default()
	cfg.Scanning.PortScanRange = "22,80"
	cfg.Scanning.ScanInterval = 300
	h := newTestHandler(t, store, cfg)

	var scannedTargets []string
	var scanMu sync.Mutex
	h.scanner.SetRemoteRunner(&testControlledRemoteRunner{
		fn: func(ctx context.Context, target string, args []string) ([]byte, error) {
			scanMu.Lock()
			scannedTargets = append(scannedTargets, target)
			scanMu.Unlock()
			return []byte(`<nmaprun><host><status state="up"/><address addr="10.20.0.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>`), nil
		},
	})

	now := time.Now()
	_ = store.UpdateDevice(&types.Device{
		IP:        "10.20.0.10",
		MAC:       "00:11:22:33:20:10",
		Hostname:  "new-online",
		FirstSeen: now,
		LastSeen:  now,
	})
	_ = store.UpdateDevice(&types.Device{
		IP:        "10.20.0.11",
		MAC:       "00:11:22:33:20:11",
		Hostname:  "new-offline",
		FirstSeen: now.Add(-2 * time.Hour),
		LastSeen:  now.Add(-2 * time.Hour),
	})

	job := &scanJob{
		networks:       []string{"10.20.0.0/24"},
		accumulatedNew: []string{"10.20.0.10", "10.20.0.11", "10.99.0.1"},
	}
	job.runNewDeviceDeepScan(context.Background(), h)

	if len(scannedTargets) != 1 || scannedTargets[0] != "10.20.0.10" {
		t.Fatalf("scannedTargets = %v, want [10.20.0.10]", scannedTargets)
	}
	updated := store.GetDevice("10.20.0.10")
	if updated == nil || len(updated.OpenPorts) != 1 || updated.OpenPorts[0] != 80 {
		t.Fatalf("expected open port 80 recorded on 10.20.0.10, got %+v", updated)
	}
}

func TestScanJob_OpenWrtAndOPNsensePollingInRun(t *testing.T) {
	store := newScanJobTestStore(t)
	cfg := config.Default()
	cfg.Scanning.Networks = []string{"10.0.0.0/24"}
	cfg.OpenWrt = config.OpenWrtConfig{
		Enable:  true,
		SSHHost: "10.0.0.2",
	}
	cfg.OPNsense = config.OPNsenseConfig{
		Enable:  true,
		SSHHost: "10.0.0.1",
	}
	h := newTestHandler(t, store, cfg)
	h.scanner.SetRemoteRunner(&testControlledRemoteRunner{
		fn: func(ctx context.Context, target string, args []string) ([]byte, error) {
			return []byte(`<nmaprun><host><status state="up"/><address addr="10.0.0.10" addrtype="ipv4"/><address addr="00:11:22:33:44:10" addrtype="mac"/></host></nmaprun>`), nil
		},
	})

	h.fetchOpenWrtDHCP = func(ctx context.Context, wrt config.OpenWrtConfig) ([]types.Device, []types.Device, error) {
		return []types.Device{{IP: "10.0.0.20", MAC: "00:11:22:33:44:20", Hostname: "wrt-lease", RouterSource: "OpenWrt"}},
			[]types.Device{{IP: "10.0.0.21", MAC: "00:11:22:33:44:21", Hostname: "wrt-static", RouterSource: "OpenWrt"}},
			nil
	}
	h.fetchOPNsenseDHCP = func(ctx context.Context, opn config.OPNsenseConfig) ([]types.Device, []types.Device, []types.Device, error) {
		return []types.Device{{IP: "10.0.0.30", MAC: "00:11:22:33:44:30", Hostname: "opn-lease", RouterSource: "OPNsense"}},
			nil,
			[]types.Device{{IP: "10.0.0.31", MAC: "00:11:22:33:44:31", Hostname: "opn-arp"}},
			nil
	}

	job := h.startScanJob([]string{"10.0.0.0/24"}, false, scanModeQuick)
	h.WaitForScans()

	snap := job.snapshot(cfg, store)
	if snap.Status != "done" {
		t.Fatalf("job status = %q, want done", snap.Status)
	}
	foundDHCP := false
	for _, res := range snap.Networks {
		if res.Network == "OpenWrt & OPNsense DHCP" && res.Status == "scanned" && res.DeviceCount == 3 {
			foundDHCP = true
		}
	}
	if !foundDHCP {
		t.Fatalf("expected 'OpenWrt & OPNsense DHCP' supplemental result in %+v", snap.Networks)
	}
	for _, ip := range []string{"10.0.0.20", "10.0.0.21", "10.0.0.30", "10.0.0.31"} {
		if store.GetDevice(ip) == nil {
			t.Errorf("expected router-discovered device %s in storage", ip)
		}
	}
}
