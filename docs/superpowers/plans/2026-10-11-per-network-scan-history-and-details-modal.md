# Per-Network Scan History, Scan Details Modal, and Resilient Failure Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide accurate per-network scan history records with discovered device snapshots, a detail popup modal on the Scans page, resilient Slack alert fallback, and accurate failure badges in the sidebar.

**Architecture:** Add a database migration for `devices_found` in `scan_history`, scope online/presence calculations to the scanned subnet, record per-network scan entries on discovery sweep completion, add fallback Slack webhook lookup, and implement a responsive device detail modal on `/scans`.

**Tech Stack:** Go (SQLite, database/sql, goose migrations, net/http), Vanilla JS/HTML/CSS (Web Components / DOM Modal).

**Spec:** `docs/superpowers/specs/2026-10-11-per-network-scan-history-and-details-modal.md`

## Global Constraints

- Never use LaTeX notation in terminal output.
- All Go code must format cleanly with `gofmt -l .` and pass `go vet ./...`.
- All tests must pass with race detection enabled: `go test -race ./...`.
- All JavaScript unit tests must pass with `node --test internal/web/static/*.test.js`.

---

### Task 1: Schema Migration and Data Types for Scan Devices

**Files:**
- Create: `internal/storage/migrations/00012_add_scan_history_devices.sql`
- Modify: `internal/types/types.go:250-265`
- Test: `internal/storage/storage_test.go`

**Interfaces:**
- Produces: `types.ScanDeviceRecord`, `types.ScanHistoryRecord.DevicesFound []ScanDeviceRecord`

- [ ] **Step 1: Write migration and types**

Create `internal/storage/migrations/00012_add_scan_history_devices.sql`:
```sql
-- +goose Up
ALTER TABLE scan_history ADD COLUMN devices_found TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE scan_history DROP COLUMN devices_found;
```

Update `internal/types/types.go` around line 250:
```go
// ScanDeviceRecord represents a device snapshot discovered during a scan
type ScanDeviceRecord struct {
	IP           string   `json:"ip"`
	MAC          string   `json:"mac,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
	Vendor       string   `json:"vendor,omitempty"`
	ResponseTime *float64 `json:"response_time,omitempty"`
	OpenPorts    []int    `json:"open_ports,omitempty"`
}

// ScanHistoryRecord represents a past scan execution log
type ScanHistoryRecord struct {
	ID              int                `json:"id"`
	Network         string             `json:"network"`
	Success         bool               `json:"success"`
	Error           string             `json:"error,omitempty"`
	DevicesOnline   int                `json:"devices_online"`
	DevicesJoined   int                `json:"devices_joined"`
	DevicesReturned int                `json:"devices_returned"`
	DevicesLeft     int                `json:"devices_left"`
	Duration        float64            `json:"duration"`
	Timestamp       time.Time          `json:"timestamp"`
	DevicesFound    []ScanDeviceRecord `json:"devices_found,omitempty"`
}
```

- [ ] **Step 2: Update storage schema test and verify migration runs**

Add a test in `internal/storage/storage_test.go` that verifies the `devices_found` column exists and defaults to `'[]'`.

- [ ] **Step 3: Run storage tests to verify migration passes**

Run: `go test -v ./internal/storage -run TestMigrations`

- [ ] **Step 4: Commit**

```bash
git add internal/storage/migrations/00012_add_scan_history_devices.sql internal/types/types.go internal/storage/storage_test.go
git commit -m "feat(storage): add devices_found column to scan_history"
```

---

### Task 2: Subnet-Scoped Metrics and Device Snapshot in Storage

**Files:**
- Modify: `internal/storage/storage.go:1935-1980`
- Modify: `internal/storage/storage.go:2583-2610`
- Test: `internal/storage/storage_test.go`

**Interfaces:**
- Produces: `Storage.RecordScanHistory(network string, success bool, errStr string, startedAt time.Time, duration float64, devices []types.ScanDeviceRecord) error`
- Produces: `Storage.GetScanHistory() ([]types.ScanHistoryRecord, error)` (with unmarshaled `DevicesFound`)

- [ ] **Step 1: Write failing unit test in storage_test.go**

Test that `RecordScanHistory` for `10.0.0.0/24`:
1. Scopes `devices_online` strictly to IPs inside `10.0.0.0/24` (ignoring devices in `10.5.5.0/24`).
2. Scopes presence event counts (`joined`, `returned`, `left`) to IPs inside `10.0.0.0/24`.
3. Stores `devices` as JSON in `devices_found`.
4. `GetScanHistory()` correctly returns the unmarshaled devices.

- [ ] **Step 2: Run test to confirm it fails**

Run: `go test -v ./internal/storage -run TestRecordScanHistory_ScopedMetrics`

- [ ] **Step 3: Implement scoped metrics and serialization in storage.go**

In `internal/storage/storage.go`:
Parse `network` with `net.ParseCIDR(network)`.
Filter online devices by checking `ipNet.Contains(net.ParseIP(d.IP))`.
Filter presence events by IP in subnet.
Serialize `devices` to JSON.
In `GetScanHistory()`, scan `devices_found` column and unmarshal into `r.DevicesFound`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v ./internal/storage -run TestRecordScanHistory_ScopedMetrics`

- [ ] **Step 5: Commit**

```bash
git add internal/storage/storage.go internal/storage/storage_test.go
git commit -m "feat(storage): scope scan history metrics to subnet CIDR and persist devices found"
```

---

### Task 3: Per-Network Scan History and Sweep Failure Recording in ScanJob

**Files:**
- Modify: `internal/api/scanjob.go:335-460`
- Modify: `internal/api/scanjob_test.go`

**Interfaces:**
- Consumes: `Storage.RecordScanHistory`

- [ ] **Step 1: Write failing test in scanjob_test.go**

Create a test `TestScanJob_RecordsPerNetworkScanHistoryOnSuccessAndFailure`:
- Run a scan with 2 networks (one succeeds with 2 devices, one fails with an error).
- Assert that `GetScanHistory()` contains TWO distinct records:
  - Network 1: `Success: true`, `DevicesOnline: 2`, `DevicesFound: 2`.
  - Network 2: `Success: false`, `Error: "sweep error"`, `DevicesOnline: 0`.

- [ ] **Step 2: Run test to confirm failure**

Run: `go test -v ./internal/api -run TestScanJob_RecordsPerNetworkScanHistoryOnSuccessAndFailure`

- [ ] **Step 3: Update scanjob.go to record per-network history**

In `scanjob.go`:
- In the loop over `list` in `run()`:
  - Record `sweepStarted := time.Now()`.
  - On error:
    `h.store.RecordScanHistory(cidr, false, err.Error(), sweepStarted, time.Since(sweepStarted).Seconds(), nil)`
  - On success:
    Convert `result.Devices` to `[]types.ScanDeviceRecord` and call:
    `h.store.RecordScanHistory(cidr, true, "", sweepStarted, result.Duration, scanDevs)`
- Remove monolithic aggregate `RecordScanHistory` call in defer.

- [ ] **Step 4: Run test to confirm pass**

Run: `go test -v ./internal/api -run TestScanJob_RecordsPerNetworkScanHistoryOnSuccessAndFailure`

- [ ] **Step 5: Commit**

```bash
git add internal/api/scanjob.go internal/api/scanjob_test.go
git commit -m "feat(api): record per-network scan history on discovery sweep completion and failure"
```

---

### Task 4: Resilient Notification Webhook Fallback

**Files:**
- Modify: `internal/api/api.go:994-1130`
- Modify: `internal/api/scanjob_test.go`

**Interfaces:**
- Produces: Fallback Slack webhook resolution across `notifyRemoteScannerFailure`, `notifyRouterAPIFailure`, and general scan failures.

- [ ] **Step 1: Write failing test in scanjob_test.go**

Test that if a subnet (e.g. `10.5.5.0/24`) has NO entry in `network_notifications`, but another subnet (`10.0.0.0/24`) has an enabled Slack webhook:
A failure on `10.5.5.0/24` dispatches the Slack alert to the fallback webhook.

- [ ] **Step 2: Run test to verify failure**

Run: `go test -v ./internal/api -run TestNotifyFailure_FallbackWebhook`

- [ ] **Step 3: Implement getEffectiveSlackWebhook helper in api.go**

In `internal/api/api.go`:
Create `func (h *Handler) getEffectiveSlackWebhook(cidr string) string`:
Check `h.store.GetNetworkNotification(cidr)`. If not found or empty, search `h.store.GetNetworkNotifications()` for the first enabled webhook.
Use this helper in `notifyRemoteScannerFailure`, `notifyRemoteScannerSuccess`, `notifyRouterAPIFailure`, and `notifyRouterAPISuccess`.

- [ ] **Step 4: Run test to verify pass**

Run: `go test -v ./internal/api -run TestNotifyFailure_FallbackWebhook`

- [ ] **Step 5: Commit**

```bash
git add internal/api/api.go internal/api/scanjob_test.go
git commit -m "feat(api): fall back to primary active webhook when target subnet has no dedicated Slack webhook"
```

---

### Task 5: Sidebar Status & Scan Outcome Toast Warning

**Files:**
- Modify: `internal/web/templates/index.html:110-135`
- Modify: `internal/web/static/app.js:283-299`
- Modify: `internal/web/static/scan-refresh.js:40-60`
- Test: `internal/web/static/scan-refresh.test.js`

- [ ] **Step 1: Write failing JS test in scan-refresh.test.js**

Add test asserting that when `failed.length > 0`, the scan completion summary identifies the failed networks and returns a warning level rather than success.

- [ ] **Step 2: Run JS test to verify failure**

Run: `node --test internal/web/static/scan-refresh.test.js`

- [ ] **Step 3: Implement fixes in template and JS**

In `internal/web/templates/index.html`:
Check `{{if .ScanError}}` before `{{else if .IsCompleted}}` so any subnet with a scan error immediately displays `⚠ Failed` with tooltip.
In `internal/web/static/app.js`:
If `failed.length > 0` (or `scanned.length === 0`), trigger `showToast(msg, 'warning')` (not `'success'`).

- [ ] **Step 4: Run JS tests to verify pass**

Run: `node --test internal/web/static/*.test.js`

- [ ] **Step 5: Commit**

```bash
git add internal/web/templates/index.html internal/web/static/app.js internal/web/static/scan-refresh.js internal/web/static/scan-refresh.test.js
git commit -m "fix(ui): prioritize scan errors in sidebar status and show warning toast on partial scan failures"
```

---

### Task 6: Scan Details Modal on Scans Page

**Files:**
- Modify: `internal/web/templates/scans.html`
- Modify: `internal/web/static/app.js`
- Modify: `internal/web/static/style.css`

- [ ] **Step 1: Add modal markup to scans.html**

Add modal container `#scan-detail-modal`:
- Modal header with Title, Status badge, Timestamp, Duration, and Close button.
- Error box `#scan-modal-error` (hidden when success).
- Filter input `#scan-modal-search` and count `#scan-modal-count`.
- Devices table `#scan-modal-devices-table` with columns: IP, Hostname, Vendor/MAC, Ping, Ports.

- [ ] **Step 2: Add styles in style.css**

Add CSS for clickable history rows: `.scan-history-row { cursor: pointer; transition: background 0.15s; }` and `.scan-history-row:hover { background: var(--bg-card-hover); }`.

- [ ] **Step 3: Implement openScanDetailModal in app.js**

- Attach click handler to each row in `renderScanHistory`.
- Save fetched history list in memory (`currentScanHistory = history`).
- Implement `openScanDetailModal(scanId)` and `filterScanModalDevices()`.
- Implement `closeScanDetailModal()`.

- [ ] **Step 4: Verify manual DOM rendering and run automated checks**

Run: `node --test internal/web/static/*.test.js`

- [ ] **Step 5: Commit**

```bash
git add internal/web/templates/scans.html internal/web/static/app.js internal/web/static/style.css
git commit -m "feat(ui): add scan details popup modal on execution history click"
```

---

### Task 7: Full System Verification, gofmt, and Release

**Files:**
- All modified files

- [ ] **Step 1: Run full Go test suite with -race**

Run: `go test -race ./...`

- [ ] **Step 2: Run all JavaScript unit tests**

Run: `node --test internal/web/static/*.test.js`

- [ ] **Step 3: Format and check code quality**

Run: `gofmt -w . && gofmt -l . && go vet ./...`

- [ ] **Step 4: Tag and push release**

Tag `v3.15.8` and push `main` and `v3.15.8`.
