# Implementation Plan: Scan History Cleanup, 3-Tier Status, and Compact Presence Timeline

## Proposed Changes

### 1. Storage Migration and Types
* Add `internal/storage/migrations/00013_add_scan_history_type_and_status.sql`:
  * Add `scan_type TEXT NOT NULL DEFAULT 'sweep'` and `status TEXT NOT NULL DEFAULT 'success'`.
  * Backfill existing data.
* Update `internal/types/types.go`:
  * Update `ScanHistory` struct with `ScanType` and `Status`.
* Update `internal/storage/storage.go`:
  * Add `RecordScanHistoryWithDetails` supporting `scanType` and `status`.
  * Update `GetScanHistory` with optional date, type, and search filters.
  * Add unit tests in `internal/storage/storage_test.go`.

### 2. Service Scan (Deep Scan) Accuracy in `internal/api/scanjob.go`
* Track host scan outcomes during deep scans (`runDeepQueue` and `scanPortHost`).
* Store per-host scan device records with `OpenPorts` and error info.
* Mark deep scans as:
  * `failed`: if gateway error or 100% of hosts failed.
  * `warning`: if partial failure (>0 passed, >0 failed).
  * `success`: if 100% of hosts scanned cleanly.
* Record history with `scan_type = "deep"`.

### 3. API Handlers in `internal/api/handlers.go`
* Update `handleGetScanHistory` to accept `?date=YYYY-MM-DD`, `?type=sweep|deep|all`, and `?q=...`.
* Add unit test in `internal/api/api_test.go` or `scanjob_test.go`.

### 4. UI: Scans Page & Presence Timeline
* In `internal/web/templates/scans.html`:
  * Add date pagination controls and search toolbar above the Execution History table.
  * Update the Presence Timeline container for the high-density activity stream layout.
* In `internal/web/static/app.js`:
  * Update `renderScanHistory` to support Day Paging ("Today", "Yesterday", historical dates), search filter, and Type tags (`[Sweep]` and `[Deep]`).
  * Update `renderPresenceTimeline` to use the slim vertical line, micro-dots, sticky date headers, and high-density rows.
* In `internal/web/static/style.css`:
  * Add CSS classes for `.scan-history-toolbar`, `.timeline-spine`, `.timeline-dot`, etc.
* In `internal/web/static/scans.test.js` or `app.test.js`:
  * Add JS test cases for timeline event formatting and history filtering.

---

## Verification Plan

### Automated Tests
1. `go test -v -race ./internal/storage -run TestScanHistory`
2. `go test -v -race ./internal/api -run "TestScanHistory|TestDeepScan"`
3. `node --test internal/web/static/*.test.js`
4. Full test suite: `go test -race ./...`

### Standards
1. `gofmt -w . && gofmt -l .`
2. `go vet ./...`
