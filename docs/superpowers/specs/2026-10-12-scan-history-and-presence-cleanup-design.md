# Spec: Scan History Cleanup, 3-Tier Status, and Compact Presence Timeline

## Summary
The Scans page (`/scans`) currently displays an unbounded monolithic table of past scan runs and an oversized presence timeline. Furthermore, Stage 2 deep scans currently record a scan as "successful" even when target hosts encounter scanner errors (such as missing OpenSSL DTLS support on OpenWrt gateways).

This feature introduces:
1. **Accurate Scan Evaluation**: A 3-tier status model (`success`, `warning` / partial, `failed`) that accurately tracks host-level scan results for deep service scans instead of blindly asserting success when a job context completes.
2. **Scan Type Differentiation**: Adding `scan_type` (`sweep` vs `deep`) to distinguish Stage 1 host discovery sweeps from Stage 2 deep port/service scans in database records, API endpoints, and UI views.
3. **Day-by-Day Pagination & History Search**: A top toolbar for the Execution History table featuring Day Paging tabs ("Today", "Yesterday", "Oct 10", etc., plus a date picker), scan type filters (`All`, `Sweep`, `Deep`), and a live search input for network CIDRs and target host IPs/hostnames.
4. **Presence Timeline Redesign**: A sleek, compact activity stream replacing oversized circular badges and cards with a high-density vertical line, micro-dots, sticky date headers, and relative timestamps, reducing vertical space usage by ~60%.

---

## 1. Data Model & Storage

### 1.1 Database Migration: `00013_add_scan_history_type_and_status.sql`
Add columns to `scan_history`:
- `scan_type TEXT NOT NULL DEFAULT 'sweep'` (`sweep` for Stage 1 discovery, `deep` for Stage 2 service scans)
- `status TEXT NOT NULL DEFAULT 'success'` (`success`, `warning`, `failed`)

Backfill existing rows:
- `scan_type = 'sweep'`
- `status = CASE WHEN success = 1 THEN 'success' ELSE 'failed' END`

### 1.2 `ScanHistory` and `ScanDeviceRecord` Types in `internal/types/types.go`
```go
type ScanHistory struct {
    ID              int64              `json:"id"`
    Network         string             `json:"network"`
    ScanType        string             `json:"scan_type"` // "sweep" | "deep"
    Success         bool               `json:"success"`   // legacy bool support
    Status          string             `json:"status"`    // "success" | "warning" | "failed"
    Error           string             `json:"error"`
    DevicesOnline   int                `json:"devices_online"`
    DevicesJoined   int                `json:"devices_joined"`
    DevicesReturned int                `json:"devices_returned"`
    DevicesLeft     int                `json:"devices_left"`
    Duration        float64            `json:"duration"`
    Timestamp       time.Time          `json:"timestamp"`
    DevicesFound    []ScanDeviceRecord `json:"devices_found,omitempty"`
}
```

### 1.3 `RecordScanHistoryWithDetails` in `internal/storage/storage.go`
Update `RecordScanHistory`:
```go
func (s *Storage) RecordScanHistoryWithDetails(network string, scanType string, status string, errStr string, startedAt time.Time, duration float64, devices []types.ScanDeviceRecord) error
```
`status` rules:
- `success`: `success = 1`
- `warning`: `success = 1` (partial completion)
- `failed`: `success = 0`

Provide helper `GetScanHistory(limit int, dateFilter string, scanType string, q string)` to support date filtering and queries.

---

## 2. API Endpoints

### 2.1 `GET /api/scans/history`
Query parameters:
- `date`: Optional date in `YYYY-MM-DD` format (defaults to all or filtered date).
- `type`: Optional filter `sweep` | `deep` | `all`.
- `q`: Optional search text (matches network CIDR, network name, or device IP/hostname in `devices_found`).
- `limit`: Maximum records (default: 100).

---

## 3. Deep Scan Evaluation in `internal/api/scanjob.go`

In `runDeepScan` and `runDeepQueue`:
1. Track outcomes per host in deep scans:
   - Total target devices.
   - Succeeded device scans (ports discovered or 0 open ports).
   - Failed device scans (scanner returned an error).
2. Compute status:
   - If `failedCount == 0`: `status = "success"`
   - If `failedCount > 0 && succeededCount > 0`: `status = "warning"`, `errStr = fmt.Sprintf("%d of %d host service scans failed", failedCount, total)`
   - If `succeededCount == 0 && total > 0`: `status = "failed"`, `errStr = firstError`
   - If job was cancelled: `status = "failed"`, `errStr = "scan cancelled"`
3. Record history with `scan_type = "deep"`.

---

## 4. UI Design

### 4.1 Execution History
- Day Paging tabs above table: `[ « ] [ Yesterday ] [ Today ] [ » ] [ 📅 Date ]`.
- Filter bar: Type dropdown (`All`, `Sweep`, `Deep`), Search box (`Search history...`).
- Badges:
  - `[Sweep]` (Blue badge `#2f7fd4`)
  - `[Deep]` (Purple badge `#805ad5`)
  - `✓ Success` (Green)
  - `⚠ Warning (N failed)` (Amber)
  - `✗ Failed` (Red)

### 4.2 Presence Timeline
- Slim vertical spine (`border-left: 2px solid var(--border)`).
- Micro-dots (`8px` circular indicators):
  - Green for Join
  - Blue for Return
  - Amber for Leave
- Sticky date headers for daily clustering.
- High-density rows displaying Device Hostname, IP code pill, event description, relative time, and session/away duration.
