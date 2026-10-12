# Design Specification: Per-Network Scan History, Scan Details Modal, and Resilient Failure Reporting

**Date:** 2026-10-11  
**Status:** Approved  
**Author:** opencode

---

## 1. Overview and Problem Statement

When users view the **Scans** tab (`/scans`), the execution history currently presents misleading and incomplete data:
1. **Aggregated Stats**: When scanning a network, `scan_history` records online devices and presence changes by querying the entire database rather than scoping metrics to the scanned subnet CIDR.
2. **"All Networks" Consolidation**: Multi-network scans record only a single consolidated `"All Networks"` row rather than distinct per-network records.
3. **Scan Detail Invisibility**: Users cannot view which specific devices were discovered during a historical scan.
4. **False Success Status**: When a network sweep fails (e.g. remote SSH failure, uninstalled Nmap, host unreachable), the background job completes with `j.finish("done", "")`, marking `success = true` in `scan_history`. The Scans table and UI toasts then display green "Success" banners even though a network failed.
5. **Sidebar Misrepresentation**: While scanning is active, the left sidebar displays `✓ Completed` for a failed network because `isCompleted` is evaluated before `scanError`.
6. **Silent Notification Drops**: When a network lacks a dedicated Slack webhook in `network_notifications`, scan failure alerts are dropped entirely instead of falling back to any active enabled Slack webhook.

---

## 2. Architecture & Data Model

### 2.1 Database Schema Migration (`00012_add_scan_history_devices.sql`)
Add a `devices_found` JSON text column to `scan_history`:
```sql
-- +goose Up
ALTER TABLE scan_history ADD COLUMN devices_found TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE scan_history DROP COLUMN devices_found;
```

### 2.2 Go Types (`internal/types/types.go`)
Define a lightweight record representing each device discovered in a scan:
```go
type ScanDeviceRecord struct {
    IP           string   `json:"ip"`
    MAC          string   `json:"mac,omitempty"`
    Hostname     string   `json:"hostname,omitempty"`
    Vendor       string   `json:"vendor,omitempty"`
    Status       string   `json:"status,omitempty"`
    ResponseTime *float64 `json:"response_time,omitempty"`
    OpenPorts    []int    `json:"open_ports,omitempty"`
}

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

### 2.3 Scoped Metrics in Storage (`internal/storage/storage.go`)
Update `RecordScanHistory` to accept `devices []types.Device` (or `[]types.ScanDeviceRecord`) and compute:
* `devices_online`: Scoped to devices in the database whose IP is contained within the subnet CIDR.
* `devices_joined`, `devices_returned`, `devices_left`: Scoped to `device_presence_history` records since `startedAt` whose IP is contained within the subnet CIDR.
* `devices_found`: Serialized JSON array of `ScanDeviceRecord`.
* `GetScanHistory()`: Deserializes `devices_found` so consumers receive the full device list for each scan record.

---

## 3. Scan Job Execution & Per-Network History (`internal/api/scanjob.go`)

* In `scanJob.run()`, record scan history **per network** as each discovery sweep completes (or fails):
  * **On Sweep Success**: Call `h.store.RecordScanHistory(cidr, true, "", sweepStartedAt, result.Duration, result.Devices)`.
  * **On Sweep Failure**: Call `h.store.RecordScanHistory(cidr, false, err.Error(), sweepStartedAt, sweepDuration, nil)`.
* When the overall scan job completes, set overall job status to `"failed"` if all networks failed, or report partial failure in logs and summary.

---

## 4. Alerting & Notification Fallback (`internal/api/api.go`)

* When notifying Slack of a remote scanner failure, network scan failure, or router API failure:
  * Look up `h.store.GetNetworkNotification(cidr)`.
  * If no webhook is configured or enabled for that specific CIDR, query `h.store.GetNetworkNotifications()` and select the first enabled network notification with a non-empty `SlackWebhook`.
  * Dispatch the Slack alert to the fallback webhook so failure alerts are never dropped.

---

## 5. Frontend & Detail Modal (`scans.html`, `app.js`, `style.css`)

### 5.1 Scans Tab Detail Modal
* Add a modal `<div id="scan-detail-modal" class="modal">` to `scans.html`.
* In `app.js`, render table rows in `scan-history-tbody` with `onclick="openScanDetailModal(rowId)"` and hover pointer styling.
* The modal presents:
  * **Header**: Network name/CIDR, timestamp, duration, status badge (`Success` or `Failed`).
  * **Error Banner**: If `!row.success`, display a clear warning/error alert with `row.error`.
  * **Device Table**: If `row.success` and devices exist:
    * Search filter input to filter devices dynamically by IP, MAC, hostname, or vendor.
    * Columns: IP Address, Hostname, Vendor / MAC, Ping (ms), Open Ports.

### 5.2 Sidebar & Toast Status
* **Sidebar (`index.html`)**: Check `{{if .ScanError}}` before `{{else if .IsCompleted}}`. If a network has an error, show `⚠ Failed` with tooltip immediately.
* **Scan Outcome Toast**: If any network failed during a manual scan, use `'warning'` style instead of `'success'`, explicitly reporting failed networks.
