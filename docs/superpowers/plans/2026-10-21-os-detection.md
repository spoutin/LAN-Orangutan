# Operating System and Version Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect operating systems and versions during deep scans using active TCP/IP fingerprinting (`nmap -O`) and service banner heuristics (`-sV`), with unprivileged fallback, customizable overrides, and table/sidebar/modal presentation.

**Architecture:** Extend deep scans in `internal/scanner` to include `-O` when running privileged (local root/`CAP_NET_RAW` or remote SSH gateway with `sudo`), caching privilege status to avoid duplicate timeouts. Infer and consolidate OS family, name, and version from Nmap OS matches and service banners into `types.Device`. Store fields in SQLite via migration `00016`, update REST endpoints to support `custom_os` manual overrides, and render an OS column with icons, sidebar specs, and modal controls in the web interface.

**Tech Stack:** Go standard library, SQLite, Nmap subprocesses, Go HTML templates, Vanilla JavaScript, Node.js built-in test runner (`node --test`).

**Spec:** `docs/superpowers/specs/2026-10-21-os-detection-design.md`

## Global Constraints

- Deep scan remains the sole mechanism for OS detection; regular subnet inventory sweeps must never invoke `-O` or port scanning.
- Deep scans must never fail because `nmap -O` was denied due to missing raw socket/root privileges.
- Unprivileged local runs or remote SSH gateways without `sudo` must omit `-O` upfront or fall back cleanly to service banner inspection.
- Device updates from deep scans must preserve user-configured customizations (`custom_os`, `custom_hostname`, `custom_type`, `notes`, `label`).
- The main devices table OS column must display an icon plus version string for known families, fall back to text if no icon exists, or show `—` when unprobed/unknown.

## Review Focus

1. **Unprivileged local execution:** Local scanner without root/raw-socket access must omit `-O` (or fall back gracefully) and still complete service discovery without throwing a fatal scan error. *(Tested in Task 3, Step 1)*
2. **Remote SSH gateway with `sudo: false`:** Deep scan dispatched through a remote gateway without sudo must omit `-O` upfront and avoid command failure. *(Tested in Task 3, Step 1)*
3. **Custom OS override persistence:** When an operator saves a `custom_os`, subsequent deep scans must update `os`, `os_version`, and `os_family` without wiping or overriding `custom_os`. *(Tested in Task 4, Step 1)*
4. **Filtered / hardened host response:** A target with no responsive TCP ports must not hang or cause invalid XML parsing; OS resolution returns empty values without failing the host scan. *(Tested in Task 2, Step 1)*
5. **Esoteric / Unknown OS family in UI:** A device with an unfamiliar OS string must render cleanly as plain text without broken SVG tags or invalid CSS classes. *(Tested in Task 5, Step 1)*

---

## File Structure

- `internal/storage/migrations/00016_add_os_detection.sql`: Database schema migration adding `os`, `os_version`, `os_family`, and `custom_os`.
- `internal/types/types.go`: Add `OS`, `OSVersion`, `OSFamily`, and `CustomOS` fields to `types.Device`.
- `internal/storage/storage.go`: Update device queries and `UpdateDeviceFields` to persist and load OS fields.
- `internal/storage/storage_test.go`: Tests for OS persistence, custom overrides, and field preservation.
- `internal/scanner/os.go`: Nmap XML models for `<os>` and OS inference logic combining stack matches and service banners.
- `internal/scanner/os_test.go`: Unit tests for OS inference heuristics (Linux, Windows, Apple, BSD, unknown).
- `internal/scanner/scanner.go`: Privilege detection, caching, and conditional `-O` argument construction.
- `internal/scanner/scanner_test.go`: Tests for argument generation and unprivileged fallback.
- `internal/remotescan/remotescan.go`: Implement `CanRunPrivileged` on `SSHRunner`.
- `internal/remotescan/remotescan_test.go`: Test for remote runner privilege reporting.
- `internal/api/scanjob.go`: Wire detected OS fields into `scanPortHost` device updates.
- `internal/api/api.go`: Wire `custom_os` into device edit handler `PUT /api/devices/{ip}`.
- `internal/api/device_test.go`: API test for updating `custom_os`.
- `internal/api/scanjob_test.go`: Test deep scan recording OS data.
- `internal/web/icons.go`: Template helper function `osIcon(family string)`.
- `internal/web/icons_test.go`: Unit test for OS SVG helper.
- `internal/web/templates/index.html`: Table header, table cell, sidebar spec row, modal spec row, modal custom OS edit input.
- `internal/web/static/app.js`: Format OS column with SVG icon, table sorting by `os`, search matching, sidebar and modal binding.
- `internal/web/static/os-presentation.test.js`: Node unit tests for OS formatting and icon fallbacks.
- `internal/web/handler_test.go`: Dashboard template rendering test verifying OS column and modal inputs.

---

### Task 1: Data Model, SQLite Migration, and Storage Layer

**Files:**
- Create: `internal/storage/migrations/00016_add_os_detection.sql`
- Modify: `internal/types/types.go`
- Modify: `internal/storage/storage.go`
- Test: `internal/storage/storage_test.go`

**Interfaces:**
- Consumes: None
- Produces:
  - `types.Device` with `OS string`, `OSVersion string`, `OSFamily string`, `CustomOS string`
  - `storage.UpdateDeviceFields(ip, label, notes, group, customHostname, customWebURL, customType, sshOverride string, sshOverridePort int, ansibleManaged bool, notifyOnSeen bool, customOS string) error`

- [ ] **Step 1: Write failing storage tests for OS persistence and overrides**

Add test in `internal/storage/storage_test.go`:
```go
func TestStorage_OSPersistenceAndCustomOverride(t *testing.T) {
	dir := t.TempDir()
	store, err := New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer store.Close()

	dev := &types.Device{
		IP:        "192.168.1.50",
		MAC:       "00:11:22:33:44:55",
		OS:        "Ubuntu Linux",
		OSVersion: "22.04",
		OSFamily:  "Linux",
		CustomOS:  "My Custom OS",
	}
	if err := store.UpdateDevice(dev); err != nil {
		t.Fatalf("UpdateDevice failed: %v", err)
	}

	got := store.GetDevice("192.168.1.50")
	if got == nil {
		t.Fatal("GetDevice returned nil")
	}
	if got.OS != "Ubuntu Linux" || got.OSVersion != "22.04" || got.OSFamily != "Linux" || got.CustomOS != "My Custom OS" {
		t.Errorf("got OS fields %+v, want Ubuntu Linux / 22.04 / Linux / My Custom OS", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/storage -run TestStorage_OSPersistenceAndCustomOverride`
Expected: FAIL with unknown field `OS` or missing column.

- [ ] **Step 3: Create migration `00016_add_os_detection.sql`**

In `internal/storage/migrations/00016_add_os_detection.sql`:
```sql
ALTER TABLE devices ADD COLUMN os TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN os_version TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN os_family TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN custom_os TEXT NOT NULL DEFAULT '';
```

- [ ] **Step 4: Update `types.Device` and `internal/storage/storage.go`**

Add fields to `types.Device` in `internal/types/types.go`:
```go
OS        string `json:"os,omitempty"`
OSVersion string `json:"os_version,omitempty"`
OSFamily  string `json:"os_family,omitempty"`
CustomOS  string `json:"custom_os,omitempty"`
```

Update SQL queries in `internal/storage/storage.go`:
- In `scanDeviceRow` / SELECT queries: scan `os`, `os_version`, `os_family`, `custom_os`.
- In `INSERT INTO devices` / `UpdateDevice`: include `os`, `os_version`, `os_family`, `custom_os`.
- In `UpdateDeviceFields`: accept `customOS string` and update `custom_os`.

- [ ] **Step 5: Run storage tests to verify they pass**

Run: `go test ./internal/storage`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/storage/migrations/00016_add_os_detection.sql internal/types/types.go internal/storage/storage.go internal/storage/storage_test.go
git commit -m "feat(storage): add os, os_version, os_family, and custom_os to device store"
```

---

### Task 2: Nmap XML Parsing & OS Inference Engine

**Files:**
- Create: `internal/scanner/os.go`
- Create: `internal/scanner/os_test.go`
- Modify: `internal/scanner/scanner.go`

**Interfaces:**
- Consumes: `types.OpenService`
- Produces:
  - `nmapOSMatch`, `nmapOSClass` structs in `internal/scanner`
  - `InferOS(osMatches []nmapOSMatch, services []types.OpenService) (osName, osVersion, osFamily string)`

- [ ] **Step 1: Write failing tests for OS inference**

Create `internal/scanner/os_test.go`:
```go
package scanner

import (
	"testing"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

func TestInferOS_LinuxWithUbuntuBanner(t *testing.T) {
	osMatches := []nmapOSMatch{
		{Name: "Linux 5.4 - 5.15", Accuracy: 95, Classes: []nmapOSClass{{OSFamily: "Linux", Vendor: "Linux", OSGen: "5.X"}}},
	}
	services := []types.OpenService{
		{Port: 22, Name: "ssh", Version: "OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 Ubuntu Linux; protocol 2.0"},
	}

	name, version, family := InferOS(osMatches, services)
	if family != "Linux" {
		t.Errorf("family = %q, want Linux", family)
	}
	if name != "Ubuntu Linux" {
		t.Errorf("name = %q, want Ubuntu Linux", name)
	}
	if version != "22.04" {
		t.Errorf("version = %q, want 22.04", version)
	}
}

func TestInferOS_WindowsStackMatch(t *testing.T) {
	osMatches := []nmapOSMatch{
		{Name: "Microsoft Windows 11", Accuracy: 96, Classes: []nmapOSClass{{OSFamily: "Windows", Vendor: "Microsoft", OSGen: "11"}}},
	}
	name, version, family := InferOS(osMatches, nil)
	if family != "Windows" || name != "Windows 11" || version != "11" {
		t.Errorf("got %s / %s / %s, want Windows 11 / 11 / Windows", name, version, family)
	}
}

func TestInferOS_HardenedEmptyHost(t *testing.T) {
	name, version, family := InferOS(nil, nil)
	if name != "" || version != "" || family != "" {
		t.Errorf("got %q / %q / %q, want empty strings", name, version, family)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner -run TestInferOS_`
Expected: FAIL with undefined `InferOS`.

- [ ] **Step 3: Implement Nmap OS structs and `InferOS` in `internal/scanner/os.go`**

Define `nmapOSMatch`, `nmapOSClass`, and `InferOS`:
- Match regexes for Ubuntu (e.g. `ubuntu0\.\d+` / package versions like `3ubuntu0.10` -> `22.04`, `1ubuntu1.8` -> `20.04`), Debian, Alpine, Fedora, CentOS.
- Fall back to top `osMatch` when no banner refines it.
- Normalize `osFamily` to canonical values: `Linux`, `Windows`, `Darwin` (or `Apple`), `BSD`, `Android`.

In `internal/scanner/scanner.go`:
- Extend `nmapHost` to include `OS nmapOS `xml:"os"` `
- Extend `nmapService` to include `OSType string `xml:"ostype,attr"` `

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scanner -run TestInferOS_`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/os.go internal/scanner/os_test.go internal/scanner/scanner.go
git commit -m "feat(scanner): implement Nmap OS parsing and inference heuristics"
```

---

### Task 3: Privilege Awareness & Dual-Mode Deep Scan Execution

**Files:**
- Modify: `internal/scanner/scanner.go`
- Modify: `internal/remotescan/remotescan.go`
- Test: `internal/scanner/scanner_test.go`
- Test: `internal/remotescan/remotescan_test.go`

**Interfaces:**
- Consumes: `InferOS`
- Produces:
  - `RemoteRunner.CanRunPrivileged(target string) bool`
  - `ScanHostPortsWithTiming(...)` returning `(openPorts []int, sshPorts []int, services []types.OpenService, osName, osVersion, osFamily string, err error)`

- [ ] **Step 1: Write failing tests for argument generation and unprivileged fallback**

Add tests in `internal/scanner/scanner_test.go`:
```go
func TestPortScanArguments_PrivilegedIncludesOSFlags(t *testing.T) {
	args := portScanArgumentsWithTiming("22-80", "192.168.1.10", false, true)
	argsStr := strings.Join(args, " ")
	if !strings.Contains(argsStr, "-O") || !strings.Contains(argsStr, "--osscan-limit") {
		t.Errorf("args = %v, expected -O and --osscan-limit", args)
	}
}

func TestPortScanArguments_UnprivilegedOmitsOSFlags(t *testing.T) {
	args := portScanArgumentsWithTiming("22-80", "192.168.1.10", false, false)
	argsStr := strings.Join(args, " ")
	if strings.Contains(argsStr, "-O") {
		t.Errorf("args = %v, should NOT contain -O when unprivileged", args)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner -run TestPortScanArguments_`
Expected: FAIL

- [ ] **Step 3: Implement privilege checking and argument construction**

1. In `internal/scanner/scanner.go`:
   - Add `CanRunPrivileged(target string) bool` to `RemoteRunner` interface.
   - Add privilege caching field `localPrivileged *bool` with mutex in `Scanner`.
   - Update `portScanArgumentsWithTiming(portRange, ip string, conservative, privileged bool) []string`.
   - Update `ScanHostPortsWithTiming`:
     - Determine privilege status: if remote runner exists, check `s.remoteRunner.CanRunPrivileged(ip)`. If local, check `s.isLocalPrivileged()`.
     - Build args with privilege flag.
     - Execute Nmap. If error contains `"requires root privileges"` or `"TCP/IP fingerprinting ... requires root"`, update `localPrivileged = false` and retry immediately without `-O`.
     - Call `parsePortScanResult` to extract ports, services, and call `InferOS` to return `(openPorts, sshPorts, services, osName, osVersion, osFamily, err)`.

2. In `internal/remotescan/remotescan.go`:
   - Implement `CanRunPrivileged(target string) bool` on `SSHRunner`: returns `sc.Sudo`.

- [ ] **Step 4: Run scanner tests to verify they pass**

Run: `go test ./internal/scanner ./internal/remotescan`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/scanner.go internal/scanner/scanner_test.go internal/remotescan/remotescan.go internal/remotescan/remotescan_test.go
git commit -m "feat(scanner): add privilege awareness and conditional -O OS detection"
```

---

### Task 4: Scan Job Pipeline and Device API Integration

**Files:**
- Modify: `internal/api/scanjob.go`
- Modify: `internal/api/api.go`
- Test: `internal/api/scanjob_test.go`
- Test: `internal/api/device_test.go`

**Interfaces:**
- Consumes: `ScanHostPortsWithTiming`, `UpdateDeviceFields`
- Produces:
  - Deep scan populates `OS`, `OSVersion`, `OSFamily` on target devices.
  - `PUT /api/devices/{ip}` accepts `custom_os`.

- [ ] **Step 1: Write failing tests for deep scan OS saving and API custom_os update**

In `internal/api/device_test.go`:
```go
func TestUpdateDevice_CustomOS(t *testing.T) {
	// Test PUT /api/devices/{ip} with {"custom_os": "OpenWrt 23.05"} persists custom_os
}
```

In `internal/api/scanjob_test.go`:
```go
func TestScanPortHost_SavesDetectedOS(t *testing.T) {
	// Verify scanPortHost writes OS, OSVersion, OSFamily to database while preserving CustomOS
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api -run "TestUpdateDevice_CustomOS|TestScanPortHost_SavesDetectedOS"`
Expected: FAIL

- [ ] **Step 3: Update `internal/api/scanjob.go` and `internal/api/api.go`**

In `internal/api/scanjob.go`:
- In `scanPortHost`:
  - Receive `ports, sshPorts, services, osName, osVersion, osFamily, err := h.scanner.ScanHostPortsWithTiming(...)`
  - Update `current.OS = osName`, `current.OSVersion = osVersion`, `current.OSFamily = osFamily` (preserving `current.CustomOS`).
  - Persist updated device in `h.store.UpdateDevice(current)`.

In `internal/api/api.go`:
- In `UpdateDevice` (handling `PUT /api/devices/{ip}`):
  - Parse `CustomOS` from payload struct.
  - Pass `customOS` to `h.store.UpdateDeviceFields(...)`.

- [ ] **Step 4: Run API tests to verify they pass**

Run: `go test ./internal/api -run "TestUpdateDevice_CustomOS|TestScanPortHost_SavesDetectedOS"`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/api/scanjob.go internal/api/api.go internal/api/scanjob_test.go internal/api/device_test.go
git commit -m "feat(api): persist detected OS and support custom_os overrides in REST API"
```

---

### Task 5: Frontend UI Presentation (Table Column, Sidebar, Modal, Sorting & Search)

**Files:**
- Modify: `internal/web/icons.go`
- Modify: `internal/web/templates/index.html`
- Modify: `internal/web/static/app.js`
- Modify: `internal/web/static/style.css`
- Test: `internal/web/icons_test.go`
- Test: `internal/web/handler_test.go`
- Create: `internal/web/static/os-presentation.test.js`

**Interfaces:**
- Consumes: `types.Device.OS`, `types.Device.OSVersion`, `types.Device.OSFamily`, `types.Device.CustomOS`
- Produces:
  - Table column `<th class="col-os">` and corresponding `<td>`
  - SVG icon rendering for Linux, Windows, Apple, Android, BSD
  - Sidebar `sb-os` row
  - Modal `detail-os` and `edit-custom-os`

- [ ] **Step 1: Write failing frontend tests for OS formatting and icons**

Create `internal/web/static/os-presentation.test.js`:
```js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { formatOSDisplay } = require('./app.js'); // or extracted helper

test('formatOSDisplay renders Linux icon and Ubuntu version', () => {
    const res = formatOSDisplay({ os: 'Ubuntu Linux', os_version: '22.04', os_family: 'Linux' });
    assert.match(res.html, /svg class="os-icon"/);
    assert.match(res.html, /Ubuntu 22\.04/);
});

test('formatOSDisplay prioritizes custom_os override', () => {
    const res = formatOSDisplay({ os: 'Linux', os_version: '5.15', os_family: 'Linux', custom_os: 'Debian 12' });
    assert.match(res.html, /Debian 12/);
});

test('formatOSDisplay falls back to plain text for esoteric OS without icon', () => {
    const res = formatOSDisplay({ os: 'Plan9', os_version: '4th Edition', os_family: 'Plan9' });
    assert.equal(res.html, 'Plan9 4th Edition');
});

test('formatOSDisplay returns dash for unprobed device', () => {
    const res = formatOSDisplay({ os: '', os_version: '', os_family: '' });
    assert.equal(res.html, '—');
});
```

In `internal/web/icons_test.go`:
```go
func TestOSIcon(t *testing.T) {
	for _, fam := range []string{"Linux", "Windows", "Darwin", "Apple", "Android", "BSD"} {
		html := string(osIcon(fam))
		if !strings.Contains(html, "<svg") {
			t.Errorf("family %q has no icon", fam)
		}
	}
	if got := osIcon("Unknown"); got != "" {
		t.Errorf("unknown family should yield empty, got %q", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test internal/web/static/os-presentation.test.js`
Run: `go test ./internal/web -run TestOSIcon`
Expected: FAIL

- [ ] **Step 3: Implement SVG helpers and frontend rendering**

1. In `internal/web/icons.go`:
   - Add `osIcons` map containing SVGs for Linux, Windows, Apple, Android, BSD.
   - Implement `osIcon(family string) template.HTML`.
   - Register `osIcon` and `formatDeviceOS` template functions in `template.FuncMap`.

2. In `internal/web/templates/index.html`:
   - In `<thead>`: add `<th class="col-os" data-sort="os" onclick="sortTable('os')">OS <span class="sort-icon">↕</span></th>` after `Vendor`.
   - In device table rows: add `<td class="col-os">...</td>` rendering the formatted OS.
   - In sidebar specs list: add `<li><span class="spec-label">OS:</span> <span class="spec-val" id="sb-os">—</span></li>`.
   - In device detail modal specs list: add `<li><span class="spec-label">Operating System:</span> <span class="spec-val" id="detail-os">—</span></li>`.
   - In device detail modal edit form: add `<input type="text" id="edit-custom-os" class="form-input" placeholder="e.g. Ubuntu 22.04">`.

3. In `internal/web/static/app.js`:
   - Implement `formatOSDisplay(dev)`: generates icon + text, or text, or `—`.
   - Update `renderDeviceRow` / row updates to populate `.col-os`.
   - Update `sortTable('os')` comparator.
   - Update device search filter to match `dev.os`, `dev.os_version`, and `dev.custom_os`.
   - Update `openDeviceModal` to populate `detail-os` and `edit-custom-os`.
   - Update save device handler to send `custom_os` in PUT request.
   - Update sidebar selection to populate `sb-os`.

4. In `internal/web/static/style.css`:
   - Add styling for `.col-os` and `.os-icon` (`width: 14px; height: 14px; vertical-align: middle; margin-right: 4px;`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test internal/web/static/os-presentation.test.js`
Run: `go test ./internal/web`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/web/icons.go internal/web/icons_test.go internal/web/templates/index.html internal/web/static/app.js internal/web/static/style.css internal/web/static/os-presentation.test.js internal/web/handler_test.go
git commit -m "feat(ui): add OS column with family icons, sidebar display, and modal edit controls"
```

---

### Task 6: Full Integration Verification

**Files:**
- All modified components across storage, scanner, API, and web.

- [ ] **Step 1: Run comprehensive Go test suite across changed packages**

Run:
```bash
go test -v ./internal/storage ./internal/scanner ./internal/remotescan ./internal/web
```
Expected: PASS with 0 failures.

- [ ] **Step 2: Run static Node.js test suite**

Run:
```bash
node --test internal/web/static/*.test.js
```
Expected: PASS with all tests passing.

- [ ] **Step 3: Verification commit (if needed)**

```bash
git status
```
Verify working tree is clean.
