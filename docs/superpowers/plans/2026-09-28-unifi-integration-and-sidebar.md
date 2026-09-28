# UniFi Controller Integration & Table/Sidebar Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate Ubiquiti UniFi Controller telemetry (SSID, AP, Signal RSSI, Channel, Link Speed, Traffic) and extended OPNsense/OpenWrt DHCP metadata into LAN-Orangutan, while redesigning the frontend with a clean 7-column table and a UniFi-style sliding sidebar drawer with inline editing.

**Architecture:** 
1. A native Go client (`internal/scanner/unifi.go`) queries the UniFi OS Console via Local API Key (`X-API-KEY`) for AP names and active wireless client metrics.
2. `internal/scanner/routers.go` is enriched to extract DHCP lease expiration, lifetime, firewall interface, and reservation notes from OPNsense and OpenWrt.
3. Database migration `00004` adds these fields to SQLite, and `storage.go` merges them by MAC/IP without overwriting user overrides.
4. The web dashboard replaces `Assignment` with `SSID` in the main table and introduces a responsive slide-out right drawer that handles deep telemetry inspection and inline device editing.

**Tech Stack:** Go 1.22+, SQLite with Goose migrations, Vanilla JavaScript/CSS, HTML5 templates.

## Global Constraints
- Strictly adhere to existing code style, imports, and naming patterns in LAN-Orangutan.
- All new database columns must be added via Goose migration with safe defaults.
- No third-party Go packages without prior agreement; use standard library `net/http`, `encoding/json`, `database/sql`.
- Preserve existing device customizations (labels, custom hostnames, custom web URLs, notes, linked MACs).

---

### Task 1: Configuration Model & Environment Parsing

**Files:**
- Modify: `internal/config/config.go`
- Modify: `config.example.ini`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.UniFiConfig` with fields `Enable bool`, `URL string`, `Site string`, `APIKey string`, `VerifySSL bool`.
- Environment Variables: `ORANGUTAN_UNIFI_ENABLE`, `ORANGUTAN_UNIFI_URL`, `ORANGUTAN_UNIFI_SITE`, `ORANGUTAN_UNIFI_API_KEY`, `ORANGUTAN_UNIFI_VERIFY_SSL`.

- [ ] **Step 1: Write the failing test for UniFi config parsing in `internal/config/config_test.go`**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Implement `UniFiConfig` in `internal/config/config.go` and update `config.example.ini`**
- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit changes**

---

### Task 2: Data Models & SQLite Migration

**Files:**
- Modify: `internal/types/types.go`
- Create: `internal/storage/migrations/00004_add_unifi_and_router_telemetry.sql`
- Modify: `internal/storage/storage.go`
- Test: `internal/storage/storage_test.go`

**Interfaces:**
- Produces: `types.Device` augmented with `SSID`, `APName`, `RadioBand`, `Channel`, `WiFiStandard`, `Signal`, `SignalQuality`, `RxRate`, `TxRate`, `RxBytes`, `TxBytes`, `AssociationUptime`, `UniFiModel`, `RouterSource`, `RouterInterface`, `LeaseExpires`, `LeaseLifetime`, `RouterNotes`.
- Produces: SQLite migration 00004 and updated `scanDevice` / `SELECT` / `INSERT` query methods in `storage.go`.

- [ ] **Step 1: Write failing storage test verifying new telemetry persistence**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Add migration 00004 and update `types.Device` & `storage.go`**
- [ ] **Step 4: Run tests to verify pass**
- [ ] **Step 5: Commit changes**

---

### Task 3: Native UniFi OS Controller Client

**Files:**
- Create: `internal/scanner/unifi.go`
- Create: `internal/scanner/unifi_test.go`

**Interfaces:**
- Produces: `scanner.FetchUniFiClients(ctx context.Context, cfg config.UniFiConfig) ([]types.Device, error)`
- Consumes: `config.UniFiConfig`, `types.Device`.
- Interacts with: UniFi OS endpoints `/proxy/network/api/s/{site}/stat/device` and `/proxy/network/api/s/{site}/stat/sta` with `/api/s/{site}/...` fallback.

- [ ] **Step 1: Write unit tests with mock HTTP server covering AP mapping and station parsing**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Implement `FetchUniFiClients` in `internal/scanner/unifi.go`**
- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit changes**

---

### Task 4: Extended OPNsense & OpenWrt Telemetry

**Files:**
- Modify: `internal/scanner/routers.go`
- Test: `internal/scanner/routers_test.go`

**Interfaces:**
- Produces: Enhanced `FetchOPNsenseDHCP` and `FetchOpenWrtDHCP` returning `RouterSource`, `RouterInterface`, `LeaseExpires`, `LeaseLifetime`, and `RouterNotes`.

- [ ] **Step 1: Write failing test checking for extended DHCP and ARP fields**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Update `routers.go` to parse lease expiration, interfaces, and descriptions**
- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit changes**

---

### Task 5: Pipeline Integration & Storage Merging

**Files:**
- Modify: `internal/storage/storage.go`
- Modify: `internal/api/scanjob.go`
- Test: `internal/storage/storage_test.go`

**Interfaces:**
- Produces: `storage.MergeUniFiClients(clients []types.Device) error`
- Modifies: `storage.MergeRouterDHCP` to persist lease expiration and router notes.
- Modifies: `internal/api/scanjob.go` to execute `FetchUniFiClients` and call `MergeUniFiClients`.

- [ ] **Step 1: Write test for `MergeUniFiClients` matching by MAC and preserving user customizations**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Implement `MergeUniFiClients` and integrate into `scanjob.go`**
- [ ] **Step 4: Run tests to verify pass**
- [ ] **Step 5: Commit changes**

---

### Task 6: Main Table Redesign & Sidebar Markup

**Files:**
- Modify: `internal/web/templates/index.html`
- Modify: `internal/web/static/style.css`

**Interfaces:**
- Modifies: Table headers: replace `Assignment` with `SSID`, remove `Type` column from main table, keep 7 core columns.
- Modifies: `tr.device-row` with rich `data-*` attributes for instant client-side sidebar display.
- Produces: `<aside id="device-sidebar" class="device-sidebar hidden">` with UniFi telemetry cards, router IPAM card, and inline editing fields.
- Produces: Flexbox desktop layout and sliding drawer CSS animations.

- [ ] **Step 1: Update table headers and row cells in `index.html`**
- [ ] **Step 2: Add device-sidebar markup and cards to `index.html`**
- [ ] **Step 3: Add CSS styling for responsive drawer, signal meter, and flex layout in `style.css`**
- [ ] **Step 4: Verify template compiles via `go test ./internal/web`**
- [ ] **Step 5: Commit changes**

---

### Task 7: Interactive Sidebar Selection & Inline Editing

**Files:**
- Modify: `internal/web/static/app.js`

**Interfaces:**
- Modifies: `selectDeviceRow(row)` to slide open sidebar on row click.
- Produces: `openDeviceSidebar(deviceData)`, `closeDeviceSidebar()`.
- Produces: Inline edit form submission (`PUT /api/devices/{ip}`) with in-place row update.
- Modifies: Search filter to index `data-ssid`. Keyboard navigation (`Esc`, `Up`, `Down`).

- [ ] **Step 1: Attach row click listener and sidebar open/close logic in `app.js`**
- [ ] **Step 2: Implement inline edit saving and toast feedback**
- [ ] **Step 3: Update search filtering to index SSID**
- [ ] **Step 4: Verify JavaScript syntax and web handler tests pass**
- [ ] **Step 5: Commit changes**

---

### Task 8: Verification & End-to-End Build

**Files:**
- Entire repository

- [ ] **Step 1: Run full test suite `go test -v ./...`**
- [ ] **Step 2: Build binary `go build -o lan-orangutan ./cmd/orangutan`**
- [ ] **Step 3: Verify clean build and functionality**
