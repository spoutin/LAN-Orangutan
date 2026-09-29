# SNMP Switch Port Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add read-only, multi-switch SNMPv3 polling to resolve inventoried MAC addresses to their current Cisco switch interface and display the result in the existing device sidebar.

**Architecture:** A `gosnmp`-backed scanner polls each configured switch once per Orangutan scan, builds VLAN-aware MAC forwarding and interface maps, and returns MAC-keyed switch connection telemetry. Storage merges these results without overwriting user, router, or UniFi information; the scan pipeline isolates individual switch failures. The frontend adds a sidebar-only Switch Connection card, leaving the main table unchanged.

**Tech Stack:** Go 1.26, `github.com/gosnmp/gosnmp`, SQLite/Goose migrations, standard IF-MIB/BRIDGE-MIB/Q-BRIDGE-MIB/POWER-ETHERNET-MIB OIDs, existing vanilla JS/CSS and Go templates.

**Spec:** `docs/superpowers/specs/2026-09-29-snmp-switch-port-integration-design.md`

## Global Constraints

- Add exactly one direct dependency: `github.com/gosnmp/gosnmp`; do not add any other package for the SNMP integration.
- Support SNMPv3 only, restricted to `authPriv`; support `SHA` authentication and `DES` or `AES` privacy.
- Never issue SNMP SET requests.
- Never log, render, return, or serialize SNMP credentials.
- Query each configured switch once per Orangutan scan, not once per device.
- Prefer VLAN-aware `Q-BRIDGE-MIB::dot1qTpFdbPort`, then fall back to `BRIDGE-MIB::dot1dTpFdbPort`.
- Ignore FDB entries with bridge-port value `0`.
- Do not add a main-table column; use a sidebar card only.
- A failed switch must not abort Nmap, OPNsense, OpenWrt, UniFi, or other switch discovery.

---

### Task 1: Multi-Switch Configuration and gosnmp Dependency

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `config.example.ini`

**Interfaces:**
- Produces `SwitchesConfig` and `SwitchConfig` with fields required by the spec.
- `Config` gains `Switches SwitchesConfig`.
- Environment variable prefix is `ORANGUTAN_SWITCH_<UPPERCASE_ID>_`.

- [ ] Write failing config tests for ordered names, INI parsing, defaults, environment overrides, and validation.
- [ ] Run `go test ./internal/config -run 'TestSwitch'` to verify failure.
- [ ] Run `go get github.com/gosnmp/gosnmp` and `go mod tidy`.
- [ ] Implement switch config parsing, normalization, defaults, environment variables, and validation.
- [ ] Document `[switches]` and `[switch.switchy]` in `config.example.ini`.
- [ ] Run `go test -v ./internal/config`.
- [ ] Commit `feat(config): add multi-switch SNMPv3 configuration`.

### Task 2: Switch Connection Model, Migration, and Storage Persistence

**Files:**
- Modify: `internal/types/types.go`
- Create: `internal/storage/migrations/00005_add_switch_connection.sql`
- Modify: `internal/storage/storage.go`
- Modify: `internal/storage/storage_test.go`

**Interfaces:**
- `types.Device` gains `SwitchName`, `SwitchHost`, `SwitchPort`, `SwitchVLAN`, `SwitchLinkState`, `SwitchLinkSpeed`, `SwitchDuplex`, `SwitchPoEWatts`, and `SwitchUpdatedAt`.
- Produces `storage.SwitchConnection` and `Storage.MergeSwitchConnections(connections []SwitchConnection, switchName string) error`.

- [ ] Write failing tests for case-insensitive merge, customization preservation, clear-on-absent after a successful scan, per-switch isolation, and nullable PoE/timestamps.
- [ ] Run `go test ./internal/storage -run 'TestMergeSwitchConnections'` to verify failure.
- [ ] Add migration 00005 and update every devices SELECT/INSERT/UPDATE/scan path in `storage.go`.
- [ ] Implement transaction-safe merge and successful-scan clear behavior.
- [ ] Run `go test -v ./internal/storage`.
- [ ] Commit `feat(storage): persist switch port connection telemetry`.

### Task 3: SNMPv3 Table Acquisition and MAC-to-Interface Resolution

**Files:**
- Create: `internal/scanner/switches.go`
- Create: `internal/scanner/switches_test.go`

**Interfaces:**
- Produces `FetchSwitchConnections(ctx context.Context, cfg config.SwitchConfig, vlanByMAC map[string]int) ([]scanner.SwitchConnection, error)`.
- Uses gosnmp read-only walks of IF-MIB, BRIDGE-MIB, Q-BRIDGE-MIB, and optional POWER-ETHERNET-MIB.

- [ ] Write failing fake-walker tests for physical port mapping, VLAN-aware preference, fallback FDB, bridge port 0 rejection, MAC normalization, port channels, and optional PoE failure.
- [ ] Run `go test ./internal/scanner -run 'TestSwitch'` to verify failure.
- [ ] Implement SNMPv3 authPriv connection construction and table retrieval with no SNMP SET use.
- [ ] Implement OID parsing and MAC/VLAN/bridge-port/interface resolution helpers.
- [ ] Run `go test -v ./internal/scanner`.
- [ ] Commit `feat(scanner): resolve MAC addresses to SNMP switch ports`.

### Task 4: Scan Pipeline Integration and Per-Switch Isolation

**Files:**
- Modify: `internal/api/scanjob.go`
- Modify: `internal/api/scanjob_test.go`

**Interfaces:**
- Consumes `cfg.Switches`, `scanner.FetchSwitchConnections`, and `Storage.MergeSwitchConnections`.
- Produces one scan summary per switch named `<switch> SNMP`.

- [ ] Write failing tests for per-switch success, isolated failure, once-per-scan polling, disabled configuration, and VLAN map propagation.
- [ ] Run `go test ./internal/api -run 'TestScanJob_Switch'` to verify failure.
- [ ] Integrate sequential switch polling after router and UniFi merges, with sanitized logs and summary rows.
- [ ] Run `go test -v ./internal/api`.
- [ ] Commit `feat(api): poll configured switches during device scans`.

### Task 5: Device Sidebar Switch Connection Presentation

**Files:**
- Modify: `internal/web/templates/index.html`
- Modify: `internal/web/static/app.js`
- Modify: `internal/web/static/style.css`
- Modify: `internal/web/handler_test.go`

**Interfaces:**
- Device rows expose all switch telemetry as `data-switch-*` attributes.
- Produces sidebar `#sb-switch-card`, shown only for an active port result.

- [ ] Write failing web test for rendering switch data attributes and sidebar card markup.
- [ ] Run `go test ./internal/web -run 'TestIndexPageRendersSwitchConnection'` to verify failure.
- [ ] Add sidebar card and data attributes to the server template.
- [ ] Populate/hide the card in `openDeviceSidebar`; distinguish port channels from physical ports and label Wi-Fi entries as upstream AP connections.
- [ ] Add compact sidebar-only status/PoE styles.
- [ ] Run `node --check internal/web/static/app.js` and `go test -v ./internal/web`.
- [ ] Commit `feat(web): show switch connection details in device sidebar`.

### Task 6: Full Verification and Documentation

**Files:**
- Modify: `README.md`
- Modify: `config.example.ini`
- Modify: `docs/INSTALL.md`

- [ ] Document multi-switch SNMPv3 configuration, SG500X SHA/DES compatibility, systemd overrides, security constraints, Wi-Fi AP-uplink semantics, and port-channel behavior.
- [ ] Run `gofmt -w internal`, `go vet ./...`, `go test -count=1 ./...`, `node --check internal/web/static/app.js`, `go build -o /tmp/orangutan-switch-test ./cmd/orangutan`, and `git diff --check`.
- [ ] Verify migration 00005 through `go test -v ./internal/storage -run 'Test.*Switch'`.
- [ ] Commit `docs: document SNMPv3 switch port integration`.
