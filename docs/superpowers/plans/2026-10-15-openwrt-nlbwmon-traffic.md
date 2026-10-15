# OpenWrt nlbwmon Firewall WAN Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate OpenWrt nlbwmon JSON-RPC bandwidth monitoring into LAN-Orangutan's TrafficCollector, attributing WAN throughput and byte volumes to devices on OpenWrt subnets.

**Architecture:** Add `nlbwmon` opt-in configuration to OpenWrt routers. Implement `FetchOpenWrtNlbwmon` in `internal/scanner/routers.go` using JSON-RPC `/ubus` with Bearer auth. In `TrafficCollector.CollectCycle()`, poll enabled OpenWrt routers, filter flows strictly to configured networks, calculate rate deltas, and persist samples with `Source: "openwrt"`. Update storage, API endpoints, and web views to treat OpenWrt WAN stats identically to OPNsense NetFlow.

**Tech Stack:** Go 1.22+, SQLite, standard `net/http` and `encoding/json`, vanilla HTML5/JS frontend.

**Spec:** `docs/superpowers/specs/2026-10-15-openwrt-nlbwmon-traffic-design.md`

## Global Constraints
- Target repository: `/Users/ablack/repos/LAN-Orangutan`.
- Code changes must conform strictly to existing project conventions, idiomatic Go, and vanilla JS styling without external libraries.
- WAN traffic attribution is strictly scoped to subnets configured under `networks` for that firewall.
- Do not run unbounded long-running background test suites; run targeted package tests.

---

### Task 1: Add `Nlbwmon` Configuration to `OpenWrtConfig`

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `config.example.ini`

**Interfaces:**
- Consumes: `config.OpenWrtConfig`
- Produces: `OpenWrtConfig.Nlbwmon bool`, `c.setOpenWrtValue(..., "nlbwmon", ...)`, environment variable parsing for `OPENWRT_NLBWMON` and `OPENWRT_<ID>_NLBWMON`.

- [ ] **Step 1: Write failing config unit tests**
Add tests in `internal/config/config_test.go` verifying that `nlbwmon = true` parses into `OpenWrt.Nlbwmon = true` both for the base `[openwrt]` section and multi-router `[openwrt.secondary]` sections, and through environment variables `OPENWRT_NLBWMON=true`.

- [ ] **Step 2: Run test to verify it fails**
Run: `go test -v ./internal/config -run TestOpenWrtNlbwmonConfig`
Expected: FAIL (field `Nlbwmon` undefined)

- [ ] **Step 3: Implement `Nlbwmon` field and parser**
In `internal/config/config.go`:
1. Add `Nlbwmon bool` to `type OpenWrtConfig struct`.
2. In `c.setOpenWrtValue(id, key, value)`, handle `case "nlbwmon": wrt.Nlbwmon = parseBool(value)`.
3. In `applyEnvOverrides()`, check `OPENWRT_NLBWMON` and router-specific env vars.
4. Update `config.example.ini` documenting `# nlbwmon = true`.

- [ ] **Step 4: Run test to verify it passes**
Run: `go test -v ./internal/config -run TestOpenWrtNlbwmonConfig`
Expected: PASS

- [ ] **Step 5: Commit**
```bash
git add internal/config/config.go internal/config/config_test.go config.example.ini
git commit -m "feat(config): add opt-in nlbwmon setting for OpenWrt routers"
```

---

### Task 2: Implement `FetchOpenWrtNlbwmon` JSON-RPC Client

**Files:**
- Modify: `internal/scanner/routers.go`
- Modify: `internal/scanner/routers_test.go`

**Interfaces:**
- Consumes: `config.OpenWrtConfig`
- Produces: `FetchOpenWrtNlbwmon(ctx context.Context, cfg config.OpenWrtConfig) (map[string]*types.NetFlowDeviceStats, error)`

- [ ] **Step 1: Write failing unit test for `FetchOpenWrtNlbwmon`**
In `internal/scanner/routers_test.go`:
Add `TestFetchOpenWrtNlbwmon` using `httptest.NewServer`:
1. Verifies HTTP POST to `/ubus` with `Authorization: Bearer <token>` and `Content-Type: application/json`.
2. Verifies JSON-RPC body format (`method: "call"`, `params: [token, "nlbwmon", "dump", {"format":"json"}]`).
3. Verifies response parsing for standard `result: [0, {"columns": ["mac","ip","in","out"], "rows": [["aa:bb:cc:dd:ee:01","10.5.5.10",1000,500]]}]` and alternate column names (`rx_bytes`, `tx_bytes`).
4. Verifies aggregation across multiple rows for the same IP.

- [ ] **Step 2: Run test to verify it fails**
Run: `go test -v ./internal/scanner -run TestFetchOpenWrtNlbwmon`
Expected: FAIL (`FetchOpenWrtNlbwmon` undefined)

- [ ] **Step 3: Implement `FetchOpenWrtNlbwmon`**
In `internal/scanner/routers.go`:
1. Create `FetchOpenWrtNlbwmon(ctx context.Context, cfg config.OpenWrtConfig) (map[string]*types.NetFlowDeviceStats, error)`.
2. Construct HTTP POST request to `cfg.URL + "/ubus"`.
3. Set `Authorization: Bearer <cfg.APIToken>`.
4. Send JSON-RPC payload.
5. Parse JSON-RPC response with dynamic column mapping and sum `RxBytes` / `TxBytes` per IP into `map[string]*types.NetFlowDeviceStats`.

- [ ] **Step 4: Run test to verify it passes**
Run: `go test -v ./internal/scanner -run TestFetchOpenWrtNlbwmon`
Expected: PASS

- [ ] **Step 5: Commit**
```bash
git add internal/scanner/routers.go internal/scanner/routers_test.go
git commit -m "feat(scanner): implement FetchOpenWrtNlbwmon JSON-RPC client"
```

---

### Task 3: Support `Source: "openwrt"` WAN Metrics in Storage

**Files:**
- Modify: `internal/storage/storage.go`
- Modify: `internal/storage/storage_test.go`

**Interfaces:**
- Consumes: `types.TrafficSample` with `Source: "openwrt"`
- Produces: Updates `wan_rx_rate_bps`, `wan_tx_rate_bps`, `wan_rx_bytes`, `wan_tx_bytes` in SQLite `devices` and `traffic_samples` table.

- [ ] **Step 1: Write failing storage unit test**
In `internal/storage/storage_test.go`:
Add `TestRecordTrafficSamples_OpenWrtWAN` verifying that samples with `Source: "openwrt"` update WAN rates and byte totals while leaving local link metrics intact.

- [ ] **Step 2: Run test to verify it fails**
Run: `go test -v ./internal/storage -run TestRecordTrafficSamples_OpenWrtWAN`
Expected: FAIL (WAN rates not updated or source overwritten as link source)

- [ ] **Step 3: Update `storage.go`**
In `internal/storage/storage.go`:
In `RecordTrafficSamples()`:
Change condition to `if sample.Source == "opnsense" || sample.Source == "openwrt"` so both firewall sources execute `stmtUpdateDeviceWAN`.

- [ ] **Step 4: Run test to verify it passes**
Run: `go test -v ./internal/storage -run TestRecordTrafficSamples_OpenWrtWAN`
Expected: PASS

- [ ] **Step 5: Commit**
```bash
git add internal/storage/storage.go internal/storage/storage_test.go
git commit -m "feat(storage): support OpenWrt WAN traffic samples in RecordTrafficSamples"
```

---

### Task 4: Integrate OpenWrt nlbwmon into `TrafficCollector.CollectCycle`

**Files:**
- Modify: `internal/api/traffic.go`
- Modify: `internal/api/traffic_test.go`

**Interfaces:**
- Consumes: `tc.cfg.AllOpenWrts()`, `fetchNlbwmon`
- Produces: Records `types.TrafficSample{Source: "openwrt"}` during `CollectCycle`.

- [ ] **Step 1: Write failing unit test in `traffic_test.go`**
Add `TestTrafficCollector_OpenWrtNlbwmon` verifying:
1. When OpenWrt has `Enable: true`, `Nlbwmon: true`, and `Networks: ["10.5.5.0/24"]`, devices within `10.5.5.0/24` have OpenWrt WAN samples recorded.
2. Devices outside `10.5.5.0/24` are filtered out.
3. If `Nlbwmon: false`, no OpenWrt collection occurs.

- [ ] **Step 2: Run test to verify it fails**
Run: `go test -v ./internal/api -run TestTrafficCollector_OpenWrtNlbwmon`
Expected: FAIL

- [ ] **Step 3: Implement OpenWrt collection in `CollectCycle`**
In `internal/api/traffic.go`:
1. Update signature / inject `fetchNlbwmon func(context.Context, config.OpenWrtConfig) (map[string]*types.NetFlowDeviceStats, error)`.
2. Default `fetchNlbwmon` in `StartTrafficCollector` to `scanner.FetchOpenWrtNlbwmon`.
3. Iterate over `tc.cfg.AllOpenWrts()`.
4. If `wrt.Enable && wrt.Nlbwmon && len(wrt.Networks) > 0 && ctx.Err() == nil`:
   - Fetch flows via `fetchNlbwmon(ctx, wrt)`.
   - Filter devices by `network.ContainsIP(wrt.Networks, dev.IP)`.
   - Calculate WAN rates with key `normMAC + ":wan"`.
   - Append `types.TrafficSample{MAC: normMAC, RxBytes: st.RxBytes, TxBytes: st.TxBytes, RxRate: rxRate, TxRate: txRate, Source: "openwrt"}`.

- [ ] **Step 4: Run test to verify it passes**
Run: `go test -v ./internal/api -run TestTrafficCollector_OpenWrtNlbwmon`
Expected: PASS

- [ ] **Step 5: Commit**
```bash
git add internal/api/traffic.go internal/api/traffic_test.go
git commit -m "feat(traffic): poll OpenWrt nlbwmon flows in TrafficCollector cycle"
```

---

### Task 5: Web Index, API Scoping & Template Presentation

**Files:**
- Modify: `internal/web/handler.go`
- Modify: `internal/web/handler_test.go`
- Modify: `internal/api/api.go`
- Modify: `internal/web/templates/index.html`
- Modify: `internal/web/static/app.js`

**Interfaces:**
- Consumes: `h.cfg.AllOpenWrts()`, `TrafficSource: "openwrt"`
- Produces: Displays `[openwrt]` WAN badges and rate lines; zeroes WAN stats outside configured firewall networks.

- [ ] **Step 1: Write failing handler test for OpenWrt WAN scoping**
In `internal/web/handler_test.go`:
Add `TestIndexPageOpenWrtWANAttribution`:
1. Configures OpenWrt with `Enable: true`, `Nlbwmon: true`, `Networks: ["10.5.5.0/24"]`.
2. Seeds a device in `10.5.5.0/24` with `TrafficSource: "openwrt"` and WAN rates.
3. Seeds a device in `192.168.1.0/24` with WAN rates.
4. Verifies inside device renders WAN rate and `[openwrt]` badge, and outside device has WAN rate zeroed.

- [ ] **Step 2: Run test to verify it fails**
Run: `go test -v ./internal/web -run TestIndexPageOpenWrtWANAttribution`
Expected: FAIL

- [ ] **Step 3: Update `handler.go`, `api.go`, `index.html`, and `app.js`**
1. In `internal/web/handler.go` (`handleIndex`):
   - Check if device is in `OPNsense.Networks` OR any enabled OpenWrt router's `Networks` with `Nlbwmon: true`.
   - If not, zero out WAN metrics and clear `TrafficSource` if `"opnsense"` or `"openwrt"`.
2. In `internal/api/api.go` (`handleDeviceTraffic`):
   - Apply the same check before returning device traffic series.
3. In `internal/web/templates/index.html`:
   - Update WAN subrow condition and label to display `[{{.TrafficSource}}]` when `TrafficSource` is `"openwrt"` or `"opnsense"`.
4. In `internal/web/static/app.js`:
   - Treat `data.trafficSource === 'openwrt'` as a WAN source so it does not override `linkSource`.
   - Include `'openwrt'` in `hasWanTraffic`.

- [ ] **Step 4: Run handler tests and JS tests**
Run: `go test -v ./internal/web -run TestIndexPageOpenWrtWANAttribution`
Run: `node --test internal/web/static/*.test.js`
Expected: PASS

- [ ] **Step 5: Commit**
```bash
git add internal/web/handler.go internal/web/handler_test.go internal/api/api.go internal/web/templates/index.html internal/web/static/app.js
git commit -m "feat(ui): display OpenWrt nlbwmon WAN throughput and scope to firewall networks"
```

---

### Task 6: Comprehensive Verification & Build

**Files:**
- All modified files

- [ ] **Step 1: Run complete test suite on affected packages**
```bash
go test -v ./internal/config -run TestOpenWrt
go test -v ./internal/scanner -run TestFetchOpenWrt
go test -v ./internal/storage -run TestRecordTraffic
go test -v ./internal/api -run 'TestTrafficCollector|TestDeviceTrafficAPI'
go test -v ./internal/web -run 'TestIndexPageWAN|TestIndexPageOpenWrt'
node --test internal/web/static/*.test.js
```

- [ ] **Step 2: Run linter, compiler, and formatting checks**
```bash
gofmt -l .
go vet ./internal/...
go build ./...
```

- [ ] **Step 3: Commit and tag release**
```bash
git status
git tag v3.21.0
git push origin main && git push origin v3.21.0
```
