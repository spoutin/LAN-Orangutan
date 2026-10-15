# OpenWrt nlbwmon Firewall WAN Telemetry Design

## 1. Purpose & Overview
Extend LAN-Orangutan to capture, track, and visualize WAN network traffic volume and live throughput for devices behind OpenWrt firewalls running `nlbwmon` (Netlink Bandwidth Monitor). This brings OpenWrt networks to feature parity with OPNsense NetFlow, capturing per-device WAN rates, total volumes, and directional metrics without disrupting local switch or wireless AP link attribution.

## 2. Configuration (`internal/config`)
Add opt-in `nlbwmon` configuration to `OpenWrtConfig`:

```ini
[openwrt]
enable = true
url = https://10.5.5.1
api_token = secret_token
nlbwmon = true
networks = 10.5.5.0/24

# Multi-router support
[openwrt.secondary]
enable = true
url = https://10.6.6.1
api_token = another_secret
nlbwmon = true
networks = 10.6.6.0/24
```

- **INI setting:** `nlbwmon = true` under `[openwrt]` and `[openwrt.<id>]`.
- **Environment variables:** `OPENWRT_NLBWMON=true` and multi-router overrides like `OPENWRT_<ID>_NLBWMON=true`.

## 3. OpenWrt `/ubus` JSON-RPC Client (`internal/scanner/routers.go`)
Implement `FetchOpenWrtNlbwmon(ctx context.Context, cfg config.OpenWrtConfig) (map[string]*types.NetFlowDeviceStats, error)`:
- **Endpoint:** `{cfg.URL}/ubus`
- **Method:** `POST`
- **Headers:**
  - `Authorization: Bearer <cfg.APIToken>`
  - `Content-Type: application/json`
  - `Accept: application/json`
- **JSON-RPC 2.0 Payload:**
  ```json
  {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "call",
    "params": [
      "<cfg.APIToken>",
      "nlbwmon",
      "dump",
      {"format": "json"}
    ]
  }
  ```
- **Response Parsing:**
  - Robustly unmarshals either `result: [0, {"columns": [...], "rows": [...]}]` or direct object `result: {"columns": [...], "rows": [...]}`.
  - Dynamically indexes columns:
    - IP: `ip`, `addr`, `host`
    - MAC: `mac`, `hw`, `ether`
    - Rx bytes: `rx_bytes`, `rx`, `in`, `in_bytes`, `download`
    - Tx bytes: `tx_bytes`, `tx`, `out`, `out_bytes`, `upload`
  - Aggregates multi-flow byte counts per IP address.
  - Returns `map[string]*types.NetFlowDeviceStats` (mapping IP to RxBytes and TxBytes).

## 4. Poller & Storage Pipeline (`internal/api/traffic.go` & `internal/storage/storage.go`)
- **Traffic Poller (`CollectCycle`):**
  - Accepts `fetchNlbwmon func(context.Context, config.OpenWrtConfig) (map[string]*types.NetFlowDeviceStats, error)`.
  - Iterates through `tc.cfg.AllOpenWrts()`.
  - Gated by: `wrt.Enable && wrt.Nlbwmon && len(wrt.Networks) > 0 && ctx.Err() == nil`.
  - Scopes flows strictly to devices on `wrt.Networks` via `network.ContainsIP(wrt.Networks, dev.IP)`.
  - Calculates rate deltas under rate key `normMAC + ":wan"` via `tc.ComputeRate`.
  - Persists `types.TrafficSample` with `Source: "openwrt"`.
- **Storage Layer (`RecordTrafficSamples`):**
  - Treats `sample.Source == "openwrt"` as a WAN source updating `wan_rx_rate_bps`, `wan_tx_rate_bps`, `wan_rx_bytes`, and `wan_tx_bytes`.
  - Preserves local link metrics (`rx_rate_bps`, `tx_rate_bps`, `rx_bytes`, `tx_bytes`) if populated by switch or UniFi AP.
  - Sets `traffic_source` fallback to `"openwrt"` if not already set by a link source.

## 5. Web UI, API Scoping & Presentation
- **Server-Side Scoping (`internal/web/handler.go` & `internal/api/api.go`):**
  - Determines if a device IP belongs to an enabled firewall network (`OPNsense.Networks` or an enabled OpenWrt router's `wrt.Networks`).
  - Outside devices have WAN rates/totals zeroed and firewall `TrafficSource` cleared.
- **Device Table (`index.html`):**
  - Displays the WAN rate row: `WAN: ↓ <rate> ↑ <rate> · Total: <bytes> [openwrt]`.
  - Renders the `.traffic-badge-wan` badge on the device row.
- **Sidebar & Client-Side JS (`app.js`):**
  - Recognizes `trafficSource === 'openwrt'` as a WAN source so it does not override switch/AP link details.
  - Activates the sidebar router traffic card for OpenWrt devices.
