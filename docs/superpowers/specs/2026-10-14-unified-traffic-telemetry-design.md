# Unified Switch, Firewall & UniFi Traffic Telemetry Design

## Purpose
Extend LAN-Orangutan to capture, track, and visualize network traffic volume and live throughput across wired, wireless, and routed devices by unifying:
1. Cisco Switch (SNMPv3): 64-bit hardware port counters (`ifHCInOctets` / `ifHCOutOctets`) for dedicated wired ports.
2. UniFi Controller: Wireless station statistics (`stat/sta` Rx/Tx bytes and PHY rates).
3. OPNsense Firewall: NetFlow telemetry (`/api/diagnostics/netflow/getData`) for routed WAN and inter-VLAN attribution.

## Core Capabilities
1. **60-Second Telemetry Worker**:
   - Gathers hardware metrics every 60 seconds independently of discovery scans.
   - Computes instantaneous throughput (`rx_rate_bytes_sec`, `tx_rate_bytes_sec`) using previous counter deltas.
2. **Two-Tier Rolling Retention**:
   - `traffic_samples`: 1-minute samples kept for 24 hours (for high-resolution 1h and 24h charts).
   - `traffic_hourly`: 1-hour rollups kept for 7 days (for multi-day historical trend analysis).
   - Hourly auto-pruning caps total database storage footprint strictly under 3–5 MB.
3. **REST API**:
   - `GET /api/devices/{mac}/traffic?range=1h|24h|7d`: Returns current rates, totals, source, and time-series data points.
4. **UI Visualizations**:
   - Main Device Table: Live bandwidth badge with directional arrows (`↓ 1.4 MB/s ↑ 84 KB/s`).
   - Device Sidebar: Dedicated Traffic & Bandwidth card with current rate, session volume, and source badge.
   - Traffic History Modal: Pure vanilla SVG area chart (zero external JS dependencies) showing dual-tone Rx/Tx curves, hover tooltips, and 1h / 24h / 7d toggles.

## Database Schema
Migration: `00014_add_traffic_metrics.sql`

```sql
CREATE TABLE IF NOT EXISTS traffic_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    rx_bytes INTEGER NOT NULL DEFAULT 0,
    tx_bytes INTEGER NOT NULL DEFAULT 0,
    rx_rate INTEGER NOT NULL DEFAULT 0,
    tx_rate INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_traffic_samples_mac_time ON traffic_samples(mac, timestamp);

CREATE TABLE IF NOT EXISTS traffic_hourly (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    bucket_time DATETIME NOT NULL,
    rx_bytes_delta INTEGER NOT NULL DEFAULT 0,
    tx_bytes_delta INTEGER NOT NULL DEFAULT 0,
    avg_rx_rate INTEGER NOT NULL DEFAULT 0,
    avg_tx_rate INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_traffic_hourly_mac_time ON traffic_hourly(mac, bucket_time);
```
