# Unified Traffic Telemetry Implementation Plan

## Goal
Implement unified traffic monitoring and historical visualization across Cisco Switch (SNMP 64-bit port octets), UniFi Controller, and OPNsense NetFlow with a 2-tier rolling storage model and SVG modal visualization.

## Phases
- [x] Spec: `docs/superpowers/specs/2026-10-14-unified-traffic-telemetry-design.md`
- [ ] Phase 1: Database Migration & Storage Engine (`00014_add_traffic_metrics.sql`, `storage.go`, tests)
- [ ] Phase 2: Cisco Switch SNMP Port 64-bit Octets (`switches.go`, tests)
- [ ] Phase 3: OPNsense NetFlow Telemetry Collection (`routers.go`, tests)
- [ ] Phase 4: Background TrafficCollector, Delta Calculations & Scheduler (`traffic.go`, `scanjob.go`, tests)
- [ ] Phase 5: REST API Endpoint `GET /api/devices/{mac}/traffic` (`api.go`, tests)
- [ ] Phase 6: Frontend Visualization (SVG chart, table bandwidth badge, sidebar card, modal)
- [ ] Phase 7: Verification (Go test -race, Node tests, gofmt, go vet)
