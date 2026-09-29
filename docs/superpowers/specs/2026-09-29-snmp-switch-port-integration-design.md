# SNMP Switch Port Integration Design

## Purpose

Extend LAN Orangutan with read-only SNMPv3 switch discovery so the device sidebar can show the currently learned switch port for wired devices and the upstream access-point port for bridged Wi-Fi clients. The first configured switch is the Cisco SG500X-24P named `switchy`, but the configuration and polling model support multiple switches.

## Scope

The feature fetches switch forwarding and interface tables once during every manual or continuous LAN Orangutan scan, maps inventory MAC addresses to switch interfaces, persists the last successful result, and presents it in a new sidebar card.

The feature does not modify switches, configure SNMP, send SNMP writes, determine topology beyond the learned forwarding entry, or add a main-table column.

## Configuration

Add multi-switch configuration under `[switches]`, with one per-switch section:

```ini
[switches]
enable = true
names = switchy

[switch.switchy]
host = 10.0.0.2
port = 161
version = 3
username = lan-orangutan
security_level = authPriv
auth_protocol = SHA
auth_password = YOUR_AUTH_PASSWORD
privacy_protocol = DES
privacy_password = YOUR_PRIVACY_PASSWORD
timeout_seconds = 5
```

`names` is a comma-separated, stable list of switch IDs. A switch ID is used as the friendly default name and identifies its `[switch.<id>]` section. The service reads matching systemd environment overrides:

```text
ORANGUTAN_SWITCHES_ENABLE
ORANGUTAN_SWITCHES_NAMES
ORANGUTAN_SWITCH_SWITCHY_HOST
ORANGUTAN_SWITCH_SWITCHY_PORT
ORANGUTAN_SWITCH_SWITCHY_VERSION
ORANGUTAN_SWITCH_SWITCHY_USERNAME
ORANGUTAN_SWITCH_SWITCHY_SECURITY_LEVEL
ORANGUTAN_SWITCH_SWITCHY_AUTH_PROTOCOL
ORANGUTAN_SWITCH_SWITCHY_AUTH_PASSWORD
ORANGUTAN_SWITCH_SWITCHY_PRIVACY_PROTOCOL
ORANGUTAN_SWITCH_SWITCHY_PRIVACY_PASSWORD
ORANGUTAN_SWITCH_SWITCHY_TIMEOUT_SECONDS
```

Environment variables override matching INI values. SNMP secrets must not be logged or included in API responses. Operators should prefer systemd overrides or environment files with restrictive permissions for the passwords.

## SNMPv3 Client

Go's standard library does not implement SNMP, so add one narrowly scoped SNMP library that supports SNMPv3 `authPriv`, SHA authentication, DES or AES privacy, request timeouts, and bulk walks. The integration is strictly read-only.

Each configured switch validates its configuration before polling:

- `version` must be `3`.
- `security_level` must be `authPriv`.
- Supported authentication protocol is `SHA`.
- Supported privacy protocols are `DES` and `AES`.
- A host, username, authentication password, and privacy password are required.
- `timeout_seconds` defaults to 5 when omitted or invalid.

Invalid switch configuration produces an isolated scan-summary failure and does not stop other discovery sources.

## Forwarding Table Resolution

The scanner queries each configured switch once per Orangutan scan and constructs in-memory maps before matching inventory devices:

1. `IF-MIB::ifName` (`1.3.6.1.2.1.31.1.1.1.1`) maps `ifIndex` to names such as `gi1/23`, `te1/2`, or `Po2`.
2. `IF-MIB::ifOperStatus`, `ifHighSpeed`, and duplex data provide optional port state, speed, and duplex values.
3. `BRIDGE-MIB::dot1dBasePortIfIndex` (`1.3.6.1.2.1.17.1.4.1.2`) maps a bridge-port number to `ifIndex`.
4. Prefer `Q-BRIDGE-MIB::dot1qTpFdbPort` (`1.3.6.1.2.1.17.7.1.2.2.1.2`) to resolve `VLAN + MAC` to a bridge port.
5. Fall back to `BRIDGE-MIB::dot1dTpFdbPort` (`1.3.6.1.2.1.17.4.3.1.2`) when a switch does not expose a VLAN-aware forwarding table.
6. Ignore entries mapping to bridge port `0`.

MAC values are normalized to lowercase colon-delimited format before matching. If an inventory device has a VLAN available from router or UniFi data, use the VLAN-aware entry for that VLAN first. If no matching VLAN-aware entry exists, use the unscoped fallback only when it has one unambiguous match.

For the validated SG500X data, bridge-port IDs map directly to physical `ifIndex` values. Example:

```text
MAC 6c:4c:bc:29:e8:c1
  -> bridge port 71
  -> ifIndex 71
  -> gi1/23
```

Port-channel interfaces such as `Po1` through `Po32` are retained as upstream/LAG results. The UI must not infer a specific member port for a port-channel entry.

## Data Model and Storage

Add a new migration to persist the latest resolved switch telemetry on `devices`:

```text
switch_name          TEXT NOT NULL DEFAULT ''
switch_host          TEXT NOT NULL DEFAULT ''
switch_port          TEXT NOT NULL DEFAULT ''
switch_vlan          INTEGER NOT NULL DEFAULT 0
switch_link_state    TEXT NOT NULL DEFAULT ''
switch_link_speed    INTEGER NOT NULL DEFAULT 0
switch_duplex        TEXT NOT NULL DEFAULT ''
switch_poe_watts     REAL
switch_updated_at    TIMESTAMP
```

The scanner returns a MAC-keyed result rather than a synthetic discovered device. Storage merges results into existing inventory records by normalized MAC without changing labels, notes, custom hostnames, assignment, UniFi telemetry, or router telemetry.

When a switch scan succeeds but its forwarding table no longer contains a device MAC, storage clears the current switch-port fields and timestamp. It does not retain a misleading stale location. If a switch itself fails to scan, existing stored switch data is left unchanged and is marked by its older `switch_updated_at` timestamp.

## Scan Pipeline and Error Handling

Switch polling runs after OPNsense, OpenWrt, and UniFi data merging, once in each manual or continuous scan job. It adds one scan-summary entry per configured switch:

```text
switchy SNMP   scanned   <resolved device count>
switchy SNMP   failed    <short error>
```

A switch failure is isolated: it never aborts Nmap, router, UniFi, or other switch discovery. Errors identify the switch ID and network condition but never include passwords or localized SNMP keys.

Successful scans log concise observability data to the service journal:

```text
Switch switchy: fetched <N> forwarding entries, resolved <N> device ports
```

## Sidebar Presentation

Keep the main table unchanged. Add a `Switch Connection` card to the existing device sidebar only when a current switch port is available:

```text
Switch Connection
Switch:      switchy
Port:        gi1/23
VLAN:        3
Link:        Up · 1 Gbps · Full duplex
PoE:         8.2 W                 # shown only when available
Updated:     Just now
```

For a port-channel result, use `Switch Uplink` and present the returned interface directly:

```text
Switch Uplink
Switch:      switchy
Interface:   Po2
Updated:     Just now
```

The card is hidden when no active FDB match exists. For bridged wireless clients, the returned port is normally the physical switch port hosting the access point; it is not a unique per-client physical connection. The UI should label the result as an upstream switch connection when the device also has a UniFi SSID.

## Testing

Unit tests use an injectable/mock SNMP transport and verify:

- SNMPv3 configuration validation and omission defaults.
- IF-MIB and bridge-port map construction.
- VLAN-aware FDB preferred over unscoped FDB.
- Standard FDB fallback behavior.
- MAC normalization and bridge port `0` rejection.
- Physical port and port-channel resolution.
- Storage persistence, clear-on-absent behavior, and preservation of user customizations.
- Per-switch failure isolation in the scan pipeline.
- Sidebar card rendering and hide/show behavior.

## Security Considerations

- Only SNMPv3 `authPriv` is supported.
- The application never sends SNMP SET requests.
- SNMP credentials are not included in logs, API output, rendered HTML, or scan summaries.
- The provided SG500X uses SHA authentication and DES privacy due to its firmware capabilities. Newer switches should use AES where available.
