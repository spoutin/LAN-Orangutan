# Controller Inventory And Deep Scan Design

## Goal

Replace the recurring active IPv4 subnet sweep with a controller-driven inventory refresh. LAN Orangutan will continue to refresh inventory every five minutes, but normal refreshes must not run Nmap host discovery or arp-scan against every address in a CIDR.

Known devices remain eligible for deliberate TCP service scans. A scheduled deep scan runs nightly at 03:00 Eastern, within a three-hour maintenance window. The dashboard provides separate manual actions for controller inventory refresh and deep scanning.

## Scope

This design changes the normal discovery job, scan scheduling, scan-mode API/UI, hostname enrichment, and automated coverage. It does not add a manual active subnet-discovery feature.

## Controller Inventory Refresh

The recurring `scan_interval` job becomes a controller inventory refresh. It continues to run every configured interval, five minutes by default, and is also available manually from the dashboard.

Each refresh collects and merges data from enabled existing sources:

- OPNsense and OpenWrt DHCP leases, reservations, and OPNsense ARP entries.
- UniFi connected wireless clients.
- Configured switch SNMP forwarding tables.
- IPv6 neighbor discovery, mDNS, and Tailscale peers.

The refresh never invokes Nmap `-sn`, arp-scan, or another address-by-address active network sweep. Controller polling uses a bounded number of connections to the configured controllers rather than connections or probes to every possible device IP.

The inventory refresh may be scoped to one network or all networks from the dashboard. Source records outside the requested scope are not merged as newly observed presence for that request. Sources that are inherently global, such as a controller client list or switch forwarding table, are fetched once and their device records are filtered to the selected CIDRs before merge and progress reporting.

Existing controller-source failure isolation remains: failure to query one configured controller does not prevent other sources from updating inventory. A job summary reports each source as scanned or failed without exposing credentials or transport-sensitive details.

## Hostname Enrichment

Controller-provided hostnames have priority. After source data is merged, LAN Orangutan identifies devices in the selected scope that remain without a hostname.

For each unnamed device, it attempts reverse DNS. Only if reverse DNS returns no hostname does it send the existing UDP/137 NetBIOS node-status query. The current bounded concurrency and timeouts remain in force. No hostname-resolution step opens TCP connections to the endpoint.

Name enrichment runs for both automatic and manual inventory refreshes. It retries existing unnamed inventory records on subsequent refreshes so a newly created DNS entry or reachable Windows host can be named later. A non-empty user override is never overwritten.

## Device Presence

Controller observations update device presence and existing metadata using the established storage merge behavior. Devices are retained when absent from a refresh and are marked stale/offline using the existing missing-device logic.

Coverage is intentionally controller-derived: a quiet static-IP device may not appear until it is represented by a DHCP/ARP record, a Wi-Fi controller, an upstream switch forwarding table, mDNS, IPv6 neighbor data, Tailscale, or a later deep scan. There is no routine active sweep fallback.

## Dashboard And API

The existing `quick`, `deep`, and `both` scan modes are replaced with two explicit operations:

- `inventory`: controller-driven inventory refresh, for one network or all networks.
- `deep`: active TCP service scan of known, currently eligible devices, for one network or all networks.

The network sidebar and All Networks controls expose these as separate actions rather than a three-value selector. The inventory action is the normal visible refresh control and uses the same backend path as automatic interval refreshes.

A manual Deep scan presents a blocking confirmation dialog before the API call. The dialog includes the selected network scope and configured port range and states that the operation actively connects to each eligible known device, can create significant firewall connection state, can trigger IDS/IPS alerts, and may affect fragile devices. It provides Cancel and an explicit Start deep scan action.

Automatic nightly scans do not require browser confirmation. Their job summary/history records that the operation was a scheduled active deep scan.

The API validates only `inventory` and `deep` modes. Any compatibility migration needed for old browser pages is limited to a clear API error; server behavior does not retain active quick or combined scan paths.

## Nightly Deep Scan

Replace the current hourly-window check inside the interval scanner with a calendar scheduler that computes the next 03:00 in `America/New_York`. It starts a deep-only job at that exact local time, including across daylight-saving transitions, then calculates the next occurrence after the attempt completes.

Before it creates targets, the nightly scheduler runs one controller inventory refresh for all networks. The deep job then selects currently eligible known devices in the configured scopes. This provides a current target set without daytime active discovery.

The nightly deep-scan context expires at 06:00 Eastern. The scheduler must not start additional hosts once the deadline is reached, and workers must honor cancellation. The progress/result record identifies targets not reached before the deadline as skipped because the maintenance window ended.

Manual deep scans use the same target selection and conservative scanning policy but do not inherit the nightly 06:00 deadline.

## Deep Scan Rate Policy

Stage 2 changes from the current `nmap -sV -Pn -p <range> -T4` policy with three concurrent workers to a conservative, bounded policy suitable for a three-hour overnight window.

- Keep service detection, no extra host-discovery probe, configured port range, XML parsing, and per-host cancellation support.
- Lower Nmap timing from `-T4` to a conservative timing template.
- Use a small global worker pool and pacing derived from remaining window time and queued targets, preventing a connection burst at the start of the job.
- Keep a finite per-host timeout, capped by the remaining job window.
- Preserve progress telemetry per network and completion counts.

The implementation will define concrete defaults in one location and cover them with tests. The policy favors predictable low concurrent firewall state over completing every possible port scan quickly. Operators can still run a manual deep scan when they need faster results, but it uses the same safe defaults.

## Scheduling And Configuration

`scan_interval` remains the controller inventory refresh cadence and defaults to 300 seconds. `continuous_scan` continues to enable or disable the recurring inventory refresh, not the nightly deep scan.

The nightly deep scheduler is enabled when a port range is configured and deep scanning is enabled. It does not depend on the interval refresh ticker aligning with the 03:00 hour. It should be possible to expose its enablement and local schedule in later UI/config work without changing the scheduling architecture.

## Error Handling And Concurrency

Only one job runs at a time. A manual request while an inventory or deep job is active attaches to the existing job using the current behavior; it does not start a duplicate scan.

An automatic interval refresh skips when another job is active. The 03:00 scheduler records a skipped nightly deep run if a job is still active when its window begins rather than competing with it. It must never start a deep scan after 06:00 as catch-up work.

All source calls, DNS lookups, NetBIOS queries, Nmap subprocesses, and worker dispatch must receive the job context so cancellation and the nightly deadline stop work promptly.

## Tests

Add or update tests for:

- Automatic and manual inventory refresh paths never call active subnet discovery.
- Enabled controller sources merge and scope their records correctly; one source failure remains isolated.
- Source hostname wins; reverse DNS runs only for unnamed devices; NetBIOS runs only after unresolved reverse DNS; user overrides are preserved.
- Inventory refresh retries later for existing unnamed devices.
- API accepts `inventory` and `deep` and rejects legacy scan modes.
- Manual deep scan UI confirmation names the scope, port range, firewall-state impact, IDS/IPS alert risk, and endpoint-impact warning.
- Calendar scheduling selects the next 03:00 Eastern occurrence and handles the 06:00 deadline without starting late work.
- Nightly deep scans perform one inventory refresh before selecting targets.
- Deep scanning uses the conservative arguments, bounded worker policy, cancellation, and per-network progress behavior.
- Existing storage behavior for stale/offline devices and deep-scan result persistence remains intact.

## Non-Goals

- No active subnet sweep during normal refreshes.
- No new manual active-discovery mode.
- No guarantee that silent static devices absent from all controller and supplemental sources are immediately discovered.
- No firewall configuration changes; the design reduces scan-generated state by avoiding routine per-address TCP discovery and throttling the remaining intentional TCP service scan.
