# Final Fix Report

## Review Findings Resolved

1. Enabled switch configurations are no longer validated during `config.Load` or `Config.ApplyEnv`, so invalid configuration cannot prevent CLI initialization or service startup. `SwitchConfig.Validate` remains unchanged and is invoked for each configured switch immediately before its scan fetch. An invalid switch produces one sanitized `<switch ID> SNMP` failed summary while subsequent switches and discovery sources continue.
2. UniFi station responses now decode the explicit `vlan` field into `types.Device`. SQLite migration `00006_add_unifi_vlan.sql` persists it, and all device scan, query, insert, update, merge, and preservation paths carry it. The scan job builds `vlanByMAC` from this explicit field, not network names. The UniFi integration test confirms the VLAN reaches the switch fetcher during the first scan.
3. Switch FDB resolution now uses only inventory MACs supplied in `vlanByMAC`. Extra forwarding-table rows do not produce connection results, scan-summary device counts, or journal-count contributions. Scanner coverage includes a non-inventory FDB entry alongside an inventory result.
4. The positional SQLite INSERT regression was corrected by restoring canonical column/value grouping for both general device upserts and transaction inserts. Existing supplemental and virtual-IP tests pass, with direct UniFi VLAN persistence and preservation tests added.
5. Every non-empty inventory MAC is now included in the switch resolver candidate map. A VLAN value of zero is retained as unknown, allowing the resolver to use its existing unambiguous standard BRIDGE FDB fallback. Known UniFi VLAN values continue to scope Q-BRIDGE FDB resolution. API coverage verifies the unknown-VLAN candidate reaches the resolver, stores the standard BRIDGE FDB result, and contributes exactly one switch summary connection.

## Security Constraints

- Switch validation continues to require SNMPv3 `authPriv`, SHA authentication, and DES or AES privacy.
- Credentials remain excluded from serialized switch configuration and are not included in scan summaries or logs.
- Switch polling remains read-only; no SNMP SET operation was added.

## Verification

All commands completed successfully on 2026-09-29:

- `go test -count=1 ./internal/api -run '^TestScanJob_SwitchesResolveUnknownVLANInventoryMACThroughBridgeFDB$'`
- `go test -count=1 ./internal/api ./internal/scanner`
- `go test -count=1 ./internal/storage`
- `go test -count=1 ./...`
- `go vet ./...`
- `node --test internal/web/static/switch-presentation.test.js`
- `node --check internal/web/static/app.js`
- `go build ./cmd/orangutan`
- `git diff --check`
