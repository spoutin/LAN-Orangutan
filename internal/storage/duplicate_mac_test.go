package storage

import (
	"testing"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

func TestDuplicateMACDeduplicationAndMerge(t *testing.T) {
	s := newTestStorage(t)
	now := time.Now()

	// 1. Initial device at 192.168.1.10 with custom overrides and presence history
	dev10 := types.Device{
		IP:             "192.168.1.10",
		MAC:            "aa:bb:cc:dd:ee:ff",
		Hostname:       "old-host",
		Vendor:         "Acme",
		Type:           "Server",
		CustomHostname: "custom-nas",
		Label:          "My Server",
		Notes:          "Rack 1",
		Group:          "Storage",
		FirstSeen:      now.Add(-2 * time.Hour),
		LastSeen:       now.Add(-1 * time.Hour),
	}
	if err := mergeDevicesForTest(s, []types.Device{dev10}); err != nil {
		t.Fatalf("failed to save initial dev10: %v", err)
	}

	// Insert presence history for 192.168.1.10
	_, err := s.db.Exec(`
		INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
		VALUES (?, ?, ?, 'join', 0, ?)
	`, "192.168.1.10", "aa:bb:cc:dd:ee:ff", "custom-nas", now.Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("failed to insert presence history: %v", err)
	}

	// 2. Discover same MAC at new IP 192.168.1.25 with new scanned values
	dev25 := types.Device{
		IP:        "192.168.1.25",
		MAC:       "aa:bb:cc:dd:ee:ff",
		Hostname:  "new-host",
		Vendor:    "Acme Corp",
		FirstSeen: now,
		LastSeen:  now,
	}
	if err := mergeDevicesForTest(s, []types.Device{dev25}); err != nil {
		t.Fatalf("failed to save dev25: %v", err)
	}

	// 3. Verify unified device: exactly 1 device exists for this MAC, with both IPs attached
	devices := s.GetDevices()
	if len(devices) != 1 {
		t.Fatalf("expected 1 unified device in database, got %d", len(devices))
	}

	var merged *types.Device
	for _, d := range devices {
		merged = d
		break
	}
	if merged == nil {
		t.Fatalf("expected unified device, got nil")
	}

	// Active IP is now .25, and old .10 is recorded in AddressHistory
	has25 := false
	for _, att := range merged.IPs {
		if att.IP == "192.168.1.25" {
			has25 = true
		}
	}
	if !has25 {
		t.Errorf("expected 192.168.1.25 in merged.IPs, got %+v", merged.IPs)
	}

	// 4. Verify 3-tier precedence
	// Tier 1: User overrides preserved
	if merged.CustomHostname != "custom-nas" {
		t.Errorf("expected custom_hostname %q, got %q", "custom-nas", merged.CustomHostname)
	}
	if merged.Label != "My Server" {
		t.Errorf("expected label %q, got %q", "My Server", merged.Label)
	}
	if merged.Notes != "Rack 1" {
		t.Errorf("expected notes %q, got %q", "Rack 1", merged.Notes)
	}
	if merged.Group != "Storage" {
		t.Errorf("expected group %q, got %q", "Storage", merged.Group)
	}

	// Tier 2: New scanned values take precedence
	if merged.Hostname != "new-host" {
		t.Errorf("expected scanned hostname %q, got %q", "new-host", merged.Hostname)
	}
	if merged.Vendor != "Acme Corp" {
		t.Errorf("expected scanned vendor %q, got %q", "Acme Corp", merged.Vendor)
	}

	// Tier 3: Old scanned attributes fall back if empty in new scan
	if merged.Type != "Server" {
		t.Errorf("expected fallback type %q, got %q", "Server", merged.Type)
	}

	// 5. Verify presence history consolidation
	events, err := s.GetPresenceEventsFiltered("", "", "192.168.1.25")
	if err != nil {
		t.Fatalf("failed to get presence events for 192.168.1.25: %v", err)
	}
	if len(events) == 0 {
		t.Errorf("expected merged presence events for new IP 192.168.1.25, got 0")
	}
}

func TestDuplicateMACSimultaneousActiveScanDeduplicated(t *testing.T) {
	s := newTestStorage(t)

	// Simultaneously discover .10 and .20 sharing the same MAC.
	// .10 has older telemetry and custom user override.
	// .20 has newer telemetry.
	dev10 := types.Device{
		IP:             "192.168.1.10",
		MAC:            "aa:bb:cc:dd:ee:ff",
		Hostname:       "old-host",
		CustomHostname: "my-custom-host",
		Label:          "Custom Label",
		Type:           "Server",
	}
	dev20 := types.Device{
		IP:       "192.168.1.20",
		MAC:      "aa:bb:cc:dd:ee:ff",
		Hostname: "new-host",
		Vendor:   "Acme",
	}

	// Insert dev10 first
	if err := mergeDevicesForTest(s, []types.Device{dev10}); err != nil {
		t.Fatalf("failed to insert dev10: %v", err)
	}

	// Now a scan discovers both or dev20 is active while dev10 was active
	if err := mergeDevicesForTest(s, []types.Device{dev10, dev20}); err != nil {
		t.Fatalf("failed to merge: %v", err)
	}

	devices := s.GetDevices()
	if len(devices) != 1 {
		t.Errorf("expected duplicate MAC to be unified to 1 device, got %d", len(devices))
	}
	var merged *types.Device
	for _, d := range devices {
		merged = d
		break
	}
	if merged == nil {
		t.Fatalf("expected unified device, got nil")
	}
	if merged.CustomHostname != "my-custom-host" || merged.Label != "Custom Label" {
		t.Errorf("overrides lost on simultaneous/active scan: %+v", merged)
	}
	if len(merged.IPs) < 2 {
		t.Errorf("expected both IPs in merged.IPs, got %+v", merged.IPs)
	}
}

func TestRetroactiveDeduplicateMACs(t *testing.T) {
	s := newTestStorage(t)
	now := time.Now()

	// Seed two separate records with the same MAC directly in the database
	_, err := s.db.Exec(`
		INSERT INTO devices (
			ip, mac, hostname, custom_hostname, label, notes, "group",
			first_seen, last_seen, last_presence_change
		) VALUES (
			'10.0.0.10', 'aa:bb:cc:dd:ee:ff', 'host-old', 'nas-override', 'My Storage', 'rack A', 'Servers',
			?, ?, ?
		)
	`, now.Add(-10*time.Hour), now.Add(-5*time.Hour), now.Add(-5*time.Hour))
	if err != nil {
		t.Fatalf("seed dev 1: %v", err)
	}

	_, err = s.db.Exec(`
		INSERT INTO devices (
			ip, mac, hostname, vendor,
			first_seen, last_seen, last_presence_change
		) VALUES (
			'10.0.0.20', 'aa:bb:cc:dd:ee:ff', 'host-new', 'Synology',
			?, ?, ?
		)
	`, now.Add(-2*time.Hour), now, now)
	if err != nil {
		t.Fatalf("seed dev 2: %v", err)
	}

	// Insert presence history for the old IP 10.0.0.10
	_, err = s.db.Exec(`
		INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
		VALUES ('10.0.0.10', 'aa:bb:cc:dd:ee:ff', 'host-old', 'join', 0, ?)
	`, now.Add(-10*time.Hour))
	if err != nil {
		t.Fatalf("seed presence: %v", err)
	}

	// Run retroactive deduplication
	if err := s.DeduplicateMACs(); err != nil {
		t.Fatalf("DeduplicateMACs failed: %v", err)
	}

	devices := s.GetDevices()
	if len(devices) != 1 {
		t.Fatalf("expected exactly 1 device after deduplication, got %d", len(devices))
	}

	dev, exists := devices["10.0.0.20"]
	if !exists || dev == nil {
		t.Fatalf("expected active device at 10.0.0.20, got nil")
	}

	// Overridden fields preserved
	if dev.CustomHostname != "nas-override" || dev.Label != "My Storage" || dev.Notes != "rack A" || dev.Group != "Servers" {
		t.Errorf("overrides not preserved: %+v", dev)
	}
	// Newer scanned fields preserved
	if dev.Hostname != "host-new" || dev.Vendor != "Synology" {
		t.Errorf("newer scanned values not preserved: %+v", dev)
	}

	// Old IP presence history migrated to new IP
	events, err := s.GetPresenceEventsFiltered("", "", "10.0.0.20")
	if err != nil {
		t.Fatalf("failed to query presence events: %v", err)
	}
	if len(events) == 0 {
		t.Errorf("expected presence events migrated to 10.0.0.20, got 0")
	}
}

func TestTask11_MACNormalizationAcrossLookupPresenceAndDeduplicate(t *testing.T) {
	s := newTestStorage(t)
	now := time.Now()

	// Seed two rows with the same MAC in different formats (hyphenated uppercase vs colon lowercase)
	_, err := s.db.Exec(`
		INSERT INTO devices (
			ip, mac, hostname, label, first_seen, last_seen, is_online, last_presence_change
		) VALUES (
			'10.0.0.10', 'AA-BB-CC-DD-EE-01', 'host-old', 'Lab Box', ?, ?, 0, ?
		)
	`, now.Add(-10*time.Hour), now.Add(-5*time.Hour), now.Add(-5*time.Hour))
	if err != nil {
		t.Fatalf("seed dev 1: %v", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO devices (
			ip, mac, hostname, first_seen, last_seen, is_online, last_presence_change
		) VALUES (
			'10.0.0.20', 'aa:bb:cc:dd:ee:01', 'host-new', ?, ?, 1, ?
		)
	`, now.Add(-1*time.Hour), now, now)
	if err != nil {
		t.Fatalf("seed dev 2: %v", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
		VALUES ('10.0.0.10', 'AA:BB:CC:DD:EE:01', 'host-old', 'join', 0, ?)
	`, now.Add(-10*time.Hour))
	if err != nil {
		t.Fatalf("seed presence: %v", err)
	}

	// GetPresenceEventsFiltered must match regardless of MAC case/hyphen formatting
	events, err := s.GetPresenceEventsFiltered("aa-bb-cc-dd-ee-01", "", "")
	if err != nil {
		t.Fatalf("GetPresenceEventsFiltered: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected GetPresenceEventsFiltered to match mixed-case/hyphenated MAC, got 0")
	}

	// DeduplicateMACs must group 'AA-BB-CC-DD-EE-01' and 'aa:bb:cc:dd:ee:01'
	if err := s.DeduplicateMACs(); err != nil {
		t.Fatalf("DeduplicateMACs: %v", err)
	}
	devices := s.GetDevices()
	if len(devices) != 1 {
		t.Fatalf("expected 1 deduplicated device across mixed MAC formats, got %d: %+v", len(devices), devices)
	}
	if dev := devices["10.0.0.20"]; dev == nil || dev.Label != "Lab Box" {
		t.Fatalf("expected surviving device 10.0.0.20 with label 'Lab Box', got %+v", dev)
	}
}

func TestTask11_DeduplicateMACsPreservesOfflineState(t *testing.T) {
	s := newTestStorage(t)
	now := time.Now()

	// Both duplicate rows are offline (last_seen 10h ago, is_online = 0)
	_, err := s.db.Exec(`
		INSERT INTO devices (
			ip, mac, hostname, first_seen, last_seen, is_online, last_presence_change
		) VALUES
			('10.0.0.30', 'aa:bb:cc:dd:ee:02', 'offline-1', ?, ?, 0, ?),
			('10.0.0.31', 'AA:BB:CC:DD:EE:02', 'offline-2', ?, ?, 0, ?)
	`, now.Add(-12*time.Hour), now.Add(-10*time.Hour), now.Add(-10*time.Hour),
		now.Add(-11*time.Hour), now.Add(-9*time.Hour), now.Add(-9*time.Hour))
	if err != nil {
		t.Fatalf("seed offline duplicates: %v", err)
	}

	if err := s.DeduplicateMACs(); err != nil {
		t.Fatalf("DeduplicateMACs: %v", err)
	}

	if devs := s.GetDevices(); len(devs) != 1 {
		t.Fatalf("expected 1 deduplicated offline device, got %d", len(devs))
	}
	var isOnline int
	if err := s.db.QueryRow(`SELECT is_online FROM devices WHERE ip = '10.0.0.30'`).Scan(&isOnline); err != nil {
		t.Fatalf("query is_online: %v", err)
	}
	if isOnline != 0 {
		t.Fatalf("DeduplicateMACs forced offline device is_online = %d, want 0", isOnline)
	}
}

func TestTask11_RelocationNoBogusJoinAndMoveEventsOnlyOnRelocation(t *testing.T) {
	s := newTestStorage(t)
	s.SetNetworkNames(map[string]string{
		"192.168.1.0/24":  "Home LAN",
		"192.168.50.0/24": "Tailscale",
	})

	// 1. Initial discovery at 192.168.1.50
	if _, _, _, err := s.MergeDevicesWithMoves([]types.Device{
		{IP: "192.168.1.50", MAC: "aa:bb:cc:11:22:99", Hostname: "roaming-box"},
	}); err != nil {
		t.Fatalf("initial merge: %v", err)
	}

	// Simulate sweep where 192.168.1.50 did not answer and 192.168.1.51 answered with mixed-case MAC (relocation)
	_, _, moved, err := s.MergeDevicesWithMoves([]types.Device{
		{IP: "192.168.1.51", MAC: "AA-BB-CC-11-22-99", Hostname: "roaming-box"},
	})
	if err != nil {
		t.Fatalf("relocation merge: %v", err)
	}
	if len(moved) != 1 || moved[0].OldIP != "192.168.1.50" || moved[0].NewIP != "192.168.1.51" {
		t.Fatalf("expected 1 move event 192.168.1.50 -> 192.168.1.51, got %+v", moved)
	}

	var joinCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM device_presence_history WHERE event = 'join'`).Scan(&joinCount); err != nil {
		t.Fatalf("count join events: %v", err)
	}
	if joinCount != 1 {
		t.Fatalf("join event count after relocation = %d, want 1 (no bogus second 'join')", joinCount)
	}

	// 2. Multi-IP attachment (both IPs active on different subnets) must NOT emit a move event
	// and must NOT overwrite primary device's network_name!
	devPrimary := types.Device{IP: "192.168.1.80", MAC: "11:22:33:44:55:66", Hostname: "multi-gw"}
	devSecondary := types.Device{IP: "192.168.50.80", MAC: "11:22:33:44:55:66", Hostname: "multi-gw"}
	if _, _, _, err := s.MergeDevicesWithMoves([]types.Device{devPrimary}); err != nil {
		t.Fatalf("merge multi-gw primary: %v", err)
	}
	_, _, moved2, err := s.MergeDevicesWithMoves([]types.Device{devPrimary, devSecondary})
	if err != nil {
		t.Fatalf("merge multi-gw secondary: %v", err)
	}
	if len(moved2) != 0 {
		t.Fatalf("expected 0 move events for active multi-IP attachment, got %+v", moved2)
	}
	gw := s.GetDevice("192.168.1.80")
	if gw == nil {
		t.Fatalf("expected multi-gw primary at 192.168.1.80")
	}
	if gw.NetworkName != "Home LAN" {
		t.Fatalf("primary network_name overwritten on secondary attachment: got %q, want 'Home LAN'", gw.NetworkName)
	}
}
