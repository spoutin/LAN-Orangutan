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

	// 3. Verify deduplication: old IP must be removed, only new IP exists
	devices := s.GetDevices()
	if _, exists := devices["192.168.1.10"]; exists {
		t.Errorf("expected old IP 192.168.1.10 to be removed, but it still exists")
	}

	merged, exists := devices["192.168.1.25"]
	if !exists || merged == nil {
		t.Fatalf("expected device at new IP 192.168.1.25, but not found")
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

	// Address history recorded
	if len(merged.AddressHistory) == 0 || merged.AddressHistory[len(merged.AddressHistory)-1].IP != "192.168.1.10" {
		t.Errorf("expected address history to record old IP 192.168.1.10, got: %+v", merged.AddressHistory)
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
		t.Errorf("expected duplicate MAC to be deduplicated to 1 device, got %d", len(devices))
	}
	if _, exists := devices["192.168.1.10"]; exists {
		t.Errorf("old IP 192.168.1.10 should have been removed")
	}
	merged := devices["192.168.1.20"]
	if merged == nil {
		t.Fatalf("new IP 192.168.1.20 should be retained")
	}
	if merged.CustomHostname != "my-custom-host" || merged.Label != "Custom Label" {
		t.Errorf("overrides lost on simultaneous/active scan: %+v", merged)
	}
	if merged.Hostname != "new-host" {
		t.Errorf("newer scanned hostname not used: %q", merged.Hostname)
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
