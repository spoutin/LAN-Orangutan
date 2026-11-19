package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

var (
	templateDBOnce  sync.Once
	templateDBBytes []byte
	templateDBErr   error
)

func getTemplateDBBytes() ([]byte, error) {
	templateDBOnce.Do(func() {
		dir, err := os.MkdirTemp("", "lan-orangutan-storage-template-*")
		if err != nil {
			templateDBErr = err
			return
		}
		defer os.RemoveAll(dir)

		s, err := New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
		if err != nil {
			templateDBErr = err
			return
		}
		if err := s.Close(); err != nil {
			templateDBErr = err
			return
		}
		templateDBBytes, templateDBErr = os.ReadFile(filepath.Join(dir, "devices.db"))
	})
	return templateDBBytes, templateDBErr
}

// newTestStorage returns storage backed by a throwaway directory.
func newTestStorage(t *testing.T) *Storage {
	t.Helper()

	tpl, err := getTemplateDBBytes()
	if err != nil {
		t.Fatalf("getTemplateDBBytes: %v", err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "devices.db"), tpl, 0600); err != nil {
		t.Fatalf("write template db: %v", err)
	}

	s, err := New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestMostRecentScanIsZeroBeforeAnyScan(t *testing.T) {
	s := newTestStorage(t)

	if got := s.GetMostRecentScan(); !got.IsZero() {
		t.Errorf("GetMostRecentScan() = %v, want the zero time before any scan", got)
	}
}

func TestMostRecentScanWithOneNetwork(t *testing.T) {
	s := newTestStorage(t)

	when := time.Now().Add(-30 * time.Minute).Truncate(time.Second)
	if err := s.SetLastScan("192.168.1.0/24", when); err != nil {
		t.Fatalf("SetLastScan: %v", err)
	}

	if got := s.GetMostRecentScan(); !got.Equal(when) {
		t.Errorf("GetMostRecentScan() = %v, want %v", got, when)
	}
}

func TestMostRecentScanPicksTheLatest(t *testing.T) {
	s := newTestStorage(t)

	older := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	newer := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	middle := time.Now().Add(-1 * time.Hour).Truncate(time.Second)

	// Set them out of order, so the result cannot come from insertion order.
	if err := s.SetLastScan("10.0.0.0/24", middle); err != nil {
		t.Fatalf("SetLastScan: %v", err)
	}
	if err := s.SetLastScan("192.168.1.0/24", newer); err != nil {
		t.Fatalf("SetLastScan: %v", err)
	}
	if err := s.SetLastScan("172.16.0.0/24", older); err != nil {
		t.Fatalf("SetLastScan: %v", err)
	}

	if got := s.GetMostRecentScan(); !got.Equal(newer) {
		t.Errorf("GetMostRecentScan() = %v, want the most recent %v", got, newer)
	}
}

func TestMostRecentScanSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	devices := filepath.Join(dir, "devices.json")
	state := filepath.Join(dir, "state.json")

	first, err := New(devices, state)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })

	when := time.Now().Add(-15 * time.Minute).Truncate(time.Second)
	if err := first.SetLastScan("192.168.1.0/24", when); err != nil {
		t.Fatalf("SetLastScan: %v", err)
	}

	// A restart must not lose the timestamp, otherwise the dashboard would
	// claim nothing had ever been scanned.
	second, err := New(devices, state)
	if err != nil {
		t.Fatalf("reopening storage: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	if got := second.GetMostRecentScan(); !got.Equal(when) {
		t.Errorf("after reload GetMostRecentScan() = %v, want %v", got, when)
	}
}

func TestContinuousScanDefaultsToConfigWhenUnset(t *testing.T) {
	s := newTestStorage(t)
	if !s.ContinuousScanEnabled(true) {
		t.Error("with no override saved, want the config default (true) to win")
	}
	if s.ContinuousScanEnabled(false) {
		t.Error("with no override saved, want the config default (false) to win")
	}
}

func TestContinuousScanOverrideSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	devices := filepath.Join(dir, "devices.json")
	state := filepath.Join(dir, "state.json")

	first, err := New(devices, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	// User turns continuous scanning off even though config defaults it on.
	if err := first.SetContinuousScan(false); err != nil {
		t.Fatal(err)
	}

	second, err := New(devices, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if second.ContinuousScanEnabled(true) {
		t.Error("saved override (false) should win over the config default (true) after reload")
	}
}

func TestMergeIPv6NeighborsEnrichesByMAC(t *testing.T) {
	s := newTestStorage(t)
	// A device found by the reliable IPv4 scan.
	if err := mergeDevicesForTest(s, []types.Device{{IP: "192.168.1.5", MAC: "00:1A:2B:3C:4D:5E"}}); err != nil {
		t.Fatal(err)
	}
	// The same physical device sighted over IPv6 (same MAC, routable address).
	if err := s.MergeIPv6Neighbors([]types.Device{{IP: "2001:db8::5", MAC: "00:1A:2B:3C:4D:5E", Hostname: "printer"}}); err != nil {
		t.Fatal(err)
	}
	devs := s.GetDevices()
	if len(devs) != 1 {
		t.Fatalf("an IPv6 sighting of a known device should enrich it, not add a second entry: got %d", len(devs))
	}
	if d, ok := devs["192.168.1.5"]; !ok || d.Hostname != "printer" {
		t.Errorf("expected the IPv4 device enriched with the hostname, got %+v", devs)
	}
}

func TestMergeIPv6NeighborsCreatesOnlyForRealMAC(t *testing.T) {
	s := newTestStorage(t)
	err := s.MergeIPv6Neighbors([]types.Device{
		{IP: "fe80::1", MAC: "00:1A:2B:3C:4D:5E"},     // link-local: never a device
		{IP: "2001:db8::a", MAC: "AA:BB:CC:DD:EE:FF"}, // randomised MAC, no match: privacy ghost
		{IP: "2001:db8::b", MAC: "00:1A:2B:3C:4D:99"}, // real MAC, no match: genuine IPv6-only device
	})
	if err != nil {
		t.Fatal(err)
	}
	devs := s.GetDevices()
	if len(devs) != 1 {
		t.Fatalf("only the real-MAC IPv6-only device should be created: got %d: %+v", len(devs), devs)
	}
	if _, ok := devs["2001:db8::b"]; !ok {
		t.Errorf("expected the real-MAC device created, got %+v", devs)
	}
}

func TestPruneEphemeralIPv6OnLoad(t *testing.T) {
	dir := t.TempDir()
	devicesFile := filepath.Join(dir, "devices.json")
	stateFile := filepath.Join(dir, "state.json")

	// An install that accumulated IPv6 phantoms.
	seed := map[string]types.Device{
		"192.168.1.5": {IP: "192.168.1.5", MAC: "00:1A:2B:3C:4D:5E"}, // real LAN device: keep
		"fe80::1":     {IP: "fe80::1", MAC: "00:1A:2B:3C:4D:5E"},     // link-local phantom: drop
		"2001:db8::a": {IP: "2001:db8::a", MAC: "AA:BB:CC:DD:EE:FF"}, // randomised IPv6 phantom: drop
		"2001:db8::b": {IP: "2001:db8::b", MAC: "00:1A:2B:3C:4D:99"}, // real IPv6-only device: keep
	}
	data, err := json.MarshalIndent(seed, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(devicesFile, data, 0600); err != nil {
		t.Fatal(err)
	}

	s, err := New(devicesFile, stateFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	devs := s.GetDevices()
	if len(devs) != 2 {
		t.Fatalf("expected 2 real devices after pruning phantoms, got %d: %+v", len(devs), devs)
	}
	if _, ok := devs["192.168.1.5"]; !ok {
		t.Error("real LAN device was pruned")
	}
	if _, ok := devs["2001:db8::b"]; !ok {
		t.Error("real IPv6-only device was pruned")
	}
	if _, ok := devs["fe80::1"]; ok {
		t.Error("link-local phantom survived the prune")
	}
	if _, ok := devs["2001:db8::a"]; ok {
		t.Error("randomised IPv6 phantom survived the prune")
	}
}

func TestPruneKeepsCuratedIPv6Device(t *testing.T) {
	dir := t.TempDir()
	devicesFile := filepath.Join(dir, "devices.json")
	stateFile := filepath.Join(dir, "state.json")

	// A device keyed by a link-local address that the user has labelled: it must
	// survive the prune with its label intact, not be wiped on every restart.
	seed := map[string]types.Device{
		"fe80::abcd": {IP: "fe80::abcd", MAC: "AA:BB:CC:DD:EE:FF", Label: "Front door cam", Group: "IoT"},
		"fe80::dead": {IP: "fe80::dead", MAC: "02:00:00:00:00:01"}, // unlabelled phantom: drop
	}
	data, err := json.MarshalIndent(seed, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(devicesFile, data, 0600); err != nil {
		t.Fatal(err)
	}

	s, err := New(devicesFile, stateFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	devs := s.GetDevices()
	if d, ok := devs["fe80::abcd"]; !ok || d.Label != "Front door cam" {
		t.Errorf("a curated device must survive the prune with its label; got %+v", devs["fe80::abcd"])
	}
	if _, ok := devs["fe80::dead"]; ok {
		t.Error("unlabelled link-local phantom should have been pruned")
	}
}

// TestIPv6RealisticDualStackNetwork simulates a real IPv6-enabled home network
// (which the IPv4-only test LAN cannot exercise) and asserts LAN Orangutan
// discovers the legitimate IPv6 devices while dropping only the privacy noise.
func TestIPv6RealisticDualStackNetwork(t *testing.T) {
	s := newTestStorage(t)

	// The IPv4/ARP scan finds the routable dual-stack devices first.
	if err := mergeDevicesForTest(s, []types.Device{
		{IP: "192.168.1.1", MAC: "3C:37:86:11:22:33", Hostname: "router"},
		{IP: "192.168.1.20", MAC: "A4:83:E7:44:55:66", Hostname: "macbook"},
	}); err != nil {
		t.Fatal(err)
	}

	// Then the IPv6 neighbour cache is read on a dual-stack network:
	err := s.MergeIPv6Neighbors([]types.Device{
		// The macbook again, over its global IPv6 (same NIC MAC): must ENRICH,
		// not create a second entry.
		{IP: "2001:db8:1::20", MAC: "A4:83:E7:44:55:66"},
		// A genuinely IPv6-only device (e.g. a NAS) with a real hardware MAC and
		// no IPv4: must be CREATED and shown.
		{IP: "2001:db8:1::50", MAC: "B8:27:EB:77:88:99", Hostname: "nas"},
		// A ULA IPv6-only device with a real MAC: must be CREATED.
		{IP: "fd00:abcd::7", MAC: "DC:A6:32:AA:BB:CC", Hostname: "camera"},
		// A privacy phone: rotating global IPv6 + randomised MAC, not seen over
		// IPv4: must be SKIPPED (this is the phantom source).
		{IP: "2001:db8:1::f1ee", MAC: "AA:BB:CC:DD:EE:F1"},
		// Link-local: never a device.
		{IP: "fe80::1", MAC: "3C:37:86:11:22:33"},
	})
	if err != nil {
		t.Fatal(err)
	}

	devs := s.GetDevices()
	// Expect exactly 4 real devices: router + macbook (dual-stack, one entry) +
	// nas + camera (IPv6-only). No phantom, no link-local, no duplicate.
	if len(devs) != 4 {
		t.Fatalf("expected 4 real devices, got %d: %+v", len(devs), devs)
	}
	want := map[string]bool{"192.168.1.1": true, "192.168.1.20": true, "2001:db8:1::50": true, "fd00:abcd::7": true}
	for ip := range want {
		if _, ok := devs[ip]; !ok {
			t.Errorf("missing expected device %s", ip)
		}
	}
	if _, ok := devs["2001:db8:1::20"]; ok {
		t.Error("dual-stack macbook was duplicated by its IPv6 address instead of enriched")
	}
	if _, ok := devs["2001:db8:1::f1ee"]; ok {
		t.Error("privacy phantom (randomised MAC) was created")
	}
	if _, ok := devs["fe80::1"]; ok {
		t.Error("link-local was listed as a device")
	}

	t.Logf("Resulting inventory on a dual-stack network:")
	for ip, d := range devs {
		t.Logf("  %-18s %s", ip, d.Hostname)
	}
}

func TestGetPresenceEventsFilteredAndPruning(t *testing.T) {
	s := newTestStorage(t)

	// Insert dummy devices and events directly to test DB queries
	now := time.Now()
	sixMonthsAgo := now.AddDate(0, -6, 0) // 6 months ago (not pruned)
	twoYearsAgo := now.AddDate(-2, 0, 0)  // 2 years ago (pruned)

	// Add an offline stale device seen 2 years ago using direct SQL to bypass MergeDevices LastSeen override
	_, err := s.db.Exec(`
		INSERT INTO devices (
			ip, mac, hostname, vendor, type, web_ui, risks, label, notes, "group",
			custom_hostname, custom_web_url, custom_type, web_port, web_scheme, probed,
			assignment, network_name, first_seen, last_seen, response_time, address_history,
			is_online, missed_sweeps, last_presence_change
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
	`, "10.0.0.5", "aa:bb:cc:dd:ee:11", "stale-pc", "Unknown", "Computer", 0, "[]",
		"", "", "", "", "", "", 0, "", 0, "Discovered", "LAN", twoYearsAgo, twoYearsAgo, nil, "[]", 0, twoYearsAgo)
	if err != nil {
		t.Fatal(err)
	}

	// Add a fresh active device
	if err := mergeDevicesForTest(s, []types.Device{
		{IP: "10.0.0.6", MAC: "aa:bb:cc:dd:ee:22", Hostname: "fresh-pc"},
	}); err != nil {
		t.Fatal(err)
	}

	// Now insert presence events into device_presence_history table
	_, err = s.db.Exec(`
		INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
		VALUES 
		('10.0.0.1', 'aa:bb:cc:dd:ee:ff', 'router', 'join', 0.0, ?),
		('10.0.0.2', 'aa:bb:cc:dd:ee:aa', 'switch', 'return', 12.0, ?),
		('10.0.0.3', 'aa:bb:cc:dd:ee:bb', 'stale-event', 'leave', 45.0, ?)
	`, now, sixMonthsAgo, twoYearsAgo)
	if err != nil {
		t.Fatal(err)
	}

	// Insert scan history records
	_, err = s.db.Exec(`
		INSERT INTO scan_history (network, success, error, devices_online, timestamp)
		VALUES 
		('10.0.0.0/24', 1, '', 2, ?),
		('10.0.0.0/24', 1, '', 1, ?)
	`, now, twoYearsAgo)
	if err != nil {
		t.Fatal(err)
	}

	// Test 1: Fetch presence events with no filter
	events, err := s.GetPresenceEventsFiltered("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	// We expect 4 events: 3 inserted directly + 1 automatic 'join' event for the fresh-pc MergeDevices
	if len(events) != 4 {
		t.Errorf("expected 4 events, got %d", len(events))
	}

	// Test 2: Fetch presence events with query filter (by hostname)
	events, err = s.GetPresenceEventsFiltered("", "", "router")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].IP != "10.0.0.1" {
		t.Errorf("expected 1 event matching 'router', got %d", len(events))
	}

	// Test 3: Fetch presence events with query filter (by MAC)
	events, err = s.GetPresenceEventsFiltered("", "", "ee:aa")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Hostname != "switch" {
		t.Errorf("expected 1 event matching MAC 'ee:aa', got %d", len(events))
	}

	// Test 4: Fetch presence events by specific IP
	events, err = s.GetPresenceEventsFiltered("", "10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Hostname != "router" {
		t.Errorf("expected 1 event matching IP '10.0.0.1', got %d", len(events))
	}

	// Test 5: Pruning data older than 1 year
	oneYearAgoBoundary := now.AddDate(-1, 0, 0)
	deleted, err := s.PruneOldHistory(oneYearAgoBoundary)
	if err != nil {
		t.Fatal(err)
	}

	// We expect:
	// - 1 stale presence event deleted ('stale-event' at 2 years ago).
	// - 1 stale scan history deleted (at 2 years ago).
	// - 1 stale offline device deleted (stale-pc at 2 years ago).
	// Total rows affected should be 3.
	if deleted != 3 {
		t.Errorf("expected 3 pruned rows, got %d", deleted)
	}

	// Verify events are pruned
	events, err = s.GetPresenceEventsFiltered("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	// We expect 3 presence events remaining (one stale-event at 2 years ago was pruned)
	if len(events) != 3 {
		t.Errorf("expected 3 presence events remaining, got %d", len(events))
	}

	// Verify the stale-pc device was deleted
	devices := s.GetDevices()
	if _, ok := devices["10.0.0.5"]; ok {
		t.Error("stale-pc should have been pruned from devices table")
	}
	if _, ok := devices["10.0.0.6"]; !ok {
		t.Error("fresh-pc should still exist in devices table")
	}

	// Test 6: Verify auto-healing synthesis for a legacy device with absolutely 0 logged history records
	_, err = s.db.Exec(`
		INSERT INTO devices (
			ip, mac, hostname, vendor, type, web_ui, risks, label, notes, "group",
			custom_hostname, custom_web_url, custom_type, web_port, web_scheme, probed,
			assignment, network_name, first_seen, last_seen, response_time, address_history,
			is_online, missed_sweeps, last_presence_change
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
	`, "10.0.0.100", "aa:bb:cc:dd:ee:99", "legacy-online-pc", "Unknown", "Computer", 0, "[]",
		"", "", "", "", "", "", 0, "", 0, "Discovered", "LAN", now.Add(-5*time.Hour), now, nil, "[]", 1, now)
	if err != nil {
		t.Fatal(err)
	}

	synthEvents, err := s.GetPresenceEventsFiltered("", "10.0.0.100", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(synthEvents) != 1 {
		t.Fatalf("expected 1 synthesized event, got %d", len(synthEvents))
	}
	if synthEvents[0].Event != "join" || synthEvents[0].ID != -1 {
		t.Errorf("expected synthesized 'join' event, got: %+v", synthEvents[0])
	}
}

func TestLinkedDevicesAndCombinedTimeline(t *testing.T) {
	s := newTestStorage(t)

	// Step 1: Create Parent Device (galaxy-parent on OpenWrt)
	parentIP := "10.5.5.50"
	parentMAC := "aa:bb:cc:11:11:11"
	if err := mergeDevicesForTest(s, []types.Device{
		{IP: parentIP, MAC: parentMAC, Hostname: "Galaxy-S10"},
	}); err != nil {
		t.Fatal(err)
	}

	// Customize parent device settings
	labelVal := "My Parent S10"
	notesVal := "Owner: John Doe"
	if err := s.UpdateDeviceFields(parentIP, &labelVal, &notesVal, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	// Step 2: Create Child Device (galaxy-child on OPNsense)
	childIP := "10.0.4.80"
	childMAC := "aa:bb:cc:22:22:22"
	if err := mergeDevicesForTest(s, []types.Device{
		{IP: childIP, MAC: childMAC, Hostname: "galaxy-s10"},
	}); err != nil {
		t.Fatal(err)
	}

	// Link Child Device to Parent Device using parentMAC
	if err := s.UpdateDeviceFields(childIP, nil, nil, nil, nil, nil, nil, &parentMAC, nil, nil, nil, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	// Step 3: Verify child inherits customizations from the parent via SQL LEFT JOIN!
	childDev := s.GetDevice(childIP)
	if childDev == nil {
		t.Fatal("expected child device to exist")
	}
	if childDev.Label != "My Parent S10" {
		t.Errorf("expected child to inherit label 'My Parent S10', got: %q", childDev.Label)
	}
	if childDev.Notes != "Owner: John Doe" {
		t.Errorf("expected child to inherit notes 'Owner: John Doe', got: %q", childDev.Notes)
	}

	// Step 4: Verify combined presence timeline logs
	now := time.Now()
	// Insert separate presence events for both devices
	_, err := s.db.Exec(`
		INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
		VALUES 
		(?, ?, 'Galaxy-S10', 'return', 60.0, ?),
		(?, ?, 'galaxy-s10', 'leave', 30.0, ?)
	`, parentIP, parentMAC, now.Add(-10*time.Minute), childIP, childMAC, now.Add(-5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	// Querying timeline for either child or parent should return the unified family history!
	parentEvents, err := s.GetPresenceEventsFiltered(parentMAC, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// We expect 3 events: parent's auto-join on MergeDevices, parent's return event, child's auto-join, and child's leave event!
	// Wait, parent got auto-join on MergeDevices. Child got auto-join on MergeDevices.
	// So 4 events in total!
	if len(parentEvents) < 3 {
		t.Errorf("expected combined timeline containing multiple entries, got %d: %+v", len(parentEvents), parentEvents)
	}

	childEvents, err := s.GetPresenceEventsFiltered("", childIP, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(childEvents) != len(parentEvents) {
		t.Errorf("child timeline length (%d) should equal parent timeline length (%d)", len(childEvents), len(parentEvents))
	}
}

func TestUpdateDeviceFields_GroupInheritanceMixedCaseAndTxRollback(t *testing.T) {
	s := newTestStorage(t)
	defer s.Close()

	parentIP := "10.5.5.60"
	parentMAC := "aa:bb:cc:33:33:33"
	childIP := "10.5.5.61"
	childMAC := "aa:bb:cc:44:44:44"

	if err := mergeDevicesForTest(s, []types.Device{
		{IP: parentIP, MAC: parentMAC, Hostname: "parent-host"},
		{IP: childIP, MAC: childMAC, Hostname: "child-host"},
	}); err != nil {
		t.Fatal(err)
	}

	parentGroup := "Servers"
	parentLabel := "Main Server"
	if err := s.UpdateDeviceFields(parentIP, &parentLabel, nil, &parentGroup, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("update parent: %v", err)
	}

	// Give child its own label & group before linking, then link with mixed-case hyphenated MAC.
	childLabel := "Child Pre-Link Label"
	childGroup := "Pre-Link Group"
	if err := s.UpdateDeviceFields(childIP, &childLabel, nil, &childGroup, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("update child pre-link: %v", err)
	}

	mixedLinkedMAC := "AA-BB-CC-33-33-33"
	if err := s.UpdateDeviceFields(childIP, nil, nil, nil, nil, nil, nil, &mixedLinkedMAC, nil, nil, nil, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("link child with mixed-case MAC: %v", err)
	}

	// Verify group inheritance across GetDevice, GetDevices, GetDeviceLocked, GetDeviceByMAC.
	if got := s.GetDevice(childIP); got == nil || got.Group != "Servers" || got.Label != "Main Server" {
		t.Fatalf("GetDevice(child) = %+v, want Group=Servers, Label=Main Server", got)
	}
	if got := s.GetDeviceByMAC(childMAC); got == nil || got.Group != "Servers" || got.Label != "Main Server" {
		t.Fatalf("GetDeviceByMAC(child) = %+v, want Group=Servers, Label=Main Server", got)
	}
	all := s.GetDevices()
	if got := all[childIP]; got == nil || got.Group != "Servers" || got.Label != "Main Server" {
		t.Fatalf("GetDevices()[child] = %+v, want Group=Servers, Label=Main Server", got)
	}
	if parentInAll := all[parentIP]; parentInAll == nil || len(parentInAll.LinkedChildren) != 1 {
		t.Fatalf("GetDevices()[parent].LinkedChildren = %+v, want 1 child", parentInAll)
	}
	s.mu.RLock()
	lockedChild := s.GetDeviceLocked(childIP)
	s.mu.RUnlock()
	if lockedChild == nil || lockedChild.Group != "Servers" {
		t.Fatalf("GetDeviceLocked(child) = %+v, want Group=Servers", lockedChild)
	}

	// Updating group through child should forward to parent and reflect on both.
	newGroup := "Critical Infra"
	if err := s.UpdateDeviceFields(childIP, nil, nil, &newGroup, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("update group via child: %v", err)
	}
	if got := s.GetDevice(parentIP); got == nil || got.Group != "Critical Infra" {
		t.Fatalf("parent Group = %+v, want Critical Infra", got)
	}
	if got := s.GetDevice(childIP); got == nil || got.Group != "Critical Infra" {
		t.Fatalf("child Group = %+v, want Critical Infra", got)
	}

	// Test transaction rollback: force parent UPDATE to fail while updating child's own unlinked/linked transition,
	// or updating parent via linked child when child already has values (unlink+relink or direct parent fail).
	// Unlink first and set child's own label/group so we can verify child values aren't wiped if parent fails.
	empty := ""
	if err := s.UpdateDeviceFields(childIP, &childLabel, nil, &childGroup, nil, nil, nil, &empty, nil, nil, nil, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("unlink child: %v", err)
	}

	if _, err := s.db.Exec(`
		CREATE TRIGGER fail_parent_update
		BEFORE UPDATE ON devices
		WHEN NEW.ip = '10.5.5.60'
		BEGIN
			SELECT RAISE(ABORT, 'simulated parent update failure');
		END;
	`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	forwardedLabel := "Should Rollback"
	err := s.UpdateDeviceFields(childIP, &forwardedLabel, nil, nil, nil, nil, nil, &parentMAC, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("expected UpdateDeviceFields to return error when parent update fails")
	}

	// Child's pre-existing label, group, and unlinked state must be preserved by rollback!
	var rawLabel, rawGroup, rawLinked string
	if err := s.db.QueryRow(`SELECT label, "group", linked_mac FROM devices WHERE ip = ?`, childIP).Scan(&rawLabel, &rawGroup, &rawLinked); err != nil {
		t.Fatalf("query raw child row: %v", err)
	}
	if rawLabel != childLabel || rawGroup != childGroup || rawLinked != "" {
		t.Fatalf("child row corrupted after parent failure: label=%q group=%q linked_mac=%q", rawLabel, rawGroup, rawLinked)
	}
}

func mergeDevicesForTest(s *Storage, discovered []types.Device) error {
	_, _, err := s.MergeDevices(discovered)
	return err
}

func TestDeviceTelemetryPersistence(t *testing.T) {
	s := newTestStorage(t)

	leaseExp := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	dev := &types.Device{
		IP:                "192.168.1.50",
		MAC:               "00:11:22:33:44:55",
		Hostname:          "living-room-speaker",
		Vendor:            "Sonos",
		SSID:              "Orangutan-IoT",
		APName:            "Living Room AP",
		RadioBand:         "5GHz",
		Channel:           36,
		WiFiStandard:      "WiFi 6 (11ax)",
		Signal:            -65,
		SignalQuality:     82,
		RxRate:            1200000,
		TxRate:            1200000,
		RxBytes:           1048576000,
		TxBytes:           524288000,
		AssociationUptime: 7200,
		UniFiModel:        "U6-Pro",
		RouterSource:      "OPNsense",
		RouterInterface:   "igb1",
		LeaseExpires:      leaseExp,
		LeaseLifetime:     86400,
		RouterNotes:       "Static reservation for living room speaker",
	}

	if err := s.UpdateDevice(dev); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	// 1. Verify retrieval via GetDevice
	got := s.GetDevice(dev.IP)
	if got == nil {
		t.Fatalf("GetDevice(%s) returned nil", dev.IP)
	}

	if got.SSID != dev.SSID {
		t.Errorf("SSID = %q, want %q", got.SSID, dev.SSID)
	}
	if got.APName != dev.APName {
		t.Errorf("APName = %q, want %q", got.APName, dev.APName)
	}
	if got.RadioBand != dev.RadioBand {
		t.Errorf("RadioBand = %q, want %q", got.RadioBand, dev.RadioBand)
	}
	if got.Channel != dev.Channel {
		t.Errorf("Channel = %d, want %d", got.Channel, dev.Channel)
	}
	if got.WiFiStandard != dev.WiFiStandard {
		t.Errorf("WiFiStandard = %q, want %q", got.WiFiStandard, dev.WiFiStandard)
	}
	if got.Signal != dev.Signal {
		t.Errorf("Signal = %d, want %d", got.Signal, dev.Signal)
	}
	if got.SignalQuality != dev.SignalQuality {
		t.Errorf("SignalQuality = %d, want %d", got.SignalQuality, dev.SignalQuality)
	}
	if got.RxRate != dev.RxRate {
		t.Errorf("RxRate = %d, want %d", got.RxRate, dev.RxRate)
	}
	if got.TxRate != dev.TxRate {
		t.Errorf("TxRate = %d, want %d", got.TxRate, dev.TxRate)
	}
	if got.RxBytes != dev.RxBytes {
		t.Errorf("RxBytes = %d, want %d", got.RxBytes, dev.RxBytes)
	}
	if got.TxBytes != dev.TxBytes {
		t.Errorf("TxBytes = %d, want %d", got.TxBytes, dev.TxBytes)
	}
	if got.AssociationUptime != dev.AssociationUptime {
		t.Errorf("AssociationUptime = %d, want %d", got.AssociationUptime, dev.AssociationUptime)
	}
	if got.UniFiModel != dev.UniFiModel {
		t.Errorf("UniFiModel = %q, want %q", got.UniFiModel, dev.UniFiModel)
	}
	if got.RouterSource != dev.RouterSource {
		t.Errorf("RouterSource = %q, want %q", got.RouterSource, dev.RouterSource)
	}
	if got.RouterInterface != dev.RouterInterface {
		t.Errorf("RouterInterface = %q, want %q", got.RouterInterface, dev.RouterInterface)
	}
	if !got.LeaseExpires.Equal(dev.LeaseExpires) {
		t.Errorf("LeaseExpires = %v, want %v", got.LeaseExpires, dev.LeaseExpires)
	}
	if got.LeaseLifetime != dev.LeaseLifetime {
		t.Errorf("LeaseLifetime = %d, want %d", got.LeaseLifetime, dev.LeaseLifetime)
	}
	if got.RouterNotes != dev.RouterNotes {
		t.Errorf("RouterNotes = %q, want %q", got.RouterNotes, dev.RouterNotes)
	}

	// 2. Verify retrieval via GetDevices() map
	all := s.GetDevices()
	gotMap, exists := all[dev.IP]
	if !exists || gotMap == nil {
		t.Fatalf("GetDevices() missing device %s", dev.IP)
	}
	if gotMap.SSID != dev.SSID {
		t.Errorf("GetDevices() SSID = %q, want %q", gotMap.SSID, dev.SSID)
	}
	if gotMap.RouterNotes != dev.RouterNotes {
		t.Errorf("GetDevices() RouterNotes = %q, want %q", gotMap.RouterNotes, dev.RouterNotes)
	}
	if !gotMap.LeaseExpires.Equal(dev.LeaseExpires) {
		t.Errorf("GetDevices() LeaseExpires = %v, want %v", gotMap.LeaseExpires, dev.LeaseExpires)
	}

	// 3. Verify nullable LeaseExpires (zero time) does not fail on read/write
	devNullLease := &types.Device{
		IP:       "192.168.1.51",
		MAC:      "00:11:22:33:44:56",
		Hostname: "wired-pc",
		SSID:     "", // wired
	}
	if err := s.UpdateDevice(devNullLease); err != nil {
		t.Fatalf("UpdateDevice with zero LeaseExpires: %v", err)
	}
	gotNull := s.GetDevice(devNullLease.IP)
	if gotNull == nil {
		t.Fatalf("GetDevice(%s) returned nil", devNullLease.IP)
	}
	if !gotNull.LeaseExpires.IsZero() {
		t.Errorf("expected zero LeaseExpires for %s, got %v", devNullLease.IP, gotNull.LeaseExpires)
	}
}

func TestUpdateDevicePersistsUniFiVLAN(t *testing.T) {
	s := newTestStorage(t)
	device := &types.Device{IP: "192.168.1.230", MAC: "00:11:22:33:44:55", VLAN: 42}
	if err := s.UpdateDevice(device); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	stored := s.GetDevice(device.IP)
	if stored == nil || stored.VLAN != 42 {
		t.Fatalf("stored device = %+v, want VLAN 42", stored)
	}
}

func TestUpdateDevicePersistsAnsibleManaged(t *testing.T) {
	s := newTestStorage(t)
	device := &types.Device{IP: "192.168.1.240", MAC: "00:11:22:33:44:77", AnsibleManaged: true}
	if err := s.UpdateDevice(device); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	stored := s.GetDevice(device.IP)
	if stored == nil || !stored.AnsibleManaged {
		t.Fatalf("stored device = %+v, want AnsibleManaged true", stored)
	}

	// Update without touching AnsibleManaged, verify it is preserved
	if err := s.UpdateDevice(&types.Device{IP: "192.168.1.240", MAC: "00:11:22:33:44:77", Hostname: "server1"}); err != nil {
		t.Fatalf("UpdateDevice second pass: %v", err)
	}
	stored = s.GetDevice("192.168.1.240")
	if stored == nil || !stored.AnsibleManaged {
		t.Fatalf("stored device = %+v, want AnsibleManaged preserved as true", stored)
	}

	// Now toggle off via UpdateDeviceFields
	ansibleOff := false
	if err := s.UpdateDeviceFields("192.168.1.240", nil, nil, nil, nil, nil, nil, nil, nil, nil, &ansibleOff, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("UpdateDeviceFields: %v", err)
	}
	stored = s.GetDevice("192.168.1.240")
	if stored == nil || stored.AnsibleManaged {
		t.Fatalf("stored device = %+v, want AnsibleManaged false after toggle", stored)
	}
}

func TestUpdateOpenPortsPersistsDeepScanResults(t *testing.T) {
	s := newTestStorage(t)
	if err := s.UpdateDevice(&types.Device{IP: "192.168.1.250", Hostname: "server"}); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	services := []types.OpenService{{Port: 22, Name: "ssh", Version: "OpenSSH 9.2p1"}, {Port: 443, Name: "https"}}
	if err := s.UpdateOpenPorts("192.168.1.250", []int{22, 443, 2222}, services); err != nil {
		t.Fatalf("UpdateOpenPorts: %v", err)
	}
	got := s.GetDevice("192.168.1.250")
	if len(got.OpenPorts) != 3 || got.OpenPorts[0] != 22 || got.OpenPorts[1] != 443 || got.OpenPorts[2] != 2222 {
		t.Errorf("OpenPorts = %v, want [22 443 2222]", got.OpenPorts)
	}
	if len(got.OpenServices) != 2 || got.OpenServices[0].Name != "ssh" || got.OpenServices[0].Version != "OpenSSH 9.2p1" {
		t.Errorf("OpenServices = %+v, want persisted service details", got.OpenServices)
	}
	if got.LastDeepScanAt.IsZero() {
		t.Error("LastDeepScanAt is zero after a successful deep scan")
	}
}

func TestUpdateDevicePreservesUniFiVLANWhenOmitted(t *testing.T) {
	s := newTestStorage(t)
	if err := s.UpdateDevice(&types.Device{IP: "192.168.1.231", MAC: "00:11:22:33:44:56", VLAN: 42}); err != nil {
		t.Fatalf("UpdateDevice initial: %v", err)
	}
	if err := s.UpdateDevice(&types.Device{IP: "192.168.1.231", MAC: "00:11:22:33:44:56", Hostname: "updated"}); err != nil {
		t.Fatalf("UpdateDevice update: %v", err)
	}

	if got := s.GetDevice("192.168.1.231"); got == nil || got.VLAN != 42 {
		t.Fatalf("stored device = %+v, want preserved VLAN 42", got)
	}
}

func TestStorage_OSPersistenceAndCustomOverride(t *testing.T) {
	s := newTestStorage(t)

	dev := &types.Device{
		IP:        "192.168.1.50",
		MAC:       "00:11:22:33:44:55",
		OS:        "Ubuntu Linux",
		OSVersion: "22.04",
		OSFamily:  "Linux",
		CustomOS:  "My Custom OS",
	}
	if err := s.UpdateDevice(dev); err != nil {
		t.Fatalf("UpdateDevice failed: %v", err)
	}

	got := s.GetDevice("192.168.1.50")
	if got == nil {
		t.Fatal("GetDevice returned nil")
	}
	if got.OS != "Ubuntu Linux" || got.OSVersion != "22.04" || got.OSFamily != "Linux" || got.CustomOS != "My Custom OS" {
		t.Errorf("got OS fields %+v, want Ubuntu Linux / 22.04 / Linux / My Custom OS", got)
	}

	// Test UpdateDeviceFields for custom_os
	newCustomOS := "Debian 12"
	if err := s.UpdateDeviceFields("192.168.1.50", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, &newCustomOS, nil, nil, nil, nil); err != nil {
		t.Fatalf("UpdateDeviceFields with customOS: %v", err)
	}
	updated := s.GetDevice("192.168.1.50")
	if updated == nil || updated.CustomOS != "Debian 12" {
		t.Fatalf("updated CustomOS = %q, want Debian 12", updated.CustomOS)
	}
}

func TestAPITokensAndDeviceFactsStorage(t *testing.T) {
	s := newTestStorage(t)

	// 1. Create API token
	rawToken := "ora_test12345678901234567890"
	created, err := s.CreateAPIToken("Ansible Server", rawToken)
	if err != nil {
		t.Fatalf("CreateAPIToken failed: %v", err)
	}
	if created.Name != "Ansible Server" {
		t.Errorf("created.Name = %q, want 'Ansible Server'", created.Name)
	}
	if created.TokenPrefix != "ora_test12" {
		t.Errorf("created.TokenPrefix = %q, want 'ora_test12'", created.TokenPrefix)
	}
	if created.LastUsedAt != nil {
		t.Errorf("created.LastUsedAt should be nil initially")
	}

	// 2. List API tokens
	tokens, err := s.ListAPITokens()
	if err != nil {
		t.Fatalf("ListAPITokens failed: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("got %d tokens, want 1", len(tokens))
	}
	if tokens[0].ID != created.ID {
		t.Errorf("token ID = %d, want %d", tokens[0].ID, created.ID)
	}

	// 3. Validate and Touch API token
	valid, err := s.ValidateAndTouchAPIToken(rawToken)
	if err != nil || !valid {
		t.Fatalf("ValidateAndTouchAPIToken with valid token: valid=%v, err=%v", valid, err)
	}
	invalid, err := s.ValidateAndTouchAPIToken("ora_wrongtoken")
	if err != nil || invalid {
		t.Fatalf("ValidateAndTouchAPIToken with invalid token: invalid=%v, err=%v", invalid, err)
	}

	// Verify last_used_at was updated
	tokensAfter, err := s.ListAPITokens()
	if err != nil {
		t.Fatalf("ListAPITokens failed: %v", err)
	}
	if tokensAfter[0].LastUsedAt == nil {
		t.Errorf("LastUsedAt should not be nil after validation")
	}

	// 4. Device lookup and update by MAC
	dev := &types.Device{
		IP:  "192.168.1.75",
		MAC: "AA:BB:CC:11:22:33",
	}
	if err := s.UpdateDevice(dev); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	foundByMAC := s.GetDeviceByMAC("aa:bb:cc:11:22:33")
	if foundByMAC == nil || foundByMAC.IP != "192.168.1.75" {
		t.Fatalf("GetDeviceByMAC returned %+v, want device with IP 192.168.1.75", foundByMAC)
	}

	// Update device OS overrides by MAC
	if err := s.UpdateDeviceCustomOS("aa-bb-cc-11-22-33", "Ubuntu", "24.04 LTS", "Linux"); err != nil {
		t.Fatalf("UpdateDeviceCustomOS failed: %v", err)
	}
	updatedDev := s.GetDevice("192.168.1.75")
	if updatedDev == nil {
		t.Fatal("device not found after update")
	}
	if updatedDev.CustomOS != "Ubuntu" || updatedDev.CustomOSVersion != "24.04 LTS" || updatedDev.CustomOSFamily != "Linux" {
		t.Errorf("device custom OS = %q / %q / %q, want Ubuntu / 24.04 LTS / Linux",
			updatedDev.CustomOS, updatedDev.CustomOSVersion, updatedDev.CustomOSFamily)
	}

	// 5. Delete API token
	if err := s.DeleteAPIToken(created.ID); err != nil {
		t.Fatalf("DeleteAPIToken failed: %v", err)
	}
	tokensFinal, err := s.ListAPITokens()
	if err != nil {
		t.Fatalf("ListAPITokens failed: %v", err)
	}
	if len(tokensFinal) != 0 {
		t.Errorf("got %d tokens after delete, want 0", len(tokensFinal))
	}
}

func TestCreateAPITokenRejectsShortTokens(t *testing.T) {
	s := newTestStorage(t)
	if _, err := s.CreateAPIToken("too-short", "short123"); err == nil {
		t.Fatal("CreateAPIToken should reject tokens shorter than 16 characters")
	}
}

func TestMergeUniFiClients(t *testing.T) {
	s := newTestStorage(t)
	s.SetNetworkNames(map[string]string{
		"192.168.1.0/24":  "Home LAN",
		"192.168.20.0/24": "IoT LAN",
	})

	// 1. Matching existing device by MAC (case-insensitive) and updating wireless telemetry
	// while preserving user customizations
	existing := &types.Device{
		IP:             "192.168.1.100",
		MAC:            "AA:BB:CC:DD:EE:01",
		Hostname:       "my-iphone",
		Vendor:         "Apple",
		Type:           "Mobile",
		Label:          "Custom Label",
		Notes:          "Personal phone",
		Group:          "Family",
		CustomHostname: "Johnny's iPhone",
		CustomWebURL:   "http://iphone.local",
		CustomType:     "Phone",
		LinkedMAC:      "11:22:33:44:55:66",
		NotifyOnSeen:   true,
	}
	if err := s.UpdateDevice(existing); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	client := types.Device{
		IP:                "192.168.1.100",
		MAC:               "aa:bb:cc:dd:ee:01", // lowercase
		Hostname:          "unifi-iphone",
		SSID:              "Home-WiFi",
		APName:            "Living Room AP",
		RadioBand:         "5GHz",
		Channel:           36,
		WiFiStandard:      "WiFi 6 (11ax)",
		Signal:            -58,
		SignalQuality:     88,
		RxRate:            1201000,
		TxRate:            1201000,
		RxBytes:           987654321,
		TxBytes:           123456789,
		AssociationUptime: 3600,
		UniFiModel:        "U6-Pro",
	}

	if _, _, err := s.MergeUniFiClients([]types.Device{client}); err != nil {
		t.Fatalf("MergeUniFiClients: %v", err)
	}

	updated := s.GetDevice("192.168.1.100")
	if updated == nil {
		t.Fatalf("GetDevice(192.168.1.100) returned nil")
	}

	// Wireless telemetry updated
	if updated.SSID != client.SSID {
		t.Errorf("SSID = %q, want %q", updated.SSID, client.SSID)
	}
	if updated.APName != client.APName {
		t.Errorf("APName = %q, want %q", updated.APName, client.APName)
	}
	if updated.RadioBand != client.RadioBand {
		t.Errorf("RadioBand = %q, want %q", updated.RadioBand, client.RadioBand)
	}
	if updated.Channel != client.Channel {
		t.Errorf("Channel = %d, want %d", updated.Channel, client.Channel)
	}
	if updated.WiFiStandard != client.WiFiStandard {
		t.Errorf("WiFiStandard = %q, want %q", updated.WiFiStandard, client.WiFiStandard)
	}
	if updated.Signal != client.Signal {
		t.Errorf("Signal = %d, want %d", updated.Signal, client.Signal)
	}
	if updated.SignalQuality != client.SignalQuality {
		t.Errorf("SignalQuality = %d, want %d", updated.SignalQuality, client.SignalQuality)
	}
	if updated.RxRate != client.RxRate {
		t.Errorf("RxRate = %d, want %d", updated.RxRate, client.RxRate)
	}
	if updated.TxRate != client.TxRate {
		t.Errorf("TxRate = %d, want %d", updated.TxRate, client.TxRate)
	}
	if updated.RxBytes != client.RxBytes {
		t.Errorf("RxBytes = %d, want %d", updated.RxBytes, client.RxBytes)
	}
	if updated.TxBytes != client.TxBytes {
		t.Errorf("TxBytes = %d, want %d", updated.TxBytes, client.TxBytes)
	}
	if updated.AssociationUptime != client.AssociationUptime {
		t.Errorf("AssociationUptime = %d, want %d", updated.AssociationUptime, client.AssociationUptime)
	}
	if updated.UniFiModel != client.UniFiModel {
		t.Errorf("UniFiModel = %q, want %q", updated.UniFiModel, client.UniFiModel)
	}

	// User customizations must NOT be overwritten
	if updated.Label != existing.Label {
		t.Errorf("Label = %q, want %q", updated.Label, existing.Label)
	}
	if updated.Notes != existing.Notes {
		t.Errorf("Notes = %q, want %q", updated.Notes, existing.Notes)
	}
	if updated.Group != existing.Group {
		t.Errorf("Group = %q, want %q", updated.Group, existing.Group)
	}
	if updated.CustomHostname != existing.CustomHostname {
		t.Errorf("CustomHostname = %q, want %q", updated.CustomHostname, existing.CustomHostname)
	}
	if updated.CustomWebURL != existing.CustomWebURL {
		t.Errorf("CustomWebURL = %q, want %q", updated.CustomWebURL, existing.CustomWebURL)
	}
	if updated.CustomType != existing.CustomType {
		t.Errorf("CustomType = %q, want %q", updated.CustomType, existing.CustomType)
	}
	if updated.LinkedMAC != existing.LinkedMAC {
		t.Errorf("LinkedMAC = %q, want %q", updated.LinkedMAC, existing.LinkedMAC)
	}
	if updated.NotifyOnSeen != existing.NotifyOnSeen {
		t.Errorf("NotifyOnSeen = %v, want %v", updated.NotifyOnSeen, existing.NotifyOnSeen)
	}

	// 2. Matching existing device by IP when MAC is unavailable
	noMacDev := &types.Device{
		IP:       "192.168.1.101",
		MAC:      "",
		Hostname: "ip-only-device",
	}
	if err := s.UpdateDevice(noMacDev); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	ipClient := types.Device{
		IP:     "192.168.1.101",
		MAC:    "",
		SSID:   "Guest-WiFi",
		APName: "Hall AP",
	}
	if _, _, err := s.MergeUniFiClients([]types.Device{ipClient}); err != nil {
		t.Fatalf("MergeUniFiClients: %v", err)
	}
	updatedIPDev := s.GetDevice("192.168.1.101")
	if updatedIPDev == nil {
		t.Fatalf("GetDevice(192.168.1.101) returned nil")
	}
	if updatedIPDev.SSID != "Guest-WiFi" {
		t.Errorf("SSID = %q, want %q", updatedIPDev.SSID, "Guest-WiFi")
	}
	if updatedIPDev.APName != "Hall AP" {
		t.Errorf("APName = %q, want %q", updatedIPDev.APName, "Hall AP")
	}

	// 3. Insert new discovered client not yet in the database
	before := time.Now().Add(-1 * time.Second)
	newClient := types.Device{
		IP:           "192.168.1.200",
		MAC:          "AA:BB:CC:DD:EE:02",
		Hostname:     "smart-thermostat",
		Vendor:       "Ecobee",
		SSID:         "IoT-WiFi",
		APName:       "Living Room AP",
		RadioBand:    "2.4GHz",
		Channel:      6,
		WiFiStandard: "WiFi 4 (11n)",
		Signal:       -70,
	}
	newDevs, seenDevs, err := s.MergeUniFiClients([]types.Device{newClient})
	if err != nil {
		t.Fatalf("MergeUniFiClients new device: %v", err)
	}
	if len(newDevs) != 1 || newDevs[0].IP != "192.168.1.200" {
		t.Errorf("expected 1 new device 192.168.1.200, got %v", newDevs)
	}
	if len(seenDevs) != 0 {
		t.Errorf("expected 0 seen devices, got %v", seenDevs)
	}
	inserted := s.GetDevice("192.168.1.200")
	if inserted == nil {
		t.Fatalf("GetDevice(192.168.1.200) returned nil for newly inserted client")
	}
	if inserted.Assignment != "Discovered" {
		t.Errorf("Assignment = %q, want %q", inserted.Assignment, "Discovered")
	}
	if inserted.NetworkName != "Home LAN" {
		t.Errorf("NetworkName = %q, want %q", inserted.NetworkName, "Home LAN")
	}
	if inserted.FirstSeen.Before(before) {
		t.Errorf("FirstSeen = %v, expected after %v", inserted.FirstSeen, before)
	}
	if inserted.LastSeen.Before(before) {
		t.Errorf("LastSeen = %v, expected after %v", inserted.LastSeen, before)
	}
	if inserted.SSID != "IoT-WiFi" {
		t.Errorf("SSID = %q, want %q", inserted.SSID, "IoT-WiFi")
	}
	if inserted.APName != "Living Room AP" {
		t.Errorf("APName = %q, want %q", inserted.APName, "Living Room AP")
	}
	if inserted.Channel != 6 {
		t.Errorf("Channel = %d, want %d", inserted.Channel, 6)
	}

	// 4. Empty client list returns nil
	if _, _, err := s.MergeUniFiClients([]types.Device{}); err != nil {
		t.Fatalf("MergeUniFiClients with empty list: %v", err)
	}

	// 5. Client with no IP and no MAC is skipped
	if _, _, err := s.MergeUniFiClients([]types.Device{{}}); err != nil {
		t.Fatalf("MergeUniFiClients with blank device: %v", err)
	}

	// 6. Device moves IP: MAC matched, moves to free IP on different subnet, records address history and resolves new network_name
	movingClient := types.Device{
		IP:     "192.168.20.205",
		MAC:    "AA:BB:CC:DD:EE:02", // same MAC as 192.168.1.200
		SSID:   "IoT-WiFi-Moved",
		APName: "Garage AP",
	}
	if _, _, err := s.MergeUniFiClients([]types.Device{movingClient}); err != nil {
		t.Fatalf("MergeUniFiClients moving IP: %v", err)
	}
	moved := s.GetDevice("192.168.20.205")
	if moved == nil {
		t.Fatalf("expected device at 192.168.20.205, got nil")
	}
	if moved.SSID != "IoT-WiFi-Moved" {
		t.Errorf("SSID = %q, want %q", moved.SSID, "IoT-WiFi-Moved")
	}
	if moved.NetworkName != "IoT LAN" {
		t.Errorf("NetworkName = %q, want %q", moved.NetworkName, "IoT LAN")
	}
	if len(moved.AddressHistory) == 0 {
		t.Errorf("expected address history recorded for moved device, got none")
	} else if moved.AddressHistory[0].IP != "192.168.1.200" {
		t.Errorf("address history old IP = %q, want %q", moved.AddressHistory[0].IP, "192.168.1.200")
	}

	// 7. Presence history and notifications on reconnection (is_online 0 -> 1)
	reconnectingDev := &types.Device{
		IP:           "192.168.1.210",
		MAC:          "AA:BB:CC:DD:EE:03",
		Hostname:     "presence-test-dev",
		NotifyOnSeen: true,
	}
	if err := s.UpdateDevice(reconnectingDev); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	// Mark device offline 2 hours ago
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	_, err = s.db.Exec("UPDATE devices SET is_online = 0, last_presence_change = ? WHERE ip = ?", twoHoursAgo, "192.168.1.210")
	if err != nil {
		t.Fatalf("mark offline: %v", err)
	}

	reconnectingClient := types.Device{
		IP:     "192.168.1.210",
		MAC:    "aa:bb:cc:dd:ee:03",
		SSID:   "Home-WiFi",
		APName: "Living Room AP",
	}
	newDevs, seenDevs, err = s.MergeUniFiClients([]types.Device{reconnectingClient})
	if err != nil {
		t.Fatalf("MergeUniFiClients reconnecting: %v", err)
	}
	if len(newDevs) != 0 {
		t.Errorf("expected 0 new devices, got %d", len(newDevs))
	}
	if len(seenDevs) != 1 || seenDevs[0].IP != "192.168.1.210" {
		t.Fatalf("expected 1 seen device 192.168.1.210, got %v", seenDevs)
	}
	events, err := s.GetPresenceEvents()
	if err != nil {
		t.Fatalf("GetPresenceEvents: %v", err)
	}
	var returnEvent *types.PresenceEventRecord
	for _, ev := range events {
		if ev.IP == "192.168.1.210" && ev.Event == "return" {
			returnEvent = &ev
			break
		}
	}
	if returnEvent == nil {
		t.Fatalf("expected 'return' presence event for 192.168.1.210, found none")
	}
	if returnEvent.Duration < 7100 || returnEvent.Duration > 7300 {
		t.Errorf("return event duration = %f, expected ~7200", returnEvent.Duration)
	}
	var dbIsOnline int
	var dbLastPresenceChange time.Time
	err = s.db.QueryRow("SELECT is_online, last_presence_change FROM devices WHERE ip = ?", "192.168.1.210").Scan(&dbIsOnline, &dbLastPresenceChange)
	if err != nil {
		t.Fatalf("scan db: %v", err)
	}
	if dbIsOnline != 1 {
		t.Errorf("expected dbIsOnline == 1, got %d", dbIsOnline)
	}
	if time.Since(dbLastPresenceChange) > 5*time.Second {
		t.Errorf("expected dbLastPresenceChange to be updated to now, got %v", dbLastPresenceChange)
	}
}

func TestMergeUniFiClients_UniFiNameAndFallback(t *testing.T) {
	s := newTestStorage(t)

	// Case 1: Device already has a normal-method hostname. UniFiName is stored,
	// but normal-method hostname is preserved.
	devWithHostname := &types.Device{
		IP:       "192.168.1.50",
		MAC:      "aa:bb:cc:11:22:33",
		Hostname: "router.lan",
	}
	if err := s.UpdateDevice(devWithHostname); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	_, _, err := s.MergeUniFiClients([]types.Device{
		{
			IP:        "192.168.1.50",
			MAC:       "aa:bb:cc:11:22:33",
			UniFiName: "Main Router",
		},
	})
	if err != nil {
		t.Fatalf("MergeUniFiClients: %v", err)
	}

	d1 := s.GetDevice("192.168.1.50")
	if d1 == nil {
		t.Fatalf("device 192.168.1.50 not found")
	}
	if d1.UniFiName != "Main Router" {
		t.Errorf("d1.UniFiName = %q, want %q", d1.UniFiName, "Main Router")
	}
	if d1.Hostname != "router.lan" {
		t.Errorf("d1.Hostname = %q, want %q (normal method should take priority)", d1.Hostname, "router.lan")
	}

	// Case 2: Device has NO normal-method hostname. UniFiName is stored AND used as fallback hostname.
	devNoHostname := &types.Device{
		IP:       "192.168.1.51",
		MAC:      "aa:bb:cc:44:55:66",
		Hostname: "",
	}
	if err := s.UpdateDevice(devNoHostname); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	_, _, err = s.MergeUniFiClients([]types.Device{
		{
			IP:        "192.168.1.51",
			MAC:       "aa:bb:cc:44:55:66",
			UniFiName: "Living Room Lightstrip",
		},
	})
	if err != nil {
		t.Fatalf("MergeUniFiClients: %v", err)
	}

	d2 := s.GetDevice("192.168.1.51")
	if d2 == nil {
		t.Fatalf("device 192.168.1.51 not found")
	}
	if d2.UniFiName != "Living Room Lightstrip" {
		t.Errorf("d2.UniFiName = %q, want %q", d2.UniFiName, "Living Room Lightstrip")
	}
	if d2.Hostname != "Living Room Lightstrip" {
		t.Errorf("d2.Hostname = %q, want %q (fallback to UniFi name)", d2.Hostname, "Living Room Lightstrip")
	}

	// Case 3: Brand new device discovered via UniFi with UniFiName
	_, _, err = s.MergeUniFiClients([]types.Device{
		{
			IP:        "192.168.1.52",
			MAC:       "aa:bb:cc:77:88:99",
			UniFiName: "Office AP",
		},
	})
	if err != nil {
		t.Fatalf("MergeUniFiClients: %v", err)
	}

	d3 := s.GetDevice("192.168.1.52")
	if d3 == nil {
		t.Fatalf("device 192.168.1.52 not found")
	}
	if d3.UniFiName != "Office AP" {
		t.Errorf("d3.UniFiName = %q, want %q", d3.UniFiName, "Office AP")
	}
	if d3.Hostname != "Office AP" {
		t.Errorf("d3.Hostname = %q, want %q (fallback to UniFi name)", d3.Hostname, "Office AP")
	}
}

func TestMergeRouterDHCP_Telemetry(t *testing.T) {
	s := newTestStorage(t)
	s.SetNetworkNames(map[string]string{"192.168.1.0/24": "Home LAN"})

	existing := &types.Device{
		IP:             "192.168.1.50",
		MAC:            "00:11:22:33:44:01",
		Hostname:       "existing-dev",
		Label:          "Custom Label",
		CustomHostname: "Custom Host",
	}
	if err := s.UpdateDevice(existing); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	leaseExp := time.Now().Add(12 * time.Hour).Truncate(time.Second)
	leases := []types.Device{
		{
			IP:              "192.168.1.50",
			MAC:             "00:11:22:33:44:01",
			Hostname:        "router-lease-name",
			RouterSource:    "OPNsense",
			RouterInterface: "vtnet0 (LAN)",
			LeaseExpires:    leaseExp,
			LeaseLifetime:   43200,
		},
	}
	reservations := []types.Device{
		{
			IP:           "192.168.1.50",
			MAC:          "00:11:22:33:44:01",
			RouterSource: "OPNsense",
			RouterNotes:  "Server static mapping",
		},
	}

	if err := s.MergeRouterDHCP(leases, reservations); err != nil {
		t.Fatalf("MergeRouterDHCP: %v", err)
	}

	dev := s.GetDevice("192.168.1.50")
	if dev == nil {
		t.Fatalf("device 192.168.1.50 not found")
	}
	if dev.Assignment != "Static" {
		t.Errorf("Assignment = %q, want %q", dev.Assignment, "Static")
	}
	if dev.RouterSource != "OPNsense" {
		t.Errorf("RouterSource = %q, want %q", dev.RouterSource, "OPNsense")
	}
	if dev.RouterInterface != "vtnet0 (LAN)" {
		t.Errorf("RouterInterface = %q, want %q", dev.RouterInterface, "vtnet0 (LAN)")
	}
	if !dev.LeaseExpires.Equal(leaseExp) {
		t.Errorf("LeaseExpires = %v, want %v", dev.LeaseExpires, leaseExp)
	}
	if dev.LeaseLifetime != 43200 {
		t.Errorf("LeaseLifetime = %d, want %d", dev.LeaseLifetime, 43200)
	}
	if dev.RouterNotes != "Server static mapping" {
		t.Errorf("RouterNotes = %q, want %q", dev.RouterNotes, "Server static mapping")
	}
	// Customizations preserved
	if dev.Label != "Custom Label" {
		t.Errorf("Label = %q, want %q", dev.Label, "Custom Label")
	}
	if dev.CustomHostname != "Custom Host" {
		t.Errorf("CustomHostname = %q, want %q", dev.CustomHostname, "Custom Host")
	}

	// Seed another device with Static assignment, but don't include it in next DHCP merge
	nonDHCPDev := &types.Device{
		IP:         "192.168.1.60",
		MAC:        "00:11:22:33:44:02",
		Assignment: "Static",
	}
	if err := s.UpdateDevice(nonDHCPDev); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	// Run MergeRouterDHCP with only 192.168.1.50
	if err := s.MergeRouterDHCP(leases, reservations); err != nil {
		t.Fatalf("MergeRouterDHCP second pass: %v", err)
	}

	updatedNonDHCP := s.GetDevice("192.168.1.60")
	if updatedNonDHCP == nil {
		t.Fatalf("device 192.168.1.60 not found")
	}
	if updatedNonDHCP.Assignment != "Discovered" {
		t.Errorf("Assignment = %q, want %q", updatedNonDHCP.Assignment, "Discovered")
	}
}

func TestMergeSwitchConnectionsUpdatesMatchingDeviceWithoutOverwritingOtherTelemetry(t *testing.T) {
	s := newTestStorage(t)

	poeWatts := 8.2
	updatedAt := time.Now().Add(-time.Minute).Truncate(time.Second)
	existing := &types.Device{
		IP:              "192.168.1.50",
		MAC:             "AA:BB:CC:DD:EE:01",
		Label:           "Living room AP",
		Notes:           "Do not move",
		Group:           "Infrastructure",
		CustomHostname:  "ap-living-room",
		CustomWebURL:    "https://ap.example.test",
		CustomType:      "Access Point",
		Assignment:      "Static",
		SSID:            "Home Wi-Fi",
		APName:          "Living Room AP",
		RouterSource:    "OPNsense",
		RouterInterface: "igb1",
		RouterNotes:     "DHCP reservation",
	}
	if err := s.UpdateDevice(existing); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	err := s.MergeSwitchConnections([]SwitchConnection{{
		MAC:        "aa:bb:cc:dd:ee:01",
		SwitchName: "switchy",
		SwitchHost: "10.0.0.2",
		Port:       "gi1/23",
		VLAN:       3,
		LinkState:  "up",
		LinkSpeed:  1000,
		Duplex:     "full",
		PoEWatts:   &poeWatts,
		UpdatedAt:  updatedAt,
	}}, "switchy")
	if err != nil {
		t.Fatalf("MergeSwitchConnections: %v", err)
	}

	got := s.GetDevice(existing.IP)
	if got == nil {
		t.Fatalf("GetDevice(%s) returned nil", existing.IP)
	}
	if got.SwitchName != "switchy" || got.SwitchHost != "10.0.0.2" || got.SwitchPort != "gi1/23" {
		t.Errorf("switch identity = (%q, %q, %q), want (switchy, 10.0.0.2, gi1/23)", got.SwitchName, got.SwitchHost, got.SwitchPort)
	}
	if got.SwitchVLAN != 3 || got.SwitchLinkState != "up" || got.SwitchLinkSpeed != 1000 || got.SwitchDuplex != "full" {
		t.Errorf("switch link telemetry = (%d, %q, %d, %q), want (3, up, 1000, full)", got.SwitchVLAN, got.SwitchLinkState, got.SwitchLinkSpeed, got.SwitchDuplex)
	}
	if got.SwitchPoEWatts == nil || *got.SwitchPoEWatts != 8.2 {
		t.Errorf("SwitchPoEWatts = %v, want 8.2", got.SwitchPoEWatts)
	}
	if !got.SwitchUpdatedAt.Equal(updatedAt) {
		t.Errorf("SwitchUpdatedAt = %v, want %v", got.SwitchUpdatedAt, updatedAt)
	}
	if got.Label != existing.Label || got.Notes != existing.Notes || got.Group != existing.Group || got.CustomHostname != existing.CustomHostname || got.CustomWebURL != existing.CustomWebURL || got.CustomType != existing.CustomType {
		t.Errorf("user customizations changed: %+v", got)
	}
	if got.Assignment != existing.Assignment || got.SSID != existing.SSID || got.APName != existing.APName || got.RouterSource != existing.RouterSource || got.RouterInterface != existing.RouterInterface || got.RouterNotes != existing.RouterNotes {
		t.Errorf("non-switch telemetry changed: %+v", got)
	}
}

func TestMergeSwitchConnectionsEmptyResultClearsOnlyNamedSwitch(t *testing.T) {
	s := newTestStorage(t)
	first := &types.Device{IP: "192.168.1.51", MAC: "AA:BB:CC:DD:EE:02"}
	second := &types.Device{IP: "192.168.1.52", MAC: "AA:BB:CC:DD:EE:03"}
	if err := s.UpdateDevice(first); err != nil {
		t.Fatalf("UpdateDevice first: %v", err)
	}
	if err := s.UpdateDevice(second); err != nil {
		t.Fatalf("UpdateDevice second: %v", err)
	}

	if err := s.MergeSwitchConnections([]SwitchConnection{{MAC: first.MAC, SwitchName: "switchy", Port: "gi1/1", UpdatedAt: time.Now()}}, "switchy"); err != nil {
		t.Fatalf("merge switchy: %v", err)
	}
	if err := s.MergeSwitchConnections([]SwitchConnection{{MAC: second.MAC, SwitchName: "switch-two", Port: "gi1/2", UpdatedAt: time.Now()}}, "switch-two"); err != nil {
		t.Fatalf("merge switch-two: %v", err)
	}

	if err := s.MergeSwitchConnections(nil, "switchy"); err != nil {
		t.Fatalf("clear switchy: %v", err)
	}

	cleared := s.GetDevice(first.IP)
	if cleared == nil {
		t.Fatalf("GetDevice(%s) returned nil", first.IP)
	}
	if cleared.SwitchName != "" || cleared.SwitchHost != "" || cleared.SwitchPort != "" || cleared.SwitchVLAN != 0 || cleared.SwitchLinkState != "" || cleared.SwitchLinkSpeed != 0 || cleared.SwitchDuplex != "" || cleared.SwitchPoEWatts != nil || !cleared.SwitchUpdatedAt.IsZero() {
		t.Errorf("switchy fields were not cleared: %+v", cleared)
	}
	preserved := s.GetDevice(second.IP)
	if preserved == nil || preserved.SwitchName != "switch-two" || preserved.SwitchPort != "gi1/2" {
		t.Errorf("other switch connection was changed: %+v", preserved)
	}
}

func TestMergeSwitchConnectionsStoresNullPoEAndTimestamp(t *testing.T) {
	s := newTestStorage(t)
	device := &types.Device{IP: "192.168.1.53", MAC: "AA:BB:CC:DD:EE:04"}
	if err := s.UpdateDevice(device); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	if err := s.MergeSwitchConnections([]SwitchConnection{{MAC: device.MAC, SwitchName: "switchy", Port: "gi1/3"}}, "switchy"); err != nil {
		t.Fatalf("MergeSwitchConnections: %v", err)
	}

	got := s.GetDevice(device.IP)
	if got == nil {
		t.Fatalf("GetDevice(%s) returned nil", device.IP)
	}
	if got.SwitchPoEWatts != nil {
		t.Errorf("SwitchPoEWatts = %v, want nil", *got.SwitchPoEWatts)
	}
	if !got.SwitchUpdatedAt.IsZero() {
		t.Errorf("SwitchUpdatedAt = %v, want zero time", got.SwitchUpdatedAt)
	}
}

func TestUpdateDevicePreservesExistingSwitchTelemetryWhenOmitted(t *testing.T) {
	s := newTestStorage(t)
	device := &types.Device{
		IP:       "192.168.1.54",
		MAC:      "AA:BB:CC:DD:EE:05",
		Hostname: "original-name",
	}
	if err := s.UpdateDevice(device); err != nil {
		t.Fatalf("UpdateDevice initial: %v", err)
	}

	poeWatts := 4.6
	updatedAt := time.Now().Add(-time.Minute).Truncate(time.Second)
	if err := s.MergeSwitchConnections([]SwitchConnection{{
		MAC:        device.MAC,
		SwitchName: "switchy",
		SwitchHost: "10.0.0.2",
		Port:       "gi1/4",
		VLAN:       20,
		LinkState:  "up",
		LinkSpeed:  1000,
		Duplex:     "full",
		PoEWatts:   &poeWatts,
		UpdatedAt:  updatedAt,
	}}, "switchy"); err != nil {
		t.Fatalf("MergeSwitchConnections: %v", err)
	}

	if err := s.UpdateDevice(&types.Device{IP: device.IP, MAC: device.MAC, Hostname: "updated-name"}); err != nil {
		t.Fatalf("UpdateDevice update: %v", err)
	}

	got := s.GetDevice(device.IP)
	if got == nil {
		t.Fatalf("GetDevice(%s) returned nil", device.IP)
	}
	if got.SwitchName != "switchy" || got.SwitchHost != "10.0.0.2" || got.SwitchPort != "gi1/4" || got.SwitchVLAN != 20 || got.SwitchLinkState != "up" || got.SwitchLinkSpeed != 1000 || got.SwitchDuplex != "full" {
		t.Errorf("switch telemetry was not preserved: %+v", got)
	}
	if got.SwitchPoEWatts == nil || *got.SwitchPoEWatts != 4.6 {
		t.Errorf("SwitchPoEWatts = %v, want 4.6", got.SwitchPoEWatts)
	}
	if !got.SwitchUpdatedAt.Equal(updatedAt) {
		t.Errorf("SwitchUpdatedAt = %v, want %v", got.SwitchUpdatedAt, updatedAt)
	}
}

func TestStorage_MultiNetworkScanning(t *testing.T) {
	s := newTestStorage(t)

	if s.IsNetworkScanning("10.0.0.0/24") {
		t.Fatal("expected 10.0.0.0/24 not scanning initially")
	}

	// Activate both networks concurrently
	s.SetNetworkScanning("10.0.0.0/24", true)
	s.SetNetworkScanning("10.5.5.0/24", true)

	if !s.IsNetworkScanning("10.0.0.0/24") {
		t.Error("expected 10.0.0.0/24 is scanning")
	}
	if !s.IsNetworkScanning("10.5.5.0/24") {
		t.Error("expected 10.5.5.0/24 is scanning")
	}

	active := s.GetActiveScanningNetworks()
	if len(active) != 2 || active[0] != "10.0.0.0/24" || active[1] != "10.5.5.0/24" {
		t.Fatalf("unexpected active networks: %v", active)
	}

	// Deactivate one
	s.SetNetworkScanning("10.0.0.0/24", false)
	if s.IsNetworkScanning("10.0.0.0/24") {
		t.Error("expected 10.0.0.0/24 no longer scanning")
	}
	if !s.IsNetworkScanning("10.5.5.0/24") {
		t.Error("expected 10.5.5.0/24 still scanning")
	}

	// Clear all
	s.ClearScanningNetworks()
	if s.IsNetworkScanning("10.5.5.0/24") {
		t.Error("expected 10.5.5.0/24 no longer scanning after clear")
	}
}

func TestStorage_NetworkScanErrors(t *testing.T) {
	s := newTestStorage(t)

	if errStr := s.GetNetworkScanError("10.5.5.0/24"); errStr != "" {
		t.Fatalf("expected empty scan error initially, got %q", errStr)
	}

	s.SetNetworkScanError("10.5.5.0/24", "connection refused")
	if got := s.GetNetworkScanError("10.5.5.0/24"); got != "connection refused" {
		t.Fatalf("expected 'connection refused', got %q", got)
	}

	s.ClearNetworkScanError("10.5.5.0/24")
	if got := s.GetNetworkScanError("10.5.5.0/24"); got != "" {
		t.Fatalf("expected empty after clear, got %q", got)
	}
}

func TestStorage_NetworkDeepScanning(t *testing.T) {
	s := newTestStorage(t)

	if s.IsNetworkDeepScanning("10.5.5.0/24") {
		t.Fatal("expected 10.5.5.0/24 not deep scanning initially")
	}

	s.SetNetworkDeepScanning("10.5.5.0/24", true)
	if !s.IsNetworkDeepScanning("10.5.5.0/24") {
		t.Fatal("expected 10.5.5.0/24 deep scanning after set")
	}

	s.SetNetworkDeepScanning("10.5.5.0/24", false)
	if s.IsNetworkDeepScanning("10.5.5.0/24") {
		t.Fatal("expected 10.5.5.0/24 not deep scanning after clear")
	}
}

func TestMigration_00012_ScanHistoryDevicesColumn(t *testing.T) {
	s := newTestStorage(t)

	var defVal string
	err := s.db.QueryRow("SELECT devices_found FROM scan_history LIMIT 1").Scan(&defVal)
	// If no rows, sql.ErrNoRows is fine; it means the column exists!
	if err != nil && err.Error() != "sql: no rows in result set" {
		t.Fatalf("expected devices_found column to exist in scan_history: %v", err)
	}
}

func TestRecordScanHistory_ScopedMetrics(t *testing.T) {
	s := newTestStorage(t)

	// Seed devices in different subnets
	_, err := s.db.Exec(`
		INSERT INTO devices (ip, mac, hostname, is_online, first_seen, last_seen, last_presence_change) VALUES
		('10.0.0.10', '00:11:22:33:44:01', 'dev1', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
		('10.0.0.20', '00:11:22:33:44:02', 'dev2', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
		('10.5.5.5', '00:11:22:33:44:03', 'dev3', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
		('10.5.5.6', '00:11:22:33:44:04', 'dev4', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
	`)
	if err != nil {
		t.Fatalf("seed devices: %v", err)
	}

	startedAt := time.Now().Add(-1 * time.Minute)
	// Seed presence events
	_, err = s.db.Exec(`
		INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at) VALUES
		('10.0.0.10', '00:11:22:33:44:01', 'dev1', 'join', 0, ?),
		('10.5.5.5', '00:11:22:33:44:03', 'dev3', 'join', 0, ?);
	`, time.Now(), time.Now())
	if err != nil {
		t.Fatalf("seed presence: %v", err)
	}

	devs := []types.ScanDeviceRecord{
		{IP: "10.0.0.10", Hostname: "dev1", Vendor: "HP"},
		{IP: "10.0.0.20", Hostname: "dev2", Vendor: "Apple"},
	}

	err = s.RecordScanHistory("10.0.0.0/24", true, "", startedAt, 1.5, devs)
	if err != nil {
		t.Fatalf("RecordScanHistory: %v", err)
	}

	history, err := s.GetScanHistory()
	if err != nil {
		t.Fatalf("GetScanHistory: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected 1 history record, got %d", len(history))
	}
	h := history[0]
	if h.Network != "10.0.0.0/24" {
		t.Errorf("network = %q, want '10.0.0.0/24'", h.Network)
	}
	if h.DevicesOnline != 2 {
		t.Errorf("devices_online = %d, want 2 (only 10.0.0.x)", h.DevicesOnline)
	}
	if h.DevicesJoined != 1 {
		t.Errorf("devices_joined = %d, want 1 (only 10.0.0.10)", h.DevicesJoined)
	}
	if len(h.DevicesFound) != 2 {
		t.Fatalf("expected 2 devices found, got %d", len(h.DevicesFound))
	}
	if h.DevicesFound[0].IP != "10.0.0.10" || h.DevicesFound[0].Vendor != "HP" {
		t.Errorf("DevicesFound[0] mismatch: %+v", h.DevicesFound[0])
	}
}

func TestRecordScanHistoryWithDetails_Filtered(t *testing.T) {
	s := newTestStorage(t)

	now := time.Now()
	// Record 1 sweep scan
	err := s.RecordScanHistoryWithDetails("10.0.0.0/24", "sweep", "success", "", now.Add(-2*time.Hour), 1.2, []types.ScanDeviceRecord{
		{IP: "10.0.0.10", Hostname: "desktop"},
	})
	if err != nil {
		t.Fatalf("record sweep: %v", err)
	}

	// Record 1 deep scan with warning (partial)
	err = s.RecordScanHistoryWithDetails("10.5.5.0/24", "deep", "warning", "1 of 4 failed", now.Add(-1*time.Hour), 5.4, []types.ScanDeviceRecord{
		{IP: "10.5.5.142", Hostname: "proxmox"},
	})
	if err != nil {
		t.Fatalf("record deep warning: %v", err)
	}

	// Record 1 deep scan failed
	err = s.RecordScanHistoryWithDetails("10.5.5.0/24", "deep", "failed", "DTLS crash", now, 0.4, nil)
	if err != nil {
		t.Fatalf("record deep failed: %v", err)
	}

	// Test default unfiltered
	all, err := s.GetScanHistory()
	if err != nil {
		t.Fatalf("GetScanHistory: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 records, got %d", len(all))
	}
	if all[0].Status != "failed" || all[0].ScanType != "deep" {
		t.Errorf("all[0] mismatch: status=%s, type=%s", all[0].Status, all[0].ScanType)
	}
	if all[1].Status != "warning" || all[1].ScanType != "deep" {
		t.Errorf("all[1] mismatch: status=%s, type=%s", all[1].Status, all[1].ScanType)
	}
	if all[2].Status != "success" || all[2].ScanType != "sweep" {
		t.Errorf("all[2] mismatch: status=%s, type=%s", all[2].Status, all[2].ScanType)
	}

	// Test filter by scan_type = "sweep"
	sweeps, err := s.GetScanHistoryFiltered("", "sweep", "")
	if err != nil {
		t.Fatalf("filter sweep: %v", err)
	}
	if len(sweeps) != 1 || sweeps[0].Network != "10.0.0.0/24" {
		t.Errorf("expected 1 sweep record for 10.0.0.0/24, got %d", len(sweeps))
	}

	// Test filter by query = "proxmox"
	matches, err := s.GetScanHistoryFiltered("", "", "proxmox")
	if err != nil {
		t.Fatalf("filter query: %v", err)
	}
	if len(matches) != 1 || matches[0].Status != "warning" {
		t.Errorf("expected 1 record matching 'proxmox', got %d", len(matches))
	}

	// Test filter by today's date
	todayStr := now.Format("2006-01-02")
	todayRecs, err := s.GetScanHistoryFiltered(todayStr, "", "")
	if err != nil {
		t.Fatalf("filter date: %v", err)
	}
	if len(todayRecs) != 3 {
		t.Errorf("expected 3 records today (%s), got %d", todayStr, len(todayRecs))
	}
}

func TestTrafficStorage_RecordSeriesRollupPrune(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	defer s.Close()
	now := time.Now()

	// 1. Create a device
	dev := types.Device{
		IP:       "10.0.0.88",
		MAC:      "00:11:22:33:44:55",
		Hostname: "test-station",
	}
	if err := s.UpdateDevice(&dev); err != nil {
		t.Fatalf("failed to create device: %v", err)
	}

	// 2. Record samples
	samples := []types.TrafficSample{
		{
			MAC:       "00:11:22:33:44:55",
			Timestamp: now.Add(-30 * time.Minute),
			RxBytes:   1000000,
			TxBytes:   200000,
			RxRate:    15000,
			TxRate:    3000,
			Source:    "switch",
		},
		{
			MAC:       "00:11:22:33:44:55",
			Timestamp: now.Add(-5 * time.Minute),
			RxBytes:   1500000,
			TxBytes:   250000,
			RxRate:    25000,
			TxRate:    5000,
			Source:    "switch",
		},
	}
	if err := s.RecordTrafficSamples(samples); err != nil {
		t.Fatalf("RecordTrafficSamples failed: %v", err)
	}

	// 3. Verify device rates were updated in devices table
	updatedDev := s.GetDevice("10.0.0.88")
	if updatedDev == nil {
		t.Fatal("device not found")
	}
	if updatedDev.TrafficSource != "switch" {
		t.Errorf("expected TrafficSource 'switch', got %s", updatedDev.TrafficSource)
	}
	if updatedDev.RxRateBps != 25000 || updatedDev.TxRateBps != 5000 {
		t.Errorf("expected rates 25000/5000, got %d/%d", updatedDev.RxRateBps, updatedDev.TxRateBps)
	}
	if updatedDev.RxBytes != 1500000 || updatedDev.TxBytes != 250000 {
		t.Errorf("expected bytes 1500000/250000, got %d/%d", updatedDev.RxBytes, updatedDev.TxBytes)
	}

	// 4. Test GetDeviceTrafficSeries for "1h" and "24h"
	resp1h, err := s.GetDeviceTrafficSeries("00:11:22:33:44:55", "1h")
	if err != nil {
		t.Fatalf("GetDeviceTrafficSeries(1h) failed: %v", err)
	}
	if len(resp1h.Series) != 2 {
		t.Errorf("expected 2 series points in 1h, got %d", len(resp1h.Series))
	}
	if resp1h.Current.RxRateBytesSec != 25000 {
		t.Errorf("expected Current.RxRateBytesSec 25000, got %d", resp1h.Current.RxRateBytesSec)
	}

	// 5. Test RollupAndPruneTraffic
	pruned, err := s.RollupAndPruneTraffic(24, 7)
	if err != nil {
		t.Fatalf("RollupAndPruneTraffic failed: %v", err)
	}
	t.Logf("pruned rows: %d", pruned)
}

func TestRollupAndPruneTraffic_IdempotentAndUTC(t *testing.T) {
	s := newTestStorage(t)
	defer s.Close()

	mac := "aa:bb:cc:dd:ee:99"
	if err := s.UpdateDevice(&types.Device{
		IP:       "10.0.0.99",
		MAC:      mac,
		Hostname: "rollup-test",
	}); err != nil {
		t.Fatalf("UpdateDevice failed: %v", err)
	}

	// Use non-UTC timezones (UTC-5 and UTC+5) to verify timestamps are normalized to UTC
	// so SQLite strftime/datetime comparisons never compare local wall-clock strings against UTC 'now'.
	est := time.FixedZone("EST", -5*3600)
	ist := time.FixedZone("IST", 5*3600)

	nowUTC := time.Now().UTC()
	// Completed hour 2 hours ago (two samples within the same UTC hour)
	completedHourStart := nowUTC.Truncate(time.Hour).Add(-2 * time.Hour)
	// Older completed hour 26 hours ago (eligible for raw-sample pruning with retention=24h, kept in 7d hourly)
	oldHourStart := nowUTC.Truncate(time.Hour).Add(-26 * time.Hour)
	// Current incomplete hour (1 minute after start of current UTC hour, expressed in UTC-5)
	currentHourSample := nowUTC.Truncate(time.Hour).Add(1 * time.Minute).In(est)

	samples := []types.TrafficSample{
		{
			MAC:       mac,
			Timestamp: completedHourStart.Add(10 * time.Minute).In(est),
			RxBytes:   1000,
			TxBytes:   200,
			RxRate:    100,
			TxRate:    20,
			Source:    "unifi",
		},
		{
			MAC:       mac,
			Timestamp: completedHourStart.Add(40 * time.Minute).In(ist),
			RxBytes:   2500,
			TxBytes:   700,
			RxRate:    200,
			TxRate:    40,
			Source:    "unifi",
		},
		{
			MAC:       mac,
			Timestamp: oldHourStart.Add(15 * time.Minute).In(est),
			RxBytes:   500,
			TxBytes:   100,
			RxRate:    50,
			TxRate:    10,
			Source:    "unifi",
		},
		{
			MAC:       mac,
			Timestamp: oldHourStart.Add(45 * time.Minute).In(est),
			RxBytes:   900,
			TxBytes:   250,
			RxRate:    70,
			TxRate:    20,
			Source:    "unifi",
		},
		{
			MAC:       mac,
			Timestamp: currentHourSample,
			RxBytes:   3000,
			TxBytes:   900,
			RxRate:    300,
			TxRate:    60,
			Source:    "unifi",
		},
	}
	if err := s.RecordTrafficSamples(samples); err != nil {
		t.Fatalf("RecordTrafficSamples failed: %v", err)
	}

	// First rollup: should roll up the 2 completed hours (2h ago & 26h ago), NOT the current hour,
	// and prune the 2 samples from 26h ago (beyond 24h retention).
	pruned1, err := s.RollupAndPruneTraffic(24, 7)
	if err != nil {
		t.Fatalf("first RollupAndPruneTraffic failed: %v", err)
	}
	if pruned1 != 2 {
		t.Fatalf("first RollupAndPruneTraffic pruned = %d, want 2", pruned1)
	}

	// Second rollup: must be idempotent (still exactly 2 hourly rows, no duplicates).
	pruned2, err := s.RollupAndPruneTraffic(24, 7)
	if err != nil {
		t.Fatalf("second RollupAndPruneTraffic failed: %v", err)
	}
	if pruned2 != 0 {
		t.Fatalf("second RollupAndPruneTraffic pruned = %d, want 0", pruned2)
	}

	var hourlyCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM traffic_hourly WHERE mac = ? AND source = 'unifi'`, mac).Scan(&hourlyCount); err != nil {
		t.Fatalf("count traffic_hourly failed: %v", err)
	}
	if hourlyCount != 2 {
		t.Fatalf("traffic_hourly row count after 2 rollups = %d, want 2 (no duplicates, no current incomplete hour)", hourlyCount)
	}

	// Verify 7d series retrieves the 2 hourly buckets with UTC timestamps and expected deltas.
	resp7d, err := s.GetDeviceTrafficSeries(mac, "7d")
	if err != nil {
		t.Fatalf("GetDeviceTrafficSeries(7d) failed: %v", err)
	}
	if len(resp7d.Series) != 2 {
		t.Fatalf("GetDeviceTrafficSeries(7d) returned %d points, want 2: %+v", len(resp7d.Series), resp7d.Series)
	}
	if resp7d.Series[0].RxBytes != 400 || resp7d.Series[0].TxBytes != 150 {
		t.Errorf("oldest bucket deltas = %d/%d, want 400/150", resp7d.Series[0].RxBytes, resp7d.Series[0].TxBytes)
	}
	if resp7d.Series[1].RxBytes != 1500 || resp7d.Series[1].TxBytes != 500 {
		t.Errorf("recent bucket deltas = %d/%d, want 1500/500", resp7d.Series[1].RxBytes, resp7d.Series[1].TxBytes)
	}
	for i, pt := range resp7d.Series {
		if pt.Timestamp.Location() != time.UTC {
			t.Errorf("series[%d].Timestamp location = %v, want UTC", i, pt.Timestamp.Location())
		}
	}

	// Verify 24h series retrieves remaining raw samples (2 from 2h ago + 1 from current hour = 3)
	resp24h, err := s.GetDeviceTrafficSeries(mac, "24h")
	if err != nil {
		t.Fatalf("GetDeviceTrafficSeries(24h) failed: %v", err)
	}
	if len(resp24h.Series) != 3 {
		t.Fatalf("GetDeviceTrafficSeries(24h) returned %d points, want 3", len(resp24h.Series))
	}
}

func TestRecordTrafficSamples_OpenWrtWAN(t *testing.T) {
	s := newTestStorage(t)
	defer s.Close()
	now := time.Now()

	// Device 1: Has link traffic metrics from "switch"
	dev1 := types.Device{
		IP:       "10.0.0.101",
		MAC:      "00:11:22:33:44:01",
		Hostname: "switch-device",
	}
	if err := s.UpdateDevice(&dev1); err != nil {
		t.Fatalf("failed to create dev1: %v", err)
	}

	linkSamples := []types.TrafficSample{
		{
			MAC:       dev1.MAC,
			Timestamp: now.Add(-10 * time.Minute),
			RxBytes:   1000000,
			TxBytes:   200000,
			RxRate:    15000,
			TxRate:    3000,
			Source:    "switch",
		},
	}
	if err := s.RecordTrafficSamples(linkSamples); err != nil {
		t.Fatalf("RecordTrafficSamples(switch) failed: %v", err)
	}

	// Device 2: Fresh device with empty traffic_source
	dev2 := types.Device{
		IP:       "10.0.0.102",
		MAC:      "00:11:22:33:44:02",
		Hostname: "fresh-device",
	}
	if err := s.UpdateDevice(&dev2); err != nil {
		t.Fatalf("failed to create dev2: %v", err)
	}

	// Device 3: Fresh device with empty traffic_source tested with opnsense
	dev3 := types.Device{
		IP:       "10.0.0.103",
		MAC:      "00:11:22:33:44:03",
		Hostname: "opnsense-device",
	}
	if err := s.UpdateDevice(&dev3); err != nil {
		t.Fatalf("failed to create dev3: %v", err)
	}

	// Record WAN traffic samples with Source: "openwrt" and "opnsense"
	wanSamples := []types.TrafficSample{
		{
			MAC:       dev1.MAC,
			Timestamp: now.Add(-1 * time.Minute),
			RxBytes:   5000000,
			TxBytes:   800000,
			RxRate:    50000,
			TxRate:    8000,
			Source:    "openwrt",
		},
		{
			MAC:       dev2.MAC,
			Timestamp: now.Add(-1 * time.Minute),
			RxBytes:   7000000,
			TxBytes:   900000,
			RxRate:    70000,
			TxRate:    9000,
			Source:    "openwrt",
		},
		{
			MAC:       dev3.MAC,
			Timestamp: now.Add(-1 * time.Minute),
			RxBytes:   3000000,
			TxBytes:   400000,
			RxRate:    30000,
			TxRate:    4000,
			Source:    "opnsense",
		},
	}
	if err := s.RecordTrafficSamples(wanSamples); err != nil {
		t.Fatalf("RecordTrafficSamples(wanSamples) failed: %v", err)
	}

	// 1, 3, 4: Verify dev1:
	// - WAN metrics updated
	// - Link metrics preserved (not overwritten)
	// - traffic_source preserved as "switch"
	updatedDev1 := s.GetDevice(dev1.IP)
	if updatedDev1 == nil {
		t.Fatalf("dev1 not found")
	}
	if updatedDev1.TrafficSource != "switch" {
		t.Errorf("dev1: expected traffic_source 'switch', got %q", updatedDev1.TrafficSource)
	}
	if updatedDev1.WanRxRateBps != 50000 || updatedDev1.WanTxRateBps != 8000 {
		t.Errorf("dev1: expected wan rates 50000/8000, got %d/%d", updatedDev1.WanRxRateBps, updatedDev1.WanTxRateBps)
	}
	if updatedDev1.WanRxBytes != 5000000 || updatedDev1.WanTxBytes != 800000 {
		t.Errorf("dev1: expected wan bytes 5000000/800000, got %d/%d", updatedDev1.WanRxBytes, updatedDev1.WanTxBytes)
	}
	if updatedDev1.RxRateBps != 15000 || updatedDev1.TxRateBps != 3000 {
		t.Errorf("dev1: expected link rates preserved at 15000/3000, got %d/%d", updatedDev1.RxRateBps, updatedDev1.TxRateBps)
	}
	if updatedDev1.RxBytes != 1000000 || updatedDev1.TxBytes != 200000 {
		t.Errorf("dev1: expected link bytes preserved at 1000000/200000, got %d/%d", updatedDev1.RxBytes, updatedDev1.TxBytes)
	}

	// 1, 4: Verify dev2:
	// - WAN metrics updated
	// - traffic_source set to "openwrt" (was empty)
	// - Link metrics remain 0
	updatedDev2 := s.GetDevice(dev2.IP)
	if updatedDev2 == nil {
		t.Fatalf("dev2 not found")
	}
	if updatedDev2.TrafficSource != "openwrt" {
		t.Errorf("dev2: expected traffic_source 'openwrt', got %q", updatedDev2.TrafficSource)
	}
	if updatedDev2.WanRxRateBps != 70000 || updatedDev2.WanTxRateBps != 9000 {
		t.Errorf("dev2: expected wan rates 70000/9000, got %d/%d", updatedDev2.WanRxRateBps, updatedDev2.WanTxRateBps)
	}
	if updatedDev2.WanRxBytes != 7000000 || updatedDev2.WanTxBytes != 900000 {
		t.Errorf("dev2: expected wan bytes 7000000/900000, got %d/%d", updatedDev2.WanRxBytes, updatedDev2.WanTxBytes)
	}
	if updatedDev2.RxRateBps != 0 || updatedDev2.TxRateBps != 0 {
		t.Errorf("dev2: expected link rates to remain 0, got %d/%d", updatedDev2.RxRateBps, updatedDev2.TxRateBps)
	}
	if updatedDev2.RxBytes != 0 || updatedDev2.TxBytes != 0 {
		t.Errorf("dev2: expected link bytes to remain 0, got %d/%d", updatedDev2.RxBytes, updatedDev2.TxBytes)
	}

	// Verify dev3 (opnsense):
	// - WAN metrics updated
	// - traffic_source set to "opnsense" (was empty)
	// - Link metrics remain 0
	updatedDev3 := s.GetDevice(dev3.IP)
	if updatedDev3 == nil {
		t.Fatalf("dev3 not found")
	}
	if updatedDev3.TrafficSource != "opnsense" {
		t.Errorf("dev3: expected traffic_source 'opnsense', got %q", updatedDev3.TrafficSource)
	}
	if updatedDev3.WanRxRateBps != 30000 || updatedDev3.WanTxRateBps != 4000 {
		t.Errorf("dev3: expected wan rates 30000/4000, got %d/%d", updatedDev3.WanRxRateBps, updatedDev3.WanTxRateBps)
	}
	if updatedDev3.WanRxBytes != 3000000 || updatedDev3.WanTxBytes != 400000 {
		t.Errorf("dev3: expected wan bytes 3000000/400000, got %d/%d", updatedDev3.WanRxBytes, updatedDev3.WanTxBytes)
	}
	if updatedDev3.RxRateBps != 0 || updatedDev3.TxRateBps != 0 {
		t.Errorf("dev3: expected link rates to remain 0, got %d/%d", updatedDev3.RxRateBps, updatedDev3.TxRateBps)
	}
	if updatedDev3.RxBytes != 0 || updatedDev3.TxBytes != 0 {
		t.Errorf("dev3: expected link bytes to remain 0, got %d/%d", updatedDev3.RxBytes, updatedDev3.TxBytes)
	}

	// 2: Verify samples are recorded in traffic_samples table with source = 'openwrt'
	for _, mac := range []string{dev1.MAC, dev2.MAC} {
		var count int
		err := s.db.QueryRow("SELECT COUNT(*) FROM traffic_samples WHERE LOWER(mac) = LOWER(?) AND source = 'openwrt'", mac).Scan(&count)
		if err != nil {
			t.Fatalf("failed to query traffic_samples for %s: %v", mac, err)
		}
		if count != 1 {
			t.Errorf("expected 1 traffic_sample with source='openwrt' for %s, got %d", mac, count)
		}
	}

	// Also verify dev3 sample was recorded with source = 'opnsense'
	var opnSampleCount int
	err := s.db.QueryRow("SELECT COUNT(*) FROM traffic_samples WHERE LOWER(mac) = LOWER(?) AND source = 'opnsense'", dev3.MAC).Scan(&opnSampleCount)
	if err != nil {
		t.Fatalf("failed to query traffic_samples for %s: %v", dev3.MAC, err)
	}
	if opnSampleCount != 1 {
		t.Errorf("expected 1 traffic_sample with source='opnsense' for %s, got %d", dev3.MAC, opnSampleCount)
	}
}

func TestUpdateDeviceHostnameIfBlank(t *testing.T) {
	s := newTestStorage(t)

	// Case 1: Device with blank hostname updated by MAC
	dev1 := &types.Device{
		IP:       "192.168.1.51",
		MAC:      "00:11:22:33:44:55",
		Hostname: "",
	}
	if err := s.UpdateDevice(dev1); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	if err := s.UpdateDeviceHostnameIfBlank("00:11:22:33:44:55", "web01", false); err != nil {
		t.Fatalf("UpdateDeviceHostnameIfBlank failed: %v", err)
	}
	res1 := s.GetDevice("192.168.1.51")
	if res1 == nil || res1.Hostname != "web01" {
		t.Fatalf("expected Hostname to be 'web01', got %+v", res1)
	}
	if res1.CustomHostname != "" {
		t.Fatalf("expected CustomHostname to remain empty, got %q", res1.CustomHostname)
	}

	// Case 2: Device with existing hostname is NOT overwritten
	dev2 := &types.Device{
		IP:       "192.168.1.52",
		MAC:      "00:11:22:33:44:56",
		Hostname: "scanned-box",
	}
	if err := s.UpdateDevice(dev2); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	if err := s.UpdateDeviceHostnameIfBlank("00:11:22:33:44:56", "web02", false); err != nil {
		t.Fatalf("UpdateDeviceHostnameIfBlank failed: %v", err)
	}
	res2 := s.GetDevice("192.168.1.52")
	if res2 == nil || res2.Hostname != "scanned-box" {
		t.Fatalf("expected Hostname to remain 'scanned-box', got %+v", res2)
	}

	// Case 3: Device with blank hostname updated by IP fallback
	dev3 := &types.Device{
		IP:       "192.168.1.53",
		MAC:      "",
		Hostname: "",
	}
	if err := s.UpdateDevice(dev3); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	if err := s.UpdateDeviceHostnameIfBlank("192.168.1.53", "db01", true); err != nil {
		t.Fatalf("UpdateDeviceHostnameIfBlank by IP failed: %v", err)
	}
	res3 := s.GetDevice("192.168.1.53")
	if res3 == nil || res3.Hostname != "db01" {
		t.Fatalf("expected Hostname to be 'db01', got %+v", res3)
	}
}

func TestMergeRouterDHCP_PreservesSliceAndOnlineLastSeenAndRespectsScanInterval(t *testing.T) {
	s := newTestStorage(t)
	s.SetNetworkNames(map[string]string{"192.168.1.0/24": "Home LAN"})
	s.SetScanInterval(1800) // 30m -> online window is 90m

	now := time.Now()

	// Online device at 192.168.1.10
	if err := s.UpdateDevice(&types.Device{
		IP:        "192.168.1.10",
		MAC:       "aa:bb:cc:77:77:01",
		Hostname:  "online-box",
		FirstSeen: now.Add(-2 * time.Hour),
		LastSeen:  now.Add(-2 * time.Minute),
	}); err != nil {
		t.Fatalf("seed 192.168.1.10: %v", err)
	}

	// Device seen 70m ago: online under 30m scan interval (3*30m = 90m), offline under default 60m
	if err := s.UpdateDevice(&types.Device{
		IP:        "192.168.1.11",
		MAC:       "aa:bb:cc:77:77:02",
		Hostname:  "interval-box",
		FirstSeen: now.Add(-3 * time.Hour),
		LastSeen:  now.Add(-70 * time.Minute),
	}); err != nil {
		t.Fatalf("seed 192.168.1.11: %v", err)
	}

	// Device seen 4h ago, currently marked is_online = 1 in DB -> should transition to offline and log 'leave'
	if _, err := s.db.Exec(`
		INSERT INTO devices (ip, mac, hostname, first_seen, last_seen, is_online, last_presence_change)
		VALUES ('192.168.1.12', 'aa:bb:cc:77:77:03', 'stale-box', ?, ?, 1, ?)
	`, now.Add(-6*time.Hour), now.Add(-4*time.Hour), now.Add(-5*time.Hour)); err != nil {
		t.Fatalf("seed 192.168.1.12: %v", err)
	}

	// Reservations slice with extra capacity to catch in-place append mutation
	reservations := make([]types.Device, 1, 4)
	reservations[0] = types.Device{
		IP:           "192.168.1.20",
		MAC:          "aa:bb:cc:77:77:01", // same MAC as online 192.168.1.10
		Hostname:     "online-box-dhcp",
		RouterSource: "OPNsense",
	}
	resBacking := reservations[:cap(reservations)]
	resBacking[1] = types.Device{IP: "9.9.9.9", Hostname: "canary"}

	leases := []types.Device{
		{
			IP:           "192.168.1.30",
			MAC:          "aa:bb:cc:77:77:04", // brand-new offline DHCP-only device
			Hostname:     "new-dhcp-only",
			RouterSource: "OPNsense",
		},
	}

	if err := s.MergeRouterDHCP(leases, reservations); err != nil {
		t.Fatalf("MergeRouterDHCP: %v", err)
	}

	// 1. Caller's reservations backing array must NOT be mutated
	if resBacking[1].IP != "9.9.9.9" {
		t.Fatalf("MergeRouterDHCP mutated caller's reservations backing array: got %+v", resBacking[1])
	}

	// 2. Online device 192.168.1.10 must NOT have LastSeen regressed to now.Add(-65m)
	dev10 := s.GetDevice("192.168.1.10")
	if dev10 == nil {
		t.Fatalf("expected 192.168.1.10 to remain primary")
	}
	if time.Since(dev10.LastSeen) > 10*time.Minute {
		t.Fatalf("192.168.1.10 LastSeen regressed by DHCP merge: %v", dev10.LastSeen)
	}

	// 3. 192.168.1.11 (70m ago) must stay is_online = 1 under 30m scan interval
	var isOnline11 int
	if err := s.db.QueryRow(`SELECT is_online FROM devices WHERE ip = '192.168.1.11'`).Scan(&isOnline11); err != nil {
		t.Fatalf("query is_online 1.11: %v", err)
	}
	if isOnline11 != 1 {
		t.Fatalf("192.168.1.11 is_online = %d, want 1 under 30m scan interval", isOnline11)
	}

	// 4. 192.168.1.12 (4h ago, was is_online=1) must transition to 0 and log 'leave'
	var isOnline12 int
	if err := s.db.QueryRow(`SELECT is_online FROM devices WHERE ip = '192.168.1.12'`).Scan(&isOnline12); err != nil {
		t.Fatalf("query is_online 1.12: %v", err)
	}
	if isOnline12 != 0 {
		t.Fatalf("192.168.1.12 is_online = %d, want 0", isOnline12)
	}
	var leaveCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM device_presence_history WHERE ip = '192.168.1.12' AND event = 'leave'`).Scan(&leaveCount); err != nil {
		t.Fatalf("count leave: %v", err)
	}
	if leaveCount != 1 {
		t.Fatalf("expected 1 'leave' event for 192.168.1.12, got %d", leaveCount)
	}

	// 5. Brand-new DHCP-only device 192.168.1.30 must be offline in BOTH DB and IsOnline(scanInterval)
	var isOnline30 int
	if err := s.db.QueryRow(`SELECT is_online FROM devices WHERE ip = '192.168.1.30'`).Scan(&isOnline30); err != nil {
		t.Fatalf("query is_online 1.30: %v", err)
	}
	if isOnline30 != 0 {
		t.Fatalf("new DHCP-only device is_online = %d, want 0", isOnline30)
	}
	dev30 := s.GetDevice("192.168.1.30")
	if dev30 == nil || dev30.IsOnline(s.GetScanInterval()) {
		t.Fatalf("new DHCP-only device must not report IsOnline(scanInterval) == true: %+v", dev30)
	}
}

func TestMergeUniFiClients_RelocationMigratesHistoryPortsIPsAndChecksNotifyOnSeen(t *testing.T) {
	s := newTestStorage(t)
	s.SetNetworkNames(map[string]string{
		"192.168.1.0/24":  "Home LAN",
		"192.168.20.0/24": "IoT LAN",
	})

	now := time.Now()
	if _, err := s.db.Exec(`
		INSERT INTO devices (
			ip, mac, hostname, network_name, first_seen, last_seen, is_online, last_presence_change, notify_on_seen, ips
		) VALUES (
			'192.168.1.80', 'aa:bb:cc:88:88:01', 'wifi-client', 'Home LAN', ?, ?, 0, ?, 1,
			'[{"ip":"192.168.1.80","network_name":"Home LAN","is_active":true}]'
		)
	`, now.Add(-2*time.Hour), now.Add(-90*time.Minute), now.Add(-90*time.Minute)); err != nil {
		t.Fatalf("seed wifi-client: %v", err)
	}
	if _, err := s.db.Exec(`
		INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
		VALUES ('192.168.1.80', 'aa:bb:cc:88:88:01', 'wifi-client', 'join', 0, ?)
	`, now.Add(-2*time.Hour)); err != nil {
		t.Fatalf("seed presence: %v", err)
	}
	if err := s.UpdateOpenPorts("192.168.1.80", []int{22}, []types.OpenService{{Port: 22, Name: "ssh"}}); err != nil {
		t.Fatalf("seed open ports: %v", err)
	}

	// Relocate via UniFi with mixed-case/hyphenated MAC to 192.168.20.80
	_, seen, err := s.MergeUniFiClients([]types.Device{
		{
			IP:   "192.168.20.80",
			MAC:  "AA-BB-CC-88-88-01",
			SSID: "IoT-WiFi",
		},
	})
	if err != nil {
		t.Fatalf("MergeUniFiClients: %v", err)
	}
	if len(seen) != 1 || seen[0].IP != "192.168.20.80" {
		t.Fatalf("expected 1 seenDevice at 192.168.20.80, got %+v", seen)
	}

	relocated := s.GetDevice("192.168.20.80")
	if relocated == nil {
		t.Fatalf("expected relocated device at 192.168.20.80")
	}
	if relocated.NetworkName != "IoT LAN" {
		t.Errorf("relocated NetworkName = %q, want 'IoT LAN'", relocated.NetworkName)
	}
	if len(relocated.OpenPorts) != 1 || relocated.OpenPorts[0] != 22 {
		t.Errorf("expected open port 22 migrated to 192.168.20.80, got %+v", relocated.OpenPorts)
	}
	hasNewIP, hasOldIP := false, false
	for _, att := range relocated.IPs {
		if att.IP == "192.168.20.80" {
			hasNewIP = true
		}
		if att.IP == "192.168.1.80" {
			hasOldIP = true
		}
	}
	if !hasNewIP || hasOldIP {
		t.Errorf("expected relocated.IPs to replace 192.168.1.80 with 192.168.20.80, got %+v", relocated.IPs)
	}

	var presCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM device_presence_history WHERE ip = '192.168.20.80'`).Scan(&presCount); err != nil {
		t.Fatalf("count migrated presence: %v", err)
	}
	if presCount < 2 {
		t.Errorf("expected original 'join' + new 'return' at 192.168.20.80 (count >= 2), got %d", presCount)
	}
}

func TestUpdateDevice_SSHOverrideConflict_GetStatsInterval_SetLastDuration_SetNetworkNamesClone(t *testing.T) {
	s := newTestStorage(t)
	s.SetScanInterval(1800) // 30m -> 90m online threshold

	// 1. UpdateDevice ON CONFLICT must update ssh_override and ssh_override_port
	now := time.Now()
	if err := s.UpdateDevice(&types.Device{
		IP:        "10.88.0.10",
		MAC:       "00:11:22:33:44:88",
		Hostname:  "ssh-host",
		FirstSeen: now.Add(-2 * time.Hour),
		LastSeen:  now.Add(-75 * time.Minute), // online under 30m scan interval (90m), offline under 60m
		Group:     "Infra",
	}); err != nil {
		t.Fatalf("initial UpdateDevice: %v", err)
	}
	if err := s.UpdateDevice(&types.Device{
		IP:              "10.88.0.10",
		MAC:             "00:11:22:33:44:88",
		Hostname:        "ssh-host",
		FirstSeen:       now.Add(-2 * time.Hour),
		LastSeen:        now.Add(-75 * time.Minute),
		Group:           "Infra",
		SSHOverride:     "force_on",
		SSHOverridePort: 2222,
	}); err != nil {
		t.Fatalf("conflict UpdateDevice: %v", err)
	}
	got := s.GetDevice("10.88.0.10")
	if got == nil || got.SSHOverride != "force_on" || got.SSHOverridePort != 2222 {
		t.Fatalf("UpdateDevice ON CONFLICT dropped ssh_override*: %+v", got)
	}

	// 2. GetStats must use s.GetScanInterval()
	stats := s.GetStats()
	if stats.Online != 1 || stats.Offline != 0 {
		t.Fatalf("GetStats() = %+v, want Online=1 Offline=0 under 30m scan interval", stats)
	}

	// 3. SetLastDuration before SetLastScan must not insert zero time.Time{}
	if err := s.SetLastDuration("10.88.0.0/24", 4.25); err != nil {
		t.Fatalf("SetLastDuration: %v", err)
	}
	if dur := s.GetLastDuration("10.88.0.0/24"); dur != 4.25 {
		t.Fatalf("GetLastDuration = %v, want 4.25", dur)
	}
	if last := s.GetLastScan("10.88.0.0/24"); last.Year() <= 1 {
		t.Fatalf("SetLastDuration inserted zero/year-1 timestamp into scan_state: %v", last)
	}

	// 4. SetNetworkNames must clone the caller's map
	nets := map[string]string{"10.88.0.0/24": "Original Net"}
	s.SetNetworkNames(nets)
	nets["10.88.0.0/24"] = "Mutated Net"
	if _, _, err := s.MergeDevices([]types.Device{{IP: "10.88.0.20", MAC: "00:11:22:33:44:89"}}); err != nil {
		t.Fatalf("MergeDevices: %v", err)
	}
	d20 := s.GetDevice("10.88.0.20")
	if d20 == nil || d20.NetworkName != "Original Net" {
		t.Fatalf("SetNetworkNames did not clone caller map: got %q, want 'Original Net'", d20.NetworkName)
	}
}

func TestStorage_DeviceLifecycleStatsAndCounts(t *testing.T) {
	s := newTestStorage(t)
	s.SetScanInterval(600) // 10m -> online threshold 30m

	now := time.Now()
	seed := []types.Device{
		{IP: "10.0.0.1", MAC: "00:11:22:33:44:01", Hostname: "gw", NetworkName: "Core", Group: "Infra", FirstSeen: now.Add(-2 * time.Hour), LastSeen: now.Add(-5 * time.Minute)},
		{IP: "10.0.0.2", MAC: "00:11:22:33:44:02", Hostname: "nas", NetworkName: "Core", Group: "Storage", FirstSeen: now.Add(-5 * time.Minute), LastSeen: now.Add(-2 * time.Minute)},
		{IP: "10.0.1.10", MAC: "00:11:22:33:44:03", Hostname: "iot", NetworkName: "IoT", Group: "Infra", FirstSeen: now.Add(-3 * time.Minute), LastSeen: now.Add(-2 * time.Hour)},
	}
	for i := range seed {
		if err := s.UpdateDevice(&seed[i]); err != nil {
			t.Fatalf("seed %s: %v", seed[i].IP, err)
		}
	}

	// GetStats: 2 online (10.0.0.1, 10.0.0.2), 1 offline (10.0.1.10), Groups: Infra=2, Storage=1
	stats := s.GetStats()
	if stats.Total != 3 || stats.Online != 2 || stats.Offline != 1 || stats.Groups["Infra"] != 2 || stats.Groups["Storage"] != 1 {
		t.Fatalf("unexpected GetStats(): %+v", stats)
	}

	// GetNewDevicesCount
	if got := s.GetNewDevicesCount(now.Add(-10 * time.Minute)); got != 2 {
		t.Fatalf("GetNewDevicesCount(-10m) = %d, want 2", got)
	}

	// UpdateDeviceCustomOSByIP
	if err := s.UpdateDeviceCustomOSByIP("", "Linux", "24.04", "Ubuntu"); err == nil {
		t.Fatal("UpdateDeviceCustomOSByIP('') expected error")
	}
	if err := s.UpdateDeviceCustomOSByIP("10.0.0.99", "Linux", "24.04", "Ubuntu"); err == nil {
		t.Fatal("UpdateDeviceCustomOSByIP(missing) expected error")
	}
	if err := s.UpdateDeviceCustomOSByIP("10.0.0.2", "TrueNAS SCALE", "24.10", "Linux"); err != nil {
		t.Fatalf("UpdateDeviceCustomOSByIP: %v", err)
	}
	d2 := s.GetDevice("10.0.0.2")
	if d2 == nil || d2.CustomOS != "TrueNAS SCALE" || d2.CustomOSVersion != "24.10" || d2.CustomOSFamily != "Linux" {
		t.Fatalf("unexpected custom OS fields: %+v", d2)
	}

	// UpdateDeviceMAC (with and without vendor, error on empty MAC)
	if err := s.UpdateDeviceMAC("10.0.0.2", "", "Vendor"); err == nil {
		t.Fatal("UpdateDeviceMAC('') expected error")
	}
	if err := s.UpdateDeviceMAC("10.0.0.2", "AA-BB-CC-DD-EE-02", "iXsystems"); err != nil {
		t.Fatalf("UpdateDeviceMAC with vendor: %v", err)
	}
	d2 = s.GetDevice("10.0.0.2")
	if d2.MAC != "aa:bb:cc:dd:ee:02" || d2.Vendor != "iXsystems" {
		t.Fatalf("unexpected MAC/Vendor after UpdateDeviceMAC: %q / %q", d2.MAC, d2.Vendor)
	}
	if err := s.UpdateDeviceMAC("10.0.0.2", "AA:BB:CC:DD:EE:99", ""); err != nil {
		t.Fatalf("UpdateDeviceMAC without vendor: %v", err)
	}
	d2 = s.GetDevice("10.0.0.2")
	if d2.MAC != "aa:bb:cc:dd:ee:99" || d2.Vendor != "iXsystems" {
		t.Fatalf("UpdateDeviceMAC without vendor cleared vendor or missed MAC: %q / %q", d2.MAC, d2.Vendor)
	}

	// DeleteDevice (success and not found)
	if err := s.DeleteDevice("10.0.0.1"); err != nil {
		t.Fatalf("DeleteDevice(10.0.0.1): %v", err)
	}
	if s.GetDevice("10.0.0.1") != nil {
		t.Fatal("10.0.0.1 still present after DeleteDevice")
	}
	if err := s.DeleteDevice("10.0.0.1"); err == nil {
		t.Fatal("DeleteDevice(missing) expected error")
	}

	// ClearDevices by network name (case-insensitive) and "all"
	cleared, err := s.ClearDevices("core")
	if err != nil {
		t.Fatalf("ClearDevices('core'): %v", err)
	}
	if cleared != 1 {
		t.Fatalf("ClearDevices('core') = %d, want 1", cleared)
	}
	if s.GetDevice("10.0.0.2") != nil || s.GetDevice("10.0.1.10") == nil {
		t.Fatal("ClearDevices('core') did not remove only Core devices")
	}
	clearedAll, err := s.ClearDevices("all")
	if err != nil {
		t.Fatalf("ClearDevices('all'): %v", err)
	}
	if clearedAll != 1 || len(s.GetDevices()) != 0 {
		t.Fatalf("ClearDevices('all') = %d, remaining=%d", clearedAll, len(s.GetDevices()))
	}

	// Verify MergeDevicesWithMoves preserves full device fields (e.g. DetectedSSHPort, CustomOS)
	// when a previously offline device returns and notifies, and GetDeviceByMAC matches GetDevice for linked children.
	parentDev := types.Device{
		IP:             "10.10.0.10",
		MAC:            "aa:bb:cc:77:88:01",
		Hostname:       "parent-box",
		Vendor:         "ParentVendor",
		Type:           "Server",
		FirstSeen:      now.Add(-2 * time.Hour),
		LastSeen:       now.Add(-5 * time.Minute),
		NotifyOnSeen:   true,
		AnsibleManaged: true,
	}
	childDev := types.Device{
		IP:              "10.10.0.11",
		MAC:             "aa:bb:cc:77:88:02",
		Hostname:        "child-nic",
		Vendor:          "ChildVendor",
		Type:            "VM",
		LinkedMAC:       "aa:bb:cc:77:88:01",
		DetectedSSHPort: 2222,
		CustomOS:        "Debian",
		FirstSeen:       now.Add(-2 * time.Hour),
		LastSeen:        now.Add(-2 * time.Hour),
	}
	if err := s.UpdateDevice(&parentDev); err != nil {
		t.Fatalf("UpdateDevice(parent): %v", err)
	}
	if err := s.UpdateDevice(&childDev); err != nil {
		t.Fatalf("UpdateDevice(child): %v", err)
	}
	// Mark child offline so MergeDevicesWithMoves emits it in seenDevices when parent NotifyOnSeen=true or child returns.
	if _, err := s.db.Exec("UPDATE devices SET is_online = 0, notify_on_seen = 1 WHERE ip = ?", childDev.IP); err != nil {
		t.Fatalf("mark child offline: %v", err)
	}
	_, seen, _, err := s.MergeDevicesWithMoves([]types.Device{{
		IP:  childDev.IP,
		MAC: childDev.MAC,
	}})
	if err != nil {
		t.Fatalf("MergeDevicesWithMoves(child return): %v", err)
	}
	if len(seen) != 1 || seen[0].DetectedSSHPort != 2222 || seen[0].CustomOS != "Debian" {
		t.Fatalf("MergeDevicesWithMoves lost full device columns on seen device: %+v", seen)
	}

	byIP := s.GetDevice(childDev.IP)
	byMAC := s.GetDeviceByMAC(childDev.MAC)
	if byIP == nil || byMAC == nil {
		t.Fatalf("expected child via GetDevice and GetDeviceByMAC, got %v / %v", byIP, byMAC)
	}
	if byMAC.Hostname != byIP.Hostname || byMAC.Vendor != byIP.Vendor || byMAC.Type != byIP.Type {
		t.Fatalf("GetDeviceByMAC mismatch vs GetDevice: MAC=(%q,%q,%q) IP=(%q,%q,%q)",
			byMAC.Hostname, byMAC.Vendor, byMAC.Type, byIP.Hostname, byIP.Vendor, byIP.Type)
	}
}

func TestStorage_NetworkNotificationsAndDurations(t *testing.T) {
	s := newTestStorage(t)

	// Missing duration returns 0.0; updating existing scan_state updates duration
	if got := s.GetLastDuration("10.99.0.0/24"); got != 0.0 {
		t.Fatalf("GetLastDuration(missing) = %v, want 0", got)
	}
	if err := s.SetLastScan("10.99.0.0/24", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("SetLastScan: %v", err)
	}
	if err := s.SetLastDuration("10.99.0.0/24", 12.5); err != nil {
		t.Fatalf("SetLastDuration(update): %v", err)
	}
	if got := s.GetLastDuration("10.99.0.0/24"); got != 12.5 {
		t.Fatalf("GetLastDuration(updated) = %v, want 12.5", got)
	}

	// Network notifications CRUD
	missing, err := s.GetNetworkNotification("10.99.0.0/24")
	if err != nil || missing != nil {
		t.Fatalf("GetNetworkNotification(missing) = (%v, %v), want (nil, nil)", missing, err)
	}
	if err := s.SaveNetworkNotification("10.99.0.0/24", "https://hooks.slack.com/services/A/B/C", true); err != nil {
		t.Fatalf("SaveNetworkNotification insert: %v", err)
	}
	if err := s.SaveNetworkNotification("10.99.0.0/24", "https://hooks.slack.com/services/X/Y/Z", false); err != nil {
		t.Fatalf("SaveNetworkNotification upsert: %v", err)
	}
	got, err := s.GetNetworkNotification("10.99.0.0/24")
	if err != nil || got == nil {
		t.Fatalf("GetNetworkNotification: (%v, %v)", got, err)
	}
	if got.SlackWebhook != "https://hooks.slack.com/services/X/Y/Z" || got.Enabled {
		t.Fatalf("unexpected GetNetworkNotification result: %+v", got)
	}
	all, err := s.GetNetworkNotifications()
	if err != nil || len(all) != 1 {
		t.Fatalf("GetNetworkNotifications = (%+v, %v), want 1 item", all, err)
	}

	// Verify 00021_add_performance_indexes.sql created all 6 performance indexes.
	expectedIndexes := []string{
		"idx_devices_mac",
		"idx_devices_linked_mac",
		"idx_devices_is_online",
		"idx_presence_ip_created",
		"idx_presence_mac_created",
		"idx_scan_history_timestamp",
	}
	for _, idxName := range expectedIndexes {
		var name string
		err := s.db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`, idxName).Scan(&name)
		if err != nil || name != idxName {
			t.Fatalf("expected index %s in sqlite_master, got (%q, %v)", idxName, name, err)
		}
	}

	// Verify cached longest-prefix CIDR resolution in SetNetworkNames / inSameSubnetLocked.
	s.SetNetworkNames(map[string]string{
		"10.20.0.0/16": "Supernet",
		"10.20.5.0/24": "Specific Subnet",
	})
	s.mu.RLock()
	if len(s.networkCIDRs) != 2 {
		s.mu.RUnlock()
		t.Fatalf("expected 2 cached networkCIDRs, got %d", len(s.networkCIDRs))
	}
	if got := s.resolveNetworkNameLocked("10.20.5.42"); got != "Specific Subnet" {
		s.mu.RUnlock()
		t.Fatalf("resolveNetworkNameLocked(10.20.5.42) = %q, want Specific Subnet", got)
	}
	if got := s.resolveNetworkNameLocked("10.20.9.42"); got != "Supernet" {
		s.mu.RUnlock()
		t.Fatalf("resolveNetworkNameLocked(10.20.9.42) = %q, want Supernet", got)
	}
	if !s.inSameSubnetLocked("10.20.5.10", "10.20.5.20") {
		s.mu.RUnlock()
		t.Fatal("inSameSubnetLocked(10.20.5.10, 10.20.5.20) = false, want true")
	}
	if s.inSameSubnetLocked("10.20.5.10", "172.16.0.10") {
		s.mu.RUnlock()
		t.Fatal("inSameSubnetLocked(10.20.5.10, 172.16.0.10) = true, want false")
	}
	s.mu.RUnlock()
}

func TestStorage_MigrateLegacyJSON(t *testing.T) {
	dir := t.TempDir()
	devicesPath := filepath.Join(dir, "devices.json")
	statePath := filepath.Join(dir, "state.json")

	now := time.Now().UTC().Truncate(time.Second)
	legacyDevices := map[string]types.Device{
		"192.168.50.10": {
			IP:          "192.168.50.10",
			MAC:         "00:11:22:33:50:10",
			Hostname:    "legacy-host",
			NetworkName: "Legacy LAN",
			FirstSeen:   now.Add(-time.Hour),
			LastSeen:    now,
			WebUI:       true,
		},
	}
	devBytes, err := json.Marshal(legacyDevices)
	if err != nil {
		t.Fatalf("marshal devices.json: %v", err)
	}
	if err := os.WriteFile(devicesPath, devBytes, 0600); err != nil {
		t.Fatalf("write devices.json: %v", err)
	}

	cont := true
	legacyState := types.ScanState{
		LastScan:       map[string]time.Time{"192.168.50.0/24": now.Add(-5 * time.Minute)},
		LastDuration:   map[string]float64{"192.168.50.0/24": 3.75},
		ContinuousScan: &cont,
	}
	stateBytes, err := json.Marshal(legacyState)
	if err != nil {
		t.Fatalf("marshal state.json: %v", err)
	}
	if err := os.WriteFile(statePath, stateBytes, 0600); err != nil {
		t.Fatalf("write state.json: %v", err)
	}

	s, err := New(devicesPath, statePath)
	if err != nil {
		t.Fatalf("New with legacy JSON: %v", err)
	}
	defer s.Close()

	d := s.GetDevice("192.168.50.10")
	if d == nil || d.Hostname != "legacy-host" || !d.WebUI {
		t.Fatalf("migrated device mismatch: %+v", d)
	}
	if dur := s.GetLastDuration("192.168.50.0/24"); dur != 3.75 {
		t.Fatalf("migrated last_duration = %v, want 3.75", dur)
	}
	if s.GetLastScan("192.168.50.0/24").IsZero() {
		t.Fatal("migrated last_scan is zero")
	}
	if !s.ContinuousScanEnabled(false) {
		t.Fatal("migrated ContinuousScanEnabled(false) = false, want true")
	}
	if _, err := os.Stat(devicesPath + ".bak"); err != nil {
		t.Fatalf("expected devices.json.bak: %v", err)
	}
	if _, err := os.Stat(statePath + ".bak"); err != nil {
		t.Fatalf("expected state.json.bak: %v", err)
	}
}
