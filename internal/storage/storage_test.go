package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// newTestStorage returns storage backed by a throwaway directory.
func newTestStorage(t *testing.T) *Storage {
	t.Helper()

	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
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

	if got := second.GetMostRecentScan(); !got.Equal(when) {
		t.Errorf("after reload GetMostRecentScan() = %v, want %v", got, when)
	}
}

func TestContinuousScanDefaultsToConfigWhenUnset(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
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
	// User turns continuous scanning off even though config defaults it on.
	if err := first.SetContinuousScan(false); err != nil {
		t.Fatal(err)
	}

	second, err := New(devices, state)
	if err != nil {
		t.Fatal(err)
	}
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
	if err := s.UpdateDeviceFields(parentIP, &labelVal, &notesVal, nil, nil, nil, nil, nil, nil); err != nil {
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
	if err := s.UpdateDeviceFields(childIP, nil, nil, nil, nil, nil, nil, &parentMAC, nil); err != nil {
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

func mergeDevicesForTest(s *Storage, discovered []types.Device) error {
	_, _, err := s.MergeDevices(discovered)
	return err
}
