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

func TestMergeUniFiClients(t *testing.T) {
	s := newTestStorage(t)
	s.SetNetworkNames(map[string]string{"192.168.1.0/24": "Home LAN"})

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

	if err := s.MergeUniFiClients([]types.Device{client}); err != nil {
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
	if err := s.MergeUniFiClients([]types.Device{ipClient}); err != nil {
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
	if err := s.MergeUniFiClients([]types.Device{newClient}); err != nil {
		t.Fatalf("MergeUniFiClients new device: %v", err)
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
	if err := s.MergeUniFiClients([]types.Device{}); err != nil {
		t.Fatalf("MergeUniFiClients with empty list: %v", err)
	}

	// 5. Client with no IP and no MAC is skipped
	if err := s.MergeUniFiClients([]types.Device{{}}); err != nil {
		t.Fatalf("MergeUniFiClients with blank device: %v", err)
	}

	// 6. Device moves IP: MAC matched, moves to free IP, records address history
	movingClient := types.Device{
		IP:     "192.168.1.205",
		MAC:    "AA:BB:CC:DD:EE:02", // same MAC as 192.168.1.200
		SSID:   "IoT-WiFi-Moved",
		APName: "Garage AP",
	}
	if err := s.MergeUniFiClients([]types.Device{movingClient}); err != nil {
		t.Fatalf("MergeUniFiClients moving IP: %v", err)
	}
	moved := s.GetDevice("192.168.1.205")
	if moved == nil {
		t.Fatalf("expected device at 192.168.1.205, got nil")
	}
	if moved.SSID != "IoT-WiFi-Moved" {
		t.Errorf("SSID = %q, want %q", moved.SSID, "IoT-WiFi-Moved")
	}
	if len(moved.AddressHistory) == 0 {
		t.Errorf("expected address history recorded for moved device, got none")
	} else if moved.AddressHistory[0].IP != "192.168.1.200" {
		t.Errorf("address history old IP = %q, want %q", moved.AddressHistory[0].IP, "192.168.1.200")
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

