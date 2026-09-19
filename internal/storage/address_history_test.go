package storage

import (
	"testing"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// TestDeviceMovingIPIsTrackedByMAC covers a device that reappears at a new IP:
// it is recognised by its MAC, its identity and user data move with it, the
// stale entry is removed, and the change is recorded.
func TestDeviceMovingIPIsTrackedByMAC(t *testing.T) {
	s := newTestStorage(t)

	// First seen at .10, with user data and a type.
	if err := s.MergeDevices([]types.Device{
		{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "nas", Type: "Server"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateDeviceFields("192.168.1.10", strptr("File Server"), strptr("rack 1"), strptr("Infra"), nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	// Same MAC reappears at .25.
	if err := s.MergeDevices([]types.Device{
		{IP: "192.168.1.25", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "nas"},
	}); err != nil {
		t.Fatal(err)
	}

	devices := s.GetDevices()
	if _, stale := devices["192.168.1.10"]; stale {
		t.Error("the old IP entry should be removed after the device moved")
	}
	moved := devices["192.168.1.25"]
	if moved == nil {
		t.Fatal("the device should now be at the new IP")
	}
	if moved.Label != "File Server" || moved.Notes != "rack 1" || moved.Group != "Infra" {
		t.Errorf("user data did not move with the device: %+v", moved)
	}
	if moved.Type != "Server" {
		t.Errorf("type should carry over, got %q", moved.Type)
	}
	if len(moved.AddressHistory) != 1 || moved.AddressHistory[0].IP != "192.168.1.10" {
		t.Errorf("address change not recorded: %+v", moved.AddressHistory)
	}
	if moved.AddressHistory[0].ChangedAt.IsZero() {
		t.Error("the change should carry a timestamp")
	}
}

// TestDifferentMACsAreDistinctDevices confirms two devices with different MACs
// at different IPs are not confused for a move.
func TestDifferentMACsAreDistinctDevices(t *testing.T) {
	s := newTestStorage(t)
	_ = s.MergeDevices([]types.Device{{IP: "192.168.1.10", MAC: "aa:aa:aa:aa:aa:aa"}})
	_ = s.MergeDevices([]types.Device{{IP: "192.168.1.11", MAC: "bb:bb:bb:bb:bb:bb"}})

	devices := s.GetDevices()
	if len(devices) != 2 {
		t.Fatalf("expected two distinct devices, got %d", len(devices))
	}
	if len(devices["192.168.1.11"].AddressHistory) != 0 {
		t.Error("a distinct device should have no address history")
	}
}

func strptr(s string) *string { return &s }

// TestSupplementalMergeDoesNotClobber confirms a secondary source (mDNS/IPv6)
// fills gaps but never erases a MAC, vendor, or probe result the primary scan
// established.
func TestSupplementalMergeDoesNotClobber(t *testing.T) {
	s := newTestStorage(t)

	// Primary scan: full device with MAC, vendor, web flag and a risk.
	if err := s.MergeDevices([]types.Device{{
		IP: "192.168.1.5", MAC: "aa:bb:cc:dd:ee:ff", Vendor: "Acme",
		Type: "Server", WebUI: true, Risks: []string{"Telnet is open"},
	}}); err != nil {
		t.Fatal(err)
	}

	// mDNS supplements the same IP: a friendly name, but no MAC, no probe data.
	if err := s.MergeSupplemental([]types.Device{{
		IP: "192.168.1.5", Hostname: "fileserver",
	}}); err != nil {
		t.Fatal(err)
	}

	d := s.GetDevice("192.168.1.5")
	if d == nil {
		t.Fatal("device vanished")
	}
	if d.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC was clobbered: %q", d.MAC)
	}
	if d.Vendor != "Acme" {
		t.Errorf("vendor was clobbered: %q", d.Vendor)
	}
	if !d.WebUI || len(d.Risks) != 1 {
		t.Errorf("probe fields were clobbered: WebUI=%v Risks=%v", d.WebUI, d.Risks)
	}
	if d.Hostname != "fileserver" {
		t.Errorf("supplemental hostname not filled in: %q", d.Hostname)
	}
}

// TestVirtualIPCoexistenceSameMAC confirms that when two virtual IPs share the
// same MAC address and are discovered simultaneously in the same scan, they both
// coexist cleanly in the database without deleting each other or triggering the moved state.
func TestVirtualIPCoexistenceSameMAC(t *testing.T) {
	s := newTestStorage(t)

	// Simultaneously discover .10 and .20 sharing the same MAC.
	if err := s.MergeDevices([]types.Device{
		{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "server1", Type: "Server"},
		{IP: "192.168.1.20", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "server2", Type: "Server"},
	}); err != nil {
		t.Fatal(err)
	}

	devices := s.GetDevices()
	if len(devices) != 2 {
		t.Fatalf("expected two coexisting devices, got %d", len(devices))
	}

	dev10 := devices["192.168.1.10"]
	dev20 := devices["192.168.1.20"]

	if dev10 == nil || dev20 == nil {
		t.Fatal("both IPs should exist in the database simultaneously")
	}

	if len(dev10.AddressHistory) != 0 || len(dev20.AddressHistory) != 0 {
		t.Error("neither device should trigger an address move history record")
	}
}

// TestVirtualIPCoexistenceSweepAndPortScan confirms that coexisting virtual IPs
// on the same MAC are not deleted or recorded as moved, even when Stage 2
// individual port scan saves are performed.
func TestVirtualIPCoexistenceSweepAndPortScan(t *testing.T) {
	s := newTestStorage(t)

	// Step 1: Simulate Stage 1 Sweep (both discovered simultaneously)
	if err := s.MergeDevices([]types.Device{
		{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "server1", Type: "Server"},
		{IP: "192.168.1.20", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "server2", Type: "Server"},
	}); err != nil {
		t.Fatal(err)
	}

	// Verify both exist with clean address history
	devices := s.GetDevices()
	if len(devices) != 2 {
		t.Fatalf("expected 2 coexisting devices, got %d", len(devices))
	}

	// Step 2: Simulate Stage 2 individual port scan save on .20
	// This is where the old code used to delete .10 and record a false relocation!
	d20 := *devices["192.168.1.20"]
	d20.WebUI = true
	if err := s.MergeDevices([]types.Device{d20}); err != nil {
		t.Fatal(err)
	}

	// Step 3: Verify coexistence persists completely
	devices = s.GetDevices()
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices after port scan, got %d. Coexisting IP was deleted!", len(devices))
	}

	dev10 := devices["192.168.1.10"]
	dev20 := devices["192.168.1.20"]

	if len(dev10.AddressHistory) != 0 || len(dev20.AddressHistory) != 0 {
		t.Errorf("expected 0 address history records, got dev10=%v, dev20=%v", dev10.AddressHistory, dev20.AddressHistory)
	}
}

// TestVirtualIPCoexistenceCrossSubnet replicates a sequential multi-subnet scan:
// Subnet A is scanned (discovering only IP A), then Subnet B is scanned (discovering only IP B).
// Both virtual IPs share the same MAC and must coexist cleanly without any deletions or move history.
func TestVirtualIPCoexistenceCrossSubnet(t *testing.T) {
	s := newTestStorage(t)

	// Step 1: Declare two configured subnets
	s.SetNetworkNames(map[string]string{
		"10.0.0.0/24":    "LAN",
		"192.168.1.0/24": "Tailscale",
	})

	// Step 2: Scan Subnet A (discovers only .10)
	if err := s.MergeDevices([]types.Device{
		{IP: "10.0.0.10", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "server-lan", Type: "Server"},
	}); err != nil {
		t.Fatal(err)
	}

	// Step 3: Scan Subnet B (discovers only .20 on the same MAC)
	// This is the sequential cross-subnet sweep!
	if err := s.MergeDevices([]types.Device{
		{IP: "192.168.1.20", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "server-vpn", Type: "Server"},
	}); err != nil {
		t.Fatal(err)
	}

	// Step 4: Verify both coexist with zero history after the cross-subnet scan
	devices := s.GetDevices()
	if len(devices) != 2 {
		t.Fatalf("expected 2 coexisting devices, got %d. Cross-subnet IP was deleted!", len(devices))
	}

	devA := devices["10.0.0.10"]
	devB := devices["192.168.1.20"]

	if devA == nil || devB == nil {
		t.Fatal("both IPs must exist in the database simultaneously")
	}

	if len(devA.AddressHistory) != 0 || len(devB.AddressHistory) != 0 {
		t.Errorf("expected 0 address history records, got devA=%v, devB=%v", devA.AddressHistory, devB.AddressHistory)
	}
}
