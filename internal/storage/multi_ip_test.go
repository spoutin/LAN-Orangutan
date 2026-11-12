package storage

import (
	"testing"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

func TestMultiIPSameNetworkCoexistence(t *testing.T) {
	s := newTestStorage(t)

	s.SetNetworkNames(map[string]string{
		"10.0.0.0/24": "Home LAN",
	})

	// 1. Initial discovery of .10
	dev10 := types.Device{
		IP:             "10.0.0.10",
		MAC:            "aa:bb:cc:dd:ee:ff",
		Hostname:       "my-server",
		CustomHostname: "nas-custom",
		Label:          "Main Storage",
	}
	newDevs, _, err := s.MergeDevices([]types.Device{dev10})
	if err != nil {
		t.Fatalf("failed to merge dev10: %v", err)
	}
	if len(newDevs) != 1 {
		t.Errorf("expected 1 new device on first discovery, got %d", len(newDevs))
	}

	// 2. Discover .20 on the same MAC and network (both .10 and .20 active in sweep)
	dev20 := types.Device{
		IP:       "10.0.0.20",
		MAC:      "aa:bb:cc:dd:ee:ff",
		Hostname: "my-server-vip",
	}
	newDevs2, _, err := s.MergeDevices([]types.Device{dev10, dev20})
	if err != nil {
		t.Fatalf("failed to merge dev20: %v", err)
	}

	// Crucial: Must NOT send new device notification!
	if len(newDevs2) != 0 {
		t.Errorf("expected 0 new devices when existing MAC gets a second IP, got %d", len(newDevs2))
	}

	// 3. Exactly 1 unified device in database
	devices := s.GetDevices()
	if len(devices) != 1 {
		t.Fatalf("expected 1 unified device in database, got %d", len(devices))
	}

	var d *types.Device
	for _, dev := range devices {
		d = dev
		break
	}

	// User overrides preserved
	if d.CustomHostname != "nas-custom" || d.Label != "Main Storage" {
		t.Errorf("user overrides lost: %+v", d)
	}

	// Active IPs list must contain both .10 and .20
	if len(d.IPs) < 2 {
		t.Fatalf("expected at least 2 attached IPs in d.IPs, got %d: %+v", len(d.IPs), d.IPs)
	}

	has10 := false
	has20 := false
	for _, att := range d.IPs {
		if att.IP == "10.0.0.10" && att.NetworkName == "Home LAN" {
			has10 = true
		}
		if att.IP == "10.0.0.20" && att.NetworkName == "Home LAN" {
			has20 = true
		}
	}
	if !has10 || !has20 {
		t.Errorf("expected both 10.0.0.10 and 10.0.0.20 in d.IPs, got %+v", d.IPs)
	}
}

func TestMultiIPCrossNetworkCoexistence(t *testing.T) {
	s := newTestStorage(t)

	s.SetNetworkNames(map[string]string{
		"10.0.0.0/24":    "Home LAN",
		"192.168.1.0/24": "Tailscale",
	})

	// 1. Discover on Home LAN
	devLAN := types.Device{
		IP:       "10.0.0.10",
		MAC:      "aa:bb:cc:dd:ee:ff",
		Hostname: "gateway-lan",
		Vendor:   "Protectli",
	}
	if _, _, err := s.MergeDevices([]types.Device{devLAN}); err != nil {
		t.Fatalf("failed to merge devLAN: %v", err)
	}

	// 2. Discover on Tailscale
	devTailscale := types.Device{
		IP:       "192.168.1.10",
		MAC:      "aa:bb:cc:dd:ee:ff",
		Hostname: "gateway-vpn",
	}
	newDevs, _, err := s.MergeDevices([]types.Device{devTailscale})
	if err != nil {
		t.Fatalf("failed to merge devTailscale: %v", err)
	}

	// Must NOT report new device
	if len(newDevs) != 0 {
		t.Errorf("expected 0 new devices for cross-subnet attachment on known MAC, got %d", len(newDevs))
	}

	devices := s.GetDevices()
	if len(devices) != 1 {
		t.Fatalf("expected 1 unified device, got %d", len(devices))
	}

	var d *types.Device
	for _, dev := range devices {
		d = dev
		break
	}

	if len(d.IPs) < 2 {
		t.Fatalf("expected at least 2 attached IPs, got %d: %+v", len(d.IPs), d.IPs)
	}

	hasLAN := false
	hasTailscale := false
	for _, att := range d.IPs {
		if att.IP == "10.0.0.10" && att.NetworkName == "Home LAN" {
			hasLAN = true
		}
		if att.IP == "192.168.1.10" && att.NetworkName == "Tailscale" {
			hasTailscale = true
		}
	}
	if !hasLAN || !hasTailscale {
		t.Errorf("expected both Home LAN and Tailscale attachments, got %+v", d.IPs)
	}
}

func TestMultiIPAttachedSecondaryIPsNotDuplicated(t *testing.T) {
	s := newTestStorage(t)

	// 1. Initial router device at 10.0.4.1 with attached VIPs on other subnets
	devRouter := types.Device{
		IP:       "10.0.4.1",
		MAC:      "aa:bb:cc:dd:ee:01",
		Hostname: "router-gateway",
		IPs: []types.IPAttachment{
			{IP: "10.0.4.1", NetworkName: "VLAN 4"},
			{IP: "10.0.0.1", NetworkName: "Home LAN"},
			{IP: "10.0.1.1", NetworkName: "IoT LAN"},
			{IP: "10.0.3.1", NetworkName: "Guest LAN"},
		},
	}
	if _, _, err := s.MergeDevices([]types.Device{devRouter}); err != nil {
		t.Fatalf("failed to merge devRouter: %v", err)
	}

	// 2. Later, a sweep on 10.0.0.0/24 discovers 10.0.0.1 (even with no MAC or same MAC)
	sweepDev := types.Device{
		IP:       "10.0.0.1",
		Hostname: "router-gateway",
	}
	if _, _, err := s.MergeDevices([]types.Device{sweepDev}); err != nil {
		t.Fatalf("failed to merge sweepDev: %v", err)
	}

	// Must NOT create a separate device entry for 10.0.0.1
	devices := s.GetDevices()
	if len(devices) != 1 {
		t.Fatalf("expected 1 unified router device, got %d devices: %+v", len(devices), devices)
	}
	if _, exists := devices["10.0.0.1"]; exists {
		t.Errorf("found separate device entry for 10.0.0.1, should be unified under primary device")
	}

	// 3. What if a separate standalone row for 10.0.1.1 existed in SQLite?
	// Seed standalone row for 10.0.1.1 directly in DB
	_, err := s.db.Exec(`
		INSERT INTO devices (ip, mac, hostname, first_seen, last_seen, is_online, last_presence_change)
		VALUES ('10.0.1.1', '', 'old-standalone', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, CURRENT_TIMESTAMP)
	`)
	if err != nil {
		t.Fatalf("failed to seed standalone row: %v", err)
	}

	// DeduplicateMACs should detect that 10.0.1.1 is already an attached IP on 10.0.4.1 and remove the standalone row
	if err := s.DeduplicateMACs(); err != nil {
		t.Fatalf("DeduplicateMACs failed: %v", err)
	}

	devicesAfterDedup := s.GetDevices()
	if len(devicesAfterDedup) != 1 {
		t.Fatalf("expected 1 unified router device after dedup, got %d: %+v", len(devicesAfterDedup), devicesAfterDedup)
	}
}
