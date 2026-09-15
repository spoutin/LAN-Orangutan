package network

import (
	"testing"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

func TestDockerPrivateRangeDetection(t *testing.T) {
	// isDockerPrivate now backs only the in-container isolation check, and uses
	// the narrow Docker default bridge (172.17.0.0/16), not the whole /12, so a
	// real 172.x LAN is not mistaken for container networking.
	tests := []struct {
		cidr    string
		private bool
	}{
		{"172.17.0.0/16", true},   // Docker default bridge
		{"192.168.65.0/24", true}, // Docker Desktop VM
		{"10.88.0.0/16", true},    // podman
		{"172.18.0.0/16", false},  // no longer assumed to be Docker
		{"172.20.20.0/24", false}, // the reporter's real LAN, must not match
		{"192.168.1.0/24", false}, // a real home LAN
		{"192.168.68.0/22", false},
		{"10.0.0.0/24", false},
		{"not-a-cidr", false},
	}
	for _, tt := range tests {
		if got := isDockerPrivate(tt.cidr); got != tt.private {
			t.Errorf("isDockerPrivate(%q) = %v, want %v", tt.cidr, got, tt.private)
		}
	}
}

func TestIsContainerInterface(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"docker0", true},
		{"br-1a2b3c4d5e6f", true}, // Docker user-defined bridge
		{"veth3a2b1c", true},
		{"podman0", true},
		{"cni-podman0", true},
		{"eth0", false},
		{"enp3s0", false},
		{"wlan0", false},
		{"br0", false},     // an ordinary Linux bridge, could carry a real LAN
		{"bridge0", false}, // likewise
		{"", false},
	}
	for _, tt := range tests {
		if got := isContainerInterface(tt.name); got != tt.want {
			t.Errorf("isContainerInterface(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestIsolationWarningOnlyWhenIsolated(t *testing.T) {
	if w := IsolationWarning([]types.Network{{CIDR: "172.17.0.0/16"}}); !InContainer() && w != "" {
		t.Error("no warning should be produced when not running in a container")
	}
}

func TestRealNetworkMeansNotIsolated(t *testing.T) {
	networks := []types.Network{
		{CIDR: "172.17.0.0/16"},
		{CIDR: "192.168.1.0/24"},
	}
	if IsolatedFromLAN(networks) {
		t.Error("a visible real network means the container is not isolated")
	}
}

// TestExcludeContainerNetworks covers the reported bug: exclusion keys off the
// interface name, not the address range, so a real LAN on 172.x is kept while
// Docker bridges are dropped regardless of the range they use.
func TestExcludeContainerNetworks(t *testing.T) {
	in := []types.Network{
		{CIDR: "172.20.20.0/24", Interface: "eth0"},         // the reporter's real LAN
		{CIDR: "172.17.0.0/16", Interface: "docker0"},       // Docker default bridge
		{CIDR: "172.18.0.0/16", Interface: "br-a1b2c3d4e5"}, // Docker user bridge
		{CIDR: "192.168.0.0/20", Interface: "br-9f8e7d6c"},  // Docker bridge on 192.168.x
		{CIDR: "192.168.1.0/24", Interface: "wlan0"},        // real LAN
		{CIDR: "10.0.5.0/24", Interface: "veth12ab34"},      // container veth
	}
	got := ExcludeContainerNetworks(in)

	kept := map[string]bool{}
	for _, n := range got {
		kept[n.CIDR] = true
	}
	if !kept["172.20.20.0/24"] {
		t.Error("the real 172.20 LAN on eth0 must be kept (the reported bug)")
	}
	if !kept["192.168.1.0/24"] {
		t.Error("the real LAN on wlan0 must be kept")
	}
	if kept["172.17.0.0/16"] || kept["172.18.0.0/16"] || kept["192.168.0.0/20"] || kept["10.0.5.0/24"] {
		t.Errorf("a container bridge was kept: %v", got)
	}
	if len(got) != 2 {
		t.Fatalf("expected exactly the two real LANs, got %d: %v", len(got), got)
	}
}

func TestConfiguredContainerNetworkIsStillHonoured(t *testing.T) {
	// Filtering applies to detection, not to a network the user asked for.
	got := WithConfigured(nil, Filter{Configured: []string{"172.17.0.0/16"}})
	if len(got) != 1 || got[0].CIDR != "172.17.0.0/16" {
		t.Errorf("an explicitly configured network should survive, got %v", got)
	}
}

// TestOnlyConfiguredIgnoresDetected confirms that with only-configured on, the
// auto-detected networks are dropped entirely and only declared ones remain.
func TestOnlyConfiguredIgnoresDetected(t *testing.T) {
	detected := []types.Network{
		{CIDR: "192.168.1.0/24", Interface: "eth0"},
		{CIDR: "10.0.0.0/24", Interface: "wlan0"},
	}
	got := WithConfigured(detected, Filter{Configured: []string{"172.20.20.0/24"}, OnlyConfigured: true})
	if len(got) != 1 || got[0].CIDR != "172.20.20.0/24" {
		t.Errorf("only-configured should return just the declared network, got %v", got)
	}
}

// TestExcludeNetworks confirms the blocklist drops a real detected network the
// user does not want, including subnets inside a wider excluded block, while
// leaving the rest of auto-detection intact and never touching a configured net.
func TestExcludeNetworks(t *testing.T) {
	detected := []types.Network{
		{CIDR: "192.168.1.0/24", Interface: "eth0"}, // keep
		{CIDR: "192.168.5.0/24", Interface: "eth1"}, // inside excluded 192.168.4.0/22, drop
		{CIDR: "10.10.0.0/24", Interface: "eth2"},   // excluded exactly, drop
	}
	got := WithConfigured(detected, Filter{
		Excluded: []string{"192.168.4.0/22", "10.10.0.0/24"},
	})

	kept := map[string]bool{}
	for _, n := range got {
		kept[n.CIDR] = true
	}
	if !kept["192.168.1.0/24"] {
		t.Error("a network outside the excludes must be kept")
	}
	if kept["192.168.5.0/24"] || kept["10.10.0.0/24"] {
		t.Errorf("an excluded network was kept: %v", got)
	}

	// A configured network is never excluded, even if it falls in an exclude.
	got = WithConfigured(nil, Filter{
		Configured: []string{"10.10.0.0/24"},
		Excluded:   []string{"10.10.0.0/24"},
	})
	if len(got) != 1 || got[0].CIDR != "10.10.0.0/24" {
		t.Errorf("an explicitly configured network must survive an exclude, got %v", got)
	}
}
