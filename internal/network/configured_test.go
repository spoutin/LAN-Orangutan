package network

import "testing"

func TestParseNetworkList(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"192.168.1.0/24", 1},
		{"192.168.1.0/24,10.0.0.0/24", 2},
		{"192.168.1.0/24, 10.0.0.0/24", 2},
		{"192.168.1.0/24 10.0.0.0/24", 2},
		{"  192.168.1.0/24  ,  ", 1},
		{"", 0},
		{"   ", 0},
	}
	for _, tt := range tests {
		if got := ParseNetworkList(tt.in); len(got) != tt.want {
			t.Errorf("ParseNetworkList(%q) returned %d entries, want %d", tt.in, len(got), tt.want)
		}
	}
}

func TestConfiguredNetworksAreAdded(t *testing.T) {
	got := WithConfigured(nil, Filter{Configured: []string{"192.168.50.0/24"}})
	if len(got) != 1 {
		t.Fatalf("expected the configured network to be added, got %d", len(got))
	}
	if got[0].CIDR != "192.168.50.0/24" {
		t.Errorf("CIDR = %q", got[0].CIDR)
	}
	if got[0].Interface != "configured" {
		t.Errorf("configured networks should be labelled as such, got %q", got[0].Interface)
	}
}

func TestDuplicatesAreNotAddedTwice(t *testing.T) {
	detected := WithConfigured(nil, Filter{Configured: []string{"192.168.50.0/24"}})
	again := WithConfigured(detected, Filter{Configured: []string{"192.168.50.0/24"}})

	if len(again) != 1 {
		t.Errorf("a network already present should not be added again, got %d", len(again))
	}
}

func TestInvalidCIDRsAreIgnored(t *testing.T) {
	got := WithConfigured(nil, Filter{Configured: []string{"not-a-network", "192.168.1.999/24", "192.168.50.0/24"}})
	if len(got) != 1 {
		t.Fatalf("only the valid network should survive, got %d", len(got))
	}
	if got[0].CIDR != "192.168.50.0/24" {
		t.Errorf("kept the wrong network: %q", got[0].CIDR)
	}
}

func TestContainsIP(t *testing.T) {
	networks := []string{"10.0.0.0/24", "10.0.1.0/24"}

	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.0.0.254", true},
		{"10.0.1.50", true},
		{"10.0.2.1", false},
		{"192.168.1.1", false},
		{"", false},
		{"invalid-ip", false},
	}

	for _, tt := range tests {
		if got := ContainsIP(networks, tt.ip); got != tt.want {
			t.Errorf("ContainsIP(%v, %q) = %v, want %v", networks, tt.ip, got, tt.want)
		}
	}

	if ContainsIP(nil, "10.0.0.1") {
		t.Errorf("ContainsIP(nil, ...) should be false")
	}
	if ContainsIP([]string{}, "10.0.0.1") {
		t.Errorf("ContainsIP([], ...) should be false")
	}
}
