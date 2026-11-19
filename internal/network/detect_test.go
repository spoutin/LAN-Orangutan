package network

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestCalculateCIDR_InvalidPrefixDoesNotPanic(t *testing.T) {
	if got := calculateCIDR("192.168.1.5", -1); got != "" {
		t.Fatalf("calculateCIDR(-1) = %q, want empty", got)
	}
	if got := calculateCIDR("192.168.1.5", 33); got != "" {
		t.Fatalf("calculateCIDR(33) = %q, want empty", got)
	}
	if got := calculateCIDR("192.168.1.5", 24); got != "192.168.1.0/24" {
		t.Fatalf("calculateCIDR(24) = %q, want 192.168.1.0/24", got)
	}
}

func TestParsePortRange_RejectsTrailingGarbage(t *testing.T) {
	invalid := []string{"80abc-443", "80-443xyz", "80-443-8080", "443-80", "0-80", "1-65536", "abc-100"}
	for _, in := range invalid {
		if _, _, err := ParsePortRange(in); err == nil {
			t.Errorf("ParsePortRange(%q) succeeded, want error", in)
		}
	}
	start, end, err := ParsePortRange(" 80 - 443 ")
	if err != nil || start != 80 || end != 443 {
		t.Fatalf("ParsePortRange(' 80 - 443 ') = (%d, %d, %v), want (80, 443, nil)", start, end, err)
	}
}

func TestParseDefaultGatewayLinux_SkipsEmptyFirstRoute(t *testing.T) {
	output := []byte(`[{"dst":"default","dev":"wg0"},{"dst":"default","gateway":"10.0.0.1","dev":"eth0"}]`)
	if got := parseDefaultGateway("linux", output); got != "10.0.0.1" {
		t.Fatalf("parseDefaultGateway = %q, want 10.0.0.1", got)
	}
}

func TestParseDNSFromResolvConfFile_ReadsFileWithoutGrep(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	content := "# comment\nsearch lan\nnameserver 1.1.1.1\nnameserver invalid-ip\nnameserver 8.8.8.8 # inline\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	got := parseDNSFromResolvConfFile(path)
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "8.8.8.8" {
		t.Fatalf("parseDNSFromResolvConfFile = %v, want [1.1.1.1 8.8.8.8]", got)
	}
}

func TestDetectNetworks_FiltersLoopbackDownAndIPv6(t *testing.T) {
	origList := listInterfacesFunc
	t.Cleanup(func() { listInterfacesFunc = origList })

	listInterfacesFunc = func() ([]netInterfaceInfo, error) {
		return []netInterfaceInfo{
			{
				Name:  "lo0",
				Flags: net.FlagUp | net.FlagLoopback,
				Addrs: []net.Addr{&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)}},
			},
			{
				Name:  "eth1",
				Flags: 0, // down
				Addrs: []net.Addr{&net.IPNet{IP: net.ParseIP("10.1.0.5"), Mask: net.CIDRMask(24, 32)}},
			},
			{
				Name:  "en0",
				Flags: net.FlagUp,
				Addrs: []net.Addr{
					&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
					&net.IPNet{IP: net.ParseIP("192.168.1.42"), Mask: net.CIDRMask(24, 32)},
				},
			},
			{
				Name:  "utun4",
				Flags: net.FlagUp,
				Addrs: []net.Addr{
					&net.IPNet{IP: net.ParseIP("100.64.10.2"), Mask: net.CIDRMask(32, 32)},
				},
			},
		}, nil
	}

	nets, err := DetectNetworks()
	if err != nil {
		t.Fatalf("DetectNetworks: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("got %d networks, want 2: %+v", len(nets), nets)
	}
	if nets[0].CIDR != "192.168.1.0/24" || nets[0].FriendlyName != "Wi-Fi" || !nets[0].IsWireless {
		t.Errorf("unexpected en0 network: %+v", nets[0])
	}
	if nets[1].CIDR != "100.64.10.2/32" || !nets[1].IsTailscale || nets[1].FriendlyName != "Tailscale VPN" {
		t.Errorf("unexpected utun4 network: %+v", nets[1])
	}

	listInterfacesFunc = func() ([]netInterfaceInfo, error) {
		return nil, errors.New("netlink failed")
	}
	if _, err := DetectNetworks(); err == nil {
		t.Fatal("DetectNetworks expected error when interface listing fails")
	}
}

func TestGetDefaultGatewayAndDNSServers(t *testing.T) {
	origRun := runCommandFunc
	origRead := readFileFunc
	t.Cleanup(func() {
		runCommandFunc = origRun
		readFileFunc = origRead
	})

	runCommandFunc = func(name string, args ...string) ([]byte, error) {
		if name == "netstat" {
			return []byte("Routing tables\ndefault            192.168.1.1        UGScg           en0\n"), nil
		}
		if name == "ip" {
			return []byte(`[{"dst":"default","gateway":"10.0.0.1"}]`), nil
		}
		return nil, errors.New("unsupported")
	}

	gw, err := GetDefaultGateway()
	if err != nil {
		t.Fatalf("GetDefaultGateway: %v", err)
	}
	if gw != "192.168.1.1" && gw != "10.0.0.1" {
		t.Fatalf("GetDefaultGateway = %q, want 192.168.1.1 or 10.0.0.1", gw)
	}

	runCommandFunc = func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("command failed")
	}
	if _, err := GetDefaultGateway(); err == nil {
		t.Fatal("GetDefaultGateway expected error when command fails")
	}

	// DNS via resolvectl
	runCommandFunc = func(name string, args ...string) ([]byte, error) {
		if name == "resolvectl" {
			return []byte("Link 2 (eth0)\n  DNS Servers: 10.0.0.53 1.1.1.1 not-an-ip\n"), nil
		}
		return nil, errors.New("unused")
	}
	dns := GetDNSServers()
	if len(dns) != 2 || dns[0] != "10.0.0.53" || dns[1] != "1.1.1.1" {
		t.Fatalf("GetDNSServers(resolvectl) = %v, want [10.0.0.53 1.1.1.1]", dns)
	}

	// DNS fallback to /etc/resolv.conf
	runCommandFunc = func(string, ...string) ([]byte, error) {
		return nil, errors.New("no resolvectl")
	}
	readFileFunc = func(string) ([]byte, error) {
		return []byte("nameserver 9.9.9.9\nnameserver 149.112.112.112\n"), nil
	}
	dns = GetDNSServers()
	if len(dns) != 2 || dns[0] != "9.9.9.9" || dns[1] != "149.112.112.112" {
		t.Fatalf("GetDNSServers(resolv.conf) = %v, want [9.9.9.9 149.112.112.112]", dns)
	}

	if !ValidateCIDR("192.168.1.0/24") || ValidateCIDR("bad-cidr") {
		t.Fatal("ValidateCIDR returned unexpected result")
	}
	if !IsTailscaleNetwork("100.100.1.5/32") || IsTailscaleNetwork("192.168.1.0/24") || IsTailscaleNetwork("invalid") {
		t.Fatal("IsTailscaleNetwork returned unexpected result")
	}
	if !isTailscaleInterface("tailscale0", nil) || !isTailscaleInterface("utun2", net.ParseIP("100.64.0.1")) || isTailscaleInterface("eth0", net.ParseIP("100.64.0.1")) {
		t.Fatal("isTailscaleInterface returned unexpected result")
	}
	if getFriendlyName("eth0", nil) != "Ethernet" || getFriendlyName("wlan0", nil) != "Wi-Fi" || getFriendlyName("custom9", nil) != "custom9" {
		t.Fatal("getFriendlyName returned unexpected result")
	}
}
