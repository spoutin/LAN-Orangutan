package scanner

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

func offlineHooks() Hooks {
	return Hooks{
		LookPath: func(file string) (string, error) {
			return "", fmt.Errorf("%s disabled in unit test", file)
		},
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return nil, fmt.Errorf("command %s disabled in unit test", name)
		},
		GetInterface:   func(context.Context, string) string { return "eth0" },
		ReverseDNS:     func(context.Context, string, string) string { return "" },
		NetBIOSName:    func(context.Context, string) string { return "" },
		EnrichServices: func(context.Context, []types.Device) {},
		QueryMDNS:      func(context.Context) [][]byte { return nil },
		IPv6Interfaces: func() []string { return nil },
		RunIPv6Command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return nil, fmt.Errorf("ipv6 command %s disabled in unit test", name)
		},
	}
}

func TestPortScanArgumentsSkipDiscoveryAndAllowRetries(t *testing.T) {
	got := portScanArguments("1-1024", "10.0.0.15")
	want := []string{"-sV", "-Pn", "-p", "1-1024", "-T4", "-n", "--max-retries", "2", "--host-timeout", "180s", "-oX", "-", "10.0.0.15"}
	if len(got) != len(want) {
		t.Fatalf("portScanArguments() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("portScanArguments()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNightlyPortScanArgumentsUseConservativeTiming(t *testing.T) {
	got := portScanArgumentsWithTiming("1-1024", "10.0.0.15", true, false)
	for i, arg := range got {
		if arg == "-T2" {
			return
		}
		if arg == "-T4" {
			t.Fatalf("argument %d = %q, nightly scans must use -T2", i, arg)
		}
	}
	t.Fatalf("arguments = %v, want -T2", got)
}

func TestPortScanArguments_PrivilegedIncludesOSFlags(t *testing.T) {
	args := portScanArgumentsWithTiming("22-80", "192.168.1.10", false, true)
	argsStr := strings.Join(args, " ")
	if !strings.Contains(argsStr, "-O") || !strings.Contains(argsStr, "--osscan-limit") || !strings.Contains(argsStr, "--osscan-guess") {
		t.Errorf("args = %v, expected -O, --osscan-limit, and --osscan-guess", args)
	}
}

func TestPortScanArguments_UnprivilegedOmitsOSFlags(t *testing.T) {
	args := portScanArgumentsWithTiming("22-80", "192.168.1.10", false, false)
	argsStr := strings.Join(args, " ")
	if strings.Contains(argsStr, "-O") {
		t.Errorf("args = %v, should NOT contain -O when unprivileged", args)
	}
}

func TestParsePortScanResultRecordsDetectedSSHPort(t *testing.T) {
	xmlOutput := []byte(`<?xml version="1.0"?>
<nmaprun><host><ports>
  <port protocol="tcp" portid="2222"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2p1" extrainfo="Debian"/></port>
  <port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy" product="nginx"/></port>
  <port protocol="tcp" portid="23"><state state="closed"/></port>
</ports></host></nmaprun>`)

	ports, sshPorts, services, _, _, _, err := parsePortScanResult(xmlOutput)
	if err != nil {
		t.Fatalf("parsePortScanResult() error = %v", err)
	}
	if len(ports) != 2 || ports[0] != 2222 || ports[1] != 8080 {
		t.Errorf("open ports = %v, want [2222 8080]", ports)
	}
	if len(sshPorts) != 1 || sshPorts[0] != 2222 {
		t.Errorf("SSH ports = %v, want [2222]", sshPorts)
	}
	if len(services) != 2 || services[0].Name != "ssh" || services[0].Version != "OpenSSH 9.2p1 Debian" {
		t.Errorf("services = %+v, want parsed Nmap service details", services)
	}
}

type mockRemoteRunner struct {
	hasTarget bool
	runOutput []byte
	runErr    error
	called    bool
	lastArgs  []string
}

func (m *mockRemoteRunner) CanRunPrivileged(target string) bool {
	return false
}

func (m *mockRemoteRunner) HasRemoteScannerForTarget(target string) bool {
	return m.hasTarget
}

func (m *mockRemoteRunner) GetGatewayForTarget(target string) string {
	return "test-gateway (10.0.0.1)"
}

func (m *mockRemoteRunner) RunScan(ctx context.Context, target string, args []string) ([]byte, error) {
	m.called = true
	m.lastArgs = args
	return m.runOutput, m.runErr
}

func TestScanUsesRemoteRunnerWhenConfigured(t *testing.T) {
	mock := &mockRemoteRunner{
		hasTarget: true,
		runOutput: []byte(`<nmaprun><host><status state="up"/><address addr="10.0.0.22" addrtype="ipv4"/><address addr="00:11:22:33:44:55" addrtype="mac"/></host></nmaprun>`),
	}
	s := New(30, false, false, "")
	s.SetHooks(offlineHooks())
	s.SetRemoteRunner(mock)

	result, err := s.Scan(context.Background(), "10.0.0.0/24")
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if !mock.called {
		t.Fatal("expected RemoteRunner to be called")
	}
	if !result.Success {
		t.Fatalf("expected success=true, got error: %s", result.Error)
	}
	if len(result.Devices) != 1 || result.Devices[0].IP != "10.0.0.22" {
		t.Fatalf("expected device 10.0.0.22, got %+v", result.Devices)
	}
}

func TestScanRemoteRunnerFailureDoesNotFallbackToArpScan(t *testing.T) {
	mock := &mockRemoteRunner{
		hasTarget: true,
		runErr:    fmt.Errorf("remote nmap failed on gateway"),
	}
	s := New(30, false, false, "")
	s.SetHooks(offlineHooks())
	s.SetRemoteRunner(mock)

	result, err := s.Scan(context.Background(), "10.0.0.0/24")
	if err != nil {
		t.Fatalf("unexpected Scan error: %v", err)
	}
	if !mock.called {
		t.Fatal("expected RemoteRunner to be called")
	}
	if result.Success {
		t.Fatal("expected result.Success=false when remote scan fails")
	}
	if !strings.Contains(result.Error, "remote nmap failed on gateway") {
		t.Fatalf("result.Error = %q, want remote error", result.Error)
	}
}

func TestScanHostPortsWithTimingUsesRemoteRunner(t *testing.T) {
	mock := &mockRemoteRunner{
		hasTarget: true,
		runOutput: []byte(`<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`),
	}
	s := New(30, false, false, "")
	s.SetHooks(offlineHooks())
	s.SetRemoteRunner(mock)

	ports, _, services, _, _, _, err := s.ScanHostPortsWithTiming(context.Background(), "10.0.0.15", "443", false)
	if err != nil {
		t.Fatalf("ScanHostPortsWithTiming error: %v", err)
	}
	if !mock.called {
		t.Fatal("expected RemoteRunner to be called")
	}
	if len(ports) != 1 || ports[0] != 443 {
		t.Fatalf("expected port 443, got %v", ports)
	}
	if len(services) != 1 || services[0].Name != "https" {
		t.Fatalf("expected service https, got %+v", services)
	}
}

func TestScanHostPortsWithTimingRejectsInvalidIP(t *testing.T) {
	invalidIPs := []string{
		"",
		"   ",
		"not-an-ip",
		"-oN /tmp/pwn",
		"10.0.0.1; id",
		"10.0.0.1 $(whoami)",
		"10.0.0.1\n-sS",
	}

	for _, ip := range invalidIPs {
		mock := &mockRemoteRunner{hasTarget: true}
		s := New(30, false, false, "")
		s.SetRemoteRunner(mock)

		_, _, _, _, _, _, err := s.ScanHostPortsWithTiming(context.Background(), ip, "80", false)
		if err == nil {
			t.Errorf("ScanHostPortsWithTiming(%q, \"80\") expected error, got nil", ip)
		}
		if mock.called {
			t.Errorf("ScanHostPortsWithTiming(%q, \"80\") should not invoke RemoteRunner on invalid IP", ip)
		}
	}
}

func TestScanHostPortsWithTimingRejectsInvalidPortRange(t *testing.T) {
	invalidRanges := []string{
		"",
		"   ",
		"80; id",
		"80 --script=evil",
		"80\n443",
		"$(id)",
		"0",
		"65536",
		"1024-80",
		"80-abc",
		"22,,80",
		"-80",
		"80-",
	}

	for _, pr := range invalidRanges {
		mock := &mockRemoteRunner{hasTarget: true}
		s := New(30, false, false, "")
		s.SetRemoteRunner(mock)

		_, _, _, _, _, _, err := s.ScanHostPortsWithTiming(context.Background(), "10.0.0.15", pr, false)
		if err == nil {
			t.Errorf("ScanHostPortsWithTiming(\"10.0.0.15\", %q) expected error, got nil", pr)
		}
		if mock.called {
			t.Errorf("ScanHostPortsWithTiming(\"10.0.0.15\", %q) should not invoke RemoteRunner on invalid port range", pr)
		}
	}
}

func TestScanHostPortsWithTimingAcceptsValidInputs(t *testing.T) {
	cases := []struct {
		ip        string
		portRange string
	}{
		{" 10.0.0.15 ", " 1-1024 "},
		{"10.0.0.15", "22,80,443"},
		{"10.0.0.15", "T:22,80-443,U:53"},
		{"fe80::1", "22-25"},
	}

	for _, tc := range cases {
		mock := &mockRemoteRunner{
			hasTarget: true,
			runOutput: []byte(`<?xml version="1.0"?><nmaprun></nmaprun>`),
		}
		s := New(30, false, false, "")
		s.SetRemoteRunner(mock)

		if _, _, _, _, _, _, err := s.ScanHostPortsWithTiming(context.Background(), tc.ip, tc.portRange, false); err != nil {
			t.Errorf("ScanHostPortsWithTiming(%q, %q) unexpected error: %v", tc.ip, tc.portRange, err)
		}
		if !mock.called {
			t.Errorf("ScanHostPortsWithTiming(%q, %q) expected RemoteRunner to be called", tc.ip, tc.portRange)
		}
	}
}

func TestRemoteScanOmitsNoDNSFlag(t *testing.T) {
	mock := &mockRemoteRunner{
		hasTarget: true,
		runOutput: []byte(`<nmaprun><host><status state="up"/><address addr="10.5.5.10" addrtype="ipv4"/><hostnames><hostname name="beacon.black.internal" type="PTR"/></hostnames></host></nmaprun>`),
	}
	s := New(30, false, false, "")
	s.SetHooks(offlineHooks())
	s.SetRemoteRunner(mock)

	result, err := s.Scan(context.Background(), "10.5.5.0/24")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, arg := range mock.lastArgs {
		if arg == "-n" {
			t.Errorf("expected remote scan args not to include '-n' (disable DNS), but found it in %v", mock.lastArgs)
		}
	}
	if len(result.Devices) != 1 || result.Devices[0].Hostname != "beacon.black.internal" {
		t.Fatalf("expected device hostname 'beacon.black.internal', got %+v", result.Devices)
	}
}

func TestExtractHostFromGateway(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"openwrt (10.5.5.1)", "10.5.5.1"},
		{"opnsense (10.0.0.1)", "10.0.0.1"},
		{"router", ""},
		{"gateway (  192.168.1.1  )", "192.168.1.1"},
	}
	for _, tt := range tests {
		if got := extractHostFromGateway(tt.input); got != tt.want {
			t.Errorf("extractHostFromGateway(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestScanner_LocalPrivilegedConcurrentAccess(t *testing.T) {
	s := New(30, false, false, "")
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(idx int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				_ = s.isLocalPrivileged()
				if idx%2 == 0 {
					s.setLocalPrivileged(false)
				}
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

func TestScanner_ScanCancelledContextPreservesErrorWithoutFallback(t *testing.T) {
	s := New(30, false, false, "")
	hooks := offlineHooks()
	hooks.LookPath = func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	}
	hooks.RunCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, ctx.Err()
	}
	s.SetHooks(hooks)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := s.Scan(ctx, "192.0.2.0/24")
	if err != nil {
		t.Fatalf("Scan returned unexpected top-level err: %v", err)
	}
	if res.Success {
		t.Fatal("expected cancelled Scan to fail")
	}
	if !strings.Contains(res.Error, "nmap") && !strings.Contains(res.Error, "context canceled") {
		t.Fatalf("expected nmap or context error to be preserved, got %q", res.Error)
	}
}

func TestArpScanArgs_UsesTargetCIDRInsteadOfLocalnet(t *testing.T) {
	got := arpScanArgs("10.5.5.0/24", "eth0")
	want := []string{"10.5.5.0/24", "-q", "-I", "eth0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("arpScanArgs() = %v, want %v", got, want)
	}
	for _, a := range got {
		if a == "--localnet" {
			t.Fatalf("arpScanArgs should not use --localnet when CIDR is provided: %v", got)
		}
	}
}

func TestReverseDNSWithServer_HonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	got := reverseDNSWithServer(ctx, "192.0.2.1", "192.0.2.254")
	if got != "" {
		t.Fatalf("reverseDNSWithServer on cancelled ctx = %q, want empty", got)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("reverseDNSWithServer took %v on cancelled ctx; expected immediate return", elapsed)
	}
}

func TestScanner_HooksIsolateLocalScanAndProbes(t *testing.T) {
	s := New(30, true, false, "")
	var enriched bool
	var netbiosCalled bool
	hooks := offlineHooks()
	hooks.LookPath = func(file string) (string, error) {
		if file == "arp-scan" {
			return "/usr/sbin/arp-scan", nil
		}
		return "", fmt.Errorf("nmap missing")
	}
	hooks.RunCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name != "arp-scan" {
			return nil, fmt.Errorf("unexpected command %s", name)
		}
		return []byte("192.168.1.50\t00:11:22:33:44:55\tTestVendor\n"), nil
	}
	hooks.NetBIOSName = func(ctx context.Context, ip string) string {
		netbiosCalled = true
		if ip == "192.168.1.50" {
			return "WIN-DESKTOP"
		}
		return ""
	}
	hooks.EnrichServices = func(ctx context.Context, devices []types.Device) {
		enriched = true
	}
	s.SetHooks(hooks)

	res, err := s.Scan(context.Background(), "192.168.1.0/24")
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if !res.Success || res.Scanner != "arp-scan" {
		t.Fatalf("unexpected scan result: %+v", res)
	}
	if len(res.Devices) != 1 || res.Devices[0].Hostname != "WIN-DESKTOP" {
		t.Fatalf("devices = %+v, want WIN-DESKTOP via NetBIOS hook", res.Devices)
	}
	if !netbiosCalled || !enriched {
		t.Fatalf("expected NetBIOSName (%v) and EnrichServices (%v) hooks to run", netbiosCalled, enriched)
	}
}

func TestScanner_HooksIsolateMDNSAndIPv6(t *testing.T) {
	s := New(30, false, false, "")
	var ipv6Commands []string
	hooks := offlineHooks()
	hooks.QueryMDNS = func(context.Context) [][]byte { return nil }
	hooks.IPv6Interfaces = func() []string { return []string{"en0"} }
	hooks.RunIPv6Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		ipv6Commands = append(ipv6Commands, name)
		return nil, nil
	}
	s.SetHooks(hooks)

	if got := s.DiscoverMDNS(context.Background()); len(got) != 0 {
		t.Fatalf("DiscoverMDNS = %+v, want empty", got)
	}
	if got := s.DiscoverIPv6(context.Background()); len(got) != 0 {
		t.Fatalf("DiscoverIPv6 = %+v, want empty", got)
	}
	if len(ipv6Commands) != 2 {
		t.Fatalf("ipv6Commands = %v, want 2 hooked calls (solicit + neighbor read)", ipv6Commands)
	}
}
