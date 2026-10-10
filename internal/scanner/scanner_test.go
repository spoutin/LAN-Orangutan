package scanner

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

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
	got := portScanArgumentsWithTiming("1-1024", "10.0.0.15", true)
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

func TestParsePortScanResultRecordsDetectedSSHPort(t *testing.T) {
	xmlOutput := []byte(`<?xml version="1.0"?>
<nmaprun><host><ports>
  <port protocol="tcp" portid="2222"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2p1" extrainfo="Debian"/></port>
  <port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy" product="nginx"/></port>
  <port protocol="tcp" portid="23"><state state="closed"/></port>
</ports></host></nmaprun>`)

	ports, sshPorts, services, err := parsePortScanResult(xmlOutput)
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
}

func (m *mockRemoteRunner) HasRemoteScannerForTarget(target string) bool {
	return m.hasTarget
}

func (m *mockRemoteRunner) GetGatewayForTarget(target string) string {
	return "test-gateway (10.0.0.1)"
}

func (m *mockRemoteRunner) RunScan(ctx context.Context, target string, args []string) ([]byte, error) {
	m.called = true
	return m.runOutput, m.runErr
}

func TestScanUsesRemoteRunnerWhenConfigured(t *testing.T) {
	mock := &mockRemoteRunner{
		hasTarget: true,
		runOutput: []byte(`<nmaprun><host><status state="up"/><address addr="10.0.0.22" addrtype="ipv4"/><address addr="00:11:22:33:44:55" addrtype="mac"/></host></nmaprun>`),
	}
	s := New(30, false, false, "")
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
	s.SetRemoteRunner(mock)

	ports, _, services, err := s.ScanHostPortsWithTiming(context.Background(), "10.0.0.15", "443", false)
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
