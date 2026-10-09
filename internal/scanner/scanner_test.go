package scanner

import "testing"

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
	// An open custom port is SSH only when Nmap's service detection identifies it
	// as such. Other open ports must remain in the port list without becoming SSH.
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
