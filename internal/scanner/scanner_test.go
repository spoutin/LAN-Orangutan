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

func TestParsePortScanResultRecordsDetectedSSHPort(t *testing.T) {
	// An open custom port is SSH only when Nmap's service detection identifies it
	// as such. Other open ports must remain in the port list without becoming SSH.
	xmlOutput := []byte(`<?xml version="1.0"?>
<nmaprun><host><ports>
  <port protocol="tcp" portid="2222"><state state="open"/><service name="ssh"/></port>
  <port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy"/></port>
  <port protocol="tcp" portid="23"><state state="closed"/></port>
</ports></host></nmaprun>`)

	ports, sshPorts, err := parsePortScanResult(xmlOutput)
	if err != nil {
		t.Fatalf("parsePortScanResult() error = %v", err)
	}
	if len(ports) != 2 || ports[0] != 2222 || ports[1] != 8080 {
		t.Errorf("open ports = %v, want [2222 8080]", ports)
	}
	if len(sshPorts) != 1 || sshPorts[0] != 2222 {
		t.Errorf("SSH ports = %v, want [2222]", sshPorts)
	}
}
