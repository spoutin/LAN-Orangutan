package scanner

import (
	"context"
	"net"
	"testing"

	"github.com/291-Group/LAN-Orangutan/internal/types"
)

func TestRisksFromPorts(t *testing.T) {
	// Telnet and FTP open: two risks, in the fixed serviceProbePorts order
	// (FTP=21 before Telnet=23).
	risks := risksFromPorts([]int{80, 23, 21})
	if len(risks) != 2 {
		t.Fatalf("expected 2 risks, got %d: %v", len(risks), risks)
	}
	if risks[0] != riskyServices[21] || risks[1] != riskyServices[23] {
		t.Errorf("risks not in stable order: %v", risks)
	}

	// Only safe ports: no risks.
	if r := risksFromPorts([]int{22, 443, 9100}); len(r) != 0 {
		t.Errorf("expected no risks, got %v", r)
	}
	if r := risksFromPorts(nil); len(r) != 0 {
		t.Errorf("expected no risks for empty ports, got %v", r)
	}
}

func TestHasWebPort(t *testing.T) {
	if !hasWebPort([]int{22, 80}) {
		t.Error("80 should count as a web port")
	}
	if !hasWebPort([]int{443}) {
		t.Error("443 should count as a web port")
	}
	if !hasWebPort([]int{8080}) {
		t.Error("8080 should count as a web port")
	}
	if hasWebPort([]int{22, 9100}) {
		t.Error("no web port present, should be false")
	}
	if hasWebPort(nil) {
		t.Error("empty ports should be false")
	}
}

// listenLoopback opens a TCP listener on an ephemeral loopback port and returns
// the listener and its port. The caller closes the listener.
func listenLoopback(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// TestProbeServices_FindsOpenPort confirms the probe reports a port that is
// actually listening. It overrides the probe set with the ephemeral test port so
// the test never depends on a well-known port being free.
func TestProbeServices_FindsOpenPort(t *testing.T) {
	ln, port := listenLoopback(t)
	defer ln.Close()

	orig := serviceProbePorts
	serviceProbePorts = []int{port}
	defer func() { serviceProbePorts = orig }()

	open := probeServices(context.Background(), "127.0.0.1")
	if len(open) != 1 || open[0] != port {
		t.Fatalf("expected [%d] open, got %v", port, open)
	}
}

// TestEnrichWithServices_SetsWebUI stands up a real listener and confirms the
// enrichment flags WebUI when that port counts as a web port, without disturbing
// a type already set from the hostname.
func TestEnrichWithServices_SetsWebUI(t *testing.T) {
	ln, port := listenLoopback(t)
	defer ln.Close()

	origPorts, origWeb := serviceProbePorts, webPorts
	serviceProbePorts = []int{port}
	webPorts = map[int]bool{port: true}
	defer func() { serviceProbePorts, webPorts = origPorts, origWeb }()

	devices := []types.Device{{IP: "127.0.0.1", Hostname: "raspberrypi"}}
	devices[0].Type = Classify(devices[0].Vendor, devices[0].Hostname, nil)
	if devices[0].Type != TypeServer {
		t.Fatalf("precondition: expected Server, got %q", devices[0].Type)
	}

	EnrichWithServices(context.Background(), devices)

	if !devices[0].WebUI {
		t.Error("expected WebUI true after probing an open web port")
	}
	if devices[0].Type != TypeServer {
		t.Errorf("hostname type should still win, got %q", devices[0].Type)
	}
}

// TestProbeServices_NothingListening confirms a probe against closed ports
// returns nothing and does not hang.
func TestProbeServices_NothingListening(t *testing.T) {
	// Reserve a port then close it, so it is almost certainly closed.
	ln, port := listenLoopback(t)
	ln.Close()

	orig := serviceProbePorts
	serviceProbePorts = []int{port}
	defer func() { serviceProbePorts = orig }()

	if open := probeServices(context.Background(), "127.0.0.1"); len(open) != 0 {
		t.Errorf("expected no open ports, got %v", open)
	}
}
