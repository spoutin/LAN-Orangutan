package network

import (
	"errors"
	"testing"
)

func TestGetTailscaleStatus_PrefersIPv4ForSelfIP(t *testing.T) {
	origFind := findTailscaleBinaryFunc
	origRun := runCommandFunc
	t.Cleanup(func() {
		findTailscaleBinaryFunc = origFind
		runCommandFunc = origRun
	})

	findTailscaleBinaryFunc = func() string { return "/usr/bin/tailscale" }
	runCommandFunc = func(name string, args ...string) ([]byte, error) {
		return []byte(`{
			"Version": "1.60.0",
			"BackendState": "Running",
			"CurrentTailnet": {"Name": "example.ts.net"},
			"Self": {
				"DNSName": "host.example.ts.net.",
				"TailscaleIPs": ["fd7a:115c:a1e0::1", "100.64.0.10"]
			},
			"Peer": {}
		}`), nil
	}

	st := GetTailscaleStatus()
	if !st.Connected {
		t.Fatal("expected Connected=true")
	}
	if st.SelfIP != "100.64.0.10" {
		t.Fatalf("SelfIP = %q, want 100.64.0.10 (IPv4)", st.SelfIP)
	}
}

func TestGetTailscaleDevices_RunningWithZeroPeersReturnsNonNilEmptySlice(t *testing.T) {
	origFind := findTailscaleBinaryFunc
	origRun := runCommandFunc
	t.Cleanup(func() {
		findTailscaleBinaryFunc = origFind
		runCommandFunc = origRun
	})

	findTailscaleBinaryFunc = func() string { return "/usr/bin/tailscale" }
	runCommandFunc = func(name string, args ...string) ([]byte, error) {
		// Running daemon, IPv6-only self and 0 peers -> connected with 0 IPv4 devices,
		// must return non-nil empty slice rather than nil ("not connected").
		return []byte(`{
			"BackendState": "Running",
			"Self": {"TailscaleIPs": ["fd7a:115c:a1e0::1"]},
			"Peer": {}
		}`), nil
	}

	devs := GetTailscaleDevices()
	if devs == nil {
		t.Fatal("expected non-nil empty slice when BackendState is Running with 0 IPv4 peers")
	}
	if len(devs) != 0 {
		t.Fatalf("expected 0 devices, got %d", len(devs))
	}
}

func TestGetTailscaleDevices_PeersAndStates(t *testing.T) {
	origFind := findTailscaleBinaryFunc
	origRun := runCommandFunc
	t.Cleanup(func() {
		findTailscaleBinaryFunc = origFind
		runCommandFunc = origRun
	})

	// Not installed
	findTailscaleBinaryFunc = func() string { return "" }
	if devs := GetTailscaleDevices(); devs != nil {
		t.Fatalf("expected nil when tailscale not installed, got %+v", devs)
	}

	findTailscaleBinaryFunc = func() string { return "/usr/bin/tailscale" }

	// Command failure & invalid JSON
	runCommandFunc = func(string, ...string) ([]byte, error) { return nil, errors.New("boom") }
	if devs := GetTailscaleDevices(); devs != nil {
		t.Fatalf("expected nil on command error, got %+v", devs)
	}
	runCommandFunc = func(string, ...string) ([]byte, error) { return []byte("{bad"), nil }
	if devs := GetTailscaleDevices(); devs != nil {
		t.Fatalf("expected nil on bad json, got %+v", devs)
	}

	// Stopped state
	runCommandFunc = func(string, ...string) ([]byte, error) {
		return []byte(`{"BackendState":"Stopped","Self":{"TailscaleIPs":["100.64.0.1"]}}`), nil
	}
	if devs := GetTailscaleDevices(); devs != nil {
		t.Fatalf("expected nil when stopped, got %+v", devs)
	}

	// Running with online/offline/IPv6-only peers + DNSName fallback
	runCommandFunc = func(string, ...string) ([]byte, error) {
		return []byte(`{
			"BackendState": "Running",
			"Self": {"HostName": "selfbox", "OS": "linux", "TailscaleIPs": ["100.64.0.1"]},
			"Peer": {
				"p1": {"DNSName": "laptop.tailnet.ts.net.", "OS": "macOS", "Online": true, "TailscaleIPs": ["fd7a::2", "100.64.0.2"]},
				"p2": {"HostName": "offline-box", "OS": "windows", "Online": false, "TailscaleIPs": ["100.64.0.3"]},
				"p3": {"HostName": "v6only", "OS": "linux", "Online": true, "TailscaleIPs": ["fd7a::3"]}
			}
		}`), nil
	}
	devs := GetTailscaleDevices()
	if len(devs) != 2 {
		t.Fatalf("expected 2 online IPv4 devices (self + p1), got %d: %+v", len(devs), devs)
	}
	seen := map[string]string{}
	for _, d := range devs {
		seen[d.IP] = d.Hostname
	}
	if seen["100.64.0.1"] != "selfbox" || seen["100.64.0.2"] != "laptop" {
		t.Fatalf("unexpected devices map: %+v", seen)
	}
}

func TestGetTailscaleStatus_StatesAndBinaryLookup(t *testing.T) {
	origFind := findTailscaleBinaryFunc
	origRun := runCommandFunc
	origLookPath := lookPathFunc
	t.Cleanup(func() {
		findTailscaleBinaryFunc = origFind
		runCommandFunc = origRun
		lookPathFunc = origLookPath
	})

	lookPathFunc = func(file string) (string, error) {
		if file == "tailscale" {
			return "/opt/homebrew/bin/tailscale", nil
		}
		return "", errors.New("missing")
	}
	if got := findTailscaleBinary(); got != "/opt/homebrew/bin/tailscale" {
		t.Fatalf("findTailscaleBinary() = %q, want /opt/homebrew/bin/tailscale", got)
	}

	findTailscaleBinaryFunc = func() string { return "" }
	if st := GetTailscaleStatus(); st.Installed || st.Running || st.Connected {
		t.Fatalf("expected uninstalled status, got %+v", st)
	}

	findTailscaleBinaryFunc = func() string { return "/usr/bin/tailscale" }
	runCommandFunc = func(string, ...string) ([]byte, error) { return nil, errors.New("daemon down") }
	if st := GetTailscaleStatus(); !st.Installed || st.Running || st.Connected {
		t.Fatalf("expected installed/not-running status, got %+v", st)
	}

	runCommandFunc = func(string, ...string) ([]byte, error) {
		return []byte(`{
			"Version":"1.64.0",
			"BackendState":"Running",
			"CurrentTailnet":{"Name":"home.ts.net"},
			"Self":{"HostName":"mac","DNSName":"mac.home.ts.net.","TailscaleIPs":["100.64.0.5"]},
			"Peer":{"a":{"Online":true},"b":{"Online":false}},
			"ExitNodeStatus":{"ID":"exit-1"}
		}`), nil
	}
	st := GetTailscaleStatus()
	if !st.Installed || !st.Running || !st.Connected || st.PeerCount != 2 || st.ExitNode != "exit-1" || st.SelfHostname != "mac" || st.TailnetName != "home.ts.net" {
		t.Fatalf("unexpected running TailscaleStatus: %+v", st)
	}

	runCommandFunc = func(string, ...string) ([]byte, error) {
		return []byte(`{"BackendState":"NeedsLogin"}`), nil
	}
	st = GetTailscaleStatus()
	if !st.Running || st.Connected || st.BackendState != "NeedsLogin" {
		t.Fatalf("unexpected NeedsLogin status: %+v", st)
	}
}
