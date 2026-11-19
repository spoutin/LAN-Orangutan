package cli

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/scanner"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

func setupCLITestConfig(t *testing.T) *config.Config {
	t.Helper()
	origCfg := cfg
	origCfgFile := cfgFile
	t.Cleanup(func() {
		cfg = origCfg
		cfgFile = origCfgFile
	})

	dir := t.TempDir()
	c := config.Default()
	c.Storage.DataDir = dir
	c.Scanning.ScanInterval = 300
	c.Scanning.MinScanInterval = 60
	c.Scanning.NetworkNames = map[string]string{"10.0.0.0/24": "Core LAN"}
	cfg = c
	cfgFile = filepath.Join(dir, "config.ini")
	return c
}

func seedCLIDevices(t *testing.T, c *config.Config) {
	t.Helper()
	store, err := storage.New(c.DevicesFile(), c.StateFile())
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	defer store.Close()

	now := time.Now()
	devices := []types.Device{
		{
			IP:        "10.0.0.2",
			MAC:       "00:11:22:33:44:02",
			Hostname:  "nas-box",
			Vendor:    "Synology",
			Label:     "NAS",
			Group:     "Storage",
			FirstSeen: now.Add(-2 * time.Hour),
			LastSeen:  now.Add(-30 * time.Second), // recent / online
		},
		{
			IP:        "10.0.0.10",
			MAC:       "00:11:22:33:44:10",
			Hostname:  "old-cam",
			Vendor:    "Axis",
			Label:     "Cam",
			Group:     "IoT",
			FirstSeen: now.Add(-24 * time.Hour),
			LastSeen:  now.Add(-2 * time.Hour), // offline
		},
	}
	for i := range devices {
		if err := store.UpdateDevice(&devices[i]); err != nil {
			t.Fatalf("UpdateDevice %s: %v", devices[i].IP, err)
		}
	}
}

type mockCLIRemoteRunner struct {
	sweepXMLByTarget map[string]string
}

func (m *mockCLIRemoteRunner) HasRemoteScannerForTarget(string) bool { return true }
func (m *mockCLIRemoteRunner) GetGatewayForTarget(string) string     { return "mockgw" }
func (m *mockCLIRemoteRunner) CanRunPrivileged(string) bool          { return false }
func (m *mockCLIRemoteRunner) Close() error                          { return nil }
func (m *mockCLIRemoteRunner) RunScan(ctx context.Context, target string, args []string) ([]byte, error) {
	if xml, ok := m.sweepXMLByTarget[target]; ok {
		return []byte(xml), nil
	}
	return []byte(`<nmaprun></nmaprun>`), nil
}

func TestRunList_FormatsAndFilters(t *testing.T) {
	c := setupCLITestConfig(t)
	seedCLIDevices(t, c)

	origOnline, origOffline, origGroup, origFormat := listOnline, listOffline, listGroup, listFormat
	t.Cleanup(func() {
		listOnline, listOffline, listGroup, listFormat = origOnline, origOffline, origGroup, origFormat
	})

	runWith := func(online, offline bool, group, format string) string {
		listOnline, listOffline, listGroup, listFormat = online, offline, group, format
		var buf bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&buf)
		if err := runList(cmd, nil); err != nil {
			t.Fatalf("runList(online=%v offline=%v group=%q format=%q): %v", online, offline, group, format, err)
		}
		return buf.String()
	}

	// Table format (all)
	tableOut := runWith(false, false, "", "table")
	if !strings.Contains(tableOut, "10.0.0.2") || !strings.Contains(tableOut, "10.0.0.10") || !strings.Contains(tableOut, "online") || !strings.Contains(tableOut, "offline") {
		t.Fatalf("unexpected table output:\n%s", tableOut)
	}

	// Online + group filter in JSON format
	jsonOut := runWith(true, false, "storage", "json")
	var items []listDeviceJSON
	if err := json.Unmarshal([]byte(jsonOut), &items); err != nil {
		t.Fatalf("unmarshal list JSON: %v\n%s", err, jsonOut)
	}
	if len(items) != 1 || items[0].IP != "10.0.0.2" || items[0].Group != "Storage" {
		t.Fatalf("unexpected filtered JSON list: %+v", items)
	}

	// Offline filter in CSV format
	csvOut := runWith(false, true, "", "csv")
	rows, err := csv.NewReader(strings.NewReader(csvOut)).ReadAll()
	if err != nil {
		t.Fatalf("parse list CSV: %v", err)
	}
	if len(rows) != 2 || rows[1][0] != "10.0.0.10" {
		t.Fatalf("unexpected offline CSV rows: %+v", rows)
	}
}

func TestRunExport_WritesSortedCSVAndValidatesDir(t *testing.T) {
	c := setupCLITestConfig(t)
	seedCLIDevices(t, c)

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	outPath := filepath.Join(t.TempDir(), "devices.csv")
	if err := runExport(cmd, []string{outPath}); err != nil {
		t.Fatalf("runExport: %v", err)
	}
	if !strings.Contains(buf.String(), "Exported 2 devices to ") {
		t.Fatalf("unexpected export stdout: %q", buf.String())
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile export: %v", err)
	}
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatalf("parse exported CSV: %v", err)
	}
	if len(rows) != 3 || rows[1][0] != "10.0.0.2" || rows[1][9] != "online" || rows[2][0] != "10.0.0.10" || rows[2][9] != "offline" {
		t.Fatalf("unexpected exported CSV rows: %+v", rows)
	}

	// Non-existent parent directory returns error
	missingDir := filepath.Join(t.TempDir(), "missing", "out.csv")
	if err := runExport(cmd, []string{missingDir}); err == nil {
		t.Fatal("expected error when export parent directory does not exist")
	}
}

func TestRunConfig_PrintsSectionsAndRedactsPassword(t *testing.T) {
	c := setupCLITestConfig(t)
	c.Server.Password = "super-secret-password"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	if err := runConfig(cmd, nil); err != nil {
		t.Fatalf("runConfig: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"=== LAN Orangutan Configuration ===",
		"[server]",
		"password = (set in config or environment)",
		"[scanning]",
		"[storage]",
		"[tailscale]",
		"[ui]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("runConfig output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "super-secret-password") {
		t.Fatal("runConfig leaked plaintext password")
	}
}

func TestRunNetworks_PrintsDetectedNetworksGatewayAndDNS(t *testing.T) {
	c := setupCLITestConfig(t)
	c.Scanning.NetworkNames = map[string]string{"10.0.0.0/24": "Office LAN"}

	origDetect := detectNetworksFunc
	origGW := getDefaultGatewayFunc
	origDNS := getDNSServersFunc
	t.Cleanup(func() {
		detectNetworksFunc = origDetect
		getDefaultGatewayFunc = origGW
		getDNSServersFunc = origDNS
	})

	detectNetworksFunc = func() ([]types.Network, error) {
		return []types.Network{
			{CIDR: "10.0.0.0/24", Interface: "eth0", FriendlyName: "eth0", IP: "10.0.0.5", IsWireless: true},
			{CIDR: "100.64.0.0/10", Interface: "tailscale0", FriendlyName: "Tailscale", IP: "100.64.0.2", IsTailscale: true},
		}, nil
	}
	getDefaultGatewayFunc = func() (string, error) { return "10.0.0.1", nil }
	getDNSServersFunc = func() []string { return []string{"1.1.1.1", "9.9.9.9"} }

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	if err := runNetworks(cmd, nil); err != nil {
		t.Fatalf("runNetworks: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"10.0.0.0/24",
		"Type: Office LAN",
		"Wireless: yes",
		"Tailscale: yes",
		"Default Gateway: 10.0.0.1",
		"DNS Servers: [1.1.1.1 9.9.9.9]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("runNetworks output missing %q:\n%s", want, out)
		}
	}

	// Empty network list
	detectNetworksFunc = func() ([]types.Network, error) { return nil, nil }
	buf.Reset()
	if err := runNetworks(cmd, nil); err != nil {
		t.Fatalf("runNetworks(empty): %v", err)
	}
	if !strings.Contains(buf.String(), "No networks detected") {
		t.Fatalf("expected 'No networks detected', got %q", buf.String())
	}
}

func TestRunStatus_PrintsToolsStorageNetworksAndTailscale(t *testing.T) {
	c := setupCLITestConfig(t)
	seedCLIDevices(t, c)

	origLookPath := lookPathFunc
	origVersion := getToolVersionFunc
	origDetect := detectNetworksFunc
	origTS := getTailscaleStatusFunc
	t.Cleanup(func() {
		lookPathFunc = origLookPath
		getToolVersionFunc = origVersion
		detectNetworksFunc = origDetect
		getTailscaleStatusFunc = origTS
	})

	lookPathFunc = func(name string) (string, error) {
		if name == "nmap" {
			return "/usr/bin/nmap", nil
		}
		return "", errors.New("not found")
	}
	getToolVersionFunc = func(name string) string {
		if name == "nmap" {
			return "Nmap version 7.95"
		}
		return ""
	}
	detectNetworksFunc = func() ([]types.Network, error) {
		return []types.Network{
			{CIDR: "10.0.0.0/24", Interface: "en0", IsWireless: true},
		}, nil
	}
	getTailscaleStatusFunc = func() types.TailscaleStatus {
		return types.TailscaleStatus{
			Installed:    true,
			Running:      true,
			Connected:    true,
			BackendState: "Running",
			SelfIP:       "100.64.0.10",
			SelfHostname: "orangutan-node",
			PeerCount:    3,
		}
	}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	if err := runStatus(cmd, nil); err != nil {
		t.Fatalf("runStatus: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"=== LAN Orangutan Status ===",
		"nmap: Nmap version 7.95 (/usr/bin/nmap)",
		"arp-scan: not found",
		"Devices: 2 total (1 online, 1 offline)",
		"10.0.0.0/24 (en0) [wireless]",
		"IP: 100.64.0.10",
		"Hostname: orangutan-node",
		"Peers: 3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("runStatus output missing %q:\n%s", want, out)
		}
	}
}

func buildTestMDNSPacket(host string, ip [4]byte) []byte {
	encodeName := func(n string) []byte {
		var b []byte
		for _, label := range strings.Split(strings.TrimSuffix(n, "."), ".") {
			b = append(b, byte(len(label)))
			b = append(b, label...)
		}
		return append(b, 0)
	}
	u16 := func(v int) []byte { return []byte{byte(v >> 8), byte(v)} }
	hostBytes := encodeName(host)
	var msg []byte
	msg = append(msg, 0, 0, 0x84, 0) // response
	msg = append(msg, u16(0)...)     // questions
	msg = append(msg, u16(1)...)     // answers
	msg = append(msg, u16(0)...)     // authority
	msg = append(msg, u16(0)...)     // additional
	msg = append(msg, hostBytes...)
	msg = append(msg, u16(1)...)      // type A
	msg = append(msg, u16(0x8001)...) // class
	msg = append(msg, 0, 0, 0, 60)    // ttl
	msg = append(msg, u16(4)...)      // rdlen
	msg = append(msg, ip[:]...)
	return msg
}

func TestRunScan_SingleAllDefaultAndErrors(t *testing.T) {
	setupCLITestConfig(t)

	origDetect := detectNetworksFunc
	origScannerFn := newCLIScannerFunc
	t.Cleanup(func() {
		detectNetworksFunc = origDetect
		newCLIScannerFunc = origScannerFn
	})

	detectNetworksFunc = func() ([]types.Network, error) {
		return []types.Network{
			{CIDR: "100.64.0.0/10", Interface: "tailscale0", IsTailscale: true},
			{CIDR: "10.88.0.0/24", Interface: "eth0"},
		}, nil
	}

	newCLIScannerFunc = func(cfg *config.Config) (*scanner.Scanner, func()) {
		s := scanner.New(cfg.Scanning.MinScanInterval, false, false, "")
		s.SetHooks(scanner.Hooks{
			ReverseDNS:     func(context.Context, string, string) string { return "" },
			NetBIOSName:    func(context.Context, string) string { return "" },
			EnrichServices: func(context.Context, []types.Device) {},
			IPv6Interfaces: func() []string { return []string{"eth0"} },
			RunIPv6Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
				switch name {
				case "ip":
					return []byte("2001:db8::5 dev eth0 lladdr 00:11:22:33:88:10 REACHABLE\n"), nil
				case "ndp":
					return []byte("Neighbor Linklayer Address Netif Expire St Flgs Prbs\n2001:db8::5%en0 00:11:22:33:88:10 en0 permanent R\n"), nil
				default:
					return nil, nil
				}
			},
			QueryMDNS: func(context.Context) [][]byte {
				return [][]byte{buildTestMDNSPacket("printer.local", [4]byte{10, 88, 0, 20})}
			},
		})
		s.SetRemoteRunner(&mockCLIRemoteRunner{
			sweepXMLByTarget: map[string]string{
				"10.88.0.0/24": `<nmaprun><host><status state="up"/><address addr="10.88.0.10" addrtype="ipv4"/><address addr="00:11:22:33:88:10" addrtype="mac"/><hostnames><hostname name="workstation"/></hostnames></host></nmaprun>`,
				"10.89.0.0/24": `<nmaprun><host><status state="up"/><address addr="10.89.0.5" addrtype="ipv4"/><address addr="00:11:22:33:89:05" addrtype="mac"/></host></nmaprun>`,
			},
		})
		return s, func() {}
	}

	var outBuf, errBuf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&outBuf)
	cmd.SetErr(&errBuf)

	// 1. Invalid CIDR fails immediately
	if err := runScan(cmd, []string{"not-a-cidr"}); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}

	// 2. No args skips Tailscale and scans 10.88.0.0/24
	if err := runScan(cmd, nil); err != nil {
		t.Fatalf("runScan(no args): %v", err)
	}
	if !strings.Contains(outBuf.String(), "Scanning 10.88.0.0/24...") || !strings.Contains(outBuf.String(), "10.88.0.10") {
		t.Fatalf("unexpected default runScan output:\n%s", outBuf.String())
	}

	// 3. Scanning 10.88.0.0/24 again hits rate limit
	outBuf.Reset()
	if err := runScan(cmd, []string{"10.88.0.0/24"}); err != nil {
		t.Fatalf("runScan(rate limited): %v", err)
	}
	if !strings.Contains(outBuf.String(), "Rate limited for 10.88.0.0/24") {
		t.Fatalf("expected rate-limit notice, got:\n%s", outBuf.String())
	}

	// 4. 'all' scans non-rate-limited 10.89.0.0/24, skips rate-limited 10.88.0.0/24, and merges IPv6 + mDNS
	detectNetworksFunc = func() ([]types.Network, error) {
		return []types.Network{
			{CIDR: "10.88.0.0/24", Interface: "eth0"},
			{CIDR: "10.89.0.0/24", Interface: "eth1"},
		}, nil
	}
	outBuf.Reset()
	if err := runScan(cmd, []string{"all"}); err != nil {
		t.Fatalf("runScan(all): %v", err)
	}
	out := outBuf.String()
	for _, want := range []string{
		"Rate limited for 10.88.0.0/24",
		"Scanning 10.89.0.0/24...",
		"10.89.0.5",
		"Found 1 IPv6 neighbor(s)",
		"Found 1 mDNS device(s)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("runScan(all) output missing %q:\n%s", want, out)
		}
	}
}
