package types

import (
	"testing"
	"time"
)

func TestIsRecentUsesTwoScanIntervals(t *testing.T) {
	interval := time.Hour
	device := Device{LastSeen: time.Now().Add(-119 * time.Minute)}
	if !device.IsRecent(interval) {
		t.Fatal("device seen within two scan intervals is not recent")
	}
	device.LastSeen = time.Now().Add(-121 * time.Minute)
	if device.IsRecent(interval) {
		t.Fatal("device seen beyond two scan intervals is recent")
	}
}

func TestIsOnlineUsesThreeIntervals(t *testing.T) {
	interval := 35 * time.Minute // 7 networks * 5 minutes
	device := Device{LastSeen: time.Now().Add(-100 * time.Minute)}
	if !device.IsOnline(interval) {
		t.Fatal("device seen within three cycle intervals is not online")
	}
	device.LastSeen = time.Now().Add(-106 * time.Minute)
	if device.IsOnline(interval) {
		t.Fatal("device seen beyond three cycle intervals is online")
	}
}

func TestSanitizeCSVCell(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"nas", "nas"},
		{"my-server", "my-server"},
		{"192.168.1.1", "192.168.1.1"},
		{"=CMD|'/C calc'!A0", "'=CMD|'/C calc'!A0"},
		{"+SUM(1,2)", "'+SUM(1,2)"},
		{"-1+1", "'-1+1"},
		{"@SUM(1,2)", "'@SUM(1,2)"},
		{"\t=1+1", "'\t=1+1"},
		{"\r=1+1", "'\r=1+1"},
		{"  =1+1", "'  =1+1"},
		{"  normal text", "  normal text"},
	}
	for _, tc := range cases {
		if got := SanitizeCSVCell(tc.in); got != tc.want {
			t.Errorf("SanitizeCSVCell(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	row := SanitizeCSVRow([]string{"10.0.0.1", "=1+1", "ok"})
	if len(row) != 3 || row[0] != "10.0.0.1" || row[1] != "'=1+1" || row[2] != "ok" {
		t.Errorf("SanitizeCSVRow returned unexpected slice: %+v", row)
	}
}

func TestIPToLong_ValidAndInvalidOctets(t *testing.T) {
	const invalid = int64(0x7FFFFFFFFFFFFFFF)

	if got := IPToLong("192.168.1.10"); got >= invalid || got <= 0 {
		t.Fatalf("IPToLong(192.168.1.10) = %d, want valid positive int64", got)
	}
	if IPToLong("10.0.0.2") >= IPToLong("10.0.0.10") {
		t.Fatal("expected 10.0.0.2 < 10.0.0.10")
	}

	invalids := []string{
		"",
		"1.2.3",
		"1.2.3.4.5",
		"256.0.0.1",
		"10.0.300.1",
		"10.0.0.999",
		"10.0.0.1a",
		"10.0..1",
		"-1.0.0.1",
		"+1.0.0.1",
		"abc.def.ghi.jkl",
	}
	for _, ip := range invalids {
		if got := IPToLong(ip); got != invalid {
			t.Errorf("IPToLong(%q) = %#x, want invalid sentinel %#x", ip, got, invalid)
		}
	}
}

func TestDevice_LowestIPAndMostActiveIP(t *testing.T) {
	now := time.Now()
	d := Device{
		IP: "192.168.1.50",
		IPs: []IPAttachment{
			{IP: "192.168.1.20", IsActive: false, LastSeen: now},
			{IP: "10.0.0.10", IsActive: true, LastSeen: now.Add(-5 * time.Minute)},
			{IP: "10.0.0.25", IsActive: true, LastSeen: now.Add(-1 * time.Minute)},
		},
	}
	if got := d.LowestIP(); got != "10.0.0.10" {
		t.Errorf("LowestIP() = %q, want 10.0.0.10", got)
	}
	if got := d.MostActiveIP(); got != "10.0.0.25" {
		t.Errorf("MostActiveIP() = %q, want 10.0.0.25 (most recent active)", got)
	}

	// When no attachment is active, MostActiveIP falls back to most recent attachment
	dInactive := Device{
		IP: "192.168.1.50",
		IPs: []IPAttachment{
			{IP: "192.168.1.10", IsActive: false, LastSeen: now.Add(-10 * time.Minute)},
			{IP: "192.168.1.20", IsActive: false, LastSeen: now.Add(-2 * time.Minute)},
		},
	}
	if got := dInactive.MostActiveIP(); got != "192.168.1.20" {
		t.Errorf("MostActiveIP(inactive) = %q, want 192.168.1.20", got)
	}

	// Empty IPs falls back to d.IP
	dFallback := Device{IP: "172.16.0.5"}
	if got := dFallback.LowestIP(); got != "172.16.0.5" {
		t.Errorf("LowestIP(empty) = %q, want 172.16.0.5", got)
	}
	if got := dFallback.MostActiveIP(); got != "172.16.0.5" {
		t.Errorf("MostActiveIP(empty) = %q, want 172.16.0.5", got)
	}
}

func TestDevice_WebURLAndTailscaleStatusLabel(t *testing.T) {
	if got := (Device{IP: "10.0.0.1", CustomWebURL: "https://custom.local:8443"}).WebURL(); got != "https://custom.local:8443" {
		t.Errorf("WebURL custom = %q", got)
	}
	if got := (Device{IP: "10.0.0.1", Hostname: "nas", WebScheme: "https", WebPort: 443}).WebURL(); got != "https://nas" {
		t.Errorf("WebURL https default port = %q, want https://nas", got)
	}
	if got := (Device{IP: "10.0.0.1", CustomHostname: "nas.lan", WebScheme: "http", WebPort: 8080}).WebURL(); got != "http://nas.lan:8080" {
		t.Errorf("WebURL custom port = %q, want http://nas.lan:8080", got)
	}

	labels := map[TailscaleStatus]string{
		{Installed: false}:                                                 "Not installed",
		{Installed: true, Running: false}:                                  "Not running",
		{Installed: true, Running: true, BackendState: "Running"}:          "Connected",
		{Installed: true, Running: true, BackendState: "Stopped"}:          "Stopped",
		{Installed: true, Running: true, BackendState: "NeedsLogin"}:       "Logged out",
		{Installed: true, Running: true, BackendState: "NeedsMachineAuth"}: "Awaiting approval",
		{Installed: true, Running: true, BackendState: "Starting"}:         "Starting",
		{Installed: true, Running: true, BackendState: ""}:                 "Unknown",
		{Installed: true, Running: true, BackendState: "CustomState"}:      "CustomState",
	}
	for st, want := range labels {
		if got := st.StatusLabel(); got != want {
			t.Errorf("StatusLabel(%+v) = %q, want %q", st, got, want)
		}
	}
}
