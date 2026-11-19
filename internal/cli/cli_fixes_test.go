package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/spoutin/LAN-Orangutan/internal/network"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

type failingWriter struct {
	failAfter int
	written   int
}

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.written >= f.failAfter {
		return 0, errors.New("disk full")
	}
	f.written += len(p)
	return len(p), nil
}

func TestWriteListJSON_ValidJSONWithControlCharsAndEmpty(t *testing.T) {
	var emptyBuf bytes.Buffer
	if err := writeListJSON(&emptyBuf, nil); err != nil {
		t.Fatalf("writeListJSON(nil): %v", err)
	}
	if strings.TrimSpace(emptyBuf.String()) != "[]" {
		t.Fatalf("writeListJSON(nil) = %q, want []", emptyBuf.String())
	}

	devices := []*types.Device{
		{
			IP:       "10.0.0.5",
			MAC:      "aa:bb:cc:dd:ee:05",
			Hostname: "host\x01\"line\"\nbreak",
			Vendor:   "Acme\\Corp",
			Label:    "lab\t1",
			Group:    "grp",
		},
	}
	var buf bytes.Buffer
	if err := writeListJSON(&buf, devices); err != nil {
		t.Fatalf("writeListJSON: %v", err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("writeListJSON produced invalid JSON: %v\noutput:\n%s", err, buf.String())
	}
	if len(decoded) != 1 || decoded[0]["hostname"] != "host\x01\"line\"\nbreak" {
		t.Fatalf("unexpected decoded JSON: %+v", decoded)
	}
}

func TestFormatListOutput_RejectsInvalidFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := formatListOutput(&buf, "xml", nil, time.Minute); err == nil {
		t.Fatal("expected error for invalid format 'xml'")
	}
}

func TestTruncate_RuneAware(t *testing.T) {
	// Multi-byte runes: slicing by bytes would split UTF-8 sequences.
	input := "éééééééééééé" // 12 runes, 24 bytes
	got := truncate(input, 8)
	if !utf8.ValidString(got) {
		t.Fatalf("truncate produced invalid UTF-8: %q", got)
	}
	if utf8.RuneCountInString(got) != 8 {
		t.Fatalf("rune count = %d, want 8 (%q)", utf8.RuneCountInString(got), got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("expected '...' suffix, got %q", got)
	}
}

func TestCSVWriters_CheckFlushError(t *testing.T) {
	devices := []*types.Device{
		{IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:01", FirstSeen: time.Now(), LastSeen: time.Now()},
	}
	if err := writeListCSV(&failingWriter{failAfter: 0}, devices); err == nil {
		t.Fatal("expected writeListCSV to return error when underlying writer fails on Flush")
	}
	if err := writeExportCSV(&failingWriter{failAfter: 0}, devices, time.Minute); err == nil {
		t.Fatal("expected writeExportCSV to return error when underlying writer fails on Flush")
	}
}

func TestResolveConfiguredNetworks_ChecksDetectErrorFirst(t *testing.T) {
	orig := detectNetworksFunc
	t.Cleanup(func() { detectNetworksFunc = orig })

	detectNetworksFunc = func() ([]types.Network, error) {
		return nil, errors.New("netlink failed")
	}

	_, err := resolveConfiguredNetworks(network.Filter{Configured: []string{"10.0.0.0/24"}})
	if err == nil || !strings.Contains(err.Error(), "netlink failed") {
		t.Fatalf("expected netlink failed error, got %v", err)
	}
}

func TestRootCmd_VersionAndHelpDoNotFailOnInvalidConfig(t *testing.T) {
	// Create a config file with a line >1MB or unreadable directory to force config.Load error
	badConfig := filepath.Join(t.TempDir(), "bad.ini")
	if err := os.WriteFile(badConfig, []byte("[remote_scanners]\nssh_key = "+strings.Repeat("x", 2*1024*1024)), 0600); err != nil {
		t.Fatal(err)
	}

	origCfgFile := cfgFile
	origCfg := cfg
	t.Cleanup(func() {
		cfgFile = origCfgFile
		cfg = origCfg
		rootCmd.SetArgs(nil)
	})

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)

	// Help must succeed even with broken config
	rootCmd.SetArgs([]string{"--config", badConfig, "--help"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd --help failed with bad config: %v", err)
	}

	// Version must succeed even with broken config
	out.Reset()
	rootCmd.SetArgs([]string{"--config", badConfig, "version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd version failed with bad config: %v", err)
	}
}
