package notification

import (
	"strings"
	"testing"
)

func TestFormatDeepScanCutoffSlackMessage(t *testing.T) {
	got := FormatDeepScanCutoffSlackMessage("Office", "10.20.0.0/24", 7, 3)
	for _, want := range []string{
		"Office", "10.20.0.0/24", "03:00-06:00 Eastern", "7 completed", "3 skipped",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("message %q does not contain %q", got, want)
		}
	}
}

func TestFormatRemoteScannerFailureSlackMessage(t *testing.T) {
	msg := FormatRemoteScannerFailureSlackMessage("opnsense (10.0.0.1)", "10.0.0.0/24", "nmap: not found", true)
	for _, want := range []string{
		"Remote Scanner Failure",
		"opnsense (10.0.0.1)",
		"10.0.0.0/24",
		"nmap: not found",
		"pkg install nmap",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not contain %q", msg, want)
		}
	}

	genericMsg := FormatRemoteScannerFailureSlackMessage("openwrt (10.5.5.1)", "10.5.5.0/24", "connection refused", false)
	for _, want := range []string{
		"Remote Scanner Failure",
		"openwrt (10.5.5.1)",
		"10.5.5.0/24",
		"connection refused",
		"SSH connectivity",
	} {
		if !strings.Contains(genericMsg, want) {
			t.Errorf("message %q does not contain %q", genericMsg, want)
		}
	}
}
