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
