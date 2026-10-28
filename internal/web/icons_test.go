package web

import (
	"strings"
	"testing"
)

func TestTypeIcon(t *testing.T) {
	// Every type the classifier can produce should have an icon.
	for _, dt := range []string{"Phone", "Computer", "Printer", "TV", "Media Player", "Router", "Server", "IoT", "Game Console"} {
		html := string(typeIcon(dt))
		if !strings.Contains(html, "<svg") {
			t.Errorf("type %q has no icon", dt)
		}
	}
	// An unknown type yields no icon, not broken markup.
	if got := typeIcon("Nonsense"); got != "" {
		t.Errorf("unknown type should yield empty, got %q", got)
	}
	if got := typeIcon(""); got != "" {
		t.Errorf("empty type should yield empty, got %q", got)
	}
}

func TestOSIcon(t *testing.T) {
	for _, fam := range []string{"Linux", "Windows", "Darwin", "Apple", "Android", "BSD"} {
		html := string(osIcon(fam))
		if !strings.Contains(html, "<svg") {
			t.Errorf("family %q has no icon", fam)
		}
	}
	if got := osIcon("Unknown"); got != "" {
		t.Errorf("unknown family should yield empty, got %q", got)
	}
}
