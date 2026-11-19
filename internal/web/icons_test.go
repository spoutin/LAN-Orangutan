package web

import (
	"strings"
	"testing"

	"github.com/spoutin/LAN-Orangutan/internal/types"
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

func TestFormatDeviceOS(t *testing.T) {
	cases := []struct {
		name     string
		input    interface{}
		contains []string
		excludes []string
	}{
		{
			name:     "nil device view",
			input:    (*DeviceView)(nil),
			contains: []string{"—"},
		},
		{
			name:     "nil device pointer",
			input:    (*types.Device)(nil),
			contains: []string{"—"},
		},
		{
			name:     "empty device value",
			input:    types.Device{},
			contains: []string{"—"},
		},
		{
			name: "linux strips suffix and appends version with icon",
			input: &DeviceView{
				Device: &types.Device{
					OS:        "Ubuntu Linux",
					OSVersion: "24.04",
					OSFamily:  "Linux",
				},
			},
			contains: []string{`class="os-icon"`, "<span>Ubuntu 24.04</span>"},
			excludes: []string{"Ubuntu Linux"},
		},
		{
			name: "version already contained is not duplicated",
			input: types.Device{
				OS:        "Windows 11",
				OSVersion: "11",
				OSFamily:  "Windows",
			},
			contains: []string{`class="os-icon"`, "<span>Windows 11</span>"},
			excludes: []string{"Windows 11 11"},
		},
		{
			name: "os version without os name",
			input: &types.Device{
				OSVersion: "6.8",
				OSFamily:  "Linux",
			},
			contains: []string{`class="os-icon"`, "<span>6.8</span>"},
		},
		{
			name: "custom OS takes precedence and falls back to customOS icon lookup and escapes HTML",
			input: &types.Device{
				OS:       "Ubuntu Linux",
				CustomOS: "Apple<script>",
			},
			contains: []string{"Apple&lt;script&gt;"},
			excludes: []string{"<script>", "Ubuntu"},
		},
		{
			name: "custom OS with matching family renders icon and escapes text",
			input: &types.Device{
				OSFamily: "BSD",
				CustomOS: "TrueNAS <CORE>",
			},
			contains: []string{`class="os-icon"`, "<span>TrueNAS &lt;CORE&gt;</span>"},
			excludes: []string{"<CORE>"},
		},
		{
			name: "unknown family falls back to plain escaped text",
			input: &types.Device{
				OS:        "Plan9<x>",
				OSVersion: "4e",
				OSFamily:  "Plan9",
			},
			contains: []string{"Plan9&lt;x&gt; 4e"},
			excludes: []string{"<svg", "<x>"},
		},
		{
			name: "custom OS version and family take precedence and append non-duplicate version",
			input: &types.Device{
				OS:              "Linux",
				OSVersion:       "5.15",
				OSFamily:        "",
				CustomOS:        "Ubuntu",
				CustomOSVersion: "24.04.1 LTS",
				CustomOSFamily:  "Linux",
			},
			contains: []string{`class="os-icon"`, "<span>Ubuntu 24.04.1 LTS</span>"},
			excludes: []string{"5.15"},
		},
		{
			name: "custom OS version is not duplicated when already in custom OS",
			input: &types.Device{
				CustomOS:        "Debian 12",
				CustomOSVersion: "12",
				CustomOSFamily:  "Linux",
			},
			contains: []string{`class="os-icon"`, "<span>Debian 12</span>"},
			excludes: []string{"Debian 12 12"},
		},
		{
			name: "substring OS icon matching for Ubuntu without explicit family",
			input: &types.Device{
				OS: "Ubuntu 24.04",
			},
			contains: []string{`class="os-icon"`, "<span>Ubuntu 24.04</span>"},
		},
		{
			name: "substring OS icon matching for macOS without explicit family",
			input: &types.Device{
				OS: "macOS Sequoia",
			},
			contains: []string{`class="os-icon"`, "<span>macOS Sequoia</span>"},
		},
		{
			name: "substring OS icon matching for FreeBSD custom OS",
			input: &types.Device{
				CustomOS: "FreeBSD 14",
			},
			contains: []string{`class="os-icon"`, "<span>FreeBSD 14</span>"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(formatDeviceOS(tc.input))
			for _, sub := range tc.contains {
				if !strings.Contains(got, sub) {
					t.Errorf("formatDeviceOS(%+v) = %q, expected to contain %q", tc.input, got, sub)
				}
			}
			for _, sub := range tc.excludes {
				if strings.Contains(got, sub) {
					t.Errorf("formatDeviceOS(%+v) = %q, expected NOT to contain %q", tc.input, got, sub)
				}
			}
		})
	}
}
