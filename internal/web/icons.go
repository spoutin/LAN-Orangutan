package web

import (
	"html/template"
	"strings"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// typeIcons maps a device type to a small inline SVG, in the same Lucide style
// (fill none, currentColor stroke) as the other icons in the UI. The strings are
// static, never user input, so rendering them as template.HTML is safe.
var typeIcons = map[string]string{
	"Phone":        `<rect width="14" height="20" x="5" y="2" rx="2"/><path d="M12 18h.01"/>`,
	"Computer":     `<rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/>`,
	"Printer":      `<path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect width="12" height="8" x="6" y="14"/>`,
	"TV":           `<rect width="20" height="15" x="2" y="7" rx="2"/><polyline points="17 2 12 7 7 2"/>`,
	"Media Player": `<circle cx="12" cy="12" r="10"/><polygon points="10 8 16 12 10 16 10 8"/>`,
	"Router":       `<rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6.01 18H6"/><path d="M10.01 18H10"/><path d="M15 10v4"/><path d="M17.84 7.17a4 4 0 0 0-5.66 0"/><path d="M20.66 4.34a8 8 0 0 0-11.31 0"/>`,
	"Server":       `<rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/>`,
	"IoT":          `<rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2"/>`,
	"Game Console": `<line x1="6" x2="10" y1="12" y2="12"/><line x1="8" x2="8" y1="10" y2="14"/><line x1="15" x2="15.01" y1="13" y2="13"/><line x1="18" x2="18.01" y1="11" y2="11"/><rect width="20" height="12" x="2" y="6" rx="2"/>`,
}

// typeIcon returns the inline SVG for a device type, or empty when the type is
// unknown. Used as a template function so the device list can show an icon
// beside each type badge.
func typeIcon(deviceType string) template.HTML {
	body, ok := typeIcons[deviceType]
	if !ok {
		return ""
	}
	return template.HTML(`<svg class="type-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">` + body + `</svg>`)
}

var osIcons = map[string]string{
	"Linux":   `<path d="M12 2a5 5 0 0 0-5 5v5a5 5 0 0 0 10 0V7a5 5 0 0 0-5-5z"/><path d="M7 16a4 4 0 0 0-4 4v1h18v-1a4 4 0 0 0-4-4"/><circle cx="10" cy="7" r="1"/><circle cx="14" cy="7" r="1"/>`,
	"Windows": `<rect width="8" height="8" x="3" y="3" rx="1"/><rect width="8" height="8" x="13" y="3" rx="1"/><rect width="8" height="8" x="3" y="13" rx="1"/><rect width="8" height="8" x="13" y="13" rx="1"/>`,
	"Apple":   `<path d="M12 20.94c1.5 0 2.75-1.06 4-1.06 1.22 0 2.31 1.06 3.81 1.06 1.63 0 3.19-1.47 4.19-3.03-2.19-1.25-2.5-4.47-.28-5.94-1.16-1.78-3.09-2.03-3.72-2.03-1.56 0-2.84 1-3.69 1-.84 0-2.19-1-3.53-1-2.31 0-4.66 1.78-4.66 5.34 0 3.38 2.22 7.66 3.88 7.66z"/><path d="M12 5.5c.88-1.09 1.44-2.59 1.28-4.09-1.25.06-2.81.84-3.69 1.88-.78.91-1.47 2.44-1.28 3.91 1.41.12 2.81-.66 3.69-1.7z"/>`,
	"Darwin":  `<path d="M12 20.94c1.5 0 2.75-1.06 4-1.06 1.22 0 2.31 1.06 3.81 1.06 1.63 0 3.19-1.47 4.19-3.03-2.19-1.25-2.5-4.47-.28-5.94-1.16-1.78-3.09-2.03-3.72-2.03-1.56 0-2.84 1-3.69 1-.84 0-2.19-1-3.53-1-2.31 0-4.66 1.78-4.66 5.34 0 3.38 2.22 7.66 3.88 7.66z"/><path d="M12 5.5c.88-1.09 1.44-2.59 1.28-4.09-1.25.06-2.81.84-3.69 1.88-.78.91-1.47 2.44-1.28 3.91 1.41.12 2.81-.66 3.69-1.7z"/>`,
	"Android": `<path d="M5 16v-6a7 7 0 0 1 14 0v6"/><line x1="8" x2="8" y1="3" y2="6"/><line x1="16" x2="16" y1="3" y2="6"/><circle cx="9" cy="11" r="1"/><circle cx="15" cy="11" r="1"/><rect width="14" height="6" x="5" y="16" rx="2"/>`,
	"BSD":     `<path d="M12 2v20M8 5v6a4 4 0 0 0 8 0V5M5 2l3 3M19 2l-3 3M10 22h4"/>`,
}

// osIcon returns the inline SVG for an OS family, or empty when unknown.
func osIcon(family string) template.HTML {
	body, ok := osIcons[family]
	if !ok {
		return ""
	}
	return template.HTML(`<svg class="os-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">` + body + `</svg>`)
}

// formatDeviceOS formats a device's OS for initial HTML rendering in the table.
func formatDeviceOS(v interface{}) template.HTML {
	var os, osVersion, osFamily, customOS string
	switch d := v.(type) {
	case *DeviceView:
		if d != nil && d.Device != nil {
			os = d.OS
			osVersion = d.OSVersion
			osFamily = d.OSFamily
			customOS = d.CustomOS
		}
	case *types.Device:
		if d != nil {
			os = d.OS
			osVersion = d.OSVersion
			osFamily = d.OSFamily
			customOS = d.CustomOS
		}
	case types.Device:
		os = d.OS
		osVersion = d.OSVersion
		osFamily = d.OSFamily
		customOS = d.CustomOS
	}

	if customOS != "" {
		icon := osIcon(osFamily)
		if icon == "" {
			icon = osIcon(customOS)
		}
		if icon != "" {
			return template.HTML(string(icon) + ` <span>` + template.HTMLEscapeString(customOS) + `</span>`)
		}
		return template.HTML(template.HTMLEscapeString(customOS))
	}
	if os == "" && osVersion == "" {
		return template.HTML(`<span style="color:var(--text-muted)">—</span>`)
	}
	text := os
	if osFamily == "Linux" {
		text = strings.TrimSuffix(strings.TrimSuffix(text, " Linux"), " linux")
	}
	if osVersion != "" && !strings.Contains(text, osVersion) {
		if text != "" {
			text = text + " " + osVersion
		} else {
			text = osVersion
		}
	}
	icon := osIcon(osFamily)
	if icon == "" {
		icon = osIcon(os)
	}
	if icon != "" {
		return template.HTML(string(icon) + ` <span>` + template.HTMLEscapeString(text) + `</span>`)
	}
	return template.HTML(template.HTMLEscapeString(text))
}
