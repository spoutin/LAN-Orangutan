package types

import "strings"

// SanitizeCSVCell neutralizes spreadsheet formula injection (CSV injection)
// by prefixing cells that start with =, +, -, @, tab, or carriage return
// (ignoring leading spaces) with a single quote.
func SanitizeCSVCell(s string) string {
	if s == "" {
		return ""
	}
	trimmed := strings.TrimLeft(s, " ")
	if trimmed == "" {
		return s
	}
	switch trimmed[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	default:
		return s
	}
}

// SanitizeCSVRow returns a new slice with SanitizeCSVCell applied to each cell.
func SanitizeCSVRow(row []string) []string {
	out := make([]string, len(row))
	for i, cell := range row {
		out[i] = SanitizeCSVCell(cell)
	}
	return out
}
