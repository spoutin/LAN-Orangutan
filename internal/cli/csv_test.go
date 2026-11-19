package cli

import (
	"bytes"
	"encoding/csv"
	"testing"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

func TestCLICSVExportsNeutralizeFormulaPrefixes(t *testing.T) {
	now := time.Now()
	devices := []*types.Device{
		{
			IP:        "192.168.1.10",
			MAC:       "aa:bb:cc:dd:ee:10",
			Hostname:  "=1+1",
			Vendor:    "@vendor",
			Label:     "+label",
			Notes:     "-note",
			Group:     "\tgroup",
			FirstSeen: now,
			LastSeen:  now,
		},
	}

	var listBuf bytes.Buffer
	if err := writeListCSV(&listBuf, devices); err != nil {
		t.Fatalf("writeListCSV: %v", err)
	}
	listRows, err := csv.NewReader(&listBuf).ReadAll()
	if err != nil {
		t.Fatalf("parse list CSV: %v", err)
	}
	if len(listRows) != 2 {
		t.Fatalf("list CSV rows = %d, want 2", len(listRows))
	}
	if listRows[1][2] != "'=1+1" || listRows[1][3] != "'@vendor" || listRows[1][4] != "'+label" || listRows[1][5] != "'-note" || listRows[1][6] != "'\tgroup" {
		t.Errorf("list CSV did not neutralize formula prefixes: %+v", listRows[1])
	}

	var exportBuf bytes.Buffer
	if err := writeExportCSV(&exportBuf, devices, 5*time.Minute); err != nil {
		t.Fatalf("writeExportCSV: %v", err)
	}
	exportRows, err := csv.NewReader(&exportBuf).ReadAll()
	if err != nil {
		t.Fatalf("parse export CSV: %v", err)
	}
	if len(exportRows) != 2 {
		t.Fatalf("export CSV rows = %d, want 2", len(exportRows))
	}
	if exportRows[1][2] != "'=1+1" || exportRows[1][3] != "'@vendor" || exportRows[1][4] != "'+label" || exportRows[1][5] != "'-note" || exportRows[1][6] != "'\tgroup" {
		t.Errorf("export CSV did not neutralize formula prefixes: %+v", exportRows[1])
	}
}
