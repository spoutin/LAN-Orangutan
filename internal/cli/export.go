package cli

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/spoutin/LAN-Orangutan/internal/scanner"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

var exportCmd = &cobra.Command{
	Use:   "export <file>",
	Short: "Export devices to CSV file",
	Args:  cobra.ExactArgs(1),
	RunE:  runExport,
}

func runExport(cmd *cobra.Command, args []string) error {
	outputPath := args[0]

	// Validate path (prevent path traversal)
	absPath, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	// Ensure parent directory exists
	dir := filepath.Dir(absPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("directory does not exist: %s", dir)
	}

	// Initialize storage
	store, err := storage.New(cfg.DevicesFile(), cfg.StateFile())
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer store.Close()
	store.SetScanInterval(cfg.Scanning.ScanInterval)
	store.SetNetworkNames(cfg.Scanning.NetworkNames)

	devices := store.GetDevices()

	// Convert to slice and sort by IP
	var deviceList []*types.Device
	for _, d := range devices {
		deviceList = append(deviceList, d)
	}
	sort.Slice(deviceList, func(i, j int) bool {
		return ipToSortKey(deviceList[i].IP) < ipToSortKey(deviceList[j].IP)
	})

	// Create output file
	file, err := os.Create(absPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	scanInterval := time.Duration(cfg.Scanning.ScanInterval) * time.Second
	if err := writeExportCSV(file, deviceList, scanInterval); err != nil {
		return err
	}

	fmt.Fprintf(cmdOut(cmd), "Exported %d devices to %s\n", len(deviceList), absPath)
	return nil
}

func writeExportCSV(out io.Writer, deviceList []*types.Device, scanInterval time.Duration) error {
	// Write CSV
	w := csv.NewWriter(out)

	// Header
	if err := w.Write([]string{
		"IP Address",
		"MAC Address",
		"Hostname",
		"Vendor",
		"Label",
		"Notes",
		"Group",
		"First Seen",
		"Last Seen",
		"Status",
	}); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Data rows
	for _, d := range deviceList {
		status := "offline"
		if d.IsOnline(scanInterval) {
			status = "online"
		}

		if err := w.Write(types.SanitizeCSVRow([]string{
			d.IP,
			d.MAC,
			d.Hostname,
			scanner.ResolveVendor(d.Vendor, d.MAC),
			d.Label,
			d.Notes,
			d.Group,
			d.FirstSeen.Format("2006-01-02 15:04:05"),
			d.LastSeen.Format("2006-01-02 15:04:05"),
			status,
		})); err != nil {
			return fmt.Errorf("failed to write row: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("failed to flush csv: %w", err)
	}
	return nil
}
