package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/spoutin/LAN-Orangutan/internal/scanner"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

var (
	listOnline  bool
	listOffline bool
	listGroup   string
	listFormat  string
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List discovered devices",
	Long:  `List all discovered devices with optional filtering by status or group.`,
	RunE:  runList,
}

func init() {
	listCmd.Flags().BoolVar(&listOnline, "online", false, "Show only online devices")
	listCmd.Flags().BoolVar(&listOffline, "offline", false, "Show only offline devices")
	listCmd.Flags().StringVar(&listGroup, "group", "", "Filter by group")
	listCmd.Flags().StringVar(&listFormat, "format", "table", "Output format (table, csv, json)")
}

func runList(cmd *cobra.Command, args []string) error {
	// Initialize storage
	store, err := storage.New(cfg.DevicesFile(), cfg.StateFile())
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer store.Close()
	store.SetScanInterval(cfg.Scanning.ScanInterval)
	store.SetNetworkNames(cfg.Scanning.NetworkNames)

	devices := store.GetDevices()

	scanInterval := time.Duration(cfg.Scanning.ScanInterval) * time.Second

	// Convert to slice and filter
	var filtered []*types.Device
	for _, d := range devices {
		// Apply filters
		if listOnline && !d.IsOnline(scanInterval) {
			continue
		}
		if listOffline && d.IsOnline(scanInterval) {
			continue
		}
		if listGroup != "" && !strings.EqualFold(d.Group, listGroup) {
			continue
		}
		filtered = append(filtered, d)
	}

	// Sort by IP
	sort.Slice(filtered, func(i, j int) bool {
		return ipToSortKey(filtered[i].IP) < ipToSortKey(filtered[j].IP)
	})

	// Output based on format
	return formatListOutput(cmdOut(cmd), listFormat, filtered, scanInterval)
}

func formatListOutput(out io.Writer, format string, devices []*types.Device, scanInterval time.Duration) error {
	switch format {
	case "csv":
		return writeListCSV(out, devices)
	case "json":
		return writeListJSON(out, devices)
	case "table", "":
		return writeListTable(out, devices, scanInterval)
	default:
		return fmt.Errorf("invalid format %q: must be table, csv, or json", format)
	}
}

func outputTable(devices []*types.Device, scanInterval time.Duration) error {
	return writeListTable(os.Stdout, devices, scanInterval)
}

func writeListTable(out io.Writer, devices []*types.Device, scanInterval time.Duration) error {
	if len(devices) == 0 {
		fmt.Fprintln(out, "No devices found")
		return nil
	}

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tMAC\tHOSTNAME\tVENDOR\tLABEL\tGROUP\tSTATUS")
	fmt.Fprintln(w, "--\t---\t--------\t------\t-----\t-----\t------")

	for _, d := range devices {
		status := "offline"
		if d.IsRecent(scanInterval) {
			status = "online"
		} else if d.IsOnline(scanInterval) {
			status = "seen"
		}

		hostname := truncate(d.Hostname, 25)
		vendor := truncate(scanner.ResolveVendor(d.Vendor, d.MAC), 20)

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			d.IP, d.MAC, hostname, vendor, d.Label, d.Group, status)
	}

	return w.Flush()
}

func outputCSV(devices []*types.Device) error {
	return writeListCSV(os.Stdout, devices)
}

func writeListCSV(out io.Writer, devices []*types.Device) error {
	w := csv.NewWriter(out)

	// Header
	if err := w.Write([]string{"IP", "MAC", "Hostname", "Vendor", "Label", "Notes", "Group", "First Seen", "Last Seen"}); err != nil {
		return err
	}

	for _, d := range devices {
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
		})); err != nil {
			return err
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("failed to flush csv: %w", err)
	}
	return nil
}

type listDeviceJSON struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
	Vendor   string `json:"vendor"`
	Label    string `json:"label"`
	Group    string `json:"group"`
}

func outputJSON(devices []*types.Device) error {
	return writeListJSON(os.Stdout, devices)
}

func writeListJSON(out io.Writer, devices []*types.Device) error {
	items := make([]listDeviceJSON, 0, len(devices))
	for _, d := range devices {
		items = append(items, listDeviceJSON{
			IP:       d.IP,
			MAC:      d.MAC,
			Hostname: d.Hostname,
			Vendor:   scanner.ResolveVendor(d.Vendor, d.MAC),
			Label:    d.Label,
			Group:    d.Group,
		})
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(items)
}

// ipToSortKey converts an IP to a sortable integer
func ipToSortKey(ipStr string) int64 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0x7FFFFFFFFFFFFFFF // Sort invalid IPs last
	}
	ip = ip.To4()
	if ip == nil {
		return 0x7FFFFFFFFFFFFFFF
	}
	return int64(ip[0])<<24 | int64(ip[1])<<16 | int64(ip[2])<<8 | int64(ip[3])
}
