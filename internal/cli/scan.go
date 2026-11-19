package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/network"
	"github.com/spoutin/LAN-Orangutan/internal/remotescan"
	"github.com/spoutin/LAN-Orangutan/internal/scanner"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

var (
	detectNetworksFunc = network.DetectNetworks
	newCLIScannerFunc  = func(c *config.Config) (*scanner.Scanner, func()) {
		s := scanner.New(c.Scanning.MinScanInterval, c.Scanning.EnableServiceDetection, c.Scanning.EnablePortScan, c.Scanning.PortScanRange)
		cleanup := func() {}
		if c.RemoteScanners.Enable {
			runner := remotescan.NewRunner(c.RemoteScanners)
			s.SetRemoteRunner(runner)
			cleanup = func() { _ = runner.Close() }
		}
		return s, cleanup
	}
)

func resolveConfiguredNetworks(filter network.Filter) ([]types.Network, error) {
	detected, err := detectNetworksFunc()
	if err != nil {
		return nil, err
	}
	return network.WithConfigured(detected, filter), nil
}

var scanCmd = &cobra.Command{
	Use:   "scan [network|all]",
	Short: "Scan network for devices",
	Long: `Scan a network for devices using nmap or arp-scan.
Specify a network CIDR (e.g., 192.168.1.0/24) or 'all' to scan all detected networks.
If no argument is provided, scans the first detected network.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func runScan(cmd *cobra.Command, args []string) error {
	out := cmdOut(cmd)
	errOut := cmdErr(cmd)

	// Initialize storage
	store, err := storage.New(cfg.DevicesFile(), cfg.StateFile())
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer store.Close()
	store.SetScanInterval(cfg.Scanning.ScanInterval)
	store.SetNetworkNames(cfg.Scanning.NetworkNames)

	// Create scanner
	s, cleanupScanner := newCLIScannerFunc(cfg)
	defer cleanupScanner()

	// Determine networks to scan
	var networks []string

	if len(args) == 0 || args[0] == "" {
		// Scan first detected network
		detected, err := resolveConfiguredNetworks(network.Filter{Configured: cfg.Scanning.Networks, Excluded: cfg.Scanning.ExcludeNetworks, OnlyConfigured: cfg.Scanning.OnlyConfiguredNetworks})
		if err != nil {
			return fmt.Errorf("failed to detect networks: %w", err)
		}
		if len(detected) == 0 {
			return fmt.Errorf("no networks detected")
		}
		// Skip Tailscale by default
		for _, n := range detected {
			if !n.IsTailscale {
				networks = append(networks, n.CIDR)
				break
			}
		}
		if len(networks) == 0 {
			networks = append(networks, detected[0].CIDR)
		}
	} else if args[0] == "all" {
		// Scan all detected networks
		detected, err := resolveConfiguredNetworks(network.Filter{Configured: cfg.Scanning.Networks, Excluded: cfg.Scanning.ExcludeNetworks, OnlyConfigured: cfg.Scanning.OnlyConfiguredNetworks})
		if err != nil {
			return fmt.Errorf("failed to detect networks: %w", err)
		}
		for _, n := range detected {
			networks = append(networks, n.CIDR)
		}
	} else {
		// Scan specified network
		if !network.ValidateCIDR(args[0]) {
			return fmt.Errorf("invalid CIDR: %s", args[0])
		}
		networks = append(networks, args[0])
	}

	if len(networks) == 0 {
		return fmt.Errorf("no networks to scan")
	}

	// Scan each network
	for _, cidr := range networks {
		// Check rate limit
		lastScan := store.GetLastScan(cidr)
		canScan, waitTime := s.CheckRateLimit(lastScan)
		if !canScan {
			fmt.Fprintf(out, "Rate limited for %s, wait %.0f seconds\n", cidr, waitTime.Seconds())
			continue
		}

		fmt.Fprintf(out, "Scanning %s...\n", cidr)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		result, err := s.Scan(ctx, cidr)
		cancel()

		if err != nil {
			fmt.Fprintf(errOut, "Error scanning %s: %v\n", cidr, err)
			continue
		}

		if !result.Success {
			fmt.Fprintf(errOut, "Scan failed for %s: %s\n", cidr, result.Error)
			continue
		}

		// Merge devices
		if _, _, err := store.MergeDevices(result.Devices); err != nil {
			fmt.Fprintf(errOut, "Error saving devices: %v\n", err)
			continue
		}

		// Update last scan time
		if err := store.SetLastScan(cidr, time.Now()); err != nil {
			fmt.Fprintf(errOut, "Error updating scan state: %v\n", err)
		}

		fmt.Fprintf(out, "Found %d devices using %s (%.2fs)\n\n", result.DeviceCount, result.Scanner, result.Duration)

		// Display found devices
		if len(result.Devices) > 0 {
			fmt.Fprintf(out, "%-16s %-18s %-20s %s\n", "IP", "MAC", "HOSTNAME", "VENDOR")
			fmt.Fprintf(out, "%-16s %-18s %-20s %s\n", "──────────────", "─────────────────", "───────────────────", "──────────────────────")
			hasMac := false
			for _, d := range result.Devices {
				hostname := d.Hostname
				if hostname == "" {
					hostname = "-"
				}
				vendor := d.Vendor
				if vendor == "" {
					vendor = "-"
				}
				mac := d.MAC
				if mac == "" {
					mac = "-"
				} else {
					hasMac = true
				}
				fmt.Fprintf(out, "%-16s %-18s %-20s %s\n", d.IP, mac, truncate(hostname, 20), truncate(vendor, 30))
			}
			fmt.Fprintln(out)

			// Warn if no MAC addresses found (permission issue)
			if !hasMac && os.Getuid() != 0 {
				switch runtime.GOOS {
				case "darwin":
					fmt.Fprintln(out, "Note: Run with sudo to get MAC addresses and vendor info:")
					fmt.Fprintln(out, "  sudo ./orangutan scan")
				case "linux":
					fmt.Fprintln(out, "Note: Run with sudo for MAC addresses and vendor info:")
					fmt.Fprintln(out, "  sudo orangutan scan")
				}
				fmt.Fprintln(out)
			}
		}
	}

	// When scanning everything, also pick up IPv6 neighbors and mDNS
	// announcements, which cannot be reached by sweeping a range. Both merge as
	// secondary sources so they enrich rather than overwrite.
	if len(args) > 0 && args[0] == "all" {
		ctx := context.Background()
		if ipv6 := s.DiscoverIPv6(ctx); len(ipv6) > 0 {
			if err := store.MergeSupplemental(ipv6); err != nil {
				fmt.Fprintf(errOut, "Error saving IPv6 neighbors: %v\n", err)
			} else {
				fmt.Fprintf(out, "Found %d IPv6 neighbor(s)\n", len(ipv6))
			}
		}
		if mdns := s.DiscoverMDNS(ctx); len(mdns) > 0 {
			if err := store.MergeSupplemental(mdns); err != nil {
				fmt.Fprintf(errOut, "Error saving mDNS devices: %v\n", err)
			} else {
				fmt.Fprintf(out, "Found %d mDNS device(s)\n", len(mdns))
			}
		}
	}

	return nil
}

// truncate shortens a string to maxLen runes, adding "..." if truncated
func truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-3]) + "..."
}
