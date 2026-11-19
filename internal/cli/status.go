package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/spoutin/LAN-Orangutan/internal/network"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
)

var (
	lookPathFunc           = exec.LookPath
	getToolVersionFunc     = getToolVersion
	getTailscaleStatusFunc = network.GetTailscaleStatus
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show system and service status",
	RunE:  runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	out := cmdOut(cmd)
	fmt.Fprintln(out, "=== LAN Orangutan Status ===")
	fmt.Fprintln(out)

	// System info
	fmt.Fprintln(out, "System:")
	fmt.Fprintf(out, "  Go Version: %s\n", runtime.Version())
	fmt.Fprintf(out, "  OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	// Check tools
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Tools:")
	checkTool(out, "nmap")
	checkTool(out, "arp-scan")
	checkTool(out, "tailscale")

	// Storage
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Storage:")
	store, err := storage.New(cfg.DevicesFile(), cfg.StateFile())
	if err != nil {
		fmt.Fprintf(out, "  Error: %v\n", err)
	} else {
		defer store.Close()
		store.SetScanInterval(cfg.Scanning.ScanInterval)
		store.SetNetworkNames(cfg.Scanning.NetworkNames)
		stats := store.GetStats()
		fmt.Fprintf(out, "  Devices: %d total (%d online, %d offline)\n", stats.Total, stats.Online, stats.Offline)
		fmt.Fprintf(out, "  Data directory: %s\n", cfg.Storage.DataDir)
	}

	// Networks
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Networks:")
	networks, err := resolveConfiguredNetworks(network.Filter{Configured: cfg.Scanning.Networks, Excluded: cfg.Scanning.ExcludeNetworks, OnlyConfigured: cfg.Scanning.OnlyConfiguredNetworks})
	if err != nil {
		fmt.Fprintf(out, "  Error detecting: %v\n", err)
	} else {
		for _, n := range networks {
			flags := []string{}
			if n.IsTailscale {
				flags = append(flags, "tailscale")
			}
			if n.IsWireless {
				flags = append(flags, "wireless")
			}
			flagStr := ""
			if len(flags) > 0 {
				flagStr = " [" + strings.Join(flags, ", ") + "]"
			}
			fmt.Fprintf(out, "  %s (%s)%s\n", n.CIDR, n.Interface, flagStr)
		}
	}

	// Tailscale
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Tailscale:")
	ts := getTailscaleStatusFunc()
	if !ts.Installed {
		fmt.Fprintln(out, "  Not installed")
	} else if !ts.Running {
		fmt.Fprintln(out, "  Installed but not running")
	} else {
		fmt.Fprintf(out, "  Status: %s\n", ts.StatusLabel())
		// The IP and peer count are cached from the last session and go stale
		// once Tailscale stops, so only report them while connected.
		if ts.Connected {
			fmt.Fprintf(out, "  IP: %s\n", ts.SelfIP)
			fmt.Fprintf(out, "  Hostname: %s\n", ts.SelfHostname)
			fmt.Fprintf(out, "  Peers: %d\n", ts.PeerCount)
		}
	}

	// Server config
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Server:")
	fmt.Fprintf(out, "  Port: %d\n", cfg.Server.Port)
	fmt.Fprintf(out, "  Bind: %s\n", cfg.Server.BindAddress)
	fmt.Fprintf(out, "  API enabled: %v\n", cfg.Server.EnableAPI)

	return nil
}

func checkTool(out io.Writer, name string) {
	path, err := lookPathFunc(name)
	if err != nil {
		fmt.Fprintf(out, "  %s: not found\n", name)
	} else {
		// Get version
		version := getToolVersionFunc(name)
		if version != "" {
			fmt.Fprintf(out, "  %s: %s (%s)\n", name, version, path)
		} else {
			fmt.Fprintf(out, "  %s: %s\n", name, path)
		}
	}
}

func getToolVersion(name string) string {
	var cmd *exec.Cmd
	switch name {
	case "nmap":
		cmd = exec.Command("nmap", "--version")
	case "arp-scan":
		cmd = exec.Command("arp-scan", "--version")
	case "tailscale":
		cmd = exec.Command("tailscale", "--version")
	default:
		return ""
	}

	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Extract first line
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
