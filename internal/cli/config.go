package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/spoutin/LAN-Orangutan/internal/auth"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Display current configuration",
	RunE:  runConfig,
}

func runConfig(cmd *cobra.Command, args []string) error {
	out := cmdOut(cmd)
	fmt.Fprintln(out, "=== LAN Orangutan Configuration ===")
	fmt.Fprintf(out, "Config file: %s\n", cfgFile)
	fmt.Fprintln(out)

	fmt.Fprintln(out, "[server]")
	fmt.Fprintf(out, "  port = %d\n", cfg.Server.Port)
	fmt.Fprintf(out, "  bind_address = %s\n", cfg.Server.BindAddress)
	fmt.Fprintf(out, "  enable_api = %v\n", cfg.Server.EnableAPI)
	// Never print the password or its hash. Show only whether one is set, and
	// where it came from, which is what someone checking their setup needs.
	fmt.Fprintf(out, "  password = %s\n", passwordSummary())
	fmt.Fprintf(out, "  session_hours = %d\n", cfg.Server.SessionHours)
	fmt.Fprintf(out, "  allow_insecure = %v\n", cfg.Server.AllowInsecure)
	fmt.Fprintln(out)

	fmt.Fprintln(out, "[scanning]")
	fmt.Fprintf(out, "  scan_interval = %d\n", cfg.Scanning.ScanInterval)
	fmt.Fprintf(out, "  min_scan_interval = %d\n", cfg.Scanning.MinScanInterval)
	fmt.Fprintf(out, "  enable_port_scan = %v\n", cfg.Scanning.EnablePortScan)
	fmt.Fprintf(out, "  port_scan_range = %s\n", cfg.Scanning.PortScanRange)
	fmt.Fprintln(out)

	fmt.Fprintln(out, "[storage]")
	fmt.Fprintf(out, "  max_devices = %d\n", cfg.Storage.MaxDevices)
	fmt.Fprintf(out, "  retention_days = %d\n", cfg.Storage.RetentionDays)
	fmt.Fprintf(out, "  data_dir = %s\n", cfg.Storage.DataDir)
	fmt.Fprintln(out)

	fmt.Fprintln(out, "[tailscale]")
	fmt.Fprintf(out, "  enable = %v\n", cfg.Tailscale.Enable)
	fmt.Fprintf(out, "  auto_detect = %v\n", cfg.Tailscale.AutoDetect)
	fmt.Fprintln(out)

	fmt.Fprintln(out, "[ui]")
	fmt.Fprintf(out, "  theme = %s\n", cfg.UI.Theme)

	return nil
}

// passwordSummary describes the password state without revealing it.
func passwordSummary() string {
	if cfg.Server.Password != "" {
		return "(set in config or environment)"
	}
	if auth.LoadHash(cfg.PasswordFile()) != "" {
		return "(set during first run setup)"
	}
	if cfg.RequiresSetup() {
		return "(not set - you will be asked to create one on first visit)"
	}
	return "(not set - not required with this bind address)"
}
