package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/spoutin/LAN-Orangutan/internal/network"
)

var (
	getDefaultGatewayFunc = network.GetDefaultGateway
	getDNSServersFunc     = network.GetDNSServers
)

var networksCmd = &cobra.Command{
	Use:   "networks",
	Short: "List detected network interfaces",
	RunE:  runNetworks,
}

func runNetworks(cmd *cobra.Command, args []string) error {
	out := cmdOut(cmd)
	networks, err := resolveConfiguredNetworks(network.Filter{Configured: cfg.Scanning.Networks, Excluded: cfg.Scanning.ExcludeNetworks, OnlyConfigured: cfg.Scanning.OnlyConfiguredNetworks})
	if err != nil {
		return fmt.Errorf("failed to detect networks: %w", err)
	}

	// Override FriendlyName using our custom network names configuration
	for i, n := range networks {
		if name, ok := cfg.Scanning.NetworkNames[n.CIDR]; ok {
			networks[i].FriendlyName = name
		}
	}

	if len(networks) == 0 {
		fmt.Fprintln(out, "No networks detected")
		return nil
	}

	fmt.Fprintln(out, "Detected Networks:")
	fmt.Fprintln(out)

	for _, n := range networks {
		fmt.Fprintf(out, "  %s\n", n.CIDR)
		fmt.Fprintf(out, "    Interface: %s\n", n.Interface)
		fmt.Fprintf(out, "    Type: %s\n", n.FriendlyName)
		fmt.Fprintf(out, "    IP: %s\n", n.IP)
		if n.IsTailscale {
			fmt.Fprintf(out, "    Tailscale: yes\n")
		}
		if n.IsWireless {
			fmt.Fprintf(out, "    Wireless: yes\n")
		}
		fmt.Fprintln(out)
	}

	// Show gateway and DNS
	gateway, err := getDefaultGatewayFunc()
	if err == nil && gateway != "" {
		fmt.Fprintf(out, "Default Gateway: %s\n", gateway)
	}

	dns := getDNSServersFunc()
	if len(dns) > 0 {
		fmt.Fprintf(out, "DNS Servers: %v\n", dns)
	}

	return nil
}
