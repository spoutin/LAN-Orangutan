package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/spoutin/LAN-Orangutan/internal/network"
)

var networksCmd = &cobra.Command{
	Use:   "networks",
	Short: "List detected network interfaces",
	RunE:  runNetworks,
}

func runNetworks(cmd *cobra.Command, args []string) error {
	networks, err := network.DetectNetworks()
	networks = network.WithConfigured(networks, network.Filter{Configured: cfg.Scanning.Networks, Excluded: cfg.Scanning.ExcludeNetworks, OnlyConfigured: cfg.Scanning.OnlyConfiguredNetworks})
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
		fmt.Println("No networks detected")
		return nil
	}

	fmt.Println("Detected Networks:")
	fmt.Println()

	for _, n := range networks {
		fmt.Printf("  %s\n", n.CIDR)
		fmt.Printf("    Interface: %s\n", n.Interface)
		fmt.Printf("    Type: %s\n", n.FriendlyName)
		fmt.Printf("    IP: %s\n", n.IP)
		if n.IsTailscale {
			fmt.Printf("    Tailscale: yes\n")
		}
		if n.IsWireless {
			fmt.Printf("    Wireless: yes\n")
		}
		fmt.Println()
	}

	// Show gateway and DNS
	gateway, err := network.GetDefaultGateway()
	if err == nil && gateway != "" {
		fmt.Printf("Default Gateway: %s\n", gateway)
	}

	dns := network.GetDNSServers()
	if len(dns) > 0 {
		fmt.Printf("DNS Servers: %v\n", dns)
	}

	return nil
}
