package network

import (
	"net"
	"strings"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// Filter describes how the detected network list should be adjusted before it
// is offered for scanning.
type Filter struct {
	// Configured are CIDRs the user declared explicitly. They are always
	// included, even a container bridge, since the user asked for them.
	Configured []string
	// Excluded are CIDRs to drop from the detected list, for real networks the
	// user does not want scanned (a guest VLAN, a slow /16, an overlay). A
	// detected network is dropped when its address falls inside an excluded
	// range. Explicitly configured networks are never excluded.
	Excluded []string
	// OnlyConfigured, when true, ignores auto-detection entirely and offers only
	// the Configured networks. Useful where the automatic list is noisy with
	// container bridges, VLANs or routed interfaces.
	OnlyConfigured bool
}

// WithConfigured returns the detected networks, adjusted by the filter, plus any
// the user has declared explicitly, with duplicates removed.
//
// Automatic detection reads the machine's own interfaces, which is wrong in a
// container: it sees only Docker's private network and never the LAN the user
// actually wants scanned. Declaring a network makes it available to scan and
// visible on the dashboard even though no local interface belongs to it.
func WithConfigured(detected []types.Network, f Filter) []types.Network {
	if f.OnlyConfigured {
		detected = nil
	} else {
		// A container bridge is a real interface but holds containers, not
		// devices on your network. Sweeping it finds nothing and takes minutes.
		detected = ExcludeContainerNetworks(detected)
		detected = excludeNetworks(detected, f.Excluded)
	}
	configured := f.Configured

	seen := make(map[string]bool, len(detected)+len(configured))
	result := make([]types.Network, 0, len(detected)+len(configured))

	for _, n := range detected {
		if seen[n.CIDR] {
			continue
		}
		seen[n.CIDR] = true
		result = append(result, n)
	}

	for _, cidr := range configured {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" || seen[cidr] {
			continue
		}
		if !ValidateCIDR(cidr) {
			continue
		}
		seen[cidr] = true
		result = append(result, types.Network{
			CIDR:         cidr,
			Interface:    "configured",
			FriendlyName: friendlyNameFor(cidr),
		})
	}

	return result
}

// excludeNetworks drops detected networks that fall inside any of the excluded
// CIDRs. A detected network matches when its own address is contained in an
// excluded range, so excluding a wide block (192.168.0.0/20) also drops the
// smaller subnets inside it. Unparseable excludes are ignored.
func excludeNetworks(detected []types.Network, excluded []string) []types.Network {
	if len(excluded) == 0 {
		return detected
	}

	blocks := make([]*net.IPNet, 0, len(excluded))
	for _, cidr := range excluded {
		if _, block, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil {
			blocks = append(blocks, block)
		}
	}
	if len(blocks) == 0 {
		return detected
	}

	out := make([]types.Network, 0, len(detected))
	for _, n := range detected {
		ip, _, err := net.ParseCIDR(n.CIDR)
		if err != nil {
			out = append(out, n) // keep anything we cannot parse rather than drop it
			continue
		}
		if containsAny(blocks, ip) {
			continue
		}
		out = append(out, n)
	}
	return out
}

func containsAny(blocks []*net.IPNet, ip net.IP) bool {
	for _, b := range blocks {
		if b.Contains(ip) {
			return true
		}
	}
	return false
}

// friendlyNameFor labels a declared network so it is distinguishable from one
// that was detected.
func friendlyNameFor(cidr string) string {
	if ip, _, err := net.ParseCIDR(cidr); err == nil {
		return "Configured (" + ip.String() + ")"
	}
	return "Configured"
}

// ParseNetworkList splits a comma or space separated list of CIDRs, as supplied
// through the config file or the environment.
func ParseNetworkList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})

	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
