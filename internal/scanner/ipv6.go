package scanner

import (
	"context"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// ipv6CommandTimeout bounds each helper command (a ping or a neighbor-table
// read). Kept short; these answer locally in well under a second.
const ipv6CommandTimeout = 3 * time.Second

// DiscoverIPv6 finds IPv6 devices on the local links.
//
// An IPv6 subnet holds 2^64 addresses, so sweeping it the way IPv4 is swept is
// impossible. Instead this solicits neighbors with an all-nodes multicast ping,
// prompting hosts to reveal themselves, and then reads the neighbor cache, which
// is the IPv6 equivalent of the ARP table. Only routable neighbors are returned
// (link-local is skipped); storage folds these into the inventory by MAC rather
// than listing each address as its own device.
func (s *Scanner) DiscoverIPv6(ctx context.Context) []types.Device {
	solicitIPv6Neighbors(ctx)

	devices := readIPv6Neighbors(ctx)
	for i := range devices {
		if devices[i].Vendor == "" && devices[i].MAC != "" {
			devices[i].Vendor = GetMACVendor(devices[i].MAC)
		}
		devices[i].Type = Classify(devices[i].Vendor, devices[i].Hostname, nil)
	}
	return devices
}

// solicitIPv6Neighbors pings the all-nodes link-local multicast (ff02::1) on
// each IPv6 interface, so hosts reply and enter the neighbor cache. Best effort:
// failures are ignored, since the cache may already hold neighbors from ordinary
// traffic.
func solicitIPv6Neighbors(ctx context.Context) {
	for _, iface := range ipv6Interfaces() {
		target := "ff02::1%" + iface
		switch runtime.GOOS {
		case "linux":
			_, _ = runIPv6Command(ctx, "ping", "-6", "-c", "1", "-W", "1", target)
		case "darwin":
			_, _ = runIPv6Command(ctx, "ping6", "-c", "1", target)
		}
	}
}

// readIPv6Neighbors reads and parses the OS neighbor cache.
func readIPv6Neighbors(ctx context.Context) []types.Device {
	switch runtime.GOOS {
	case "linux":
		out, err := runIPv6Command(ctx, "ip", "-6", "neigh", "show")
		if err != nil {
			return nil
		}
		return parseIPNeigh(string(out))
	case "darwin":
		out, err := runIPv6Command(ctx, "ndp", "-an")
		if err != nil {
			return nil
		}
		return parseNdp(string(out))
	default:
		return nil
	}
}

func runIPv6Command(ctx context.Context, name string, args ...string) ([]byte, error) {
	c, cancel := context.WithTimeout(ctx, ipv6CommandTimeout)
	defer cancel()
	return exec.CommandContext(c, name, args...).Output()
}

// ipv6Interfaces returns the names of up, non-loopback interfaces that hold an
// IPv6 address.
func ipv6Interfaces() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var names []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() == nil && !n.IP.IsLoopback() {
				names = append(names, iface.Name)
				break
			}
		}
	}
	return names
}

// parseIPNeigh parses Linux `ip -6 neigh show` output. Each line looks like
// "fe80::1 dev eth0 lladdr 00:11:22:33:44:55 router REACHABLE"; entries without
// a link-layer address, or in a FAILED or INCOMPLETE state, are skipped.
func parseIPNeigh(output string) []types.Device {
	var devices []types.Device
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]

		mac := ""
		for i, f := range fields {
			if f == "lladdr" && i+1 < len(fields) {
				mac = fields[i+1]
				break
			}
		}
		if mac == "" {
			continue
		}
		state := fields[len(fields)-1]
		if state == "FAILED" || state == "INCOMPLETE" {
			continue
		}
		if !isUsableIPv6(ip) {
			continue
		}
		devices = append(devices, types.Device{IP: ip, MAC: normalizeMAC(mac)})
	}
	return devices
}

// parseNdp parses macOS `ndp -an` output. The first column is the neighbor
// (address%interface), the second the link-layer address or "(incomplete)".
func parseNdp(output string) []types.Device {
	var devices []types.Device
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "Neighbor" { // header row
			continue
		}
		ip := fields[0]
		if i := strings.IndexByte(ip, '%'); i >= 0 {
			ip = ip[:i]
		}
		mac := fields[1]
		if !strings.Contains(mac, ":") { // "(incomplete)" or similar
			continue
		}
		if !isUsableIPv6(ip) {
			continue
		}
		devices = append(devices, types.Device{IP: ip, MAC: normalizeMAC(mac)})
	}
	return devices
}

// isUsableIPv6 reports whether s is an IPv6 address worth recording from the
// neighbour cache: a routable unicast address. Link-local (fe80::) is excluded
// on purpose -- every device has one, they are not routable, and modern devices
// rotate them behind randomised MACs, so treating each as a device produces
// hundreds of phantoms. Loopback, multicast and the unspecified address are
// dropped too.
func isUsableIPv6(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		return false
	}
	return !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast()
}

// normalizeMAC renders a MAC in a consistent AA:BB:CC:DD:EE:FF form. Some tools
// print octets without a leading zero (0:11:...), which would otherwise not
// match a vendor lookup.
func normalizeMAC(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return strings.ToUpper(strings.TrimSpace(s))
	}
	for i, p := range parts {
		if len(p) == 1 {
			p = "0" + p
		}
		parts[i] = strings.ToUpper(p)
	}
	return strings.Join(parts, ":")
}
