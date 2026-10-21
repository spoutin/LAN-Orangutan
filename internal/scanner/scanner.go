// Package scanner handles network device discovery using nmap and arp-scan
package scanner

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/network"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// RemoteRunner executes scans on remote gateways over SSH
type RemoteRunner interface {
	HasRemoteScannerForTarget(target string) bool
	GetGatewayForTarget(target string) string
	RunScan(ctx context.Context, target string, args []string) ([]byte, error)
	CanRunPrivileged(target string) bool
}

// Scanner performs network scans
type Scanner struct {
	minInterval time.Duration
	// serviceDetection turns on the opt-in probe that identifies devices by
	// their open ports. Off by default; a scan stays a quiet ping sweep.
	serviceDetection bool
	enablePortScan   bool
	portScanRange    string
	remoteRunner     RemoteRunner
	localPrivileged  *bool
}

// New creates a new Scanner. serviceDetection enables the opt-in port probe
// used to identify devices more precisely.
func New(minIntervalSeconds int, serviceDetection bool, enablePortScan bool, portScanRange string) *Scanner {
	return &Scanner{
		minInterval:      time.Duration(minIntervalSeconds) * time.Second,
		serviceDetection: serviceDetection,
		enablePortScan:   enablePortScan,
		portScanRange:    portScanRange,
	}
}

// SetRemoteRunner registers a remote execution runner for edge gateways
func (s *Scanner) SetRemoteRunner(runner RemoteRunner) {
	s.remoteRunner = runner
}

// GetRemoteRunner returns the registered remote runner, or nil
func (s *Scanner) GetRemoteRunner() RemoteRunner {
	return s.remoteRunner
}

// nmapRun represents the root element of nmap XML output
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	PortID   int           `xml:"portid,attr"`
	Protocol string        `xml:"protocol,attr"`
	State    nmapPortState `xml:"state"`
	Service  nmapService   `xml:"service"`
}

type nmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	OSType    string `xml:"ostype,attr"`
}

type nmapPortState struct {
	State string `xml:"state,attr"`
}

// nmapHost represents a host element in nmap XML output
type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Hostnames nmapHostnames `xml:"hostnames"`
	Times     nmapTimes     `xml:"times"`
	Ports     nmapPorts     `xml:"ports"`
	OS        nmapOS        `xml:"os"`
}

// nmapStatus represents the host status
type nmapStatus struct {
	State string `xml:"state,attr"`
}

// nmapAddress represents an address element
type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

// nmapHostnames contains hostname information
type nmapHostnames struct {
	Hostnames []nmapHostname `xml:"hostname"`
}

// nmapHostname represents a single hostname
type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// nmapTimes contains timing information
type nmapTimes struct {
	SRTT string `xml:"srtt,attr"`
}

// Scan performs a network scan on the given CIDR
func (s *Scanner) Scan(ctx context.Context, cidr string) (*types.ScanResult, error) {
	// Validate CIDR
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	startTime := time.Now()

	// Tailscale gives every node its own /32, so there is no subnet to sweep
	// and a scan could only ever find this machine. Tailscale already knows the
	// whole tailnet, so ask it for the peers instead.
	if network.IsTailscaleNetwork(cidr) {
		return s.scanTailscale(cidr, startTime), nil
	}

	// If a remote scanner is registered for this CIDR, use it without falling back to local scanning
	if s.remoteRunner != nil && s.remoteRunner.HasRemoteScannerForTarget(cidr) {
		devices, scannerName, err := s.scanWithNmap(ctx, cidr)
		if err != nil {
			return &types.ScanResult{
				Success:   false,
				Error:     err.Error(),
				Network:   cidr,
				Scanner:   scannerName,
				Timestamp: time.Now(),
			}, nil
		}
		fillWindowsNames(ctx, devices)
		if s.serviceDetection {
			EnrichWithServices(ctx, devices)
		}
		return &types.ScanResult{
			Success:     true,
			Devices:     devices,
			DeviceCount: len(devices),
			Network:     cidr,
			Scanner:     scannerName,
			Duration:    time.Since(startTime).Seconds(),
			Timestamp:   time.Now(),
		}, nil
	}

	// Try nmap first
	devices, scanner, err := s.scanWithNmap(ctx, cidr)
	if err != nil {
		// Fallback to arp-scan
		devices, scanner, err = s.scanWithArpScan(ctx, cidr)
		if err != nil {
			return &types.ScanResult{
				Success:   false,
				Error:     err.Error(),
				Network:   cidr,
				Timestamp: time.Now(),
			}, nil
		}
	}

	// Recover names for devices that reverse DNS could not name, over NetBIOS.
	// This is name resolution like the reverse DNS lookup above, so it always
	// runs, and only touches devices that still have no hostname.
	fillWindowsNames(ctx, devices)

	// With service detection on, probe each device's well-known ports to refine
	// its type and flag a web interface. This is the only step that sends more
	// than a ping or a name query, so it stays behind the opt-in flag.
	if s.serviceDetection {
		EnrichWithServices(ctx, devices)
	}

	duration := time.Since(startTime).Seconds()

	return &types.ScanResult{
		Success:     true,
		Devices:     devices,
		DeviceCount: len(devices),
		Network:     cidr,
		Scanner:     scanner,
		Duration:    duration,
		Timestamp:   time.Now(),
	}, nil
}

// scanTailscale lists the devices reachable over Tailscale.
func (s *Scanner) scanTailscale(cidr string, startTime time.Time) *types.ScanResult {
	devices := network.GetTailscaleDevices()
	if devices == nil {
		return &types.ScanResult{
			Success:   false,
			Error:     "Tailscale is not connected",
			Network:   cidr,
			Timestamp: time.Now(),
		}
	}

	return &types.ScanResult{
		Success:     true,
		Devices:     devices,
		DeviceCount: len(devices),
		Network:     cidr,
		Scanner:     "tailscale",
		Duration:    time.Since(startTime).Seconds(),
		Timestamp:   time.Now(),
	}
}

// scanWithNmap performs a scan using nmap
func (s *Scanner) scanWithNmap(ctx context.Context, cidr string) ([]types.Device, string, error) {
	args := []string{"-sn", "-n", "-oX", "-", cidr}
	var output []byte
	var err error
	scannerName := "nmap"

	if s.remoteRunner != nil && s.remoteRunner.HasRemoteScannerForTarget(cidr) {
		scannerName = "remote-nmap"
		// On the edge router, omit -n so Nmap uses the router's local resolver to resolve hostnames
		remoteArgs := []string{"-sn", "-oX", "-", cidr}
		output, err = s.remoteRunner.RunScan(ctx, cidr, remoteArgs)
		if err != nil {
			return nil, "", err
		}
	} else {
		// Check if nmap is available
		if _, lookErr := exec.LookPath("nmap"); lookErr != nil {
			return nil, "", fmt.Errorf("nmap not found")
		}

		// Run nmap with a fast ping sweep and disable reverse DNS (we decouple port scanning to run asynchronously in Stage 2)
		cmd := exec.CommandContext(ctx, "nmap", args...)
		output, err = cmd.Output()
		if err != nil {
			return nil, "", fmt.Errorf("nmap failed: %w", err)
		}
	}

	// Parse XML output
	var result nmapRun
	if err := xml.Unmarshal(output, &result); err != nil {
		return nil, "", fmt.Errorf("failed to parse nmap output: %w", err)
	}

	var devices []types.Device
	for _, host := range result.Hosts {
		if host.Status.State != "up" {
			continue
		}

		device := types.Device{}

		// Extract addresses
		for _, addr := range host.Addresses {
			switch addr.AddrType {
			case "ipv4":
				device.IP = addr.Addr
			case "mac":
				device.MAC = addr.Addr
				if addr.Vendor != "" {
					device.Vendor = addr.Vendor
				}
			}
		}

		if device.IP == "" {
			continue
		}

		// Get vendor from MAC if not set
		if device.Vendor == "" && device.MAC != "" {
			device.Vendor = GetMACVendor(device.MAC)
		}

		// Extract hostname
		for _, hostname := range host.Hostnames.Hostnames {
			if hostname.Name != "" {
				device.Hostname = hostname.Name
				break
			}
		}

		// Try reverse DNS if no hostname
		if device.Hostname == "" {
			device.Hostname = s.reverseDNSForTarget(device.IP, cidr)
		}

		// Parse response time
		if host.Times.SRTT != "" {
			if srtt, err := parseResponseTime(host.Times.SRTT); err == nil {
				device.ResponseTime = &srtt
			}
		}

		// Extract open ports if present
		var openPorts []int
		for _, port := range host.Ports.Ports {
			if port.State.State == "open" {
				openPorts = append(openPorts, port.PortID)
			}
		}
		device.OpenPorts = openPorts

		// Infer the device type from the vendor and hostname. Port signals are
		// not available here yet; a ping scan finds no open ports. Opt-in
		// service detection will pass them in a later step.
		device.Type = Classify(device.Vendor, device.Hostname, openPorts)

		devices = append(devices, device)
	}

	return devices, scannerName, nil
}

// scanWithArpScan performs a scan using arp-scan
func (s *Scanner) scanWithArpScan(ctx context.Context, cidr string) ([]types.Device, string, error) {
	// Check if arp-scan is available
	if _, err := exec.LookPath("arp-scan"); err != nil {
		return nil, "", fmt.Errorf("arp-scan not found")
	}

	// Extract interface from CIDR if possible
	iface := getInterfaceForCIDR(ctx, cidr)

	// Run arp-scan
	args := []string{"--localnet", "-q"}
	if iface != "" {
		args = append(args, "-I", iface)
	}
	cmd := exec.CommandContext(ctx, "arp-scan", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, "", fmt.Errorf("arp-scan failed: %w", err)
	}

	// Parse output (format: IP\tMAC\tVendor)
	var devices []types.Device
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Interface:") || strings.HasPrefix(line, "Starting") || strings.HasPrefix(line, "Ending") {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}

		ip := strings.TrimSpace(parts[0])
		mac := strings.TrimSpace(parts[1])

		// Validate IP
		if net.ParseIP(ip) == nil {
			continue
		}

		device := types.Device{
			IP:  ip,
			MAC: mac,
		}

		// Get vendor
		if len(parts) >= 3 {
			device.Vendor = strings.TrimSpace(parts[2])
		}
		if device.Vendor == "" {
			device.Vendor = GetMACVendor(mac)
		}

		// Try reverse DNS
		device.Hostname = s.reverseDNSForTarget(ip, cidr)

		device.Type = Classify(device.Vendor, device.Hostname, nil)

		devices = append(devices, device)
	}

	return devices, "arp-scan", nil
}

func extractHostFromGateway(gw string) string {
	start := strings.Index(gw, "(")
	end := strings.Index(gw, ")")
	if start != -1 && end != -1 && end > start+1 {
		return strings.TrimSpace(gw[start+1 : end])
	}
	return ""
}

func (s *Scanner) reverseDNSForTarget(ip, cidr string) string {
	dnsServer := ""
	if s.remoteRunner != nil && s.remoteRunner.HasRemoteScannerForTarget(cidr) {
		gw := s.remoteRunner.GetGatewayForTarget(cidr)
		dnsServer = extractHostFromGateway(gw)
	}
	return reverseDNSWithServer(ip, dnsServer)
}

func reverseDNSWithServer(ip, dnsServer string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan string, 1)
	go func() {
		var resolver *net.Resolver
		if dnsServer != "" {
			resolver = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 2 * time.Second}
					return d.DialContext(ctx, "udp", net.JoinHostPort(dnsServer, "53"))
				},
			}
		} else {
			resolver = net.DefaultResolver
		}
		names, err := resolver.LookupAddr(ctx, ip)
		if err != nil || len(names) == 0 {
			if dnsServer != "" {
				if defNames, defErr := net.DefaultResolver.LookupAddr(ctx, ip); defErr == nil && len(defNames) > 0 {
					done <- strings.TrimSuffix(defNames[0], ".")
					return
				}
			}
			done <- ""
			return
		}
		done <- strings.TrimSuffix(names[0], ".")
	}()

	select {
	case <-ctx.Done():
		return ""
	case hostname := <-done:
		return hostname
	}
}

// reverseDNS performs a reverse DNS lookup
func reverseDNS(ip string) string {
	return reverseDNSWithServer(ip, "")
}

// parseResponseTime parses nmap SRTT value (microseconds) to milliseconds
func parseResponseTime(srtt string) (float64, error) {
	var usec int
	if _, err := fmt.Sscanf(srtt, "%d", &usec); err != nil {
		return 0, err
	}
	return float64(usec) / 1000.0, nil
}

// CheckRateLimit checks if a scan can proceed based on rate limiting
func (s *Scanner) CheckRateLimit(lastScan time.Time) (bool, time.Duration) {
	if lastScan.IsZero() {
		return true, 0
	}

	elapsed := time.Since(lastScan)
	if elapsed >= s.minInterval {
		return true, 0
	}

	return false, s.minInterval - elapsed
}

// getInterfaceForCIDR tries to determine which network interface to use for a given CIDR
func getInterfaceForCIDR(ctx context.Context, cidr string) string {
	targetIP := strings.Split(cidr, "/")[0]

	switch runtime.GOOS {
	case "linux":
		// Linux: use ip route get
		cmd := exec.CommandContext(ctx, "ip", "route", "get", targetIP)
		if output, err := cmd.Output(); err == nil {
			parts := strings.Fields(string(output))
			for i, p := range parts {
				if p == "dev" && i+1 < len(parts) {
					return parts[i+1]
				}
			}
		}

	case "darwin":
		// macOS: use route get
		cmd := exec.CommandContext(ctx, "route", "-n", "get", targetIP)
		if output, err := cmd.Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "interface:") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						return parts[len(parts)-1]
					}
				}
			}
		}
	}

	// Fallback: try to find an interface that matches the CIDR using Go's net package
	_, cidrNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if cidrNet.Contains(ipNet.IP) {
					return iface.Name
				}
			}
		}
	}

	return ""
}

// isLocalPrivileged checks if the current process has root privileges to run nmap -O.
func (s *Scanner) isLocalPrivileged() bool {
	if s.localPrivileged != nil {
		return *s.localPrivileged
	}
	isPriv := os.Geteuid() == 0
	s.localPrivileged = &isPriv
	return isPriv
}

func (s *Scanner) setLocalPrivileged(val bool) {
	s.localPrivileged = &val
}

// ScanHostPorts performs a high-speed targeted port scan on a single IP address.
func (s *Scanner) ScanHostPorts(ctx context.Context, ip string, portRange string) ([]int, []int, []types.OpenService, string, string, string, error) {
	return s.ScanHostPortsWithTiming(ctx, ip, portRange, false)
}

// ScanHostPortsWithTiming runs a targeted service scan. Nightly scans use the
// conservative timing profile to keep connection state pressure low.
func (s *Scanner) ScanHostPortsWithTiming(ctx context.Context, ip string, portRange string, conservative bool) ([]int, []int, []types.OpenService, string, string, string, error) {
	privileged := false
	isRemote := s.remoteRunner != nil && s.remoteRunner.HasRemoteScannerForTarget(ip)
	if isRemote {
		privileged = s.remoteRunner.CanRunPrivileged(ip)
	} else {
		privileged = s.isLocalPrivileged()
	}

	args := portScanArgumentsWithTiming(portRange, ip, conservative, privileged)
	var output []byte
	var err error

	if isRemote {
		output, err = s.remoteRunner.RunScan(ctx, ip, args)
		if err != nil {
			return nil, nil, nil, "", "", "", err
		}
	} else {
		if _, lookErr := exec.LookPath("nmap"); lookErr != nil {
			return nil, nil, nil, "", "", "", fmt.Errorf("nmap not found")
		}

		cmd := exec.CommandContext(ctx, "nmap", args...)
		output, err = cmd.Output()
		if err != nil && privileged {
			errMsg := err.Error()
			if exitErr, ok := err.(*exec.ExitError); ok {
				errMsg += " " + string(exitErr.Stderr)
			}
			if strings.Contains(strings.ToLower(errMsg), "requires root") || strings.Contains(strings.ToLower(errMsg), "root privileges") {
				s.setLocalPrivileged(false)
				fallbackArgs := portScanArgumentsWithTiming(portRange, ip, conservative, false)
				cmd = exec.CommandContext(ctx, "nmap", fallbackArgs...)
				output, err = cmd.Output()
			}
		}
		if err != nil {
			return nil, nil, nil, "", "", "", fmt.Errorf("nmap port scan failed: %w", err)
		}
	}
	return parsePortScanResult(output)
}

func portScanArguments(portRange string, ip string) []string {
	return portScanArgumentsWithTiming(portRange, ip, false, false)
}

func portScanArgumentsWithTiming(portRange string, ip string, conservative, privileged bool) []string {
	// Stage 1 already established that this host is reachable. Skipping host
	// discovery avoids false negatives from a separate probe, while retries make
	// service detection reliable on busy or rate-limited devices.
	timing := "-T4"
	if conservative {
		timing = "-T2"
	}
	args := []string{"-sV", "-Pn", "-p", portRange, timing, "-n", "--max-retries", "2", "--host-timeout", "180s"}
	if privileged {
		args = append(args, "-O", "--osscan-limit", "--osscan-guess")
	}
	args = append(args, "-oX", "-", ip)
	return args
}

func parsePortScanResult(output []byte) ([]int, []int, []types.OpenService, string, string, string, error) {
	var result nmapRun
	if err := xml.Unmarshal(output, &result); err != nil {
		return nil, nil, nil, "", "", "", fmt.Errorf("failed to parse nmap output: %w", err)
	}

	var openPorts []int
	var sshPorts []int
	var services []types.OpenService
	var osName, osVersion, osFamily string
	if len(result.Hosts) > 0 {
		host := result.Hosts[0]
		for _, port := range host.Ports.Ports {
			if port.State.State == "open" {
				openPorts = append(openPorts, port.PortID)
				version := strings.TrimSpace(strings.Join([]string{port.Service.Product, port.Service.Version, port.Service.ExtraInfo}, " "))
				services = append(services, types.OpenService{Port: port.PortID, Name: port.Service.Name, Version: version})
				if port.Service.Name == "ssh" {
					sshPorts = append(sshPorts, port.PortID)
				}
			}
		}
		osName, osVersion, osFamily = InferOS(host.OS.Matches, services)
	}

	return openPorts, sshPorts, services, osName, osVersion, osFamily, nil
}
