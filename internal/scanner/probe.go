package scanner

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/291-Group/LAN-Orangutan/internal/types"
)

// serviceProbePorts is the short, fixed set of ports the opt-in service probe
// checks. It is deliberately small: enough to sharpen device typing and spot a
// web interface, and never a general port scan. Every port here is one the
// classifier can act on, plus the common web ports for the web-interface flag.
var serviceProbePorts = []int{
	21,    // FTP (unencrypted, a security flag)
	22,    // SSH
	23,    // Telnet (unencrypted, a security flag)
	80,    // HTTP (web interface)
	443,   // HTTPS (web interface)
	515,   // LPD printing
	548,   // AFP (NAS)
	631,   // IPP printing
	3389,  // RDP
	5000,  // Synology DSM
	5001,  // Synology DSM (TLS)
	8080,  // alt HTTP (web interface)
	8096,  // Jellyfin
	9100,  // raw JetDirect printing
	32400, // Plex
	62078, // iOS lockdown
}

// riskyServices maps an open port to a plainly worded security concern. Kept
// deliberately high-signal: Telnet and FTP are unencrypted by design, so
// finding them open is a real red flag, not noise a router's web page would be.
var riskyServices = map[int]string{
	23: "Telnet is open (unencrypted remote access)",
	21: "FTP is open (unencrypted file transfer)",
}

// webPorts are the ports that, if open, mark a device as serving a web
// interface.
var webPorts = map[int]bool{80: true, 443: true, 8080: true}

// serviceProbeTimeout bounds a single TCP connection attempt. Short, because a
// device on the LAN answers in milliseconds and a closed port should not stall
// the scan waiting for it.
const serviceProbeTimeout = 400 * time.Millisecond

// serviceProbeConcurrency caps how many devices are probed at once, so a large
// network does not open thousands of sockets in the same instant.
const serviceProbeConcurrency = 24

// enrichWithServices probes each device's well-known ports and updates its type
// and web-interface flag from what it finds. It only runs when the user has
// enabled service detection. Devices are probed concurrently up to a cap; each
// device's ports are probed concurrently in turn, so the whole pass costs about
// one timeout per batch rather than one per closed port.
func enrichWithServices(ctx context.Context, devices []types.Device) {
	sem := make(chan struct{}, serviceProbeConcurrency)
	var wg sync.WaitGroup

	for i := range devices {
		wg.Add(1)
		sem <- struct{}{}
		go func(d *types.Device) {
			defer wg.Done()
			defer func() { <-sem }()

			ports := d.OpenPorts
			if len(ports) == 0 {
				ports = probeServices(ctx, d.IP)
			}

			// Re-classify with the port evidence. Only overwrite when the fuller
			// signal yields a type, so a probe that finds nothing does not wipe
			// the vendor or hostname guess made earlier.
			if t := Classify(d.Vendor, d.Hostname, ports); t != "" {
				d.Type = t
			}

			// Check for web servers on open ports
			webPortDetected := 0
			for _, p := range ports {
				if isWebPort(ctx, d.IP, p) {
					webPortDetected = p
					break
				}
			}

			d.WebUI = webPortDetected > 0
			if webPortDetected > 0 {
				// Record the port if it's non-standard (standard ports 80/443 don't need port suffix in link)
				if webPortDetected != 80 && webPortDetected != 443 {
					d.WebPort = webPortDetected
				}
			}
			d.Risks = risksFromPorts(ports)
		}(&devices[i])
	}

	wg.Wait()
}

// isWebPort checks if an open port serves an HTTP/HTTPS web interface.
func isWebPort(ctx context.Context, ip string, port int) bool {
	// 1. Check standard list first
	if webPorts[port] {
		return true
	}

	// Skip standard non-web ports immediately to avoid noise and slow connections
	switch port {
	case 21, 22, 23, 25, 110, 143, 445, 515, 631, 9100, 3389:
		return false
	}

	// 2. Dynamic HTTP handshake probe
	url := "http://" + net.JoinHostPort(ip, strconv.Itoa(port))
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return false
	}

	// Use a very light client with extremely short timeout
	client := &http.Client{
		Timeout: 200 * time.Millisecond,
		// Do not follow redirects (if it redirects, it means there is a web server!)
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		return true
	}

	// Fallback to HTTPS probe if HTTP failed
	urlTLS := "https://" + net.JoinHostPort(ip, strconv.Itoa(port))
	reqTLS, err := http.NewRequestWithContext(ctx, "HEAD", urlTLS, nil)
	if err != nil {
		return false
	}

	// Create insecure client for self-signed certificates
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	clientTLS := &http.Client{
		Timeout:   200 * time.Millisecond,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	respTLS, err := clientTLS.Do(reqTLS)
	if err == nil {
		respTLS.Body.Close()
		return true
	}

	return false
}

// probeServices attempts a TCP connection to each port in serviceProbePorts and
// returns those that accept one. Ports are tried concurrently with a short
// timeout, and the whole context deadline still applies so a cancelled scan
// stops promptly.
func probeServices(ctx context.Context, ip string) []int {
	var (
		mu   sync.Mutex
		open []int
		wg   sync.WaitGroup
	)

	for _, port := range serviceProbePorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			dialer := net.Dialer{Timeout: serviceProbeTimeout}
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
			if err != nil {
				return
			}
			conn.Close()
			mu.Lock()
			open = append(open, p)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	return open
}

// risksFromPorts turns the open ports into any security concerns they imply, in
// the fixed order of serviceProbePorts so the result is stable.
func risksFromPorts(ports []int) []string {
	var risks []string
	seen := make(map[int]bool, len(ports))
	for _, p := range ports {
		seen[p] = true
	}
	for _, p := range serviceProbePorts {
		if seen[p] {
			if msg, ok := riskyServices[p]; ok {
				risks = append(risks, msg)
			}
		}
	}
	return risks
}

// hasWebPort reports whether any of the probed open ports is a web port.
func hasWebPort(ports []int) bool {
	for _, p := range ports {
		if webPorts[p] {
			return true
		}
	}
	return false
}
