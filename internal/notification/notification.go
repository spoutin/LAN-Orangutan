package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// ErrInvalidWebhookURL indicates a webhook URL was rejected by SSRF/scheme validation.
var ErrInvalidWebhookURL = errors.New("invalid webhook URL")

// ValidateWebhookURL checks that rawURL is a valid http(s) URL that does not
// target localhost, loopback, link-local/metadata, private, or unspecified IPs.
func ValidateWebhookURL(rawURL string) error {
	return validateWebhookURL(rawURL, false)
}

func validateWebhookURL(rawURL string, allowPrivate bool) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return fmt.Errorf("%w: URL is empty", ErrInvalidWebhookURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: malformed URL", ErrInvalidWebhookURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme must be http or https", ErrInvalidWebhookURL)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: host is required", ErrInvalidWebhookURL)
	}
	if !allowPrivate {
		lowerHost := strings.ToLower(host)
		if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".localhost") ||
			lowerHost == "metadata.google.internal" || lowerHost == "metadata.goog" {
			return fmt.Errorf("%w: host %q is not allowed", ErrInvalidWebhookURL, host)
		}
		if ip := net.ParseIP(host); ip != nil && isBlockedWebhookIP(ip) {
			return fmt.Errorf("%w: IP address %q is not allowed", ErrInvalidWebhookURL, host)
		}
	}
	return nil
}

func isBlockedWebhookIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

func newWebhookDialer(lookupIP func(context.Context, string) ([]net.IPAddr, error)) func(context.Context, string, string) (net.Conn, error) {
	baseDialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if lookupIP == nil {
		lookupIP = net.DefaultResolver.LookupIPAddr
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid address", ErrInvalidWebhookURL)
		}
		if ip := net.ParseIP(host); ip != nil {
			if isBlockedWebhookIP(ip) {
				return nil, fmt.Errorf("%w: target IP is not allowed", ErrInvalidWebhookURL)
			}
			return baseDialer.DialContext(ctx, network, addr)
		}
		ips, err := lookupIP(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("%w: host did not resolve", ErrInvalidWebhookURL)
		}
		for _, ipAddr := range ips {
			if isBlockedWebhookIP(ipAddr.IP) {
				return nil, fmt.Errorf("%w: resolved IP is not allowed", ErrInvalidWebhookURL)
			}
		}
		// Dial the first validated IP directly to avoid TOCTOU DNS rebinding.
		var lastErr error
		for _, ipAddr := range ips {
			conn, dialErr := baseDialer.DialContext(ctx, network, net.JoinHostPort(ipAddr.IP.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
}

func newWebhookHTTPClient(allowPrivate bool) *http.Client {
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	if !allowPrivate {
		transport.DialContext = newWebhookDialer(nil)
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("%w: redirects are not allowed", ErrInvalidWebhookURL)
		},
	}
}

// SendSlackNotification posts a raw message string or payload to Slack
func SendSlackNotification(webhookURL, text string) error {
	return sendSlackNotificationWithClient(webhookURL, text, newWebhookHTTPClient(false), false)
}

func sendSlackNotificationWithClient(webhookURL, text string, client *http.Client, allowPrivate bool) error {
	if err := validateWebhookURL(webhookURL, allowPrivate); err != nil {
		return err
	}
	payload := map[string]interface{}{
		"text": text,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack returned status: %d", resp.StatusCode)
	}
	return nil
}

// FormatConsolidatedSlackMessage creates a beautiful mrkdwn Slack post for network scans
func FormatConsolidatedSlackMessage(networkName, networkCIDR string, newDevices []types.Device, seenDevices []types.Device) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("🔔 *LAN-Orangutan: Network Sweep Report [%s]* (`%s`)\n", networkName, networkCIDR))
	sb.WriteString(fmt.Sprintf("_Scan completed at %s_\n\n", time.Now().Format("2006-01-02 15:04:05")))

	if len(newDevices) > 0 {
		sb.WriteString(fmt.Sprintf("🆕 *%d New Device(s) Discovered:*\n", len(newDevices)))
		for _, d := range newDevices {
			name := d.Label
			if name == "" {
				name = d.CustomHostname
			}
			if name == "" {
				name = d.Hostname
			}
			if name == "" {
				name = "Unknown Device"
			}
			vendor := d.Vendor
			if vendor == "" {
				vendor = "Unknown"
			}
			sb.WriteString(fmt.Sprintf("• *%s* (%s) — _MAC:_ `%s` | _Vendor:_ %s\n", name, d.IP, d.MAC, vendor))
		}
		sb.WriteString("\n")
	}

	if len(seenDevices) > 0 {
		sb.WriteString(fmt.Sprintf("🟢 *%d Tracked Device(s) Online:*\n", len(seenDevices)))
		for _, d := range seenDevices {
			name := d.Label
			if name == "" {
				name = d.CustomHostname
			}
			if name == "" {
				name = d.Hostname
			}
			if name == "" {
				name = "Unknown Device"
			}
			vendor := d.Vendor
			if vendor == "" {
				vendor = "Unknown"
			}
			sb.WriteString(fmt.Sprintf("• *%s* (%s) — _MAC:_ `%s` | _Vendor:_ %s\n", name, d.IP, d.MAC, vendor))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// FormatConsolidatedSlackMessageWithMoves creates a beautiful mrkdwn Slack post for network scans including device moves
func FormatConsolidatedSlackMessageWithMoves(networkName, networkCIDR string, newDevices []types.Device, seenDevices []types.Device, movedDevices []types.DeviceMoveEvent) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("🔔 *LAN-Orangutan: Network Sweep Report [%s]* (`%s`)\n", networkName, networkCIDR))
	sb.WriteString(fmt.Sprintf("_Scan completed at %s_\n\n", time.Now().Format("2006-01-02 15:04:05")))

	if len(newDevices) > 0 {
		sb.WriteString(fmt.Sprintf("🆕 *%d New Device(s) Discovered:*\n", len(newDevices)))
		for _, d := range newDevices {
			name := d.Label
			if name == "" {
				name = d.CustomHostname
			}
			if name == "" {
				name = d.Hostname
			}
			if name == "" {
				name = "Unknown Device"
			}
			vendor := d.Vendor
			if vendor == "" {
				vendor = "Unknown"
			}
			sb.WriteString(fmt.Sprintf("• *%s* (%s) — _MAC:_ `%s` | _Vendor:_ %s\n", name, d.IP, d.MAC, vendor))
		}
		sb.WriteString("\n")
	}

	if len(movedDevices) > 0 {
		sb.WriteString(fmt.Sprintf("🔄 *%d Device(s) Moved / Relocated:*\n", len(movedDevices)))
		for _, m := range movedDevices {
			name := m.Label
			if name == "" {
				name = m.Hostname
			}
			if name == "" {
				name = "Device"
			}
			oldNet := m.OldNetworkName
			if oldNet == "" {
				oldNet = "Previous Network"
			}
			newNet := m.NewNetworkName
			if newNet == "" {
				newNet = "New Network"
			}
			sb.WriteString(fmt.Sprintf("• *%s* moved from %s (`%s`) ➔ %s (`%s`) — _MAC:_ `%s`\n", name, oldNet, m.OldIP, newNet, m.NewIP, m.MAC))
		}
		sb.WriteString("\n")
	}

	if len(seenDevices) > 0 {
		sb.WriteString(fmt.Sprintf("🟢 *%d Tracked Device(s) Online:*\n", len(seenDevices)))
		for _, d := range seenDevices {
			name := d.Label
			if name == "" {
				name = d.CustomHostname
			}
			if name == "" {
				name = d.Hostname
			}
			if name == "" {
				name = "Unknown Device"
			}
			vendor := d.Vendor
			if vendor == "" {
				vendor = "Unknown"
			}
			sb.WriteString(fmt.Sprintf("• *%s* (%s) — _MAC:_ `%s` | _Vendor:_ %s\n", name, d.IP, d.MAC, vendor))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// FormatDeepScanCutoffSlackMessage reports targets left unscanned when the
// nightly maintenance window ends. It deliberately includes aggregate counts
// only, not endpoint or service details.
func FormatDeepScanCutoffSlackMessage(networkName, networkCIDR string, completed, skipped int) string {
	return fmt.Sprintf(
		"⚠️ *LAN-Orangutan: Deep Scan Cut Off* [%s] (`%s`)\n"+
			"The 03:00-06:00 Eastern maintenance window ended before all targets were scanned.\n"+
			"*%d completed*, *%d skipped*.",
		networkName, networkCIDR, completed, skipped,
	)
}

// FormatRemoteScannerFailureSlackMessage formats an alert when a remote edge gateway fails to scan
func FormatRemoteScannerFailureSlackMessage(gateway, target, errorMsg string, isMissingNmap bool) string {
	action := "Scan skipped to protect firewall connection state. Please verify gateway SSH connectivity."
	if isMissingNmap {
		action = "Scan skipped to protect firewall connection state. Nmap appears to be missing on the gateway—please reinstall it (e.g. `pkg install nmap` on OPNsense or `opkg install nmap` on OpenWrt)."
	}
	return fmt.Sprintf(
		"🚨 *LAN-Orangutan: Remote Scanner Failure*\n"+
			"*Gateway:* %s\n"+
			"*Target:* `%s`\n"+
			"*Error:* %s\n"+
			"*Action:* %s",
		gateway, target, errorMsg, action,
	)
}

// FormatRemoteScannerRecoverySlackMessage formats an alert when a remote edge gateway recovers
func FormatRemoteScannerRecoverySlackMessage(gateway, target string) string {
	return fmt.Sprintf(
		"✅ *LAN-Orangutan: Remote Scanner Recovered*\n"+
			"*Gateway:* %s\n"+
			"*Target:* `%s`\n"+
			"*Status:* Remote scan succeeded. Normal edge scanning resumed.",
		gateway, target,
	)
}

// FormatRouterAPIFailureSlackMessage formats an alert when a router DHCP/hosts API poll fails
func FormatRouterAPIFailureSlackMessage(routerType, routerID, errorMsg string) string {
	return fmt.Sprintf(
		"🚨 *LAN-Orangutan: Router API Failure*\n"+
			"*Router:* %s (%s)\n"+
			"*Error:* %s\n"+
			"*Action:* DHCP lease & host discovery failed. Please check router API URL, SSL certificate, and token credentials.",
		routerType, routerID, errorMsg,
	)
}

// FormatRouterAPIRecoverySlackMessage formats an alert when a router DHCP/hosts API recovers
func FormatRouterAPIRecoverySlackMessage(routerType, routerID string) string {
	return fmt.Sprintf(
		"✅ *LAN-Orangutan: Router API Recovered*\n"+
			"*Router:* %s (%s)\n"+
			"*Status:* Router API poll succeeded. Normal DHCP telemetry resumed.",
		routerType, routerID,
	)
}
