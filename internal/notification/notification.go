package notification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// SendSlackNotification posts a raw message string or payload to Slack
func SendSlackNotification(webhookURL, text string) error {
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

	client := &http.Client{Timeout: 10 * time.Second}
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
