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
