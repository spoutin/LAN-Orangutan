// Package types defines the core domain types for LAN Orangutan
package types

import (
	"fmt"
	"time"
)

// Device represents a discovered network device
type Device struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
	Vendor   string `json:"vendor"`
	// Type is the inferred device kind (Phone, Printer, TV, and so on), or ""
	// when it could not be determined. It is derived at scan time from the
	// vendor, the hostname and, when service detection is on, the open ports.
	Type string `json:"type,omitempty"`
	// WebUI is true when the device answered on a common web port during an
	// opt-in service probe, meaning it likely serves a dashboard or admin page.
	// Always false when service detection is off.
	WebUI bool `json:"web_ui,omitempty"`
	// Risks lists security concerns found during an opt-in service probe, such as
	// an exposed unencrypted service. Empty when nothing notable was found or the
	// probe is off.
	Risks          []string  `json:"risks,omitempty"`
	Label          string    `json:"label"`
	Notes          string    `json:"notes"`
	Group          string    `json:"group"`
	CustomHostname string    `json:"custom_hostname,omitempty"`
	CustomWebURL   string    `json:"custom_web_url,omitempty"`
	CustomType     string    `json:"custom_type,omitempty"`
	WebPort        int       `json:"web_port,omitempty"`
	WebScheme      string    `json:"web_scheme,omitempty"`
	Probed         bool      `json:"probed,omitempty"`
	Assignment     string    `json:"assignment,omitempty"`
	OpenPorts      []int     `json:"-"`
	NetworkName    string    `json:"network_name,omitempty"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	ResponseTime   *float64  `json:"response_time,omitempty"`

	// AddressHistory lists earlier IPs this device (matched by its MAC) was seen
	// at, oldest first. Empty for a device that has never changed address.
	AddressHistory []AddressChange `json:"address_history,omitempty"`

	// LinkedMAC specifies the parent MAC address this device is linked (aliased) to.
	LinkedMAC string `json:"linked_mac,omitempty"`

	// NotifyOnSeen specifies if a Slack notification should be sent each time the device comes online.
	NotifyOnSeen bool `json:"notify_on_seen"`

	// LinkedChildren lists the display labels of child devices linked to this device.
	LinkedChildren []string `json:"linked_children,omitempty"`

	// LinkedChildrenDetails stores structured details about each linked child device.
	LinkedChildrenDetails []LinkedChild `json:"linked_children_details,omitempty"`
}

// LinkedChild represents brief state details of a linked child device
type LinkedChild struct {
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	Hostname    string `json:"hostname"`
	NetworkName string `json:"network_name"`
	IsOnline    bool   `json:"is_online"`
}

// AddressChange records an IP a device was previously seen at, and when it moved
// away from it, so the dashboard can show that a device has changed address.
type AddressChange struct {
	IP        string    `json:"ip"`
	ChangedAt time.Time `json:"changed_at"`
}

// IsOnline returns true if the device was seen within the last 3 scan intervals (or 1 hour default)
func (d *Device) IsOnline(scanIntervals ...time.Duration) bool {
	interval := time.Hour
	if len(scanIntervals) > 0 && scanIntervals[0] > 0 {
		interval = 3 * scanIntervals[0]
	}
	return time.Since(d.LastSeen) < interval
}

// IsRecent returns true if the device was seen within the last scan interval + grace buffer (or 5 min default)
func (d *Device) IsRecent(scanIntervals ...time.Duration) bool {
	interval := 5 * time.Minute
	if len(scanIntervals) > 0 && scanIntervals[0] > 0 {
		interval = scanIntervals[0]
	}
	// Add 20% grace buffer, minimum of 2 minutes, so it waits for the next scan to finish before turning yellow
	buffer := interval / 5
	if buffer < 2*time.Minute {
		buffer = 2 * time.Minute
	}
	return time.Since(d.LastSeen) < interval+buffer
}

// Network represents a detected network interface
type Network struct {
	CIDR         string `json:"cidr"`
	Interface    string `json:"interface"`
	FriendlyName string `json:"friendly_name"`
	IP           string `json:"ip"`
	IsTailscale  bool   `json:"is_tailscale"`
	IsWireless   bool   `json:"is_wireless"`
}

// ScanState holds the last scan time for rate limiting
type ScanState struct {
	LastScan map[string]time.Time `json:"last_scan"`
	// LastDuration records how long the previous scan of each network took,
	// in seconds, so the UI can estimate progress for subsequent scans.
	LastDuration map[string]float64 `json:"last_duration,omitempty"`
	// ContinuousScan is a runtime override for background scanning, set from the
	// UI. nil means "use the configured default"; a set value wins over config
	// so the user's choice survives a restart.
	ContinuousScan *bool `json:"continuous_scan,omitempty"`
}

// ScanResult represents the outcome of a network scan
type ScanResult struct {
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
	Devices     []Device  `json:"devices"`
	DeviceCount int       `json:"device_count"`
	Network     string    `json:"network"`
	Scanner     string    `json:"scanner"`
	Duration    float64   `json:"duration"`
	Timestamp   time.Time `json:"timestamp"`
}

// TailscaleStatus represents Tailscale connection status
type TailscaleStatus struct {
	Installed bool `json:"installed"`
	// Running reports only that the Tailscale daemon answered. It stays true
	// when the user is logged out or has stopped Tailscale, so it must not be
	// used to decide whether traffic can flow: use Connected for that.
	Running bool `json:"running"`
	// Connected reports whether Tailscale is actually up and usable.
	Connected    bool   `json:"connected"`
	BackendState string `json:"backend_state"`
	Version      string `json:"version"`
	TailnetName  string `json:"tailnet_name"`
	SelfIP       string `json:"self_ip"`
	SelfHostname string `json:"self_hostname"`
	PeerCount    int    `json:"peer_count"`
	ExitNode     string `json:"exit_node,omitempty"`
}

// StatusLabel describes the Tailscale connection in words suitable for display.
func (t TailscaleStatus) StatusLabel() string {
	if !t.Installed {
		return "Not installed"
	}
	if !t.Running {
		return "Not running"
	}

	switch t.BackendState {
	case "Running":
		return "Connected"
	case "Stopped":
		return "Stopped"
	case "NeedsLogin":
		return "Logged out"
	case "NeedsMachineAuth":
		return "Awaiting approval"
	case "Starting":
		return "Starting"
	case "NoState", "":
		return "Unknown"
	default:
		return t.BackendState
	}
}

// APIResponse is the standard API response wrapper
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// ScanHistoryRecord represents a past scan execution log
type ScanHistoryRecord struct {
	ID              int       `json:"id"`
	Network         string    `json:"network"`
	Success         bool      `json:"success"`
	Error           string    `json:"error,omitempty"`
	DevicesOnline   int       `json:"devices_online"`
	DevicesJoined   int       `json:"devices_joined"`
	DevicesReturned int       `json:"devices_returned"`
	DevicesLeft     int       `json:"devices_left"`
	Duration        float64   `json:"duration"`
	Timestamp       time.Time `json:"timestamp"`
}

// PresenceEventRecord represents a device presence history log
type PresenceEventRecord struct {
	ID          int       `json:"id"`
	IP          string    `json:"ip"`
	MAC         string    `json:"mac"`
	Hostname    string    `json:"hostname"`
	Event       string    `json:"event"`
	Duration    float64   `json:"duration"`
	CreatedAt   time.Time `json:"created_at"`
	NetworkName string    `json:"network_name,omitempty"`
}

// DeviceStats holds device statistics for the dashboard
type DeviceStats struct {
	Total   int            `json:"total"`
	Online  int            `json:"online"`
	Offline int            `json:"offline"`
	Groups  map[string]int `json:"groups"`
}

// WebURL returns the full web interface URL for the device.
func (d Device) WebURL() string {
	if d.CustomWebURL != "" {
		return d.CustomWebURL
	}

	scheme := d.WebScheme
	if scheme == "" {
		scheme = "http" // default fallback
	}

	host := d.IP
	if d.CustomHostname != "" {
		host = d.CustomHostname
	} else if d.Hostname != "" {
		host = d.Hostname
	}

	portSuffix := ""
	if d.WebPort > 0 {
		// Only include port if it is non-standard for the scheme
		if !(scheme == "http" && d.WebPort == 80) && !(scheme == "https" && d.WebPort == 443) {
			portSuffix = fmt.Sprintf(":%d", d.WebPort)
		}
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, portSuffix)
}

// NetworkNotification represents the webhook configurations per network CIDR
type NetworkNotification struct {
	NetworkCIDR  string `json:"network_cidr"`
	SlackWebhook string `json:"slack_webhook"`
	Enabled      bool   `json:"enabled"`
}

