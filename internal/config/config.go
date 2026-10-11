// Package config handles configuration loading and management
package config

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/network"
)

// GetDefaultDataDir returns the appropriate default data directory for the current OS
func GetDefaultDataDir() string {
	switch runtime.GOOS {
	case "darwin":
		// macOS: use Application Support
		home, err := os.UserHomeDir()
		if err != nil {
			return "/tmp/lan-orangutan"
		}
		return filepath.Join(home, "Library", "Application Support", "lan-orangutan")

	case "windows":
		// Windows: use AppData
		appData := os.Getenv("APPDATA")
		if appData == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "C:\\lan-orangutan"
			}
			return filepath.Join(home, "AppData", "Roaming", "lan-orangutan")
		}
		return filepath.Join(appData, "lan-orangutan")

	default:
		// Linux and others
		// Use /var/lib if running as root, otherwise use user's local share
		if os.Getuid() == 0 {
			return "/var/lib/lan-orangutan"
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "/tmp/lan-orangutan"
		}
		return filepath.Join(home, ".local", "share", "lan-orangutan")
	}
}

// GetDefaultConfigFile returns the appropriate default config file path for the current OS
func GetDefaultConfigFile() string {
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "/tmp/lan-orangutan/config.ini"
		}
		return filepath.Join(home, "Library", "Application Support", "lan-orangutan", "config.ini")

	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			return "C:\\lan-orangutan\\config.ini"
		}
		return filepath.Join(appData, "lan-orangutan", "config.ini")

	default:
		// Linux: use /etc if running as root, otherwise use user config
		if os.Getuid() == 0 {
			return "/etc/lan-orangutan/config.ini"
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "/tmp/lan-orangutan/config.ini"
		}
		return filepath.Join(home, ".config", "lan-orangutan", "config.ini")
	}
}

// Config holds all application configuration
type Config struct {
	Server         ServerConfig
	Scanning       ScanningConfig
	Storage        StorageConfig
	Tailscale      TailscaleConfig
	UI             UIConfig
	OpenWrt        OpenWrtConfig
	OpenWrts       OpenWrtsConfig
	OPNsense       OPNsenseConfig
	UniFi          UniFiConfig
	Switches       SwitchesConfig
	RemoteScanners RemoteScannersConfig
}

// OpenWrtConfig holds OpenWrt connection and remote scanning settings
type OpenWrtConfig struct {
	ID          string   `json:"id,omitempty"`
	Enable      bool     `json:"enable"`
	URL         string   `json:"url"`
	APIToken    string   `json:"-"`
	VerifySSL   bool     `json:"verify_ssl"`
	RemoteScan  bool     `json:"remote_scan"`
	SSHHost     string   `json:"ssh_host,omitempty"`
	SSHPort     int      `json:"ssh_port,omitempty"`
	SSHUser     string   `json:"ssh_user,omitempty"`
	SSHSudo     bool     `json:"ssh_sudo,omitempty"`
	SSHKey      string   `json:"-"`
	SSHKeyFile  string   `json:"ssh_key_file,omitempty"`
	SSHPassword string   `json:"-"`
	Networks    []string `json:"networks,omitempty"`
}

// OpenWrtsConfig holds multiple configured OpenWrt routers
type OpenWrtsConfig struct {
	Names   []string
	Configs map[string]OpenWrtConfig
}

// OPNsenseConfig holds OPNsense connection and remote scanning settings
type OPNsenseConfig struct {
	Enable      bool     `json:"enable"`
	URL         string   `json:"url"`
	APIKey      string   `json:"-"`
	APISecret   string   `json:"-"`
	VerifySSL   bool     `json:"verify_ssl"`
	RemoteScan  bool     `json:"remote_scan"`
	SSHHost     string   `json:"ssh_host,omitempty"`
	SSHPort     int      `json:"ssh_port,omitempty"`
	SSHUser     string   `json:"ssh_user,omitempty"`
	SSHSudo     bool     `json:"ssh_sudo,omitempty"`
	SSHKey      string   `json:"-"`
	SSHKeyFile  string   `json:"ssh_key_file,omitempty"`
	SSHPassword string   `json:"-"`
	Networks    []string `json:"networks,omitempty"`
}

// UniFiConfig holds UniFi controller connection settings
type UniFiConfig struct {
	Enable    bool
	URL       string
	Site      string
	APIKey    string
	VerifySSL bool
}

// SwitchesConfig holds the ordered list of SNMP switches and their settings.
type SwitchesConfig struct {
	Enable  bool
	Names   []string
	Configs map[string]SwitchConfig
}

// SwitchConfig holds SNMPv3 authPriv connection settings for one switch.
type SwitchConfig struct {
	ID              string
	Host            string
	Port            int
	Version         int
	Username        string
	SecurityLevel   string
	AuthProtocol    string
	AuthPassword    string `json:"-"`
	PrivacyProtocol string
	PrivacyPassword string `json:"-"`
	TimeoutSeconds  int
}

// RemoteScannersConfig holds settings for offloading Nmap scans to edge firewalls over SSH.
type RemoteScannersConfig struct {
	Enable      bool                           `json:"enable"`
	Sudo        bool                           `json:"sudo,omitempty"`
	SSHKey      string                         `json:"-"` // in-memory PEM encoded private key (not serialized)
	SSHKeyFile  string                         `json:"ssh_key_file,omitempty"`
	SSHPassword string                         `json:"-"` // optional password (not serialized)
	Names       []string                       `json:"names,omitempty"`
	Configs     map[string]RemoteScannerConfig `json:"configs,omitempty"`
}

// RemoteScannerConfig holds settings for one remote gateway scanner.
type RemoteScannerConfig struct {
	ID          string   `json:"id"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	User        string   `json:"user"`
	Sudo        bool     `json:"sudo"`
	Networks    []string `json:"networks"`
	SSHKey      string   `json:"-"` // per-gateway in-memory PEM key (not serialized)
	SSHKeyFile  string   `json:"ssh_key_file,omitempty"`
	SSHPassword string   `json:"-"` // per-gateway password (not serialized)
}

// FindScannerForCIDR finds the remote scanner configured for a subnet CIDR
func (c *RemoteScannersConfig) FindScannerForCIDR(cidr string) (*RemoteScannerConfig, bool) {
	if !c.Enable {
		return nil, false
	}
	cidr = strings.TrimSpace(cidr)
	for _, id := range c.Names {
		cfg := c.Configs[id]
		for _, netStr := range cfg.Networks {
			if strings.EqualFold(strings.TrimSpace(netStr), cidr) {
				return &cfg, true
			}
		}
	}
	return nil, false
}

// FindScannerForIP finds the remote scanner configured for an IP's subnet
func (c *RemoteScannersConfig) FindScannerForIP(ipStr string) (*RemoteScannerConfig, bool) {
	if !c.Enable {
		return nil, false
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return nil, false
	}
	for _, id := range c.Names {
		cfg := c.Configs[id]
		for _, netStr := range cfg.Networks {
			_, ipNet, err := net.ParseCIDR(strings.TrimSpace(netStr))
			if err == nil && ipNet.Contains(ip) {
				return &cfg, true
			}
		}
	}
	return nil, false
}

// Validate verifies that c uses the supported secure SNMPv3 configuration.
func (c SwitchConfig) Validate() error {
	if c.Version != 3 {
		return fmt.Errorf("switch %q: version must be 3", c.ID)
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("switch %q: port must be between 1 and 65535", c.ID)
	}
	if !strings.EqualFold(c.SecurityLevel, "authPriv") {
		return fmt.Errorf("switch %q: security_level must be authPriv", c.ID)
	}
	if !strings.EqualFold(c.AuthProtocol, "SHA") {
		return fmt.Errorf("switch %q: auth_protocol must be SHA", c.ID)
	}
	if !strings.EqualFold(c.PrivacyProtocol, "DES") && !strings.EqualFold(c.PrivacyProtocol, "AES") {
		return fmt.Errorf("switch %q: privacy_protocol must be DES or AES", c.ID)
	}
	if c.Host == "" {
		return fmt.Errorf("switch %q: host is required", c.ID)
	}
	if c.Username == "" {
		return fmt.Errorf("switch %q: username is required", c.ID)
	}
	if c.AuthPassword == "" {
		return fmt.Errorf("switch %q: auth_password is required", c.ID)
	}
	if c.PrivacyPassword == "" {
		return fmt.Errorf("switch %q: privacy_password is required", c.ID)
	}
	if c.TimeoutSeconds <= 0 {
		return fmt.Errorf("switch %q: timeout_seconds must be positive", c.ID)
	}
	return nil
}

// ServerConfig holds web server settings
type ServerConfig struct {
	Port        int
	BindAddress string
	EnableAPI   bool

	// Password protects the dashboard and API. Empty means no login is
	// required. May be given as plaintext or as a bcrypt hash.
	Password string

	// SessionHours is how long a login stays valid.
	SessionHours int

	// AllowInsecure permits binding to a non-loopback address without a
	// password. Off by default: doing so exposes the API, which can modify
	// stored data, to everyone on the network.
	AllowInsecure bool
}

// ScanningConfig holds scanner settings
type ScanningConfig struct {
	ScanInterval    int
	MinScanInterval int
	EnablePortScan  bool
	PortScanRange   string

	// ContinuousScan makes the server re-scan the detected networks on its own
	// every ScanInterval seconds, so the device list stays current without
	// anyone clicking Scan or keeping a browser open. On by default: a
	// discovery tool that only ever shows one stale scan is not much use. Set
	// it false to scan only on demand.
	ContinuousScan bool

	// EnableServiceDetection turns on a light probe of a few well-known ports
	// during a scan, used only to identify devices more precisely (a printer, a
	// NAS, a device with a web interface). Off by default so the scan stays a
	// quiet ping sweep unless the user opts in.
	EnableServiceDetection bool

	// OnlyConfiguredNetworks, when true, offers only the networks declared in
	// Networks and ignores everything auto-detection finds. Useful on a host
	// with many Docker bridges, VLANs or routed interfaces where the automatic
	// list is noisy.
	OnlyConfiguredNetworks bool

	// ExcludeNetworks are CIDRs to drop from the auto-detected list, for real
	// networks the user does not want scanned. A blocklist that complements
	// Networks (the allowlist): keep auto-detection but hide a few subnets.
	ExcludeNetworks []string

	// Networks are CIDRs the user has declared explicitly, for cases where
	// automatic detection cannot see the right network. A container only sees
	// Docker's private network, so without this it can never scan the LAN.
	Networks []string

	// NetworkNames maps CIDRs to their friendly/user-defined names (e.g. "10.0.0.0/24" -> "LAN")
	NetworkNames map[string]string
}

// StorageConfig holds data storage settings
type StorageConfig struct {
	MaxDevices    int
	RetentionDays int
	DataDir       string
}

// TailscaleConfig holds Tailscale integration settings
type TailscaleConfig struct {
	Enable     bool
	AutoDetect bool
}

// UIConfig holds user interface settings
type UIConfig struct {
	Theme string
}

// Sensible fallbacks for the scan timings, also used by Normalize to repair an
// out-of-range value rather than let it silently disable a feature.
const (
	defaultScanInterval    = 300
	defaultMinScanInterval = 30
)

// Default returns a Config with default values
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Port: 291,
			// Reachable from the network, because this is usually installed on
			// a server or a Pi and opened from another machine. Safety comes
			// from RequiresSetup: with no password set, the only thing a
			// visitor can reach is the page that creates one.
			BindAddress:  "0.0.0.0",
			EnableAPI:    true,
			SessionHours: 24 * 7,
		},
		Scanning: ScanningConfig{
			ScanInterval:           defaultScanInterval,
			MinScanInterval:        defaultMinScanInterval,
			EnablePortScan:         false,
			PortScanRange:          "1-1024",
			ContinuousScan:         true,
			EnableServiceDetection: false,
			NetworkNames:           make(map[string]string),
		},
		Storage: StorageConfig{
			MaxDevices:    1000,
			RetentionDays: 90,
			DataDir:       GetDefaultDataDir(),
		},
		Tailscale: TailscaleConfig{
			Enable:     true,
			AutoDetect: true,
		},
		UI: UIConfig{
			Theme: "auto",
		},
		OpenWrt: OpenWrtConfig{
			Enable:    false,
			VerifySSL: false,
		},
		OpenWrts: OpenWrtsConfig{
			Configs: make(map[string]OpenWrtConfig),
		},
		OPNsense: OPNsenseConfig{
			Enable:    false,
			VerifySSL: false,
		},
		UniFi: UniFiConfig{
			Enable:    false,
			Site:      "default",
			VerifySSL: false,
		},
		Switches: SwitchesConfig{
			Configs: make(map[string]SwitchConfig),
		},
		RemoteScanners: RemoteScannersConfig{
			Configs: make(map[string]RemoteScannerConfig),
		},
	}
}

// Load reads configuration from an INI file
func Load(path string) (*Config, error) {
	cfg := Default()

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // Return defaults if file doesn't exist
		}
		return nil, fmt.Errorf("failed to open config: %w", err)
	}
	defer file.Close()

	var currentSection string
	var currentKey string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.ToLower(line[1 : len(line)-1])
			currentKey = ""
			continue
		}

		// Key-value pair
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			currentKey = strings.TrimSpace(strings.ToLower(parts[0]))
			value := strings.TrimSpace(parts[1])
			cfg.setValue(currentSection, currentKey, value)
		} else if currentKey == "ssh_key" && currentSection == "remote_scanners" {
			cfg.RemoteScanners.SSHKey += "\n" + line
		} else if currentKey == "ssh_key" && strings.HasPrefix(currentSection, "remote_scanner.") {
			id := strings.TrimPrefix(currentSection, "remote_scanner.")
			cfg.ensureRemoteScanner(id)
			sc := cfg.RemoteScanners.Configs[id]
			sc.SSHKey += "\n" + line
			cfg.RemoteScanners.Configs[id] = sc
		} else if currentKey == "ssh_key" && currentSection == "opnsense" {
			cfg.OPNsense.SSHKey += "\n" + line
		} else if currentKey == "ssh_key" && currentSection == "openwrt" {
			cfg.OpenWrt.SSHKey += "\n" + line
		} else if currentKey == "ssh_key" && strings.HasPrefix(currentSection, "openwrt.") {
			id := strings.TrimPrefix(currentSection, "openwrt.")
			cfg.ensureOpenWrt(id)
			wrt := cfg.OpenWrts.Configs[id]
			wrt.SSHKey += "\n" + line
			cfg.OpenWrts.Configs[id] = wrt
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	cfg.Normalize()
	return cfg, nil
}

// setValue sets a configuration value based on section and key
func (c *Config) setValue(section, key, value string) {
	switch section {
	case "server":
		switch key {
		case "port":
			if v, err := strconv.Atoi(value); err == nil {
				c.Server.Port = v
			}
		case "bind_address":
			c.Server.BindAddress = value
		case "enable_api":
			c.Server.EnableAPI = parseBool(value)
		case "password":
			c.Server.Password = value
		case "session_hours":
			if v, err := strconv.Atoi(value); err == nil {
				c.Server.SessionHours = v
			}
		case "allow_insecure":
			c.Server.AllowInsecure = parseBool(value)
		}
	case "scanning":
		switch key {
		case "scan_interval":
			if v, err := strconv.Atoi(value); err == nil {
				c.Scanning.ScanInterval = v
			}
		case "min_scan_interval":
			if v, err := strconv.Atoi(value); err == nil {
				c.Scanning.MinScanInterval = v
			}
		case "enable_port_scan":
			c.Scanning.EnablePortScan = parseBool(value)
		case "port_scan_range":
			c.Scanning.PortScanRange = value
		case "continuous_scan":
			c.Scanning.ContinuousScan = parseBool(value)
		case "enable_service_detection":
			c.Scanning.EnableServiceDetection = parseBool(value)
		case "only_configured_networks":
			c.Scanning.OnlyConfiguredNetworks = parseBool(value)
		case "networks":
			c.Scanning.Networks = network.ParseNetworkList(value)
		case "exclude_networks":
			c.Scanning.ExcludeNetworks = network.ParseNetworkList(value)
		}
	case "storage":
		switch key {
		case "max_devices":
			if v, err := strconv.Atoi(value); err == nil {
				c.Storage.MaxDevices = v
			}
		case "retention_days":
			if v, err := strconv.Atoi(value); err == nil {
				c.Storage.RetentionDays = v
			}
		case "data_dir":
			c.Storage.DataDir = value
		}
	case "tailscale":
		switch key {
		case "enable":
			c.Tailscale.Enable = parseBool(value)
		case "auto_detect":
			c.Tailscale.AutoDetect = parseBool(value)
		}
	case "ui":
		switch key {
		case "theme":
			c.UI.Theme = value
		}
	case "network_names":
		if c.Scanning.NetworkNames == nil {
			c.Scanning.NetworkNames = make(map[string]string)
		}
		c.Scanning.NetworkNames[key] = value
	case "openwrt":
		switch key {
		case "enable":
			c.OpenWrt.Enable = parseBool(value)
		case "url":
			c.OpenWrt.URL = value
		case "api_token":
			c.OpenWrt.APIToken = value
		case "verify_ssl":
			c.OpenWrt.VerifySSL = parseBool(value)
		case "remote_scan":
			c.OpenWrt.RemoteScan = parseBool(value)
		case "ssh_host", "host":
			c.OpenWrt.SSHHost = value
		case "ssh_port", "port":
			if v, err := strconv.Atoi(value); err == nil && v > 0 {
				c.OpenWrt.SSHPort = v
			}
		case "ssh_user", "user", "username":
			c.OpenWrt.SSHUser = value
		case "ssh_sudo", "sudo":
			c.OpenWrt.SSHSudo = parseBool(value)
		case "ssh_key", "key":
			c.OpenWrt.SSHKey = strings.ReplaceAll(value, "\\n", "\n")
		case "ssh_key_file", "key_file":
			c.OpenWrt.SSHKeyFile = value
		case "ssh_password", "password":
			c.OpenWrt.SSHPassword = value
		case "networks":
			c.OpenWrt.Networks = network.ParseNetworkList(value)
		}
	case "openwrts":
		switch key {
		case "names":
			c.setOpenWrtNames(value)
		}
	case "opnsense":
		switch key {
		case "enable":
			c.OPNsense.Enable = parseBool(value)
		case "url":
			c.OPNsense.URL = value
		case "api_key":
			c.OPNsense.APIKey = value
		case "api_secret":
			c.OPNsense.APISecret = value
		case "verify_ssl":
			c.OPNsense.VerifySSL = parseBool(value)
		case "remote_scan":
			c.OPNsense.RemoteScan = parseBool(value)
		case "ssh_host", "host":
			c.OPNsense.SSHHost = value
		case "ssh_port", "port":
			if v, err := strconv.Atoi(value); err == nil && v > 0 {
				c.OPNsense.SSHPort = v
			}
		case "ssh_user", "user", "username":
			c.OPNsense.SSHUser = value
		case "ssh_sudo", "sudo":
			c.OPNsense.SSHSudo = parseBool(value)
		case "ssh_key", "key":
			c.OPNsense.SSHKey = strings.ReplaceAll(value, "\\n", "\n")
		case "ssh_key_file", "key_file":
			c.OPNsense.SSHKeyFile = value
		case "ssh_password", "password":
			c.OPNsense.SSHPassword = value
		case "networks":
			c.OPNsense.Networks = network.ParseNetworkList(value)
		}
	case "unifi":
		switch key {
		case "enable":
			c.UniFi.Enable = parseBool(value)
		case "url":
			c.UniFi.URL = value
		case "site":
			c.UniFi.Site = value
		case "api_key":
			c.UniFi.APIKey = value
		case "verify_ssl":
			c.UniFi.VerifySSL = parseBool(value)
		}
	case "switches":
		switch key {
		case "enable":
			c.Switches.Enable = parseBool(value)
		case "names":
			c.setSwitchNames(value)
		}
	case "remote_scanners":
		switch key {
		case "enable":
			c.RemoteScanners.Enable = parseBool(value)
		case "ssh_sudo", "sudo":
			c.RemoteScanners.Sudo = parseBool(value)
		case "ssh_key", "key":
			c.RemoteScanners.SSHKey = strings.ReplaceAll(value, "\\n", "\n")
		case "ssh_key_file", "key_file":
			c.RemoteScanners.SSHKeyFile = value
		case "ssh_password", "password":
			c.RemoteScanners.SSHPassword = value
		case "names":
			c.setRemoteScannerNames(value)
		}
	default:
		if strings.HasPrefix(section, "openwrt.") {
			c.setOpenWrtValue(strings.TrimPrefix(section, "openwrt."), key, value)
		} else if strings.HasPrefix(section, "remote_scanner.") {
			c.setRemoteScannerValue(strings.TrimPrefix(section, "remote_scanner."), key, value)
		} else if strings.HasPrefix(section, "remote_scanners.") {
			c.setRemoteScannerValue(strings.TrimPrefix(section, "remote_scanners."), key, value)
		} else if strings.HasPrefix(section, "switch.") {
			c.setSwitchValue(strings.TrimPrefix(section, "switch."), key, value)
		}
	}
}

func (c *Config) setSwitchNames(value string) {
	c.Switches.Names = nil
	for _, name := range strings.Split(value, ",") {
		id := strings.ToLower(strings.TrimSpace(name))
		if id == "" {
			continue
		}
		c.Switches.Names = append(c.Switches.Names, id)
		c.ensureSwitch(id)
	}
}

func (c *Config) ensureSwitch(id string) *SwitchConfig {
	id = strings.ToLower(strings.TrimSpace(id))
	if c.Switches.Configs == nil {
		c.Switches.Configs = make(map[string]SwitchConfig)
	}
	switchCfg, ok := c.Switches.Configs[id]
	if !ok {
		switchCfg = SwitchConfig{
			ID:              id,
			Port:            161,
			Version:         3,
			SecurityLevel:   "authPriv",
			AuthProtocol:    "SHA",
			PrivacyProtocol: "DES",
			TimeoutSeconds:  5,
		}
	}
	return &switchCfg
}

func (c *Config) setSwitchValue(id, key, value string) {
	switchCfg := c.ensureSwitch(id)
	switch key {
	case "host":
		switchCfg.Host = value
	case "port":
		if v, err := strconv.Atoi(value); err == nil {
			switchCfg.Port = v
		}
	case "version":
		if v, err := strconv.Atoi(value); err == nil {
			switchCfg.Version = v
		}
	case "username":
		switchCfg.Username = value
	case "security_level":
		switchCfg.SecurityLevel = value
	case "auth_protocol":
		switchCfg.AuthProtocol = value
	case "auth_password":
		switchCfg.AuthPassword = value
	case "privacy_protocol":
		switchCfg.PrivacyProtocol = value
	case "privacy_password":
		switchCfg.PrivacyPassword = value
	case "timeout_seconds":
		if v, err := strconv.Atoi(value); err == nil {
			switchCfg.TimeoutSeconds = v
		}
	}
	c.Switches.Configs[switchCfg.ID] = *switchCfg
}

func (c *Config) setOpenWrtNames(value string) {
	c.OpenWrts.Names = nil
	for _, name := range strings.Split(value, ",") {
		id := strings.ToLower(strings.TrimSpace(name))
		if id == "" {
			continue
		}
		c.OpenWrts.Names = append(c.OpenWrts.Names, id)
		c.ensureOpenWrt(id)
	}
}

func (c *Config) ensureOpenWrt(id string) *OpenWrtConfig {
	id = strings.ToLower(strings.TrimSpace(id))
	if c.OpenWrts.Configs == nil {
		c.OpenWrts.Configs = make(map[string]OpenWrtConfig)
	}
	cfg, ok := c.OpenWrts.Configs[id]
	if !ok {
		cfg = OpenWrtConfig{
			ID:        id,
			SSHPort:   22,
			SSHUser:   "root",
			VerifySSL: false,
		}
		c.OpenWrts.Configs[id] = cfg
	}
	return &cfg
}

func (c *Config) setOpenWrtValue(id, key, value string) {
	id = strings.ToLower(strings.TrimSpace(id))
	c.ensureOpenWrt(id)
	cfg := c.OpenWrts.Configs[id]
	switch key {
	case "enable":
		cfg.Enable = parseBool(value)
	case "url":
		cfg.URL = value
	case "api_token":
		cfg.APIToken = value
	case "verify_ssl":
		cfg.VerifySSL = parseBool(value)
	case "remote_scan":
		cfg.RemoteScan = parseBool(value)
	case "ssh_host", "host":
		cfg.SSHHost = value
	case "ssh_port", "port":
		if v, err := strconv.Atoi(value); err == nil && v > 0 {
			cfg.SSHPort = v
		}
	case "ssh_user", "user", "username":
		if value != "" {
			cfg.SSHUser = value
		}
	case "ssh_sudo", "sudo":
		cfg.SSHSudo = parseBool(value)
	case "ssh_key", "key":
		cfg.SSHKey = strings.ReplaceAll(value, "\\n", "\n")
	case "ssh_key_file", "key_file":
		cfg.SSHKeyFile = value
	case "ssh_password", "password":
		cfg.SSHPassword = value
	case "networks":
		cfg.Networks = network.ParseNetworkList(value)
	}
	c.OpenWrts.Configs[id] = cfg
	found := false
	for _, name := range c.OpenWrts.Names {
		if name == id {
			found = true
			break
		}
	}
	if !found {
		c.OpenWrts.Names = append(c.OpenWrts.Names, id)
	}
}

// AllOpenWrts returns all configured OpenWrt routers
func (c *Config) AllOpenWrts() []OpenWrtConfig {
	var list []OpenWrtConfig
	if c.OpenWrt.Enable || c.OpenWrt.RemoteScan {
		base := c.OpenWrt
		if base.ID == "" {
			base.ID = "openwrt"
		}
		list = append(list, base)
	}
	for _, name := range c.OpenWrts.Names {
		if strings.EqualFold(name, "openwrt") && len(list) > 0 {
			continue
		}
		if cfg, ok := c.OpenWrts.Configs[name]; ok && (cfg.Enable || cfg.RemoteScan) {
			list = append(list, cfg)
		}
	}
	return list
}

func extractHostFromURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err == nil {
		h := u.Hostname()
		if h != "" {
			return h
		}
	}
	return rawURL
}

func (c *Config) setRemoteScannerNames(value string) {
	c.RemoteScanners.Names = nil
	for _, name := range strings.Split(value, ",") {
		id := strings.ToLower(strings.TrimSpace(name))
		if id == "" {
			continue
		}
		c.RemoteScanners.Names = append(c.RemoteScanners.Names, id)
		c.ensureRemoteScanner(id)
	}
}

func (c *Config) ensureRemoteScanner(id string) *RemoteScannerConfig {
	id = strings.ToLower(strings.TrimSpace(id))
	if c.RemoteScanners.Configs == nil {
		c.RemoteScanners.Configs = make(map[string]RemoteScannerConfig)
	}
	cfg, ok := c.RemoteScanners.Configs[id]
	if !ok {
		cfg = RemoteScannerConfig{
			ID:   id,
			Port: 22,
			User: "root",
		}
		c.RemoteScanners.Configs[id] = cfg
	}
	return &cfg
}

func (c *Config) setRemoteScannerValue(id, key, value string) {
	id = strings.ToLower(strings.TrimSpace(id))
	c.ensureRemoteScanner(id)
	cfg := c.RemoteScanners.Configs[id]
	switch key {
	case "host", "ssh_host":
		cfg.Host = value
	case "port", "ssh_port":
		if v, err := strconv.Atoi(value); err == nil && v > 0 {
			cfg.Port = v
		}
	case "user", "ssh_user", "username":
		if value != "" {
			cfg.User = value
		}
	case "sudo", "ssh_sudo":
		cfg.Sudo = parseBool(value)
	case "networks":
		cfg.Networks = network.ParseNetworkList(value)
	case "ssh_key", "key":
		cfg.SSHKey = strings.ReplaceAll(value, "\\n", "\n")
	case "ssh_key_file", "key_file":
		cfg.SSHKeyFile = value
	case "ssh_password", "password":
		cfg.SSHPassword = value
	}
	c.RemoteScanners.Configs[id] = cfg
	found := false
	for _, name := range c.RemoteScanners.Names {
		if name == id {
			found = true
			break
		}
	}
	if !found {
		c.RemoteScanners.Names = append(c.RemoteScanners.Names, id)
	}
}

// ApplyEnv overlays settings from environment variables onto c.
//
// Environment variables take precedence over the config file, which makes the
// app configurable in a container without mounting a config file. Command line
// flags still win over both.
func (c *Config) ApplyEnv() error {
	if v := os.Getenv("ORANGUTAN_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Server.Port = n
		}
	}
	if v := os.Getenv("ORANGUTAN_BIND_ADDRESS"); v != "" {
		c.Server.BindAddress = v
	}
	if v := os.Getenv("ORANGUTAN_PASSWORD"); v != "" {
		c.Server.Password = v
	}
	// A password file keeps the secret out of the process environment, which
	// is how container secrets are normally delivered.
	if v := os.Getenv("ORANGUTAN_PASSWORD_FILE"); v != "" {
		if data, err := os.ReadFile(v); err == nil {
			if pw := strings.TrimSpace(string(data)); pw != "" {
				c.Server.Password = pw
			}
		}
	}
	if v := os.Getenv("ORANGUTAN_SESSION_HOURS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Server.SessionHours = n
		}
	}
	if v := os.Getenv("ORANGUTAN_ALLOW_INSECURE"); v != "" {
		c.Server.AllowInsecure = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_DATA_DIR"); v != "" {
		c.Storage.DataDir = v
	}
	if v := os.Getenv("ORANGUTAN_NETWORKS"); v != "" {
		c.Scanning.Networks = network.ParseNetworkList(v)
	}
	if v := os.Getenv("ORANGUTAN_ENABLE_SERVICE_DETECTION"); v != "" {
		c.Scanning.EnableServiceDetection = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_ONLY_CONFIGURED_NETWORKS"); v != "" {
		c.Scanning.OnlyConfiguredNetworks = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_EXCLUDE_NETWORKS"); v != "" {
		c.Scanning.ExcludeNetworks = network.ParseNetworkList(v)
	}
	if v := os.Getenv("ORANGUTAN_SCAN_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Scanning.ScanInterval = n
		}
	}
	if v := os.Getenv("ORANGUTAN_CONTINUOUS_SCAN"); v != "" {
		c.Scanning.ContinuousScan = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_THEME"); v != "" {
		c.UI.Theme = v
	}

	if v := os.Getenv("ORANGUTAN_OPENWRT_ENABLE"); v != "" {
		c.OpenWrt.Enable = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_OPENWRT_URL"); v != "" {
		c.OpenWrt.URL = v
	}
	if v := os.Getenv("ORANGUTAN_OPENWRT_API_TOKEN"); v != "" {
		c.OpenWrt.APIToken = v
	}
	if v := os.Getenv("ORANGUTAN_OPENWRT_VERIFY_SSL"); v != "" {
		c.OpenWrt.VerifySSL = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_OPENWRT_REMOTE_SCAN"); v != "" {
		c.OpenWrt.RemoteScan = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_OPENWRT_SSH_HOST"); v != "" {
		c.OpenWrt.SSHHost = v
	} else if v := os.Getenv("ORANGUTAN_OPENWRT_HOST"); v != "" {
		c.OpenWrt.SSHHost = v
	}
	if v := os.Getenv("ORANGUTAN_OPENWRT_SSH_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.OpenWrt.SSHPort = n
		}
	} else if v := os.Getenv("ORANGUTAN_OPENWRT_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.OpenWrt.SSHPort = n
		}
	}
	if v := os.Getenv("ORANGUTAN_OPENWRT_SSH_USER"); v != "" {
		c.OpenWrt.SSHUser = v
	} else if v := os.Getenv("ORANGUTAN_OPENWRT_USER"); v != "" {
		c.OpenWrt.SSHUser = v
	}
	if v := os.Getenv("ORANGUTAN_OPENWRT_SSH_SUDO"); v != "" {
		c.OpenWrt.SSHSudo = parseBool(v)
	} else if v := os.Getenv("ORANGUTAN_OPENWRT_SUDO"); v != "" {
		c.OpenWrt.SSHSudo = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_OPENWRT_SSH_KEY"); v != "" {
		c.OpenWrt.SSHKey = strings.ReplaceAll(v, "\\n", "\n")
	} else if v := os.Getenv("ORANGUTAN_OPENWRT_KEY"); v != "" {
		c.OpenWrt.SSHKey = strings.ReplaceAll(v, "\\n", "\n")
	}
	if v := os.Getenv("ORANGUTAN_OPENWRT_SSH_KEY_FILE"); v != "" {
		c.OpenWrt.SSHKeyFile = v
	} else if v := os.Getenv("ORANGUTAN_OPENWRT_KEY_FILE"); v != "" {
		c.OpenWrt.SSHKeyFile = v
	}
	if v := os.Getenv("ORANGUTAN_OPENWRT_SSH_PASSWORD"); v != "" {
		c.OpenWrt.SSHPassword = v
	} else if v := os.Getenv("ORANGUTAN_OPENWRT_PASSWORD"); v != "" {
		c.OpenWrt.SSHPassword = v
	}
	if v := os.Getenv("ORANGUTAN_OPENWRT_NETWORKS"); v != "" {
		c.OpenWrt.Networks = network.ParseNetworkList(v)
	}
	if v := os.Getenv("ORANGUTAN_OPENWRTS_NAMES"); v != "" {
		c.setOpenWrtNames(v)
	}
	for _, id := range c.OpenWrts.Names {
		prefix := "ORANGUTAN_OPENWRT_" + strings.ToUpper(id) + "_"
		for _, setting := range []struct {
			key string
			env string
		}{
			{"url", "URL"},
			{"api_token", "API_TOKEN"},
			{"verify_ssl", "VERIFY_SSL"},
			{"remote_scan", "REMOTE_SCAN"},
			{"ssh_host", "SSH_HOST"},
			{"host", "HOST"},
			{"ssh_port", "SSH_PORT"},
			{"port", "PORT"},
			{"ssh_user", "SSH_USER"},
			{"user", "USER"},
			{"ssh_sudo", "SSH_SUDO"},
			{"sudo", "SUDO"},
			{"ssh_key", "SSH_KEY"},
			{"key", "KEY"},
			{"ssh_key_file", "SSH_KEY_FILE"},
			{"key_file", "KEY_FILE"},
			{"ssh_password", "SSH_PASSWORD"},
			{"password", "PASSWORD"},
			{"networks", "NETWORKS"},
		} {
			if v := os.Getenv(prefix + setting.env); v != "" {
				c.setOpenWrtValue(id, setting.key, v)
			}
		}
	}

	if v := os.Getenv("ORANGUTAN_OPNSENSE_ENABLE"); v != "" {
		c.OPNsense.Enable = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_OPNSENSE_URL"); v != "" {
		c.OPNsense.URL = v
	}
	if v := os.Getenv("ORANGUTAN_OPNSENSE_API_KEY"); v != "" {
		c.OPNsense.APIKey = v
	}
	if v := os.Getenv("ORANGUTAN_OPNSENSE_API_SECRET"); v != "" {
		c.OPNsense.APISecret = v
	}
	if v := os.Getenv("ORANGUTAN_OPNSENSE_VERIFY_SSL"); v != "" {
		c.OPNsense.VerifySSL = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_OPNSENSE_REMOTE_SCAN"); v != "" {
		c.OPNsense.RemoteScan = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_OPNSENSE_SSH_HOST"); v != "" {
		c.OPNsense.SSHHost = v
	} else if v := os.Getenv("ORANGUTAN_OPNSENSE_HOST"); v != "" {
		c.OPNsense.SSHHost = v
	}
	if v := os.Getenv("ORANGUTAN_OPNSENSE_SSH_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.OPNsense.SSHPort = n
		}
	} else if v := os.Getenv("ORANGUTAN_OPNSENSE_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.OPNsense.SSHPort = n
		}
	}
	if v := os.Getenv("ORANGUTAN_OPNSENSE_SSH_USER"); v != "" {
		c.OPNsense.SSHUser = v
	} else if v := os.Getenv("ORANGUTAN_OPNSENSE_USER"); v != "" {
		c.OPNsense.SSHUser = v
	}
	if v := os.Getenv("ORANGUTAN_OPNSENSE_SSH_SUDO"); v != "" {
		c.OPNsense.SSHSudo = parseBool(v)
	} else if v := os.Getenv("ORANGUTAN_OPNSENSE_SUDO"); v != "" {
		c.OPNsense.SSHSudo = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_OPNSENSE_SSH_KEY"); v != "" {
		c.OPNsense.SSHKey = strings.ReplaceAll(v, "\\n", "\n")
	} else if v := os.Getenv("ORANGUTAN_OPNSENSE_KEY"); v != "" {
		c.OPNsense.SSHKey = strings.ReplaceAll(v, "\\n", "\n")
	}
	if v := os.Getenv("ORANGUTAN_OPNSENSE_SSH_KEY_FILE"); v != "" {
		c.OPNsense.SSHKeyFile = v
	} else if v := os.Getenv("ORANGUTAN_OPNSENSE_KEY_FILE"); v != "" {
		c.OPNsense.SSHKeyFile = v
	}
	if v := os.Getenv("ORANGUTAN_OPNSENSE_SSH_PASSWORD"); v != "" {
		c.OPNsense.SSHPassword = v
	} else if v := os.Getenv("ORANGUTAN_OPNSENSE_PASSWORD"); v != "" {
		c.OPNsense.SSHPassword = v
	}
	if v := os.Getenv("ORANGUTAN_OPNSENSE_NETWORKS"); v != "" {
		c.OPNsense.Networks = network.ParseNetworkList(v)
	}

	if v := os.Getenv("ORANGUTAN_UNIFI_ENABLE"); v != "" {
		c.UniFi.Enable = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_UNIFI_URL"); v != "" {
		c.UniFi.URL = v
	}
	if v := os.Getenv("ORANGUTAN_UNIFI_SITE"); v != "" {
		c.UniFi.Site = v
	}
	if v := os.Getenv("ORANGUTAN_UNIFI_API_KEY"); v != "" {
		c.UniFi.APIKey = v
	}
	if v := os.Getenv("ORANGUTAN_UNIFI_VERIFY_SSL"); v != "" {
		c.UniFi.VerifySSL = parseBool(v)
	}

	if v := os.Getenv("ORANGUTAN_SWITCHES_ENABLE"); v != "" {
		c.Switches.Enable = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_SWITCHES_NAMES"); v != "" {
		c.setSwitchNames(v)
	}
	for _, id := range c.Switches.Names {
		prefix := "ORANGUTAN_SWITCH_" + strings.ToUpper(id) + "_"
		for _, setting := range []struct {
			key string
			env string
		}{
			{"host", "HOST"},
			{"port", "PORT"},
			{"version", "VERSION"},
			{"username", "USERNAME"},
			{"security_level", "SECURITY_LEVEL"},
			{"auth_protocol", "AUTH_PROTOCOL"},
			{"auth_password", "AUTH_PASSWORD"},
			{"privacy_protocol", "PRIVACY_PROTOCOL"},
			{"privacy_password", "PRIVACY_PASSWORD"},
			{"timeout_seconds", "TIMEOUT_SECONDS"},
		} {
			if v := os.Getenv(prefix + setting.env); v != "" {
				c.setSwitchValue(id, setting.key, v)
			}
		}
	}

	if v := os.Getenv("ORANGUTAN_REMOTE_SCAN_ENABLE"); v != "" {
		c.RemoteScanners.Enable = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_REMOTE_SCAN_SUDO"); v != "" {
		c.RemoteScanners.Sudo = parseBool(v)
	} else if v := os.Getenv("ORANGUTAN_REMOTE_SCAN_SSH_SUDO"); v != "" {
		c.RemoteScanners.Sudo = parseBool(v)
	}
	if v := os.Getenv("ORANGUTAN_REMOTE_SCAN_KEY"); v != "" {
		c.RemoteScanners.SSHKey = strings.ReplaceAll(v, "\\n", "\n")
	}
	if v := os.Getenv("ORANGUTAN_REMOTE_SCAN_KEY_FILE"); v != "" {
		c.RemoteScanners.SSHKeyFile = v
	}
	if v := os.Getenv("ORANGUTAN_REMOTE_SCAN_PASSWORD"); v != "" {
		c.RemoteScanners.SSHPassword = v
	}
	if v := os.Getenv("ORANGUTAN_REMOTE_SCANNERS_NAMES"); v != "" {
		c.setRemoteScannerNames(v)
	}
	for _, id := range c.RemoteScanners.Names {
		for _, prefix := range []string{
			"ORANGUTAN_REMOTE_SCANNER_" + strings.ToUpper(id) + "_",
			"ORANGUTAN_REMOTE_SCAN_" + strings.ToUpper(id) + "_",
		} {
			for _, setting := range []struct {
				key string
				env string
			}{
				{"host", "HOST"},
				{"ssh_host", "SSH_HOST"},
				{"port", "PORT"},
				{"ssh_port", "SSH_PORT"},
				{"user", "USER"},
				{"ssh_user", "SSH_USER"},
				{"sudo", "SUDO"},
				{"ssh_sudo", "SSH_SUDO"},
				{"networks", "NETWORKS"},
				{"ssh_key", "SSH_KEY"},
				{"key", "KEY"},
				{"ssh_key_file", "SSH_KEY_FILE"},
				{"key_file", "KEY_FILE"},
				{"ssh_password", "SSH_PASSWORD"},
				{"password", "PASSWORD"},
			} {
				if v := os.Getenv(prefix + setting.env); v != "" {
					c.setRemoteScannerValue(id, setting.key, v)
				}
			}
		}
	}

	c.Normalize()
	return nil
}

// Normalize repairs out-of-range scan timings, clamping them back to the
// defaults, and returns a human-readable note for each value it had to correct.
// A non-positive scan_interval would otherwise silently disable the background
// scanner even with continuous_scan on, and a non-positive min_scan_interval
// would silently disable per-network rate limiting; both are corrected here so
// a config typo cannot quietly turn a feature off. Call it after loading the
// config from file and environment.
func (c *Config) Normalize() []string {
	var notes []string

	if c.Scanning.MinScanInterval <= 0 {
		notes = append(notes, fmt.Sprintf(
			"min_scan_interval was %d; using %d so per-network rate limiting stays on",
			c.Scanning.MinScanInterval, defaultMinScanInterval))
		c.Scanning.MinScanInterval = defaultMinScanInterval
	}

	if c.Scanning.ScanInterval <= 0 {
		notes = append(notes, fmt.Sprintf(
			"scan_interval was %d; using %d so continuous scanning works when enabled",
			c.Scanning.ScanInterval, defaultScanInterval))
		c.Scanning.ScanInterval = defaultScanInterval
	}

	if len(c.Scanning.Networks) == 0 && len(c.Scanning.NetworkNames) > 0 {
		for cidr := range c.Scanning.NetworkNames {
			c.Scanning.Networks = append(c.Scanning.Networks, cidr)
		}
		sort.Strings(c.Scanning.Networks)
	}

	if c.UniFi.Site == "" {
		c.UniFi.Site = "default"
	}

	for _, id := range c.Switches.Names {
		switchCfg := c.ensureSwitch(id)
		if switchCfg.TimeoutSeconds <= 0 {
			switchCfg.TimeoutSeconds = 5
		}
		c.Switches.Configs[id] = *switchCfg
	}

	// Automatically register OPNsense as a remote scanner if remote_scan is true
	if c.OPNsense.RemoteScan {
		host := c.OPNsense.SSHHost
		if host == "" {
			host = extractHostFromURL(c.OPNsense.URL)
		}
		port := c.OPNsense.SSHPort
		if port <= 0 {
			port = 22
		}
		user := c.OPNsense.SSHUser
		if user == "" {
			user = "root"
		}
		c.setRemoteScannerValue("opnsense", "host", host)
		c.setRemoteScannerValue("opnsense", "port", strconv.Itoa(port))
		c.setRemoteScannerValue("opnsense", "user", user)
		c.setRemoteScannerValue("opnsense", "sudo", strconv.FormatBool(c.OPNsense.SSHSudo))
		if len(c.OPNsense.Networks) > 0 {
			c.setRemoteScannerValue("opnsense", "networks", strings.Join(c.OPNsense.Networks, ","))
		}
		if c.OPNsense.SSHKey != "" {
			c.setRemoteScannerValue("opnsense", "ssh_key", c.OPNsense.SSHKey)
		}
		if c.OPNsense.SSHKeyFile != "" {
			c.setRemoteScannerValue("opnsense", "ssh_key_file", c.OPNsense.SSHKeyFile)
		}
		if c.OPNsense.SSHPassword != "" {
			c.setRemoteScannerValue("opnsense", "ssh_password", c.OPNsense.SSHPassword)
		}
		c.RemoteScanners.Enable = true
	}

	// Automatically register all OpenWrt routers as remote scanners if remote_scan is true
	for _, wrt := range c.AllOpenWrts() {
		if wrt.RemoteScan {
			id := wrt.ID
			if id == "" {
				id = "openwrt"
			}
			host := wrt.SSHHost
			if host == "" {
				host = extractHostFromURL(wrt.URL)
			}
			port := wrt.SSHPort
			if port <= 0 {
				port = 22
			}
			user := wrt.SSHUser
			if user == "" {
				user = "root"
			}
			c.setRemoteScannerValue(id, "host", host)
			c.setRemoteScannerValue(id, "port", strconv.Itoa(port))
			c.setRemoteScannerValue(id, "user", user)
			c.setRemoteScannerValue(id, "sudo", strconv.FormatBool(wrt.SSHSudo))
			if len(wrt.Networks) > 0 {
				c.setRemoteScannerValue(id, "networks", strings.Join(wrt.Networks, ","))
			}
			if wrt.SSHKey != "" {
				c.setRemoteScannerValue(id, "ssh_key", wrt.SSHKey)
			}
			if wrt.SSHKeyFile != "" {
				c.setRemoteScannerValue(id, "ssh_key_file", wrt.SSHKeyFile)
			}
			if wrt.SSHPassword != "" {
				c.setRemoteScannerValue(id, "ssh_password", wrt.SSHPassword)
			}
			c.RemoteScanners.Enable = true
		}
	}

	if c.RemoteScanners.Sudo {
		for _, id := range c.RemoteScanners.Names {
			cfg := c.RemoteScanners.Configs[id]
			cfg.Sudo = true
			c.RemoteScanners.Configs[id] = cfg
		}
	}

	return notes
}

// IsLoopbackBind reports whether the configured bind address only accepts
// connections from the machine the app is running on.
//
// An empty bind address means every interface, which is not loopback.
func (c *Config) IsLoopbackBind() bool {
	return isLoopbackAddress(c.Server.BindAddress)
}

func isLoopbackAddress(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	if strings.EqualFold(addr, "localhost") {
		return true
	}
	// Strip brackets from IPv6 literals such as [::1].
	addr = strings.TrimPrefix(strings.TrimSuffix(addr, "]"), "[")

	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// RequiresSetup reports whether the user must create a password before the
// dashboard becomes usable.
//
// Setup is required whenever the server can be reached from the network and no
// password exists yet. Bound to loopback the dashboard is already private, so
// a password would be friction with no benefit, and an operator who has some
// other protection in front can opt out entirely.
func (c *Config) RequiresSetup() bool {
	if c.Server.AllowInsecure {
		return false
	}
	if c.IsLoopbackBind() {
		return false
	}
	return c.Server.Password == ""
}

// PasswordFile returns the path where a password created through the setup page
// is stored.
//
// It lives beside the data rather than in the config file, so that completing
// setup does not rewrite a file the user maintains by hand.
func (c *Config) PasswordFile() string {
	return filepath.Join(c.Storage.DataDir, "auth")
}

// SessionTTL returns how long a login should remain valid.
func (c *Config) SessionTTL() time.Duration {
	if c.Server.SessionHours <= 0 {
		return 24 * 7 * time.Hour
	}
	return time.Duration(c.Server.SessionHours) * time.Hour
}

// DevicesFile returns the full path to the devices JSON file
func (c *Config) DevicesFile() string {
	return filepath.Join(c.Storage.DataDir, "devices.json")
}

// StateFile returns the full path to the scan state file
func (c *Config) StateFile() string {
	return filepath.Join(c.Storage.DataDir, "scan_state.json")
}

// parseBool parses common boolean representations
func parseBool(s string) bool {
	s = strings.ToLower(s)
	return s == "true" || s == "yes" || s == "1" || s == "on"
}
