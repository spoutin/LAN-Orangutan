package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeConfig writes body to a temporary config file and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.ini")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

func TestDefaultIsReachableButRequiresSetup(t *testing.T) {
	cfg := Default()

	// Reachable from the network, because that is how this is normally used.
	if cfg.IsLoopbackBind() {
		t.Fatalf("default bind address %q should accept connections from the network", cfg.Server.BindAddress)
	}
	if cfg.Server.Password != "" {
		t.Fatal("no password should be set by default")
	}
	if cfg.Server.AllowInsecure {
		t.Fatal("password protection must not be skipped by default")
	}

	// Safety comes from setup, not from being unreachable.
	if !cfg.RequiresSetup() {
		t.Fatal("a fresh install reachable from the network must require setup")
	}
}

func TestMissingFileFallsBackToDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.ini"))
	if err != nil {
		t.Fatalf("a missing config file should not be an error: %v", err)
	}
	if !cfg.RequiresSetup() {
		t.Fatal("a missing config file should leave the setup requirement in place")
	}
}

func TestLoadServerSettings(t *testing.T) {
	path := writeConfig(t, `
[server]
port = 8080
bind_address = 0.0.0.0
password = hunter2
session_hours = 12
allow_insecure = true
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Port != 8080 {
		t.Errorf("port = %d, want 8080", cfg.Server.Port)
	}
	if cfg.Server.BindAddress != "0.0.0.0" {
		t.Errorf("bind_address = %q, want 0.0.0.0", cfg.Server.BindAddress)
	}
	if cfg.Server.Password != "hunter2" {
		t.Errorf("password = %q, want hunter2", cfg.Server.Password)
	}
	if cfg.Server.SessionHours != 12 {
		t.Errorf("session_hours = %d, want 12", cfg.Server.SessionHours)
	}
	if !cfg.Server.AllowInsecure {
		t.Error("allow_insecure should be true")
	}
}

func TestContinuousScanDefaultsOn(t *testing.T) {
	if !Default().Scanning.ContinuousScan {
		t.Error("continuous_scan should default to true")
	}
}

func TestContinuousScanCanBeDisabled(t *testing.T) {
	path := writeConfig(t, `
[scanning]
continuous_scan = false
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Scanning.ContinuousScan {
		t.Error("continuous_scan = false in the file should disable it")
	}
}

func TestContinuousScanEnvOverride(t *testing.T) {
	t.Setenv("ORANGUTAN_CONTINUOUS_SCAN", "false")
	cfg := Default()
	cfg.ApplyEnv()
	if cfg.Scanning.ContinuousScan {
		t.Error("ORANGUTAN_CONTINUOUS_SCAN=false should disable continuous scan")
	}
}

func TestIsLoopbackBind(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.53", true},
		{"localhost", true},
		{"LOCALHOST", true},
		{"::1", true},
		{"[::1]", true},
		{"0.0.0.0", false},
		{"192.168.1.10", false},
		{"::", false},
		{"", false}, // empty means every interface
		{"not-an-address", false},
	}

	for _, tt := range tests {
		cfg := Default()
		cfg.Server.BindAddress = tt.addr
		if got := cfg.IsLoopbackBind(); got != tt.want {
			t.Errorf("IsLoopbackBind(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestRequiresSetupWhenReachableWithNoPassword(t *testing.T) {
	cfg := Default()
	cfg.Server.BindAddress = "0.0.0.0"

	if !cfg.RequiresSetup() {
		t.Fatal("a network-reachable install with no password must require setup")
	}
}

func TestRequiresSetupWithEmptyBindAddress(t *testing.T) {
	// An empty bind address listens on every interface, so it is just as
	// exposed as 0.0.0.0 and must be caught too.
	cfg := Default()
	cfg.Server.BindAddress = ""

	if !cfg.RequiresSetup() {
		t.Fatal("an empty bind address with no password must require setup")
	}
}

func TestNoSetupWhenPasswordAlreadySet(t *testing.T) {
	cfg := Default()
	cfg.Server.BindAddress = "0.0.0.0"
	cfg.Server.Password = "hunter2"

	if cfg.RequiresSetup() {
		t.Fatal("an existing password means there is nothing to set up")
	}
}

func TestNoSetupWhenLoopbackOnly(t *testing.T) {
	// Nobody else can reach it, so a password would be friction with no gain.
	cfg := Default()
	cfg.Server.BindAddress = "127.0.0.1"

	if cfg.RequiresSetup() {
		t.Fatal("a loopback-only install should not demand a password")
	}
}

func TestNoSetupWhenExplicitlyOptedOut(t *testing.T) {
	cfg := Default()
	cfg.Server.BindAddress = "0.0.0.0"
	cfg.Server.AllowInsecure = true

	if cfg.RequiresSetup() {
		t.Fatal("an explicit opt-out should be honoured")
	}
}

func TestPasswordFileLivesBesideTheData(t *testing.T) {
	cfg := Default()
	cfg.Storage.DataDir = "/tmp/example"

	if got, want := cfg.PasswordFile(), filepath.Join("/tmp/example", "auth"); got != want {
		t.Errorf("PasswordFile() = %q, want %q", got, want)
	}
}

func TestEnvOverridesConfigFile(t *testing.T) {
	path := writeConfig(t, `
[server]
port = 8080
bind_address = 127.0.0.1
password = from-file
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	t.Setenv("ORANGUTAN_PORT", "9999")
	t.Setenv("ORANGUTAN_BIND_ADDRESS", "0.0.0.0")
	t.Setenv("ORANGUTAN_PASSWORD", "from-env")
	t.Setenv("ORANGUTAN_ALLOW_INSECURE", "true")
	cfg.ApplyEnv()

	if cfg.Server.Port != 9999 {
		t.Errorf("port = %d, want the environment value 9999", cfg.Server.Port)
	}
	if cfg.Server.BindAddress != "0.0.0.0" {
		t.Errorf("bind_address = %q, want the environment value", cfg.Server.BindAddress)
	}
	if cfg.Server.Password != "from-env" {
		t.Errorf("password = %q, want the environment value", cfg.Server.Password)
	}
	if !cfg.Server.AllowInsecure {
		t.Error("allow_insecure should come from the environment")
	}
}

func TestEnvLeavesUnsetValuesAlone(t *testing.T) {
	cfg := Default()
	original := cfg.Server.Port

	cfg.ApplyEnv() // nothing set

	if cfg.Server.Port != original {
		t.Errorf("port changed to %d with no environment variable set", cfg.Server.Port)
	}
	if cfg.Server.BindAddress != Default().Server.BindAddress {
		t.Error("bind address should be untouched with no environment variable set")
	}
}

func TestPasswordFileIsRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	// Trailing newline is normal in a secret file and must be trimmed.
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatalf("writing secret: %v", err)
	}

	cfg := Default()
	t.Setenv("ORANGUTAN_PASSWORD_FILE", path)
	cfg.ApplyEnv()

	if cfg.Server.Password != "file-secret" {
		t.Errorf("password = %q, want the trimmed file contents", cfg.Server.Password)
	}
}

func TestPasswordFileWinsOverPasswordVar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("file-secret"), 0o600); err != nil {
		t.Fatalf("writing secret: %v", err)
	}

	cfg := Default()
	t.Setenv("ORANGUTAN_PASSWORD", "env-secret")
	t.Setenv("ORANGUTAN_PASSWORD_FILE", path)
	cfg.ApplyEnv()

	if cfg.Server.Password != "file-secret" {
		t.Errorf("password = %q, want the file to take precedence", cfg.Server.Password)
	}
}

func TestMissingPasswordFileIsIgnored(t *testing.T) {
	cfg := Default()
	t.Setenv("ORANGUTAN_PASSWORD", "env-secret")
	t.Setenv("ORANGUTAN_PASSWORD_FILE", filepath.Join(t.TempDir(), "nope"))
	cfg.ApplyEnv()

	// A missing file should not wipe out a password supplied another way.
	if cfg.Server.Password != "env-secret" {
		t.Errorf("password = %q, want the environment value kept", cfg.Server.Password)
	}
}

func TestSessionTTL(t *testing.T) {
	cfg := Default()
	if got := cfg.SessionTTL(); got != 7*24*time.Hour {
		t.Errorf("default SessionTTL = %v, want one week", got)
	}

	cfg.Server.SessionHours = 3
	if got := cfg.SessionTTL(); got != 3*time.Hour {
		t.Errorf("SessionTTL = %v, want 3h", got)
	}

	// Nonsense values fall back to the default rather than expiring instantly.
	cfg.Server.SessionHours = 0
	if got := cfg.SessionTTL(); got != 7*24*time.Hour {
		t.Errorf("SessionTTL with 0 hours = %v, want the default", got)
	}
	cfg.Server.SessionHours = -5
	if got := cfg.SessionTTL(); got != 7*24*time.Hour {
		t.Errorf("SessionTTL with a negative value = %v, want the default", got)
	}
}

func TestCommentsAndBlankLinesIgnored(t *testing.T) {
	path := writeConfig(t, `
# a comment
; another comment

[server]
port = 4242
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != 4242 {
		t.Errorf("port = %d, want 4242", cfg.Server.Port)
	}
}

func TestNormalizeClampsNonPositiveScanInterval(t *testing.T) {
	c := Default()
	c.Scanning.ContinuousScan = true
	c.Scanning.ScanInterval = 0

	notes := c.Normalize()

	if c.Scanning.ScanInterval != defaultScanInterval {
		t.Errorf("scan_interval = %d, want clamped to %d", c.Scanning.ScanInterval, defaultScanInterval)
	}
	if len(notes) == 0 {
		t.Error("expected a warning note about scan_interval, got none")
	}
}

func TestNormalizeClampsNonPositiveMinScanInterval(t *testing.T) {
	c := Default()
	c.Scanning.MinScanInterval = -5

	notes := c.Normalize()

	if c.Scanning.MinScanInterval != defaultMinScanInterval {
		t.Errorf("min_scan_interval = %d, want clamped to %d", c.Scanning.MinScanInterval, defaultMinScanInterval)
	}
	if len(notes) == 0 {
		t.Error("expected a warning note about min_scan_interval, got none")
	}
}

func TestNormalizeClampsScanIntervalEvenWhenContinuousScanOff(t *testing.T) {
	c := Default()
	c.Scanning.ContinuousScan = false
	c.Scanning.ScanInterval = 0

	c.Normalize()

	// Continuous scanning can be switched on at runtime from the UI, so the
	// interval must always be valid even if it starts disabled.
	if c.Scanning.ScanInterval != defaultScanInterval {
		t.Errorf("scan_interval = %d, want clamped to %d", c.Scanning.ScanInterval, defaultScanInterval)
	}
}

func TestNormalizeLeavesValidValuesAlone(t *testing.T) {
	c := Default()

	notes := c.Normalize()

	if len(notes) != 0 {
		t.Errorf("expected no warnings for default config, got %v", notes)
	}
	if c.Scanning.ScanInterval != defaultScanInterval || c.Scanning.MinScanInterval != defaultMinScanInterval {
		t.Error("Normalize changed already-valid values")
	}
}

func TestUniFiConfig(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		cfg := Default()
		if cfg.UniFi.Enable {
			t.Error("UniFi.Enable should default to false")
		}
		if cfg.UniFi.URL != "" {
			t.Errorf("UniFi.URL = %q, want empty", cfg.UniFi.URL)
		}
		if cfg.UniFi.Site != "default" {
			t.Errorf("UniFi.Site = %q, want %q", cfg.UniFi.Site, "default")
		}
		if cfg.UniFi.APIKey != "" {
			t.Errorf("UniFi.APIKey = %q, want empty", cfg.UniFi.APIKey)
		}
		if cfg.UniFi.VerifySSL {
			t.Error("UniFi.VerifySSL should default to false")
		}
	})

	t.Run("load from ini", func(t *testing.T) {
		path := writeConfig(t, `
[unifi]
enable = true
url = https://192.168.1.1
site = mysite
api_key = test-api-key-123
verify_ssl = true
`)
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !cfg.UniFi.Enable {
			t.Error("UniFi.Enable should be true")
		}
		if cfg.UniFi.URL != "https://192.168.1.1" {
			t.Errorf("UniFi.URL = %q, want https://192.168.1.1", cfg.UniFi.URL)
		}
		if cfg.UniFi.Site != "mysite" {
			t.Errorf("UniFi.Site = %q, want mysite", cfg.UniFi.Site)
		}
		if cfg.UniFi.APIKey != "test-api-key-123" {
			t.Errorf("UniFi.APIKey = %q, want test-api-key-123", cfg.UniFi.APIKey)
		}
		if !cfg.UniFi.VerifySSL {
			t.Error("UniFi.VerifySSL should be true")
		}
	})

	t.Run("load from ini without site defaults to default", func(t *testing.T) {
		path := writeConfig(t, `
[unifi]
enable = true
url = https://192.168.1.1
api_key = test-key
`)
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.UniFi.Site != "default" {
			t.Errorf("UniFi.Site = %q, want default", cfg.UniFi.Site)
		}
	})

	t.Run("env overrides", func(t *testing.T) {
		t.Setenv("ORANGUTAN_UNIFI_ENABLE", "true")
		t.Setenv("ORANGUTAN_UNIFI_URL", "https://unifi.local:8443")
		t.Setenv("ORANGUTAN_UNIFI_SITE", "custom-site")
		t.Setenv("ORANGUTAN_UNIFI_API_KEY", "env-api-key")
		t.Setenv("ORANGUTAN_UNIFI_VERIFY_SSL", "true")

		cfg := Default()
		cfg.ApplyEnv()

		if !cfg.UniFi.Enable {
			t.Error("ORANGUTAN_UNIFI_ENABLE should enable UniFi")
		}
		if cfg.UniFi.URL != "https://unifi.local:8443" {
			t.Errorf("UniFi.URL = %q, want https://unifi.local:8443", cfg.UniFi.URL)
		}
		if cfg.UniFi.Site != "custom-site" {
			t.Errorf("UniFi.Site = %q, want custom-site", cfg.UniFi.Site)
		}
		if cfg.UniFi.APIKey != "env-api-key" {
			t.Errorf("UniFi.APIKey = %q, want env-api-key", cfg.UniFi.APIKey)
		}
		if !cfg.UniFi.VerifySSL {
			t.Error("ORANGUTAN_UNIFI_VERIFY_SSL should enable VerifySSL")
		}
	})
}

func TestSwitchConfig(t *testing.T) {
	t.Run("loads ordered switches with SNMPv3 defaults", func(t *testing.T) {
		path := writeConfig(t, `
[switches]
enable = true
names = switchy, core

[switch.switchy]
host = 10.0.0.2
username = monitor
auth_password = auth-secret
privacy_password = privacy-secret

[switch.core]
host = core.example.test
port = 1161
version = 3
username = core-monitor
security_level = authPriv
auth_protocol = SHA
auth_password = core-auth-secret
privacy_protocol = AES
privacy_password = core-privacy-secret
timeout_seconds = 10
`)

		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !cfg.Switches.Enable {
			t.Error("Switches.Enable should be true")
		}
		if got, want := cfg.Switches.Names, []string{"switchy", "core"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Errorf("Switches.Names = %v, want %v", got, want)
		}

		switchy := cfg.Switches.Configs["switchy"]
		if switchy.ID != "switchy" || switchy.Host != "10.0.0.2" || switchy.Port != 161 || switchy.Version != 3 || switchy.SecurityLevel != "authPriv" || switchy.AuthProtocol != "SHA" || switchy.PrivacyProtocol != "DES" || switchy.TimeoutSeconds != 5 {
			t.Error("switchy should use the configured host and SNMPv3 authPriv defaults")
		}

		core := cfg.Switches.Configs["core"]
		if core.Host != "core.example.test" || core.Port != 1161 || core.PrivacyProtocol != "AES" || core.TimeoutSeconds != 10 {
			t.Error("core should preserve configured non-secret values")
		}
	})

	t.Run("environment overrides configured switch", func(t *testing.T) {
		path := writeConfig(t, `
[switches]
enable = false
names = switchy

[switch.switchy]
host = 10.0.0.2
username = monitor
auth_password = file-auth-secret
privacy_password = file-privacy-secret
`)
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		t.Setenv("ORANGUTAN_SWITCHES_ENABLE", "true")
		t.Setenv("ORANGUTAN_SWITCH_SWITCHY_HOST", "10.0.0.3")
		t.Setenv("ORANGUTAN_SWITCH_SWITCHY_PORT", "1161")
		t.Setenv("ORANGUTAN_SWITCH_SWITCHY_PRIVACY_PROTOCOL", "AES")
		t.Setenv("ORANGUTAN_SWITCH_SWITCHY_TIMEOUT_SECONDS", "15")
		cfg.ApplyEnv()

		switchy := cfg.Switches.Configs["switchy"]
		if !cfg.Switches.Enable || switchy.Host != "10.0.0.3" || switchy.Port != 1161 || switchy.PrivacyProtocol != "AES" || switchy.TimeoutSeconds != 15 {
			t.Error("environment should override the switch's non-secret settings")
		}
	})
}

func TestSwitchConfigValidation(t *testing.T) {
	valid := SwitchConfig{
		ID:              "switchy",
		Host:            "10.0.0.2",
		Port:            161,
		Version:         3,
		Username:        "monitor",
		SecurityLevel:   "authPriv",
		AuthProtocol:    "SHA",
		AuthPassword:    "auth-secret",
		PrivacyProtocol: "AES",
		PrivacyPassword: "privacy-secret",
		TimeoutSeconds:  5,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v for valid SNMPv3 authPriv configuration", err)
	}

	for name, mutate := range map[string]func(*SwitchConfig){
		"requires version 3":                  func(c *SwitchConfig) { c.Version = 2 },
		"requires authPriv":                   func(c *SwitchConfig) { c.SecurityLevel = "authNoPriv" },
		"requires SHA authentication":         func(c *SwitchConfig) { c.AuthProtocol = "MD5" },
		"requires DES or AES privacy":         func(c *SwitchConfig) { c.PrivacyProtocol = "3DES" },
		"requires a host":                     func(c *SwitchConfig) { c.Host = "" },
		"requires a username":                 func(c *SwitchConfig) { c.Username = "" },
		"requires an authentication password": func(c *SwitchConfig) { c.AuthPassword = "" },
		"requires a privacy password":         func(c *SwitchConfig) { c.PrivacyPassword = "" },
		"requires a positive timeout":         func(c *SwitchConfig) { c.TimeoutSeconds = 0 },
		"rejects ports below 1":               func(c *SwitchConfig) { c.Port = 0 },
		"rejects ports above 65535":           func(c *SwitchConfig) { c.Port = 65536 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want rejection")
			}
		})
	}
}

func TestLoadAllowsInvalidEnabledSwitchConfig(t *testing.T) {
	for name, setting := range map[string]string{
		"SNMPv2":              "version = 2",
		"authNoPriv":          "security_level = authNoPriv",
		"MD5":                 "auth_protocol = MD5",
		"3DES":                "privacy_protocol = 3DES",
		"missing auth key":    "auth_password =",
		"missing privacy key": "privacy_password =",
		"port below range":    "port = 0",
		"port above range":    "port = 65536",
	} {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, "[switches]\nenable = true\nnames = switchy\n\n[switch.switchy]\nhost = 10.0.0.2\nusername = monitor\nauth_password = auth-secret\nprivacy_password = privacy-secret\n"+setting+"\n")
			if _, err := Load(path); err != nil {
				t.Fatalf("Load() error = %v, want invalid switch configuration retained for scan-time isolation", err)
			}
		})
	}
}

func TestApplyEnvAllowsInvalidEnabledSwitchConfig(t *testing.T) {
	for name, env := range map[string]string{
		"SNMPv2":           "ORANGUTAN_SWITCH_SWITCHY_VERSION=2",
		"authNoPriv":       "ORANGUTAN_SWITCH_SWITCHY_SECURITY_LEVEL=authNoPriv",
		"MD5":              "ORANGUTAN_SWITCH_SWITCHY_AUTH_PROTOCOL=MD5",
		"3DES":             "ORANGUTAN_SWITCH_SWITCHY_PRIVACY_PROTOCOL=3DES",
		"port below range": "ORANGUTAN_SWITCH_SWITCHY_PORT=0",
		"port above range": "ORANGUTAN_SWITCH_SWITCHY_PORT=65536",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validEnabledSwitchConfig(t)
			parts := strings.SplitN(env, "=", 2)
			t.Setenv(parts[0], parts[1])
			if err := cfg.ApplyEnv(); err != nil {
				t.Fatalf("ApplyEnv() error = %v, want invalid switch configuration retained for scan-time isolation", err)
			}
		})
	}
}

func TestApplyEnvAllowsEnabledSwitchWithMissingSecrets(t *testing.T) {
	for name, setting := range map[string]string{
		"authentication password": "auth_password =",
		"privacy password":        "privacy_password =",
	} {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, "[switches]\nenable = false\nnames = switchy\n\n[switch.switchy]\nhost = 10.0.0.2\nusername = monitor\nauth_password = auth-secret\nprivacy_password = privacy-secret\n"+setting+"\n")
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load disabled config: %v", err)
			}
			t.Setenv("ORANGUTAN_SWITCHES_ENABLE", "true")
			if err := cfg.ApplyEnv(); err != nil {
				t.Fatalf("ApplyEnv() error = %v, want missing secrets retained for scan-time isolation", err)
			}
		})
	}
}

func TestSwitchConfigPortBoundaries(t *testing.T) {
	for _, port := range []int{1, 65535} {
		cfg := SwitchConfig{ID: "switchy", Host: "10.0.0.2", Port: port, Version: 3, Username: "monitor", SecurityLevel: "authPriv", AuthProtocol: "SHA", AuthPassword: "auth-secret", PrivacyProtocol: "AES", PrivacyPassword: "privacy-secret", TimeoutSeconds: 5}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() error = %v for port %d", err, port)
		}
	}
}

func validEnabledSwitchConfig(t *testing.T) *Config {
	t.Helper()
	path := writeConfig(t, "[switches]\nenable = true\nnames = switchy\n\n[switch.switchy]\nhost = 10.0.0.2\nusername = monitor\nauth_password = auth-secret\nprivacy_password = privacy-secret\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load valid config: %v", err)
	}
	return cfg
}

func TestSwitchConfigDoesNotSerializeCredentials(t *testing.T) {
	cfg := Default()
	cfg.setSwitchNames("switchy")
	cfg.setSwitchValue("switchy", "auth_password", "auth-secret")
	cfg.setSwitchValue("switchy", "privacy_password", "privacy-secret")

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(data), "auth-secret") || strings.Contains(string(data), "privacy-secret") {
		t.Fatal("serialized configuration must not include SNMP credentials")
	}
}

func TestSwitchConfigNormalizesInvalidTimeout(t *testing.T) {
	path := writeConfig(t, `
[switches]
names = switchy

[switch.switchy]
host = 10.0.0.2
username = monitor
auth_password = auth-secret
privacy_password = privacy-secret
timeout_seconds = 0
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Switches.Configs["switchy"].TimeoutSeconds; got != 5 {
		t.Errorf("TimeoutSeconds = %d, want default 5", got)
	}
}

func TestRemoteScannersConfig_LoadFromINI(t *testing.T) {
	path := writeConfig(t, `
[remote_scanners]
enable = true
ssh_key = -----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASC
-----END PRIVATE KEY-----

[remote_scanner.opnsense]
host = 10.0.0.1
port = 22
user = root
networks = 10.0.0.0/24, 10.0.1.0/24

[remote_scanner.openwrt]
host = 10.5.5.1
port = 2222
user = admin
networks = 10.5.5.0/24, 192.168.1.0/24
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.RemoteScanners.Enable {
		t.Fatal("expected RemoteScanners.Enable = true")
	}
	if !strings.Contains(cfg.RemoteScanners.SSHKey, "BEGIN PRIVATE KEY") {
		t.Fatal("expected RemoteScanners.SSHKey to contain in-memory key")
	}
	if len(cfg.RemoteScanners.Names) != 2 {
		t.Fatalf("expected 2 scanners, got %d: %v", len(cfg.RemoteScanners.Names), cfg.RemoteScanners.Names)
	}

	// Test CIDR routing
	opn, ok := cfg.RemoteScanners.FindScannerForCIDR("10.0.0.0/24")
	if !ok || opn.Host != "10.0.0.1" || opn.User != "root" {
		t.Fatalf("FindScannerForCIDR 10.0.0.0/24: got %+v, ok=%v", opn, ok)
	}
	wrt, ok := cfg.RemoteScanners.FindScannerForCIDR("192.168.1.0/24")
	if !ok || wrt.Host != "10.5.5.1" || wrt.Port != 2222 || wrt.User != "admin" {
		t.Fatalf("FindScannerForCIDR 192.168.1.0/24: got %+v, ok=%v", wrt, ok)
	}

	// Test IP routing
	opnIP, ok := cfg.RemoteScanners.FindScannerForIP("10.0.1.55")
	if !ok || opnIP.Host != "10.0.0.1" {
		t.Fatalf("FindScannerForIP 10.0.1.55: got %+v, ok=%v", opnIP, ok)
	}
	wrtIP, ok := cfg.RemoteScanners.FindScannerForIP("10.5.5.12")
	if !ok || wrtIP.Host != "10.5.5.1" {
		t.Fatalf("FindScannerForIP 10.5.5.12: got %+v, ok=%v", wrtIP, ok)
	}

	// Unmapped IP
	unmapped, ok := cfg.RemoteScanners.FindScannerForIP("172.16.1.1")
	if ok || unmapped != nil {
		t.Fatalf("expected unmapped IP to return false, got %+v", unmapped)
	}
}

func TestRemoteScannersConfig_LoadFromEnv(t *testing.T) {
	t.Setenv("ORANGUTAN_REMOTE_SCAN_ENABLE", "true")
	t.Setenv("ORANGUTAN_REMOTE_SCAN_KEY", "-----BEGIN PRIVATE KEY-----\\nMIIE...\\n-----END PRIVATE KEY-----")
	t.Setenv("ORANGUTAN_REMOTE_SCANNERS_NAMES", "edge1")
	t.Setenv("ORANGUTAN_REMOTE_SCANNER_EDGE1_HOST", "10.10.10.1")
	t.Setenv("ORANGUTAN_REMOTE_SCANNER_EDGE1_PORT", "2200")
	t.Setenv("ORANGUTAN_REMOTE_SCANNER_EDGE1_USER", "root")
	t.Setenv("ORANGUTAN_REMOTE_SCANNER_EDGE1_NETWORKS", "10.10.10.0/24")

	path := writeConfig(t, "")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.ApplyEnv(); err != nil {
		t.Fatalf("ApplyEnv: %v", err)
	}
	if !cfg.RemoteScanners.Enable {
		t.Fatal("expected RemoteScanners.Enable = true from env")
	}
	if !strings.Contains(cfg.RemoteScanners.SSHKey, "BEGIN PRIVATE KEY") {
		t.Fatalf("SSHKey = %q, expected unescaped newlines", cfg.RemoteScanners.SSHKey)
	}
	sc, ok := cfg.RemoteScanners.FindScannerForCIDR("10.10.10.0/24")
	if !ok || sc.Host != "10.10.10.1" || sc.Port != 2200 || sc.User != "root" {
		t.Fatalf("scanner edge1 = %+v, ok=%v", sc, ok)
	}
}

func TestRemoteScannersConfigDoesNotSerializeCredentials(t *testing.T) {
	cfg := Default()
	cfg.RemoteScanners.Enable = true
	cfg.RemoteScanners.SSHKey = "super-secret-private-key"
	cfg.RemoteScanners.SSHPassword = "super-secret-password"

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(data), "super-secret-private-key") || strings.Contains(string(data), "super-secret-password") {
		t.Fatal("serialized configuration must not leak remote scanner SSH secrets")
	}
}
