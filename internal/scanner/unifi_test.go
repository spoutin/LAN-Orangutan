package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

func TestFetchUniFiClients_ProxyEndpoints(t *testing.T) {
	var receivedAuthHeader string
	var receivedAPIKeyHeader string
	var receivedAcceptHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		receivedAPIKeyHeader = r.Header.Get("X-API-KEY")
		receivedAcceptHeader = r.Header.Get("Accept")

		switch r.URL.Path {
		case "/proxy/network/api/s/default/stat/device":
			resp := map[string]interface{}{
				"meta": map[string]interface{}{"rc": "ok"},
				"data": []map[string]interface{}{
					{
						"mac":   "24:5a:4c:11:22:33",
						"name":  "Living Room AP",
						"model": "U6-Pro",
					},
					{
						"mac":   "24:5a:4c:44:55:66",
						"name":  "",
						"model": "U6-Lite",
					},
					{
						"mac":   "24:5a:4c:77:88:99",
						"name":  "",
						"model": "",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case "/proxy/network/api/s/default/stat/sta":
			resp := map[string]interface{}{
				"meta": map[string]interface{}{"rc": "ok"},
				"data": []map[string]interface{}{
					{
						"mac":         "dc:a6:32:01:02:03",
						"ip":          "192.168.1.50",
						"hostname":    "raspberrypi",
						"essid":       "HomeNet-5G",
						"ap_mac":      "24:5a:4c:11:22:33",
						"channel":     36,
						"radio":       "na",
						"radio_proto": "ac",
						"signal":      -54,
						"rx_rate":     866666,
						"tx_rate":     866666,
						"rx_bytes":    12345678,
						"tx_bytes":    87654321,
						"uptime":      3600,
						"model":       "Raspberry Pi 4B",
					},
					{
						"mac":         "00:11:22:33:44:55",
						"ip":          "192.168.1.51",
						"name":        "Smart-Plug",
						"essid":       "HomeNet-IoT",
						"ap_mac":      "24:5a:4c:44:55:66",
						"channel":     6,
						"radio":       "ng",
						"radio_proto": "n",
						"signal":      -45,
						"rx_rate":     54000,
						"tx_rate":     54000,
						"rx_bytes":    1000,
						"tx_bytes":    2000,
						"uptime":      7200,
						"unifi_model": "ESP8266",
					},
					{
						"mac":         "aa:bb:cc:dd:ee:ff",
						"ip":          "192.168.1.52",
						"hostname":    "laptop-wifi6",
						"essid":       "HomeNet-6G",
						"ap_mac":      "unknown-ap-mac",
						"channel":     69,
						"radio":       "6g",
						"radio_proto": "ax",
						"signal":      -105,
						"rx_rate":     1201000,
						"tx_rate":     1201000,
						"rx_bytes":    5000000,
						"tx_bytes":    6000000,
						"uptime":      1800,
					},
					{
						"mac":         "11:22:33:44:55:66",
						"ip":          "192.168.1.53",
						"hostname":    "phone-wifi7",
						"essid":       "HomeNet-Fast",
						"ap_mac":      "24:5a:4c:77:88:99",
						"channel":     149,
						"radio":       "ax",
						"radio_proto": "be",
						"signal":      -75,
						"rx_rate":     2402000,
						"tx_rate":     2402000,
						"rx_bytes":    90000,
						"tx_bytes":    80000,
						"uptime":      900,
					},
					{
						"mac":         "22:33:44:55:66:77",
						"ip":          "192.168.1.54",
						"hostname":    "legacy-client",
						"essid":       "HomeNet-Legacy",
						"ap_mac":      "",
						"channel":     1,
						"radio":       "ng",
						"radio_proto": "g",
						"signal":      -60,
						"rx_rate":     6000,
						"tx_rate":     6000,
						"rx_bytes":    5000,
						"tx_bytes":    4000,
						"uptime":      300,
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config.UniFiConfig{
		Enable:    true,
		URL:       server.URL,
		APIKey:    "  my-unifi-secret  ",
		Site:      "  default  ",
		VerifySSL: false,
	}

	clients, err := FetchUniFiClients(context.Background(), cfg)
	if err != nil {
		t.Fatalf("FetchUniFiClients failed: %v", err)
	}
	var _ []types.Device = clients

	if receivedAuthHeader != "Bearer my-unifi-secret" {
		t.Errorf("Authorization header = %q, want %q", receivedAuthHeader, "Bearer my-unifi-secret")
	}
	if receivedAPIKeyHeader != "my-unifi-secret" {
		t.Errorf("X-API-KEY header = %q, want %q", receivedAPIKeyHeader, "my-unifi-secret")
	}
	if receivedAcceptHeader != "application/json" {
		t.Errorf("Accept header = %q, want %q", receivedAcceptHeader, "application/json")
	}

	if len(clients) != 5 {
		t.Fatalf("expected 5 clients, got %d", len(clients))
	}

	// Verify Station 1
	c1 := clients[0]
	if c1.IP != "192.168.1.50" {
		t.Errorf("c1.IP = %q, want %q", c1.IP, "192.168.1.50")
	}
	if c1.MAC != "dc:a6:32:01:02:03" {
		t.Errorf("c1.MAC = %q, want %q", c1.MAC, "dc:a6:32:01:02:03")
	}
	if c1.Hostname != "raspberrypi" {
		t.Errorf("c1.Hostname = %q, want %q", c1.Hostname, "raspberrypi")
	}
	if c1.SSID != "HomeNet-5G" {
		t.Errorf("c1.SSID = %q, want %q", c1.SSID, "HomeNet-5G")
	}
	if c1.APName != "Living Room AP" {
		t.Errorf("c1.APName = %q, want %q", c1.APName, "Living Room AP")
	}
	if c1.Channel != 36 {
		t.Errorf("c1.Channel = %d, want 36", c1.Channel)
	}
	if c1.RadioBand != "5GHz" {
		t.Errorf("c1.RadioBand = %q, want %q", c1.RadioBand, "5GHz")
	}
	if c1.WiFiStandard != "Wi-Fi 5 (802.11ac)" {
		t.Errorf("c1.WiFiStandard = %q, want %q", c1.WiFiStandard, "Wi-Fi 5 (802.11ac)")
	}
	if c1.Signal != -54 {
		t.Errorf("c1.Signal = %d, want -54", c1.Signal)
	}
	if c1.SignalQuality != 92 {
		t.Errorf("c1.SignalQuality = %d, want 92", c1.SignalQuality)
	}
	if c1.RxRate != 867 {
		t.Errorf("c1.RxRate = %d, want 867", c1.RxRate)
	}
	if c1.TxRate != 867 {
		t.Errorf("c1.TxRate = %d, want 867", c1.TxRate)
	}
	if c1.RxBytes != 12345678 {
		t.Errorf("c1.RxBytes = %d, want 12345678", c1.RxBytes)
	}
	if c1.TxBytes != 87654321 {
		t.Errorf("c1.TxBytes = %d, want 87654321", c1.TxBytes)
	}
	if c1.AssociationUptime != 3600 {
		t.Errorf("c1.AssociationUptime = %d, want 3600", c1.AssociationUptime)
	}
	if c1.UniFiModel != "Raspberry Pi 4B" {
		t.Errorf("c1.UniFiModel = %q, want %q", c1.UniFiModel, "Raspberry Pi 4B")
	}
	if c1.Vendor == "" || c1.Vendor == "Unknown" {
		// Raspberry Pi Foundation OUI starts with dc:a6:32
		if c1.Vendor != "Raspberry Pi Trading Ltd" && c1.Vendor != "Raspberry Pi Foundation" {
			t.Logf("c1.Vendor = %q", c1.Vendor)
		}
	}
	if c1.Type == "" {
		t.Errorf("c1.Type should not be empty")
	}

	// Verify Station 2
	c2 := clients[1]
	if c2.IP != "192.168.1.51" {
		t.Errorf("c2.IP = %q, want %q", c2.IP, "192.168.1.51")
	}
	if c2.Hostname != "Smart-Plug" {
		t.Errorf("c2.Hostname = %q, want %q", c2.Hostname, "Smart-Plug")
	}
	if c2.APName != "U6-Lite" {
		t.Errorf("c2.APName = %q, want %q (model fallback)", c2.APName, "U6-Lite")
	}
	if c2.RadioBand != "2.4GHz" {
		t.Errorf("c2.RadioBand = %q, want %q", c2.RadioBand, "2.4GHz")
	}
	if c2.WiFiStandard != "Wi-Fi 4 (802.11n)" {
		t.Errorf("c2.WiFiStandard = %q, want %q", c2.WiFiStandard, "Wi-Fi 4 (802.11n)")
	}
	if c2.SignalQuality != 100 {
		t.Errorf("c2.SignalQuality = %d, want 100", c2.SignalQuality)
	}
	if c2.RxRate != 54 || c2.TxRate != 54 {
		t.Errorf("c2 rates = (%d, %d), want (54, 54)", c2.RxRate, c2.TxRate)
	}
	if c2.UniFiModel != "ESP8266" {
		t.Errorf("c2.UniFiModel = %q, want %q", c2.UniFiModel, "ESP8266")
	}

	// Verify Station 3
	c3 := clients[2]
	if c3.APName != "unknown-ap-mac" {
		t.Errorf("c3.APName = %q, want %q", c3.APName, "unknown-ap-mac")
	}
	if c3.RadioBand != "6GHz" {
		t.Errorf("c3.RadioBand = %q, want %q", c3.RadioBand, "6GHz")
	}
	if c3.WiFiStandard != "Wi-Fi 6 (802.11ax)" {
		t.Errorf("c3.WiFiStandard = %q, want %q", c3.WiFiStandard, "Wi-Fi 6 (802.11ax)")
	}
	if c3.SignalQuality != 0 {
		t.Errorf("c3.SignalQuality = %d, want 0", c3.SignalQuality)
	}
	if c3.RxRate != 1201 || c3.TxRate != 1201 {
		t.Errorf("c3 rates = (%d, %d), want (1201, 1201)", c3.RxRate, c3.TxRate)
	}

	// Verify Station 4
	c4 := clients[3]
	if c4.APName != "24:5a:4c:77:88:99" {
		t.Errorf("c4.APName = %q, want %q", c4.APName, "24:5a:4c:77:88:99")
	}
	if c4.RadioBand != "5GHz" {
		t.Errorf("c4.RadioBand = %q, want %q", c4.RadioBand, "5GHz")
	}
	if c4.WiFiStandard != "Wi-Fi 7 (802.11be)" {
		t.Errorf("c4.WiFiStandard = %q, want %q", c4.WiFiStandard, "Wi-Fi 7 (802.11be)")
	}
	if c4.SignalQuality != 50 {
		t.Errorf("c4.SignalQuality = %d, want 50", c4.SignalQuality)
	}
	if c4.RxRate != 2402 || c4.TxRate != 2402 {
		t.Errorf("c4.rates = (%d, %d), want (2402, 2402)", c4.RxRate, c4.TxRate)
	}

	// Verify Station 5 (legacy 6 Mbps rate negotiation in Kbps: 6000 -> 6)
	c5 := clients[4]
	if c5.IP != "192.168.1.54" {
		t.Errorf("c5.IP = %q, want %q", c5.IP, "192.168.1.54")
	}
	if c5.RxRate != 6 || c5.TxRate != 6 {
		t.Errorf("c5 rates = (%d, %d), want (6, 6)", c5.RxRate, c5.TxRate)
	}
}

func TestFetchUniFiClients_FallbackToLegacyAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/proxy/network/") {
			http.NotFound(w, r)
			return
		}

		switch r.URL.Path {
		case "/api/s/mysite/stat/device":
			resp := map[string]interface{}{
				"meta": map[string]interface{}{"rc": "ok"},
				"data": []map[string]interface{}{
					{"mac": "11:22:33:aa:bb:cc", "name": "Office AP"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case "/api/s/mysite/stat/sta":
			resp := map[string]interface{}{
				"meta": map[string]interface{}{"rc": "ok"},
				"data": []map[string]interface{}{
					{
						"mac":      "aa:bb:cc:11:22:33",
						"ip":       "10.0.0.99",
						"hostname": "work-laptop",
						"essid":    "WorkNet",
						"ap_mac":   "11:22:33:aa:bb:cc",
						"signal":   -60,
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config.UniFiConfig{
		Enable:    true,
		URL:       server.URL + "////", // test trailing slashes trimming
		Site:      "mysite",
		APIKey:    "legacy-key",
		VerifySSL: false,
	}

	clients, err := FetchUniFiClients(context.Background(), cfg)
	if err != nil {
		t.Fatalf("FetchUniFiClients failed with legacy fallback: %v", err)
	}

	if len(clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(clients))
	}
	if clients[0].IP != "10.0.0.99" {
		t.Errorf("IP = %q, want 10.0.0.99", clients[0].IP)
	}
	if clients[0].APName != "Office AP" {
		t.Errorf("APName = %q, want %q", clients[0].APName, "Office AP")
	}
	if clients[0].SignalQuality != 80 { // 2 * (-60 + 100) = 80
		t.Errorf("SignalQuality = %d, want 80", clients[0].SignalQuality)
	}
}

func TestFetchUniFiClients_DefaultSite(t *testing.T) {
	requestedPath := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		resp := map[string]interface{}{
			"data": []map[string]interface{}{},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := config.UniFiConfig{
		URL:  server.URL,
		Site: "   ", // whitespace site should default to "default"
	}

	_, _ = FetchUniFiClients(context.Background(), cfg)
	if !strings.Contains(requestedPath, "/api/s/default/") {
		t.Errorf("requestedPath = %q, expected to contain '/api/s/default/'", requestedPath)
	}
}

func TestFetchUniFiClients_ErrorCases(t *testing.T) {
	// 1. 401 Unauthorized
	server401 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer server401.Close()

	_, err := FetchUniFiClients(context.Background(), config.UniFiConfig{URL: server401.URL})
	if err == nil {
		t.Error("expected error on 401 Unauthorized, got nil")
	}

	// 2. 500 Internal Server Error
	server500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}))
	defer server500.Close()

	_, err = FetchUniFiClients(context.Background(), config.UniFiConfig{URL: server500.URL})
	if err == nil {
		t.Error("expected error on 500 Server Error, got nil")
	}

	// 3. 404 on both primary and fallback
	server404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server404.Close()

	_, err = FetchUniFiClients(context.Background(), config.UniFiConfig{URL: server404.URL})
	if err == nil {
		t.Error("expected error on 404 Not Found, got nil")
	}

	// 4. Invalid JSON
	serverBadJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer serverBadJSON.Close()

	_, err = FetchUniFiClients(context.Background(), config.UniFiConfig{URL: serverBadJSON.URL})
	if err == nil {
		t.Error("expected error on invalid JSON, got nil")
	}
}

func TestParseRate(t *testing.T) {
	tests := []struct {
		input float64
		want  int
	}{
		{input: 0, want: 0},
		{input: -10, want: 0},
		{input: 6000, want: 6},
		{input: 54000, want: 54},
		{input: 866666, want: 867},
		{input: 1201000, want: 1201},
		{input: 54, want: 54},
		{input: 866, want: 866},
	}
	for _, tt := range tests {
		got := parseRate(tt.input)
		if got != tt.want {
			t.Errorf("parseRate(%v) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestCalculateSignalQuality(t *testing.T) {
	tests := []struct {
		sig  int
		want int
	}{
		{sig: 0, want: 0},
		{sig: 10, want: 0},
		{sig: -105, want: 0},
		{sig: -100, want: 0},
		{sig: -50, want: 100},
		{sig: -40, want: 100},
		{sig: -54, want: 92},
		{sig: -75, want: 50},
		{sig: -60, want: 80},
	}
	for _, tt := range tests {
		got := calculateSignalQuality(tt.sig)
		if got != tt.want {
			t.Errorf("calculateSignalQuality(%d) = %d, want %d", tt.sig, got, tt.want)
		}
	}
}
