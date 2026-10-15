package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
)

func TestExtendedRouterTelemetry(t *testing.T) {
	t.Run("OPNsense_Telemetry", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/api/kea/leases4/search":
				resp := map[string]interface{}{
					"rows": []map[string]interface{}{
						{
							"address":        "192.168.1.101",
							"hwaddr":         "00:11:22:33:44:01",
							"hostname":       "device-cltt",
							"valid_lifetime": 7200,
							"cltt":           1700000000,
						},
						{
							"address":        "192.168.1.102",
							"hwaddr":         "00:11:22:33:44:02",
							"hostname":       "device-expire-epoch",
							"expire":         1700008000,
							"valid_lifetime": "3600",
						},
						{
							"address":        "192.168.1.103",
							"hwaddr":         "00:11:22:33:44:03",
							"hostname":       "device-expire-string",
							"expire":         "2026-09-28T12:00:00Z",
							"valid_lifetime": 1800,
						},
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			case "/api/kea/dhcpv4/searchReservation":
				resp := map[string]interface{}{
					"rows": []map[string]interface{}{
						{
							"ip_address":  "192.168.1.10",
							"hwaddr":      "00:11:22:33:44:10",
							"hostname":    "nas-server",
							"description": "Storage Server Reservation",
						},
						{
							"ip_address": "192.168.1.11",
							"hwaddr":     "00:11:22:33:44:11",
							"hostname":   "printer",
							"notes":      "Office Printer Fixed IP",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			case "/api/diagnostics/interface/getArp":
				resp := []map[string]interface{}{
					{
						"ip":               "192.168.1.1",
						"mac":              "00:11:22:33:44:00",
						"intf":             "vtnet0",
						"intf_description": "LAN",
					},
					{
						"ip":               "192.168.1.2",
						"mac":              "00:11:22:33:44:20",
						"intf":             "vlan0.10",
						"intf_description": "IoT",
					},
					{
						"ip":               "192.168.1.3",
						"mac":              "00:11:22:33:44:30",
						"intf":             "vtnet1",
						"intf_description": "",
					},
					{
						"ip":               "192.168.1.4",
						"mac":              "00:11:22:33:44:40",
						"intf":             "",
						"intf_description": "DMZ",
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		cfg := config.OPNsenseConfig{
			Enable:    true,
			URL:       server.URL,
			APIKey:    "test-key",
			APISecret: "test-secret",
			VerifySSL: false,
		}

		leases, reservations, arpEntries, err := FetchOPNsenseDHCP(context.Background(), cfg)
		if err != nil {
			t.Fatalf("FetchOPNsenseDHCP failed: %v", err)
		}

		// Verify Leases
		if len(leases) != 3 {
			t.Fatalf("expected 3 leases, got %d", len(leases))
		}
		for i, l := range leases {
			if l.RouterSource != "OPNsense" {
				t.Errorf("lease[%d].RouterSource = %q, want 'OPNsense'", i, l.RouterSource)
			}
		}

		// Lease 0: cltt + valid_lifetime
		if leases[0].LeaseLifetime != 7200 {
			t.Errorf("leases[0].LeaseLifetime = %d, want 7200", leases[0].LeaseLifetime)
		}
		expectedExpire0 := time.Unix(1700000000+7200, 0)
		if !leases[0].LeaseExpires.Equal(expectedExpire0) {
			t.Errorf("leases[0].LeaseExpires = %v, want %v", leases[0].LeaseExpires, expectedExpire0)
		}

		// Lease 1: expire epoch + valid_lifetime string
		if leases[1].LeaseLifetime != 3600 {
			t.Errorf("leases[1].LeaseLifetime = %d, want 3600", leases[1].LeaseLifetime)
		}
		expectedExpire1 := time.Unix(1700008000, 0)
		if !leases[1].LeaseExpires.Equal(expectedExpire1) {
			t.Errorf("leases[1].LeaseExpires = %v, want %v", leases[1].LeaseExpires, expectedExpire1)
		}

		// Lease 2: expire ISO timestamp
		expectedExpire2, _ := time.Parse(time.RFC3339, "2026-09-28T12:00:00Z")
		if !leases[2].LeaseExpires.Equal(expectedExpire2) {
			t.Errorf("leases[2].LeaseExpires = %v, want %v", leases[2].LeaseExpires, expectedExpire2)
		}
		if leases[2].LeaseLifetime != 1800 {
			t.Errorf("leases[2].LeaseLifetime = %d, want 1800", leases[2].LeaseLifetime)
		}

		// Verify Reservations
		if len(reservations) != 2 {
			t.Fatalf("expected 2 reservations, got %d", len(reservations))
		}
		for i, r := range reservations {
			if r.RouterSource != "OPNsense" {
				t.Errorf("reservation[%d].RouterSource = %q, want 'OPNsense'", i, r.RouterSource)
			}
		}
		if reservations[0].RouterNotes != "Storage Server Reservation" {
			t.Errorf("reservations[0].RouterNotes = %q, want 'Storage Server Reservation'", reservations[0].RouterNotes)
		}
		if reservations[1].RouterNotes != "Office Printer Fixed IP" {
			t.Errorf("reservations[1].RouterNotes = %q, want 'Office Printer Fixed IP'", reservations[1].RouterNotes)
		}

		// Verify ARP
		if len(arpEntries) != 4 {
			t.Fatalf("expected 4 ARP entries, got %d", len(arpEntries))
		}
		for i, a := range arpEntries {
			if a.RouterSource != "OPNsense" {
				t.Errorf("arpEntries[%d].RouterSource = %q, want 'OPNsense'", i, a.RouterSource)
			}
		}
		if arpEntries[0].RouterInterface != "vtnet0 (LAN)" {
			t.Errorf("arpEntries[0].RouterInterface = %q, want 'vtnet0 (LAN)'", arpEntries[0].RouterInterface)
		}
		if arpEntries[1].RouterInterface != "vlan0.10 (IoT)" {
			t.Errorf("arpEntries[1].RouterInterface = %q, want 'vlan0.10 (IoT)'", arpEntries[1].RouterInterface)
		}
		if arpEntries[2].RouterInterface != "vtnet1" {
			t.Errorf("arpEntries[2].RouterInterface = %q, want 'vtnet1'", arpEntries[2].RouterInterface)
		}
		if arpEntries[3].RouterInterface != "DMZ" {
			t.Errorf("arpEntries[3].RouterInterface = %q, want 'DMZ'", arpEntries[3].RouterInterface)
		}
	})

	t.Run("OpenWrt_Telemetry", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/api/v3/dhcp/leases":
				resp := []map[string]interface{}{
					{
						"ip":       "192.168.1.150",
						"mac":      "aa:bb:cc:dd:ee:01",
						"hostname": "laptop-relative-expire",
						"expires":  3600,
						"device":   "br-lan",
					},
					{
						"ip":        "192.168.1.151",
						"mac":       "aa:bb:cc:dd:ee:02",
						"hostname":  "phone-epoch-expire",
						"expires":   1759050000,
						"leasetime": 86400,
						"interface": "lan",
					},
					{
						"ip":       "192.168.1.152",
						"mac":      "aa:bb:cc:dd:ee:03",
						"hostname": "tv-network-field",
						"expires":  1800,
						"network":  "guest",
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			case "/api/v3/dhcp/hosts":
				resp := []map[string]interface{}{
					{
						"name": "static-host-1",
						"ip":   "192.168.1.200",
						"macs": []string{"aa:bb:cc:dd:ee:10"},
						"note": "Primary Smart TV",
					},
					{
						"name":    "static-host-2",
						"ip":      "192.168.1.201",
						"macs":    []string{"aa:bb:cc:dd:ee:11"},
						"comment": "Security Camera NVR",
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		cfg := config.OpenWrtConfig{
			Enable:    true,
			URL:       server.URL,
			APIToken:  "test-token",
			VerifySSL: false,
		}

		before := time.Now()
		leases, reservations, err := FetchOpenWrtDHCP(context.Background(), cfg)
		if err != nil {
			t.Fatalf("FetchOpenWrtDHCP failed: %v", err)
		}

		// Verify Leases
		if len(leases) != 3 {
			t.Fatalf("expected 3 leases, got %d", len(leases))
		}
		for i, l := range leases {
			if l.RouterSource != "OpenWrt" {
				t.Errorf("lease[%d].RouterSource = %q, want 'OpenWrt'", i, l.RouterSource)
			}
		}

		// Lease 0: relative expires = 3600, device = "br-lan"
		if leases[0].RouterInterface != "br-lan" {
			t.Errorf("leases[0].RouterInterface = %q, want 'br-lan'", leases[0].RouterInterface)
		}
		if leases[0].LeaseLifetime != 3600 {
			t.Errorf("leases[0].LeaseLifetime = %d, want 3600", leases[0].LeaseLifetime)
		}
		minExpected := before.Add(3590 * time.Second)
		maxExpected := time.Now().Add(3610 * time.Second)
		if leases[0].LeaseExpires.Before(minExpected) || leases[0].LeaseExpires.After(maxExpected) {
			t.Errorf("leases[0].LeaseExpires = %v, expected between %v and %v", leases[0].LeaseExpires, minExpected, maxExpected)
		}

		// Lease 1: epoch expires = 1759050000, leasetime = 86400, interface = "lan"
		if leases[1].RouterInterface != "lan" {
			t.Errorf("leases[1].RouterInterface = %q, want 'lan'", leases[1].RouterInterface)
		}
		if leases[1].LeaseLifetime != 86400 {
			t.Errorf("leases[1].LeaseLifetime = %d, want 86400", leases[1].LeaseLifetime)
		}
		expectedEpoch := time.Unix(1759050000, 0)
		if !leases[1].LeaseExpires.Equal(expectedEpoch) {
			t.Errorf("leases[1].LeaseExpires = %v, want %v", leases[1].LeaseExpires, expectedEpoch)
		}

		// Lease 2: relative expires = 1800, network = "guest"
		if leases[2].RouterInterface != "guest" {
			t.Errorf("leases[2].RouterInterface = %q, want 'guest'", leases[2].RouterInterface)
		}
		if leases[2].LeaseLifetime != 1800 {
			t.Errorf("leases[2].LeaseLifetime = %d, want 1800", leases[2].LeaseLifetime)
		}

		// Verify Reservations
		if len(reservations) != 2 {
			t.Fatalf("expected 2 reservations, got %d", len(reservations))
		}
		for i, r := range reservations {
			if r.RouterSource != "OpenWrt" {
				t.Errorf("reservation[%d].RouterSource = %q, want 'OpenWrt'", i, r.RouterSource)
			}
		}
		if reservations[0].RouterNotes != "Primary Smart TV" {
			t.Errorf("reservations[0].RouterNotes = %q, want 'Primary Smart TV'", reservations[0].RouterNotes)
		}
		if reservations[1].RouterNotes != "Security Camera NVR" {
			t.Errorf("reservations[1].RouterNotes = %q, want 'Security Camera NVR'", reservations[1].RouterNotes)
		}
	})
}

func TestExtendedRouterTelemetry_EdgeCases(t *testing.T) {
	t.Run("OPNsense_RelativeExpire_And_IdenticalIntf", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/api/kea/leases4/search":
				resp := map[string]interface{}{
					"rows": []map[string]interface{}{
						{
							"address": "192.168.1.50",
							"hwaddr":  "00:11:22:33:44:50",
							"expire":  600, // relative seconds
						},
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			case "/api/kea/dhcpv4/searchReservation":
				resp := map[string]interface{}{
					"rows": []map[string]interface{}{
						{
							"ip_address": "192.168.1.50",
							"hwaddr":     "00:11:22:33:44:50",
							"comment":    "Fallback comment field",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			case "/api/diagnostics/interface/getArp":
				resp := []map[string]interface{}{
					{
						"ip":               "192.168.1.50",
						"mac":              "00:11:22:33:44:50",
						"intf":             "LAN",
						"intf_description": "LAN",
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		cfg := config.OPNsenseConfig{
			Enable: true,
			URL:    server.URL,
		}

		leases, reservations, arpEntries, err := FetchOPNsenseDHCP(context.Background(), cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(leases) != 1 {
			t.Fatalf("expected 1 lease, got %d", len(leases))
		}
		if leases[0].LeaseExpires.IsZero() {
			t.Errorf("expected non-zero LeaseExpires for relative seconds")
		}
		if len(reservations) != 1 || reservations[0].RouterNotes != "Fallback comment field" {
			t.Errorf("expected reservation note 'Fallback comment field', got %+v", reservations)
		}
		if len(arpEntries) != 1 || arpEntries[0].RouterInterface != "LAN" {
			t.Errorf("expected identical intf/desc to format as 'LAN', got %q", arpEntries[0].RouterInterface)
		}
	})

	t.Run("OpenWrt_EmptyAndZeroExpires", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/api/v3/dhcp/leases":
				resp := []map[string]interface{}{
					{
						"ip":       "192.168.1.60",
						"mac":      "aa:bb:cc:dd:ee:60",
						"expires":  0,
						"hostname": "zero-expire",
					},
					{
						"ip":       "192.168.1.61",
						"mac":      "aa:bb:cc:dd:ee:61",
						"hostname": "no-expire",
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			case "/api/v3/dhcp/hosts":
				resp := []map[string]interface{}{
					{
						"ip":   "192.168.1.60",
						"mac":  "aa:bb:cc:dd:ee:60",
						"name": "zero-expire",
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		cfg := config.OpenWrtConfig{
			Enable: true,
			URL:    server.URL,
		}

		leases, reservations, err := FetchOpenWrtDHCP(context.Background(), cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(leases) != 2 {
			t.Fatalf("expected 2 leases, got %d", len(leases))
		}
		if !leases[0].LeaseExpires.IsZero() {
			t.Errorf("expected zero LeaseExpires for expires=0, got %v", leases[0].LeaseExpires)
		}
		if !leases[1].LeaseExpires.IsZero() {
			t.Errorf("expected zero LeaseExpires for missing expires, got %v", leases[1].LeaseExpires)
		}
		if len(reservations) != 1 || reservations[0].MAC != "aa:bb:cc:dd:ee:60" {
			t.Errorf("expected single mac field to populate MAC, got %+v", reservations)
		}
	})

	t.Run("OpenWrt_HTTPError", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		cfg := config.OpenWrtConfig{
			Enable: true,
			URL:    server.URL,
		}

		_, _, err := FetchOpenWrtDHCP(context.Background(), cfg)
		if err == nil {
			t.Error("expected error on 500 response, got nil")
		}
	})

	t.Run("OPNsense_HTTPError", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()

		cfg := config.OPNsenseConfig{
			Enable: true,
			URL:    server.URL,
		}

		_, _, _, err := FetchOPNsenseDHCP(context.Background(), cfg)
		if err == nil {
			t.Error("expected error on 403 response, got nil")
		}
	})
}

func TestFetchOpenWrtDHCP_PreservesAuthOnHTTPRedirectToHTTPS(t *testing.T) {
	httpsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer secret-token" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"code":"unauthorized","message":"missing or invalid token"}`))
			return
		}
		if r.URL.Path == "/api/v3/dhcp/leases" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{"ip":"10.5.5.10","mac":"00:11:22:33:44:55","hostname":"my-host"}]`))
			return
		}
		if r.URL.Path == "/api/v3/dhcp/hosts" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer httpsServer.Close()

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, httpsServer.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer httpServer.Close()

	cfg := config.OpenWrtConfig{
		Enable:    true,
		URL:       httpServer.URL,
		APIToken:  "secret-token",
		VerifySSL: false,
	}

	leases, _, err := FetchOpenWrtDHCP(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected FetchOpenWrtDHCP to succeed despite HTTP->HTTPS redirect, got: %v", err)
	}
	if len(leases) != 1 || leases[0].Hostname != "my-host" {
		t.Fatalf("unexpected leases: %+v", leases)
	}
}

func TestFetchOPNsenseNetFlow(t *testing.T) {
	t.Run("NetFlowEndpointSuccess", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/diagnostics/networkinsight/top" {
				records := []map[string]interface{}{
					{
						"source":      "10.0.0.55",
						"destination": "1.1.1.1",
						"octets":      1500000,
					},
					{
						"source":      "8.8.8.8",
						"destination": "10.0.0.55",
						"octets":      4500000,
					},
				}
				_ = json.NewEncoder(w).Encode(records)
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()

		cfg := config.OPNsenseConfig{
			Enable:    true,
			URL:       server.URL,
			APIKey:    "test-key",
			APISecret: "test-secret",
		}

		stats, err := FetchOPNsenseNetFlow(context.Background(), cfg)
		if err != nil {
			t.Fatalf("FetchOPNsenseNetFlow failed: %v", err)
		}
		dev55, ok := stats["10.0.0.55"]
		if !ok {
			t.Fatalf("expected stats for 10.0.0.55, got: %+v", stats)
		}
		if dev55.TxBytes != 1500000 || dev55.RxBytes != 4500000 {
			t.Errorf("expected 1500000 Tx and 4500000 Rx, got %d Tx, %d Rx", dev55.TxBytes, dev55.RxBytes)
		}
	})

	t.Run("FallbackToQueryStates", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/diagnostics/networkinsight/top" {
				// NetFlow returns 404 or empty
				http.NotFound(w, r)
				return
			}
			if r.URL.Path == "/api/diagnostics/firewall/query_states" {
				resp := map[string]interface{}{
					"rows": []map[string]interface{}{
						{
							"src_addr": "10.0.0.99:43210",
							"dst_addr": "142.250.190.46:443",
							"bytes":    2500000,
						},
						{
							"src_addr": "142.250.190.46:443",
							"dst_addr": "10.0.0.99:43210",
							"bytes":    7500000,
						},
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()

		cfg := config.OPNsenseConfig{
			Enable:    true,
			URL:       server.URL,
			APIKey:    "test-key",
			APISecret: "test-secret",
		}

		stats, err := FetchOPNsenseNetFlow(context.Background(), cfg)
		if err != nil {
			t.Fatalf("FetchOPNsenseNetFlow failed: %v", err)
		}
		dev99, ok := stats["10.0.0.99"]
		if !ok {
			t.Fatalf("expected stats for 10.0.0.99, got: %+v", stats)
		}
		if dev99.TxBytes != 2500000 || dev99.RxBytes != 7500000 {
			t.Errorf("expected 2500000 Tx and 7500000 Rx, got %d Tx, %d Rx", dev99.TxBytes, dev99.RxBytes)
		}
	})

	t.Run("QueryStatesArrayBytesRealOPNsenseFormat", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/diagnostics/networkinsight/top" {
				// Returns empty list like real OPNsense when NetFlow aggregation is disabled
				_ = json.NewEncoder(w).Encode([]interface{}{})
				return
			}
			if r.URL.Path == "/api/diagnostics/firewall/query_states" {
				resp := map[string]interface{}{
					"rows": []map[string]interface{}{
						{
							"label":    "c08ef1cc-5779-4f07-87a1-89d7b5ad8854",
							"descr":    "Allow internet traffic",
							"iface":    "all",
							"proto":    "tcp",
							"src_addr": "10.0.0.50",
							"src_port": "54321",
							"dst_addr": "142.250.190.46",
							"dst_port": "443",
							"bytes":    []interface{}{3450000, 8912000},
							"pkts":     []interface{}{42, 85},
						},
					},
					"rowCount": 1,
					"total":    1,
				}
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()

		cfg := config.OPNsenseConfig{
			Enable:    true,
			URL:       server.URL,
			APIKey:    "test-key",
			APISecret: "test-secret",
		}

		stats, err := FetchOPNsenseNetFlow(context.Background(), cfg)
		if err != nil {
			t.Fatalf("FetchOPNsenseNetFlow failed: %v", err)
		}
		dev50, ok := stats["10.0.0.50"]
		if !ok {
			t.Fatalf("expected stats for 10.0.0.50, got: %+v", stats)
		}
		if dev50.TxBytes != 3450000 {
			t.Errorf("expected 3450000 TxBytes for 10.0.0.50, got %d", dev50.TxBytes)
		}
		if dev50.RxBytes != 8912000 {
			t.Errorf("expected 8912000 RxBytes for 10.0.0.50, got %d", dev50.RxBytes)
		}

		devWAN, ok := stats["142.250.190.46"]
		if !ok {
			t.Fatalf("expected stats for 142.250.190.46, got: %+v", stats)
		}
		if devWAN.RxBytes != 3450000 {
			t.Errorf("expected 3450000 RxBytes for 142.250.190.46, got %d", devWAN.RxBytes)
		}
		if devWAN.TxBytes != 8912000 {
			t.Errorf("expected 8912000 TxBytes for 142.250.190.46, got %d", devWAN.TxBytes)
		}
	})

	t.Run("QueryStatesColonSeparatedStringBytes", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/diagnostics/firewall/query_states" {
				resp := map[string]interface{}{
					"rows": []map[string]interface{}{
						{
							"src_addr": "10.0.0.60:12345",
							"dst_addr": "1.1.1.1:53",
							"bytes":    "1200:4800",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()

		cfg := config.OPNsenseConfig{
			Enable:    true,
			URL:       server.URL,
			APIKey:    "test-key",
			APISecret: "test-secret",
		}

		stats, err := FetchOPNsenseNetFlow(context.Background(), cfg)
		if err != nil {
			t.Fatalf("FetchOPNsenseNetFlow failed: %v", err)
		}
		dev60, ok := stats["10.0.0.60"]
		if !ok {
			t.Fatalf("expected stats for 10.0.0.60, got: %+v", stats)
		}
		if dev60.TxBytes != 1200 || dev60.RxBytes != 4800 {
			t.Errorf("expected 1200 Tx and 4800 Rx, got %d Tx, %d Rx", dev60.TxBytes, dev60.RxBytes)
		}
	})

	t.Run("NetFlowRowsEnvelope", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/diagnostics/networkinsight/top" {
				records := map[string]interface{}{
					"rows": []map[string]interface{}{
						{
							"src":    "10.0.0.77",
							"dst":    "1.1.1.1",
							"octets": 3200000,
						},
						{
							"src":    "1.1.1.1",
							"dst":    "10.0.0.77",
							"octets": 6400000,
						},
					},
				}
				_ = json.NewEncoder(w).Encode(records)
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()

		cfg := config.OPNsenseConfig{
			Enable:    true,
			URL:       server.URL,
			APIKey:    "test-key",
			APISecret: "test-secret",
		}

		stats, err := FetchOPNsenseNetFlow(context.Background(), cfg)
		if err != nil {
			t.Fatalf("FetchOPNsenseNetFlow failed: %v", err)
		}
		dev77, ok := stats["10.0.0.77"]
		if !ok {
			t.Fatalf("expected stats for 10.0.0.77, got: %+v", stats)
		}
		if dev77.TxBytes != 3200000 || dev77.RxBytes != 6400000 {
			t.Errorf("expected 3200000 Tx and 6400000 Rx, got %d Tx, %d Rx", dev77.TxBytes, dev77.RxBytes)
		}
	})

	t.Run("QueryStatesSlashedBytesAndArrows", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/diagnostics/networkinsight/top" {
				http.NotFound(w, r)
				return
			}
			if r.URL.Path == "/api/diagnostics/firewall/query_states" {
				resp := map[string]interface{}{
					"rows": []map[string]interface{}{
						{
							"source":      "10.0.0.123:55555 -> 1.1.1.1:443",
							"destination": "1.1.1.1:443",
							"bytes":       "1000 / 2000",
						},
						{
							"source":      "1.1.1.1:443",
							"destination": "10.0.0.123:55555",
							"bytes":       "1.5 KB",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()

		cfg := config.OPNsenseConfig{
			Enable:    true,
			URL:       server.URL,
			APIKey:    "test-key",
			APISecret: "test-secret",
		}

		stats, err := FetchOPNsenseNetFlow(context.Background(), cfg)
		if err != nil {
			t.Fatalf("FetchOPNsenseNetFlow failed: %v", err)
		}
		dev123, ok := stats["10.0.0.123"]
		if !ok {
			t.Fatalf("expected stats for 10.0.0.123, got: %+v", stats)
		}
		if dev123.TxBytes != 3000 { // 1000 + 2000
			t.Errorf("expected 3000 Tx, got %d", dev123.TxBytes)
		}
		if dev123.RxBytes != 1536 { // 1.5 * 1024
			t.Errorf("expected 1536 Rx, got %d", dev123.RxBytes)
		}
	})
}

func TestFetchOpenWrtNlbwmon(t *testing.T) {
	t.Run("StandardResultAndAuth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if r.URL.Path != "/ubus" {
				t.Errorf("expected /ubus, got %s", r.URL.Path)
			}
			if auth := r.Header.Get("Authorization"); auth != "Bearer secret-token-123" {
				t.Errorf("expected Bearer secret-token-123, got %s", auth)
			}
			if ct := r.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("expected application/json, got %s", ct)
			}

			var reqBody struct {
				JSONRPC string        `json:"jsonrpc"`
				ID      int           `json:"id"`
				Method  string        `json:"method"`
				Params  []interface{} `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				t.Fatalf("failed to decode req body: %v", err)
			}
			if reqBody.Method != "call" {
				t.Errorf("expected method call, got %s", reqBody.Method)
			}
			if len(reqBody.Params) != 4 {
				t.Fatalf("expected 4 params, got %d", len(reqBody.Params))
			}
			if reqBody.Params[0] != "secret-token-123" {
				t.Errorf("expected param[0] secret-token-123, got %v", reqBody.Params[0])
			}
			if reqBody.Params[1] != "nlbwmon" {
				t.Errorf("expected param[1] nlbwmon, got %v", reqBody.Params[1])
			}
			if reqBody.Params[2] != "dump" {
				t.Errorf("expected param[2] dump, got %v", reqBody.Params[2])
			}
			p3, ok := reqBody.Params[3].(map[string]interface{})
			if !ok || p3["format"] != "json" {
				t.Errorf("expected param[3] format json, got %v", reqBody.Params[3])
			}

			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"result": []interface{}{
					0,
					map[string]interface{}{
						"columns": []string{"mac", "ip", "in", "out"},
						"rows": []interface{}{
							[]interface{}{"aa:bb:cc:dd:ee:01", "10.5.5.10", 1000, 500},
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := config.OpenWrtConfig{
			Enable:   true,
			URL:      server.URL,
			APIToken: "secret-token-123",
		}

		stats, err := FetchOpenWrtNlbwmon(context.Background(), cfg)
		if err != nil {
			t.Fatalf("FetchOpenWrtNlbwmon failed: %v", err)
		}
		if len(stats) != 1 {
			t.Fatalf("expected 1 stat, got %d", len(stats))
		}
		dev, ok := stats["10.5.5.10"]
		if !ok {
			t.Fatalf("expected stats for 10.5.5.10, got %+v", stats)
		}
		if dev.RxBytes != 1000 {
			t.Errorf("expected 1000 RxBytes, got %d", dev.RxBytes)
		}
		if dev.TxBytes != 500 {
			t.Errorf("expected 500 TxBytes, got %d", dev.TxBytes)
		}
	})

	t.Run("AlternateColumnsAndMultipleRowsAggregation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Direct object result and alternate column names
			resp := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"result": map[string]interface{}{
					"columns": []string{"host", "ether", "rx_bytes", "tx_bytes"},
					"rows": []interface{}{
						[]interface{}{"10.5.5.20", "aa:bb:cc:dd:ee:02", 2000, 1000},
						[]interface{}{"10.5.5.20", "aa:bb:cc:dd:ee:02", 3000, 500},
						[]interface{}{"10.5.5.30", "aa:bb:cc:dd:ee:03", 5000, 2500},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := config.OpenWrtConfig{
			Enable:   true,
			URL:      server.URL,
			APIToken: "token",
		}

		stats, err := FetchOpenWrtNlbwmon(context.Background(), cfg)
		if err != nil {
			t.Fatalf("FetchOpenWrtNlbwmon failed: %v", err)
		}
		if len(stats) != 2 {
			t.Fatalf("expected 2 stats, got %d", len(stats))
		}

		dev20, ok := stats["10.5.5.20"]
		if !ok {
			t.Fatalf("expected stats for 10.5.5.20, got %+v", stats)
		}
		if dev20.RxBytes != 5000 || dev20.TxBytes != 1500 {
			t.Errorf("expected 5000 Rx and 1500 Tx, got %d Rx, %d Tx", dev20.RxBytes, dev20.TxBytes)
		}

		dev30, ok := stats["10.5.5.30"]
		if !ok {
			t.Fatalf("expected stats for 10.5.5.30, got %+v", stats)
		}
		if dev30.RxBytes != 5000 || dev30.TxBytes != 2500 {
			t.Errorf("expected 5000 Rx and 2500 Tx, got %d Rx, %d Tx", dev30.RxBytes, dev30.TxBytes)
		}
	})

	t.Run("RobustNumberParsingAndAlternativeColumnAliases", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"result": []interface{}{
					0,
					map[string]interface{}{
						"columns": []string{"addr", "hw", "download", "upload"},
						"rows": []interface{}{
							[]interface{}{"10.5.5.40", "00:11:22:33:44:55", "12345", 6789.0},
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := config.OpenWrtConfig{
			Enable:   true,
			URL:      server.URL,
			APIToken: "token",
		}

		stats, err := FetchOpenWrtNlbwmon(context.Background(), cfg)
		if err != nil {
			t.Fatalf("FetchOpenWrtNlbwmon failed: %v", err)
		}
		dev40, ok := stats["10.5.5.40"]
		if !ok {
			t.Fatalf("expected stats for 10.5.5.40, got %+v", stats)
		}
		if dev40.RxBytes != 12345 || dev40.TxBytes != 6789 {
			t.Errorf("expected 12345 Rx and 6789 Tx, got %d Rx, %d Tx", dev40.RxBytes, dev40.TxBytes)
		}
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		// 1. Non-200 HTTP status
		s500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}))
		defer s500.Close()

		_, err := FetchOpenWrtNlbwmon(context.Background(), config.OpenWrtConfig{URL: s500.URL})
		if err == nil {
			t.Errorf("expected error for HTTP 500, got nil")
		}

		// 2. Ubus error code in result array
		sUbusErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"result":  []interface{}{6, nil},
			})
		}))
		defer sUbusErr.Close()

		_, err = FetchOpenWrtNlbwmon(context.Background(), config.OpenWrtConfig{URL: sUbusErr.URL})
		if err == nil {
			t.Errorf("expected error for ubus error code 6, got nil")
		}

		// 3. JSON-RPC error field
		sRPCErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"error": map[string]interface{}{
					"code":    -32600,
					"message": "Invalid Request",
				},
			})
		}))
		defer sRPCErr.Close()

		_, err = FetchOpenWrtNlbwmon(context.Background(), config.OpenWrtConfig{URL: sRPCErr.URL})
		if err == nil {
			t.Errorf("expected error for JSON-RPC error, got nil")
		}
	})
}
