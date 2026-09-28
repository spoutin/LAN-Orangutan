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
