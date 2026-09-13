package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/291-Group/LAN-Orangutan/internal/config"
	"github.com/291-Group/LAN-Orangutan/internal/types"
)

// OpenWrt API Structs
type openWrtLease struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
}

type openWrtHost struct {
	Name string   `json:"name"`
	IP   string   `json:"ip"`
	MACs []string `json:"macs"`
}

// OPNsense API Structs
type opnSenseLease struct {
	Address  string `json:"address"`
	HwAddr   string `json:"hwaddr"`
	Hostname string `json:"hostname"`
}

type opnSenseLeasesResponse struct {
	Rows []opnSenseLease `json:"rows"`
}

type opnSenseReservation struct {
	IPAddress string `json:"ip_address"`
	HwAddr    string `json:"hwaddr"`
	Hostname  string `json:"hostname"`
}

type opnSenseReservationsResponse struct {
	Rows []opnSenseReservation `json:"rows"`
}

type opnSenseArp struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

// FetchOpenWrtDHCP contacts the OpenWrt router to retrieve active leases and static reservations.
func FetchOpenWrtDHCP(ctx context.Context, cfg config.OpenWrtConfig) (leases []types.Device, reservations []types.Device, err error) {
	baseURL := strings.TrimSuffix(cfg.URL, "/")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifySSL},
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	// 1. Fetch Active Leases
	reqLeases, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/v3/dhcp/leases", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create leases request: %w", err)
	}
	reqLeases.Header.Set("Authorization", "Bearer "+cfg.APIToken)
	reqLeases.Header.Set("Accept", "application/json")

	respLeases, err := client.Do(reqLeases)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute leases request: %w", err)
	}
	defer respLeases.Body.Close()

	if respLeases.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected openwrt leases API response status: %s", respLeases.Status)
	}

	var rawLeases []openWrtLease
	if err := json.NewDecoder(respLeases.Body).Decode(&rawLeases); err != nil {
		return nil, nil, fmt.Errorf("failed to decode openwrt leases: %w", err)
	}

	for _, rl := range rawLeases {
		if rl.IP == "" {
			continue
		}
		vendor := GetMACVendor(rl.MAC)
		leases = append(leases, types.Device{
			IP:       rl.IP,
			MAC:      rl.MAC,
			Hostname: rl.Hostname,
			Vendor:   vendor,
			Type:     Classify(vendor, rl.Hostname, nil),
		})
	}

	// 2. Fetch Static Reservations (Hosts)
	reqHosts, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/v3/dhcp/hosts", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create hosts request: %w", err)
	}
	reqHosts.Header.Set("Authorization", "Bearer "+cfg.APIToken)
	reqHosts.Header.Set("Accept", "application/json")

	respHosts, err := client.Do(reqHosts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute hosts request: %w", err)
	}
	defer respHosts.Body.Close()

	if respHosts.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected openwrt hosts API response status: %s", respHosts.Status)
	}

	var rawHosts []openWrtHost
	if err := json.NewDecoder(respHosts.Body).Decode(&rawHosts); err != nil {
		return nil, nil, fmt.Errorf("failed to decode openwrt hosts: %w", err)
	}

	for _, rh := range rawHosts {
		if rh.IP == "" {
			continue
		}
		mac := ""
		if len(rh.MACs) > 0 {
			mac = rh.MACs[0]
		}
		vendor := GetMACVendor(mac)
		reservations = append(reservations, types.Device{
			IP:       rh.IP,
			MAC:      mac,
			Hostname: rh.Name,
			Vendor:   vendor,
			Type:     Classify(vendor, rh.Name, nil),
		})
	}

	return leases, reservations, nil
}

// FetchOPNsenseDHCP contacts the OPNsense firewall to retrieve Kea leases, reservations, and ARP entries.
func FetchOPNsenseDHCP(ctx context.Context, cfg config.OPNsenseConfig) (leases []types.Device, reservations []types.Device, arpEntries []types.Device, err error) {
	baseURL := strings.TrimSuffix(cfg.URL, "/")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifySSL},
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	searchBody := []byte(`{"current": 1, "rowCount": -1}`)

	// 1. Fetch Kea Leases
	reqLeases, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/api/kea/leases4/search", bytes.NewReader(searchBody))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create leases request: %w", err)
	}
	reqLeases.SetBasicAuth(cfg.APIKey, cfg.APISecret)
	reqLeases.Header.Set("Content-Type", "application/json")

	respLeases, err := client.Do(reqLeases)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to execute leases request: %w", err)
	}
	defer respLeases.Body.Close()

	if respLeases.StatusCode != http.StatusOK {
		return nil, nil, nil, fmt.Errorf("unexpected opnsense leases API response status: %s", respLeases.Status)
	}

	var rawLeases opnSenseLeasesResponse
	if err := json.NewDecoder(respLeases.Body).Decode(&rawLeases); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode opnsense leases: %w", err)
	}

	for _, rl := range rawLeases.Rows {
		if rl.Address == "" {
			continue
		}
		vendor := GetMACVendor(rl.HwAddr)
		leases = append(leases, types.Device{
			IP:       rl.Address,
			MAC:      rl.HwAddr,
			Hostname: rl.Hostname,
			Vendor:   vendor,
			Type:     Classify(vendor, rl.Hostname, nil),
		})
	}

	// 2. Fetch Kea Reservations
	reqReservations, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/api/kea/dhcpv4/searchReservation", bytes.NewReader(searchBody))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create reservations request: %w", err)
	}
	reqReservations.SetBasicAuth(cfg.APIKey, cfg.APISecret)
	reqReservations.Header.Set("Content-Type", "application/json")

	respReservations, err := client.Do(reqReservations)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to execute reservations request: %w", err)
	}
	defer respReservations.Body.Close()

	if respReservations.StatusCode != http.StatusOK {
		return nil, nil, nil, fmt.Errorf("unexpected opnsense reservations API response status: %s", respReservations.Status)
	}

	var rawReservations opnSenseReservationsResponse
	if err := json.NewDecoder(respReservations.Body).Decode(&rawReservations); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode opnsense reservations: %w", err)
	}

	for _, rr := range rawReservations.Rows {
		if rr.IPAddress == "" {
			continue
		}
		vendor := GetMACVendor(rr.HwAddr)
		reservations = append(reservations, types.Device{
			IP:       rr.IPAddress,
			MAC:      rr.HwAddr,
			Hostname: rr.Hostname,
			Vendor:   vendor,
			Type:     Classify(vendor, rr.Hostname, nil),
		})
	}

	// 3. Fetch OPNsense ARP Table as supplementary leases/devices
	reqArp, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/diagnostics/interface/getArp", nil)
	if err == nil {
		reqArp.SetBasicAuth(cfg.APIKey, cfg.APISecret)
		if respArp, err := client.Do(reqArp); err == nil {
			defer respArp.Body.Close()
			if respArp.StatusCode == http.StatusOK {
				var rawArp []opnSenseArp
				if err := json.NewDecoder(respArp.Body).Decode(&rawArp); err == nil {
					for _, ra := range rawArp {
						if ra.IP == "" {
							continue
						}
						vendor := GetMACVendor(ra.MAC)
						arpEntries = append(arpEntries, types.Device{
							IP:     ra.IP,
							MAC:    ra.MAC,
							Vendor: vendor,
							Type:   Classify(vendor, "", nil),
						})
					}
				}
			}
		}
	}

	return leases, reservations, arpEntries, nil
}
