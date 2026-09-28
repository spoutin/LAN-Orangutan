package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

type unifiDeviceResponse struct {
	Data []unifiAPDevice `json:"data"`
}

type unifiAPDevice struct {
	MAC   string `json:"mac"`
	Name  string `json:"name"`
	Model string `json:"model"`
}

type unifiStationResponse struct {
	Data []unifiStation `json:"data"`
}

type unifiStation struct {
	MAC        string  `json:"mac"`
	IP         string  `json:"ip"`
	Hostname   string  `json:"hostname"`
	Name       string  `json:"name"`
	Essid      string  `json:"essid"`
	APMAC      string  `json:"ap_mac"`
	Channel    int     `json:"channel"`
	Radio      string  `json:"radio"`
	RadioProto string  `json:"radio_proto"`
	Signal     int     `json:"signal"`
	RSSI       int     `json:"rssi"`
	RxRate     float64 `json:"rx_rate"`
	TxRate     float64 `json:"tx_rate"`
	RxBytes    int64   `json:"rx_bytes"`
	TxBytes    int64   `json:"tx_bytes"`
	Uptime     int64   `json:"uptime"`
	Model      string  `json:"model"`
	UnifiModel string  `json:"unifi_model"`
	DevModel   string  `json:"dev_model"`
}

// FetchUniFiClients queries the UniFi controller for active wireless client stations and AP telemetry.
func FetchUniFiClients(ctx context.Context, cfg config.UniFiConfig) ([]types.Device, error) {
	baseURL := strings.TrimRight(cfg.URL, "/")
	site := cfg.Site
	if site == "" {
		site = "default"
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifySSL},
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	// 1. Fetch AP devices to build mac -> name map
	devData, err := fetchUniFiEndpoint(ctx, client, baseURL, site, "stat/device", cfg.APIKey)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch unifi devices: %w", err)
	}

	var devResp unifiDeviceResponse
	if err := json.Unmarshal(devData, &devResp); err != nil {
		return nil, fmt.Errorf("failed to decode unifi devices response: %w", err)
	}

	apMap := make(map[string]string)
	for _, d := range devResp.Data {
		if d.MAC == "" {
			continue
		}
		name := d.Name
		if name == "" {
			name = d.Model
		}
		if name == "" {
			name = d.MAC
		}
		apMap[strings.ToLower(strings.TrimSpace(d.MAC))] = name
	}

	// 2. Fetch active client stations
	staData, err := fetchUniFiEndpoint(ctx, client, baseURL, site, "stat/sta", cfg.APIKey)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch unifi stations: %w", err)
	}

	var staResp unifiStationResponse
	if err := json.Unmarshal(staData, &staResp); err != nil {
		return nil, fmt.Errorf("failed to decode unifi stations response: %w", err)
	}

	var devices []types.Device
	for _, s := range staResp.Data {
		if s.MAC == "" && s.IP == "" {
			continue
		}

		hostname := s.Hostname
		if hostname == "" {
			hostname = s.Name
		}

		apName := s.APMAC
		if s.APMAC != "" {
			if name, ok := apMap[strings.ToLower(strings.TrimSpace(s.APMAC))]; ok && name != "" {
				apName = name
			}
		}

		sig := s.Signal
		if sig == 0 && s.RSSI != 0 {
			sig = s.RSSI
		}
		quality := calculateSignalQuality(sig)

		model := s.UnifiModel
		if model == "" {
			model = s.Model
		}
		if model == "" {
			model = s.DevModel
		}

		vendor := GetMACVendor(s.MAC)
		devType := Classify(vendor, hostname, nil)

		devices = append(devices, types.Device{
			IP:                s.IP,
			MAC:               s.MAC,
			Hostname:          hostname,
			Vendor:            vendor,
			Type:              devType,
			SSID:              s.Essid,
			APName:            apName,
			RadioBand:         mapRadioBand(s.Radio),
			Channel:           s.Channel,
			WiFiStandard:      mapWiFiStandard(s.RadioProto),
			Signal:            sig,
			SignalQuality:     quality,
			RxRate:            parseRate(s.RxRate),
			TxRate:            parseRate(s.TxRate),
			RxBytes:           s.RxBytes,
			TxBytes:           s.TxBytes,
			AssociationUptime: s.Uptime,
			UniFiModel:        model,
		})
	}

	return devices, nil
}

func fetchUniFiEndpoint(ctx context.Context, client *http.Client, baseURL, site, endpoint, apiKey string) ([]byte, error) {
	primaryURL := fmt.Sprintf("%s/proxy/network/api/s/%s/%s", baseURL, site, endpoint)
	data, statusCode, err := doUniFiRequest(ctx, client, primaryURL, apiKey)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request to %s: %w", primaryURL, err)
	}
	if statusCode == http.StatusOK {
		return data, nil
	}

	// Fallback to legacy endpoint on 404
	if statusCode == http.StatusNotFound {
		fallbackURL := fmt.Sprintf("%s/api/s/%s/%s", baseURL, site, endpoint)
		dataFallback, statusFallback, errFallback := doUniFiRequest(ctx, client, fallbackURL, apiKey)
		if errFallback != nil {
			return nil, fmt.Errorf("failed to execute fallback request to %s: %w", fallbackURL, errFallback)
		}
		if statusFallback == http.StatusOK {
			return dataFallback, nil
		}
		return nil, fmt.Errorf("unexpected unifi fallback response status from %s: %d", fallbackURL, statusFallback)
	}

	return nil, fmt.Errorf("unexpected unifi response status from %s: %d", primaryURL, statusCode)
}

func doUniFiRequest(ctx context.Context, client *http.Client, reqURL, apiKey string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-API-KEY", apiKey)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func mapRadioBand(radio string) string {
	switch strings.ToLower(strings.TrimSpace(radio)) {
	case "ng":
		return "2.4GHz"
	case "na", "ac", "ax", "a":
		return "5GHz"
	case "6g":
		return "6GHz"
	default:
		return radio
	}
}

func mapWiFiStandard(proto string) string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "ax":
		return "Wi-Fi 6 (802.11ax)"
	case "ac":
		return "Wi-Fi 5 (802.11ac)"
	case "n":
		return "Wi-Fi 4 (802.11n)"
	case "be":
		return "Wi-Fi 7 (802.11be)"
	default:
		return proto
	}
}

func calculateSignalQuality(sig int) int {
	if sig == 0 {
		return 0
	}
	if sig <= -100 {
		return 0
	}
	if sig >= -50 {
		return 100
	}
	return 2 * (sig + 100)
}

func parseRate(v float64) int {
	if v <= 0 {
		return 0
	}
	if v > 10000 {
		return int(v / 1000)
	}
	return int(v)
}
