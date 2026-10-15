package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/logging"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// OpenWrt API Structs
type openWrtLease struct {
	IP            string      `json:"ip"`
	MAC           string      `json:"mac"`
	Hostname      string      `json:"hostname"`
	Expires       interface{} `json:"expires"`
	LeaseTime     interface{} `json:"leasetime"`
	ValidLifetime interface{} `json:"valid_lifetime"`
	Lifetime      interface{} `json:"lifetime"`
	Device        string      `json:"device"`
	Interface     string      `json:"interface"`
	Network       string      `json:"network"`
}

type openWrtHost struct {
	Name     string   `json:"name"`
	IP       string   `json:"ip"`
	MACs     []string `json:"macs"`
	MAC      string   `json:"mac"`
	Note     string   `json:"note"`
	Notes    string   `json:"notes"`
	Comment  string   `json:"comment"`
	Comments string   `json:"comments"`
}

// OPNsense API Structs
type opnSenseLease struct {
	Address       string      `json:"address"`
	HwAddr        string      `json:"hwaddr"`
	Hostname      string      `json:"hostname"`
	ValidLifetime interface{} `json:"valid_lifetime"`
	Cltt          interface{} `json:"cltt"`
	Expire        interface{} `json:"expire"`
	Intf          string      `json:"intf"`
	Interface     string      `json:"interface"`
}

type opnSenseLeasesResponse struct {
	Rows []opnSenseLease `json:"rows"`
}

type opnSenseReservation struct {
	IPAddress   string `json:"ip_address"`
	HwAddr      string `json:"hwaddr"`
	Hostname    string `json:"hostname"`
	Description string `json:"description"`
	Notes       string `json:"notes"`
	Comment     string `json:"comment"`
	Comments    string `json:"comments"`
}

type opnSenseReservationsResponse struct {
	Rows []opnSenseReservation `json:"rows"`
}

type opnSenseArp struct {
	IP              string `json:"ip"`
	MAC             string `json:"mac"`
	Hostname        string `json:"hostname"`
	Intf            string `json:"intf"`
	IntfDescription string `json:"intf_description"`
}

func parseNumeric(v interface{}) (int64, bool) {
	if v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case float32:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			return i, true
		}
		f, err := n.Float64()
		if err == nil {
			return int64(f), true
		}
	case string:
		s := strings.TrimSpace(n)
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i, true
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return int64(f), true
		}
	}
	return 0, false
}

func parseTimeFlexible(v interface{}) (time.Time, bool) {
	if v == nil {
		return time.Time{}, false
	}
	if str, ok := v.(string); ok {
		str = strings.TrimSpace(str)
		if str == "" {
			return time.Time{}, false
		}
		layouts := []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05",
			"2006/01/02 15:04:05",
		}
		for _, l := range layouts {
			if t, err := time.Parse(l, str); err == nil {
				return t, true
			}
		}
	}
	return time.Time{}, false
}

func formatRouterInterface(intf, desc string) string {
	intf = strings.TrimSpace(intf)
	desc = strings.TrimSpace(desc)
	if intf != "" && desc != "" {
		if strings.EqualFold(intf, desc) {
			return intf
		}
		return fmt.Sprintf("%s (%s)", intf, desc)
	}
	if desc != "" {
		return desc
	}
	return intf
}

func formatOpenWrtInterface(iface, device, network string) string {
	iface = strings.TrimSpace(iface)
	device = strings.TrimSpace(device)
	network = strings.TrimSpace(network)

	if iface != "" {
		return iface
	}
	if device != "" {
		return device
	}
	return network
}

// FetchOpenWrtDHCP contacts the OpenWrt router to retrieve active leases and static reservations.
func FetchOpenWrtDHCP(ctx context.Context, cfg config.OpenWrtConfig) (leases []types.Device, reservations []types.Device, err error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifySSL},
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if len(via) > 0 && req.URL.Hostname() == via[0].URL.Hostname() {
				if auth := via[0].Header.Get("Authorization"); auth != "" {
					req.Header.Set("Authorization", auth)
				}
			}
			return nil
		},
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

		var leaseExpires time.Time
		var leaseLifetime int

		if lt, ok := parseNumeric(rl.LeaseTime); ok && lt > 0 {
			leaseLifetime = int(lt)
		} else if lt, ok := parseNumeric(rl.ValidLifetime); ok && lt > 0 {
			leaseLifetime = int(lt)
		} else if lt, ok := parseNumeric(rl.Lifetime); ok && lt > 0 {
			leaseLifetime = int(lt)
		}

		if exp, ok := parseNumeric(rl.Expires); ok && exp > 0 {
			if exp > 1000000000 {
				leaseExpires = time.Unix(exp, 0)
			} else {
				leaseExpires = time.Now().Add(time.Duration(exp) * time.Second)
				if leaseLifetime == 0 {
					leaseLifetime = int(exp)
				}
			}
		} else if t, ok := parseTimeFlexible(rl.Expires); ok {
			leaseExpires = t
		}

		leases = append(leases, types.Device{
			IP:              rl.IP,
			MAC:             rl.MAC,
			Hostname:        rl.Hostname,
			Vendor:          vendor,
			Type:            Classify(vendor, rl.Hostname, nil),
			RouterSource:    "OpenWrt",
			RouterInterface: formatOpenWrtInterface(rl.Interface, rl.Device, rl.Network),
			LeaseExpires:    leaseExpires,
			LeaseLifetime:   leaseLifetime,
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
		} else if rh.MAC != "" {
			mac = rh.MAC
		}
		vendor := GetMACVendor(mac)

		notes := strings.TrimSpace(rh.Note)
		if notes == "" {
			notes = strings.TrimSpace(rh.Notes)
		}
		if notes == "" {
			notes = strings.TrimSpace(rh.Comment)
		}
		if notes == "" {
			notes = strings.TrimSpace(rh.Comments)
		}

		reservations = append(reservations, types.Device{
			IP:           rh.IP,
			MAC:          mac,
			Hostname:     rh.Name,
			Vendor:       vendor,
			Type:         Classify(vendor, rh.Name, nil),
			RouterSource: "OpenWrt",
			RouterNotes:  notes,
		})
	}

	return leases, reservations, nil
}

// FetchOPNsenseDHCP contacts the OPNsense firewall to retrieve Kea leases, reservations, and ARP entries.
func FetchOPNsenseDHCP(ctx context.Context, cfg config.OPNsenseConfig) (leases []types.Device, reservations []types.Device, arpEntries []types.Device, err error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
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

		var leaseExpires time.Time
		var leaseLifetime int

		if vl, ok := parseNumeric(rl.ValidLifetime); ok && vl > 0 {
			leaseLifetime = int(vl)
		}

		cltt, hasCltt := parseNumeric(rl.Cltt)
		if hasCltt && cltt > 0 && leaseLifetime > 0 {
			leaseExpires = time.Unix(cltt+int64(leaseLifetime), 0)
		}

		if leaseExpires.IsZero() {
			if exp, ok := parseNumeric(rl.Expire); ok && exp > 0 {
				if exp > 1000000000 {
					leaseExpires = time.Unix(exp, 0)
				} else {
					leaseExpires = time.Now().Add(time.Duration(exp) * time.Second)
					if leaseLifetime == 0 {
						leaseLifetime = int(exp)
					}
				}
			} else if t, ok := parseTimeFlexible(rl.Expire); ok {
				leaseExpires = t
			}
		}

		leases = append(leases, types.Device{
			IP:              rl.Address,
			MAC:             rl.HwAddr,
			Hostname:        rl.Hostname,
			Vendor:          vendor,
			Type:            Classify(vendor, rl.Hostname, nil),
			RouterSource:    "OPNsense",
			RouterInterface: formatRouterInterface(rl.Intf, rl.Interface),
			LeaseExpires:    leaseExpires,
			LeaseLifetime:   leaseLifetime,
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

		notes := strings.TrimSpace(rr.Description)
		if notes == "" {
			notes = strings.TrimSpace(rr.Notes)
		}
		if notes == "" {
			notes = strings.TrimSpace(rr.Comment)
		}
		if notes == "" {
			notes = strings.TrimSpace(rr.Comments)
		}

		reservations = append(reservations, types.Device{
			IP:           rr.IPAddress,
			MAC:          rr.HwAddr,
			Hostname:     rr.Hostname,
			Vendor:       vendor,
			Type:         Classify(vendor, rr.Hostname, nil),
			RouterSource: "OPNsense",
			RouterNotes:  notes,
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
							IP:              ra.IP,
							MAC:             ra.MAC,
							Hostname:        ra.Hostname,
							Vendor:          vendor,
							Type:            Classify(vendor, ra.Hostname, nil),
							RouterSource:    "OPNsense",
							RouterInterface: formatRouterInterface(ra.Intf, ra.IntfDescription),
						})
					}
				}
			}
		}
	}

	return leases, reservations, arpEntries, nil
}

// FetchOPNsenseNetFlow queries OPNsense for per-device traffic bytes via NetFlow or active firewall states.
func FetchOPNsenseNetFlow(ctx context.Context, cfg config.OPNsenseConfig) (map[string]*types.NetFlowDeviceStats, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	if baseURL == "" || cfg.APIKey == "" || cfg.APISecret == "" {
		return nil, fmt.Errorf("missing opnsense credentials")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifySSL},
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	result := make(map[string]*types.NetFlowDeviceStats)

	// 1. Try NetFlow / NetworkInsight endpoint first
	reqFlow, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/diagnostics/networkinsight/top?field=address&measure=bytes", nil)
	if err == nil {
		reqFlow.SetBasicAuth(cfg.APIKey, cfg.APISecret)
		respFlow, err := client.Do(reqFlow)
		if err != nil {
			logging.GlobalBuffer.Add("warn", fmt.Sprintf("[traffic] OPNsense networkinsight/top connection failed: %v", err))
		} else {
			defer respFlow.Body.Close()
			rawBody, _ := io.ReadAll(respFlow.Body)
			preview := string(rawBody)
			if len(preview) > 160 {
				preview = preview[:160] + "..."
			}

			if respFlow.StatusCode != http.StatusOK {
				logging.GlobalBuffer.Add("warn", fmt.Sprintf("[traffic] OPNsense networkinsight/top returned HTTP %d %s: %s", respFlow.StatusCode, respFlow.Status, preview))
			} else {
				records := parseNetFlowRecords(rawBody)
				logging.GlobalBuffer.Add("info", fmt.Sprintf("[traffic] OPNsense networkinsight/top: HTTP 200, parsed %d flow records", len(records)))
				for _, rec := range records {
					srcIP := cleanHostIP(extractFlowField(rec, "source", "src", "src_addr", "source_address", "address", "ip"))
					dstIP := cleanHostIP(extractFlowField(rec, "destination", "dst", "dst_addr", "destination_address"))
					octets := extractFlowBytes(rec, "octets", "bytes", "byte_count", "total_bytes")
					if octets <= 0 {
						continue
					}
					if srcIP != "" {
						st, ok := result[srcIP]
						if !ok {
							st = &types.NetFlowDeviceStats{IP: srcIP}
							result[srcIP] = st
						}
						st.TxBytes += octets
					}
					if dstIP != "" {
						st, ok := result[dstIP]
						if !ok {
							st = &types.NetFlowDeviceStats{IP: dstIP}
							result[dstIP] = st
						}
						st.RxBytes += octets
					}
				}
				if len(result) > 0 {
					return result, nil
				}
			}
		}
	}

	// 2. Active firewall states query
	searchBody := []byte(`{"current": 1, "rowCount": 500}`)
	reqStates, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/api/diagnostics/firewall/query_states", bytes.NewReader(searchBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create states request: %w", err)
	}
	reqStates.SetBasicAuth(cfg.APIKey, cfg.APISecret)
	reqStates.Header.Set("Content-Type", "application/json")
	respStates, err := client.Do(reqStates)
	if err != nil {
		logging.GlobalBuffer.Add("warn", fmt.Sprintf("[traffic] OPNsense firewall/query_states connection failed: %v", err))
		return nil, fmt.Errorf("failed to execute firewall states request: %w", err)
	}
	defer respStates.Body.Close()

	if respStates.StatusCode != http.StatusOK {
		logging.GlobalBuffer.Add("warn", fmt.Sprintf("[traffic] OPNsense firewall/query_states returned HTTP %d %s", respStates.StatusCode, respStates.Status))
		// Fallback to GET /api/diagnostics/firewall/pf_states
		reqPf, errPf := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/diagnostics/firewall/pf_states", nil)
		if errPf == nil {
			reqPf.SetBasicAuth(cfg.APIKey, cfg.APISecret)
			respPf, errDo := client.Do(reqPf)
			if errDo == nil && respPf.StatusCode == http.StatusOK {
				defer respPf.Body.Close()
				rawPf, _ := io.ReadAll(respPf.Body)
				records := parseNetFlowRecords(rawPf)
				logging.GlobalBuffer.Add("info", fmt.Sprintf("[traffic] OPNsense firewall/pf_states: HTTP 200, parsed %d records", len(records)))
				for _, rec := range records {
					bytesVal := extractFlowBytes(rec, "bytes", "octets", "byte_count")
					if bytesVal <= 0 {
						continue
					}
					srcIP := cleanHostIP(extractFlowField(rec, "src_addr", "source", "src", "address"))
					dstIP := cleanHostIP(extractFlowField(rec, "dst_addr", "destination", "dst"))
					if srcIP != "" {
						st, ok := result[srcIP]
						if !ok {
							st = &types.NetFlowDeviceStats{IP: srcIP}
							result[srcIP] = st
						}
						st.TxBytes += bytesVal
					}
					if dstIP != "" {
						st, ok := result[dstIP]
						if !ok {
							st = &types.NetFlowDeviceStats{IP: dstIP}
							result[dstIP] = st
						}
						st.RxBytes += bytesVal
					}
				}
				if len(result) > 0 {
					return result, nil
				}
			} else if respPf != nil {
				respPf.Body.Close()
			}
		}
		return nil, fmt.Errorf("unexpected firewall states response status: %s", respStates.Status)
	}

	rawStates, _ := io.ReadAll(respStates.Body)
	previewStates := string(rawStates)
	if len(previewStates) > 160 {
		previewStates = previewStates[:160] + "..."
	}
	records := parseNetFlowRecords(rawStates)
	logging.GlobalBuffer.Add("info", fmt.Sprintf("[traffic] OPNsense firewall/query_states: HTTP 200, %d bytes, parsed %d records: %s", len(rawStates), len(records), previewStates))
	for _, rec := range records {
		bytesVal := extractFlowBytes(rec, "bytes", "octets", "byte_count")
		if bytesVal <= 0 {
			continue
		}
		srcIP := cleanHostIP(extractFlowField(rec, "src_addr", "source", "src", "address"))
		dstIP := cleanHostIP(extractFlowField(rec, "dst_addr", "destination", "dst"))
		if srcIP != "" {
			st, ok := result[srcIP]
			if !ok {
				st = &types.NetFlowDeviceStats{IP: srcIP}
				result[srcIP] = st
			}
			st.TxBytes += bytesVal
		}
		if dstIP != "" {
			st, ok := result[dstIP]
			if !ok {
				st = &types.NetFlowDeviceStats{IP: dstIP}
				result[dstIP] = st
			}
			st.RxBytes += bytesVal
		}
	}

	return result, nil
}

func parseNetFlowRecords(body []byte) []map[string]interface{} {
	var list []map[string]interface{}
	if err := json.Unmarshal(body, &list); err == nil && len(list) > 0 {
		return list
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err == nil {
		if rows, ok := obj["rows"].([]interface{}); ok {
			for _, r := range rows {
				if m, ok := r.(map[string]interface{}); ok {
					list = append(list, m)
				}
			}
		} else if data, ok := obj["data"].([]interface{}); ok {
			for _, r := range data {
				if m, ok := r.(map[string]interface{}); ok {
					list = append(list, m)
				}
			}
		}
	}
	return list
}

func extractFlowField(rec map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := rec[k]; ok && v != nil {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
			if m, ok := v.(map[string]interface{}); ok {
				for _, subKey := range []string{"address", "ip", "addr", "host"} {
					if subVal, ok := m[subKey].(string); ok && strings.TrimSpace(subVal) != "" {
						return strings.TrimSpace(subVal)
					}
				}
			}
		}
	}
	return ""
}

func extractFlowBytes(rec map[string]interface{}, keys ...string) int64 {
	for _, k := range keys {
		if v, ok := rec[k]; ok && v != nil {
			if n, ok := parseNumeric(v); ok && n > 0 {
				return n
			}
			if s, ok := v.(string); ok {
				if n, ok := parseBytesWithUnits(s); ok && n > 0 {
					return n
				}
			}
		}
	}
	return 0
}

func parseBytesWithUnits(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if strings.Contains(s, "/") {
		parts := strings.Split(s, "/")
		sum := int64(0)
		for _, part := range parts {
			if n, ok := parseBytesWithUnits(part); ok {
				sum += n
			}
		}
		return sum, sum > 0
	}

	lower := strings.ToLower(s)
	multiplier := float64(1)
	if strings.HasSuffix(lower, "gb") || strings.HasSuffix(lower, "g") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimRight(strings.TrimRight(s, "bB"), "gG")
	} else if strings.HasSuffix(lower, "mb") || strings.HasSuffix(lower, "m") {
		multiplier = 1024 * 1024
		s = strings.TrimRight(strings.TrimRight(s, "bB"), "mM")
	} else if strings.HasSuffix(lower, "kb") || strings.HasSuffix(lower, "k") {
		multiplier = 1024
		s = strings.TrimRight(strings.TrimRight(s, "bB"), "kK")
	} else if strings.HasSuffix(lower, "b") {
		s = strings.TrimRight(s, "bB")
	}
	s = strings.TrimSpace(s)
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return int64(f * multiplier), true
	}
	return 0, false
}

func cleanHostIP(addr string) string {
	addr = strings.TrimSpace(addr)
	if strings.Contains(addr, "->") {
		parts := strings.Split(addr, "->")
		addr = strings.TrimSpace(parts[0])
	} else if strings.Contains(addr, "<-") {
		parts := strings.Split(addr, "<-")
		addr = strings.TrimSpace(parts[0])
	}
	if idx := strings.Index(addr, ":"); idx != -1 {
		if strings.Count(addr, ":") == 1 {
			addr = addr[:idx]
		}
	}
	return addr
}
