package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

const deviceSelectColumns = `
	ip, mac, hostname, vendor, type, web_ui, risks, label, notes, "group",
	custom_hostname, custom_web_url, custom_type, web_port, web_scheme, probed, detected_ssh_port, ssh_override, ssh_override_port,
	assignment, network_name, first_seen, last_seen, response_time, address_history,
	linked_mac, notify_on_seen, ansible_managed,
	os, os_version, os_family, custom_os, custom_os_version, custom_os_family,
	ssid, ap_name, radio_band, channel, wifi_standard, signal, signal_quality,
	rx_rate, tx_rate, rx_bytes, tx_bytes, association_uptime, unifi_model, vlan, unifi_name,
	router_source, router_interface, lease_expires, lease_lifetime, router_notes,
	switch_name, switch_host, switch_port, switch_vlan, switch_link_state, switch_link_speed, switch_duplex, switch_poe_watts, switch_updated_at,
	traffic_source, rx_rate_bps, tx_rate_bps, wan_rx_rate_bps, wan_tx_rate_bps, wan_rx_bytes, wan_tx_bytes,
	COALESCE(ips, '[]') AS ips
`

const deviceJoinedSelectColumns = `
	d.ip, d.mac, d.hostname, d.vendor, d.type, d.web_ui, d.risks,
	COALESCE(NULLIF(p.label, ''), d.label) AS label,
	COALESCE(NULLIF(p.notes, ''), d.notes) AS notes,
	COALESCE(NULLIF(p."group", ''), d."group") AS "group",
	COALESCE(NULLIF(p.custom_hostname, ''), d.custom_hostname) AS custom_hostname,
	COALESCE(NULLIF(p.custom_web_url, ''), d.custom_web_url) AS custom_web_url,
	COALESCE(NULLIF(p.custom_type, ''), d.custom_type) AS custom_type,
	d.web_port, d.web_scheme, d.probed, d.detected_ssh_port,
	COALESCE(p.ssh_override, d.ssh_override), COALESCE(p.ssh_override_port, d.ssh_override_port),
	d.assignment, d.network_name, d.first_seen, d.last_seen, d.response_time, d.address_history,
	d.linked_mac,
	COALESCE(p.notify_on_seen, d.notify_on_seen) AS notify_on_seen,
	COALESCE(p.ansible_managed, d.ansible_managed) AS ansible_managed,
	d.os, d.os_version, d.os_family,
	COALESCE(NULLIF(p.custom_os, ''), d.custom_os) AS custom_os,
	COALESCE(NULLIF(p.custom_os_version, ''), d.custom_os_version) AS custom_os_version,
	COALESCE(NULLIF(p.custom_os_family, ''), d.custom_os_family) AS custom_os_family,
	d.ssid, d.ap_name, d.radio_band, d.channel, d.wifi_standard, d.signal, d.signal_quality,
	d.rx_rate, d.tx_rate, d.rx_bytes, d.tx_bytes, d.association_uptime, d.unifi_model, d.vlan, d.unifi_name,
	d.router_source, d.router_interface, d.lease_expires, d.lease_lifetime, d.router_notes,
	d.switch_name, d.switch_host, d.switch_port, d.switch_vlan, d.switch_link_state, d.switch_link_speed, d.switch_duplex, d.switch_poe_watts, d.switch_updated_at,
	d.traffic_source, d.rx_rate_bps, d.tx_rate_bps, d.wan_rx_rate_bps, d.wan_tx_rate_bps, d.wan_rx_bytes, d.wan_tx_bytes,
	COALESCE(d.ips, '[]') AS ips
`

const deviceParentJoinClause = `
	FROM devices d
	LEFT JOIN devices p ON LOWER(REPLACE(d.linked_mac, '-', ':')) = LOWER(REPLACE(p.mac, '-', ':')) AND d.linked_mac <> ''
`

func (s *Storage) scanDevice(scanner interface {
	Scan(dest ...interface{}) error
}) (*types.Device, error) {
	return scanDeviceWithExtra(scanner)
}

func (s *Storage) scanDeviceWithPresence(scanner interface {
	Scan(dest ...interface{}) error
}) (*types.Device, int, time.Time, error) {
	var isOnlineVal int
	var lastPresenceChange time.Time
	d, err := scanDeviceWithExtra(scanner, &isOnlineVal, &lastPresenceChange)
	if err != nil {
		return nil, 0, time.Time{}, err
	}
	return d, isOnlineVal, lastPresenceChange, nil
}

func scanDeviceWithExtra(scanner interface {
	Scan(dest ...interface{}) error
}, extra ...interface{}) (*types.Device, error) {
	var d types.Device
	var webUIVal, probedVal, notifyOnSeenVal, ansibleManagedVal int
	var risksStr, addressHistoryStr, ipsStr string
	var leaseExpiresVal, switchUpdatedAtVal sql.NullTime
	var switchPoEWattsVal sql.NullFloat64
	var trafficSourceVal sql.NullString
	var rxRateBpsVal, txRateBpsVal sql.NullInt64
	var wanRxRateBpsVal, wanTxRateBpsVal, wanRxBytesVal, wanTxBytesVal sql.NullInt64

	dest := []interface{}{
		&d.IP, &d.MAC, &d.Hostname, &d.Vendor, &d.Type, &webUIVal, &risksStr, &d.Label, &d.Notes, &d.Group,
		&d.CustomHostname, &d.CustomWebURL, &d.CustomType, &d.WebPort, &d.WebScheme, &probedVal, &d.DetectedSSHPort, &d.SSHOverride, &d.SSHOverridePort, &d.Assignment,
		&d.NetworkName, &d.FirstSeen, &d.LastSeen, &d.ResponseTime, &addressHistoryStr, &d.LinkedMAC,
		&notifyOnSeenVal, &ansibleManagedVal,
		&d.OS, &d.OSVersion, &d.OSFamily, &d.CustomOS, &d.CustomOSVersion, &d.CustomOSFamily,
		&d.SSID, &d.APName, &d.RadioBand, &d.Channel, &d.WiFiStandard, &d.Signal, &d.SignalQuality,
		&d.RxRate, &d.TxRate, &d.RxBytes, &d.TxBytes, &d.AssociationUptime, &d.UniFiModel, &d.VLAN, &d.UniFiName,
		&d.RouterSource, &d.RouterInterface, &leaseExpiresVal, &d.LeaseLifetime, &d.RouterNotes,
		&d.SwitchName, &d.SwitchHost, &d.SwitchPort, &d.SwitchVLAN, &d.SwitchLinkState, &d.SwitchLinkSpeed, &d.SwitchDuplex, &switchPoEWattsVal, &switchUpdatedAtVal,
		&trafficSourceVal, &rxRateBpsVal, &txRateBpsVal, &wanRxRateBpsVal, &wanTxRateBpsVal, &wanRxBytesVal, &wanTxBytesVal,
		&ipsStr,
	}
	dest = append(dest, extra...)

	if err := scanner.Scan(dest...); err != nil {
		return nil, err
	}
	d.WebUI = webUIVal != 0
	d.Probed = probedVal != 0
	d.NotifyOnSeen = notifyOnSeenVal != 0
	d.AnsibleManaged = ansibleManagedVal != 0
	if leaseExpiresVal.Valid {
		d.LeaseExpires = leaseExpiresVal.Time
	}
	if switchPoEWattsVal.Valid {
		d.SwitchPoEWatts = &switchPoEWattsVal.Float64
	}
	if switchUpdatedAtVal.Valid {
		d.SwitchUpdatedAt = switchUpdatedAtVal.Time
	}
	if trafficSourceVal.Valid {
		d.TrafficSource = trafficSourceVal.String
	}
	if rxRateBpsVal.Valid {
		d.RxRateBps = rxRateBpsVal.Int64
	}
	if txRateBpsVal.Valid {
		d.TxRateBps = txRateBpsVal.Int64
	}
	if wanRxRateBpsVal.Valid {
		d.WanRxRateBps = wanRxRateBpsVal.Int64
	}
	if wanTxRateBpsVal.Valid {
		d.WanTxRateBps = wanTxRateBpsVal.Int64
	}
	if wanRxBytesVal.Valid {
		d.WanRxBytes = wanRxBytesVal.Int64
	}
	if wanTxBytesVal.Valid {
		d.WanTxBytes = wanTxBytesVal.Int64
	}
	_ = json.Unmarshal([]byte(risksStr), &d.Risks)
	_ = json.Unmarshal([]byte(addressHistoryStr), &d.AddressHistory)
	_ = json.Unmarshal([]byte(ipsStr), &d.IPs)
	if len(d.IPs) == 0 && d.IP != "" {
		d.IPs = []types.IPAttachment{{IP: d.IP, NetworkName: d.NetworkName}}
	}
	return &d, nil
}

// GetDevices returns all devices
func (s *Storage) GetDevices() map[string]*types.Device {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`SELECT ` + deviceJoinedSelectColumns + deviceParentJoinClause)
	if err != nil {
		return make(map[string]*types.Device)
	}
	defer rows.Close()

	result := make(map[string]*types.Device)
	for rows.Next() {
		d, err := s.scanDevice(rows)
		if err == nil {
			result[d.IP] = d
		}
	}
	rows.Close()
	for _, device := range result {
		_ = s.loadOpenPorts(device)
	}

	// Build child mappings to populate LinkedChildren list on parents dynamically
	childrenMap := make(map[string][]string)
	childrenDetailsMap := make(map[string][]types.LinkedChild)
	scanInterval := s.GetScanInterval()

	for _, d := range result {
		if d.LinkedMAC != "" {
			normParent := NormalizeMAC(d.LinkedMAC)
			name := d.Label
			if name == "" {
				name = d.CustomHostname
			}
			if name == "" {
				name = d.Hostname
			}
			if name == "" {
				name = "Unknown"
			}
			childrenMap[normParent] = append(childrenMap[normParent], fmt.Sprintf("%s (%s)", name, d.IP))

			childrenDetailsMap[normParent] = append(childrenDetailsMap[normParent], types.LinkedChild{
				IP:          d.IP,
				MAC:         d.MAC,
				Hostname:    name,
				NetworkName: d.NetworkName,
				IsOnline:    d.IsOnline(scanInterval),
			})
		}
	}

	// Map child arrays back to their respective parent device
	for _, d := range result {
		if d.MAC != "" {
			normMAC := NormalizeMAC(d.MAC)
			if children, ok := childrenMap[normMAC]; ok {
				d.LinkedChildren = children
			}
			if details, ok := childrenDetailsMap[normMAC]; ok {
				d.LinkedChildrenDetails = details
			}
		}
	}

	return result
}

func (s *Storage) populateDeviceChildrenLocked(d *types.Device) {
	if d == nil || d.MAC == "" {
		return
	}
	normMAC := NormalizeMAC(d.MAC)
	rows, err := s.db.Query("SELECT label, custom_hostname, hostname, ip, mac, network_name, last_seen FROM devices WHERE LOWER(REPLACE(linked_mac, '-', ':')) = ?", normMAC)
	if err != nil {
		return
	}
	defer rows.Close()

	var children []string
	var childrenDetails []types.LinkedChild
	scanInterval := s.GetScanInterval()

	for rows.Next() {
		var label, cHost, host, ip, mac, netName string
		var lastSeen time.Time
		if err := rows.Scan(&label, &cHost, &host, &ip, &mac, &netName, &lastSeen); err == nil {
			name := label
			if name == "" {
				name = cHost
			}
			if name == "" {
				name = host
			}
			if name == "" {
				name = "Unknown"
			}
			children = append(children, fmt.Sprintf("%s (%s)", name, ip))

			// Create temporary Device viewmodel to check IsOnline cleanly
			tempDev := types.Device{LastSeen: lastSeen}
			childrenDetails = append(childrenDetails, types.LinkedChild{
				IP:          ip,
				MAC:         mac,
				Hostname:    name,
				NetworkName: netName,
				IsOnline:    tempDev.IsOnline(scanInterval),
			})
		}
	}
	d.LinkedChildren = children
	d.LinkedChildrenDetails = childrenDetails
}

// GetDevice returns a single device by IP, or nil if there is none
func (s *Storage) GetDevice(ip string) *types.Device {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`SELECT `+deviceJoinedSelectColumns+deviceParentJoinClause+`
		WHERE d.ip = ? OR instr(d.ips, '"' || ? || '"') > 0
		LIMIT 1
	`, ip, ip)
	d, err := s.scanDevice(row)
	if err != nil {
		return nil
	}
	_ = s.loadOpenPorts(d)
	s.populateDeviceChildrenLocked(d)
	return d
}

// GetDeviceByMAC looks up a device by MAC address (case-insensitive, hyphen/colon tolerant).
func (s *Storage) GetDeviceByMAC(mac string) *types.Device {
	norm := NormalizeMAC(mac)
	if norm == "" {
		return nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`SELECT `+deviceJoinedSelectColumns+deviceParentJoinClause+`
		WHERE LOWER(REPLACE(d.mac, '-', ':')) = ?
		LIMIT 1
	`, norm)

	d, err := s.scanDevice(row)
	if err != nil {
		return nil
	}
	_ = s.loadOpenPorts(d)
	s.populateDeviceChildrenLocked(d)
	return d
}

func (s *Storage) loadOpenPorts(device *types.Device) error {
	var portsJSON, servicesJSON string
	var lastDeepScanAt sql.NullTime
	if err := s.db.QueryRow("SELECT ports, services, last_deep_scan_at FROM device_open_ports WHERE ip = ?", device.IP).Scan(&portsJSON, &servicesJSON, &lastDeepScanAt); err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}
	_ = json.Unmarshal([]byte(portsJSON), &device.OpenPorts)
	if lastDeepScanAt.Valid {
		device.LastDeepScanAt = lastDeepScanAt.Time
	}
	return json.Unmarshal([]byte(servicesJSON), &device.OpenServices)
}

// UpdateOpenPorts saves the complete result of a targeted deep scan.
func (s *Storage) UpdateOpenPorts(ip string, ports []int, services []types.OpenService) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	portsJSON, err := json.Marshal(ports)
	if err != nil {
		return err
	}
	servicesJSON, err := json.Marshal(services)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO device_open_ports (ip, ports, services, last_deep_scan_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET ports = excluded.ports, services = excluded.services, last_deep_scan_at = excluded.last_deep_scan_at
	`, ip, string(portsJSON), string(servicesJSON), time.Now())
	return err
}

// GetDeviceLocked returns a device while holding a lock
func (s *Storage) GetDeviceLocked(ip string) *types.Device {
	row := s.db.QueryRow(`SELECT `+deviceJoinedSelectColumns+deviceParentJoinClause+`
		WHERE d.ip = ?
	`, ip)
	d, err := s.scanDevice(row)
	if err != nil {
		return nil
	}
	s.populateDeviceChildrenLocked(d)
	return d
}

// UpdateDevice updates or creates a device
func (s *Storage) UpdateDevice(device *types.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Preserve existing user data if device exists
	existing := s.GetDeviceLocked(device.IP)
	if existing != nil {
		if device.Label == "" {
			device.Label = existing.Label
		}
		if device.Notes == "" {
			device.Notes = existing.Notes
		}
		if device.Group == "" {
			device.Group = existing.Group
		}
		if device.CustomHostname == "" {
			device.CustomHostname = existing.CustomHostname
		}
		if device.CustomWebURL == "" {
			device.CustomWebURL = existing.CustomWebURL
		}
		if device.CustomType == "" {
			device.CustomType = existing.CustomType
		}
		if device.WebPort == 0 {
			device.WebPort = existing.WebPort
		}
		if device.WebScheme == "" {
			device.WebScheme = existing.WebScheme
		}
		if !device.Probed {
			device.Probed = existing.Probed
		}
		if device.FirstSeen.IsZero() {
			device.FirstSeen = existing.FirstSeen
		}
		device.NotifyOnSeen = existing.NotifyOnSeen
		device.AnsibleManaged = existing.AnsibleManaged
		if device.SSHOverride == "" {
			device.SSHOverride = existing.SSHOverride
		}
		if device.SSHOverridePort == 0 {
			device.SSHOverridePort = existing.SSHOverridePort
		}
		if device.SSID == "" {
			device.SSID = existing.SSID
		}
		if device.APName == "" {
			device.APName = existing.APName
		}
		if device.RadioBand == "" {
			device.RadioBand = existing.RadioBand
		}
		if device.Channel == 0 {
			device.Channel = existing.Channel
		}
		if device.WiFiStandard == "" {
			device.WiFiStandard = existing.WiFiStandard
		}
		if device.Signal == 0 {
			device.Signal = existing.Signal
		}
		if device.SignalQuality == 0 {
			device.SignalQuality = existing.SignalQuality
		}
		if device.RxRate == 0 {
			device.RxRate = existing.RxRate
		}
		if device.TxRate == 0 {
			device.TxRate = existing.TxRate
		}
		if device.RxBytes == 0 {
			device.RxBytes = existing.RxBytes
		}
		if device.TxBytes == 0 {
			device.TxBytes = existing.TxBytes
		}
		if device.AssociationUptime == 0 {
			device.AssociationUptime = existing.AssociationUptime
		}
		if device.UniFiModel == "" {
			device.UniFiModel = existing.UniFiModel
		}
		if device.VLAN == 0 {
			device.VLAN = existing.VLAN
		}
		if device.RouterSource == "" {
			device.RouterSource = existing.RouterSource
		}
		if device.RouterInterface == "" {
			device.RouterInterface = existing.RouterInterface
		}
		if device.LeaseExpires.IsZero() {
			device.LeaseExpires = existing.LeaseExpires
		}
		if device.LeaseLifetime == 0 {
			device.LeaseLifetime = existing.LeaseLifetime
		}
		if device.RouterNotes == "" {
			device.RouterNotes = existing.RouterNotes
		}
		if device.SwitchName == "" {
			device.SwitchName = existing.SwitchName
			device.SwitchHost = existing.SwitchHost
			device.SwitchPort = existing.SwitchPort
			device.SwitchVLAN = existing.SwitchVLAN
			device.SwitchLinkState = existing.SwitchLinkState
			device.SwitchLinkSpeed = existing.SwitchLinkSpeed
			device.SwitchDuplex = existing.SwitchDuplex
			device.SwitchPoEWatts = existing.SwitchPoEWatts
			device.SwitchUpdatedAt = existing.SwitchUpdatedAt
		}
		if device.TrafficSource == "" {
			device.TrafficSource = existing.TrafficSource
		}
		if device.RxRateBps == 0 {
			device.RxRateBps = existing.RxRateBps
		}
		if device.TxRateBps == 0 {
			device.TxRateBps = existing.TxRateBps
		}
		if device.WanRxRateBps == 0 {
			device.WanRxRateBps = existing.WanRxRateBps
		}
		if device.WanTxRateBps == 0 {
			device.WanTxRateBps = existing.WanTxRateBps
		}
		if device.WanRxBytes == 0 {
			device.WanRxBytes = existing.WanRxBytes
		}
		if device.WanTxBytes == 0 {
			device.WanTxBytes = existing.WanTxBytes
		}
		if len(device.IPs) == 0 && len(existing.IPs) > 0 {
			device.IPs = existing.IPs
		}
	}

	if device.FirstSeen.IsZero() {
		device.FirstSeen = time.Now()
	}

	s.syncAttachments(device)
	risksJSON, _ := json.Marshal(device.Risks)
	historyJSON, _ := json.Marshal(device.AddressHistory)
	ipsJSON, _ := json.Marshal(device.IPs)
	isOnline := 0
	if device.IsOnline(s.GetScanInterval()) {
		isOnline = 1
	}

	var leaseExpiresVal interface{}
	if !device.LeaseExpires.IsZero() {
		leaseExpiresVal = device.LeaseExpires
	}
	var switchUpdatedAtVal interface{}
	if !device.SwitchUpdatedAt.IsZero() {
		switchUpdatedAtVal = device.SwitchUpdatedAt
	}

	_, err := s.db.Exec(`
		INSERT INTO devices (
			ip, mac, hostname, vendor, type, web_ui, risks, label, notes, "group",
			custom_hostname, custom_web_url, custom_type, web_port, web_scheme, probed, detected_ssh_port, ssh_override, ssh_override_port,
			assignment, network_name, first_seen, last_seen, response_time, address_history,
			is_online, missed_sweeps, last_presence_change, linked_mac, notify_on_seen, ansible_managed,
			os, os_version, os_family, custom_os, custom_os_version, custom_os_family,
			ssid, ap_name, radio_band, channel, wifi_standard, signal, signal_quality,
			rx_rate, tx_rate, rx_bytes, tx_bytes, association_uptime, unifi_model, vlan, unifi_name,
			router_source, router_interface, lease_expires, lease_lifetime, router_notes,
			switch_name, switch_host, switch_port, switch_vlan, switch_link_state, switch_link_speed, switch_duplex, switch_poe_watts, switch_updated_at,
			traffic_source, rx_rate_bps, tx_rate_bps,
			wan_rx_rate_bps, wan_tx_rate_bps, wan_rx_bytes, wan_tx_bytes,
			ips
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?,
			?, 0, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?,
			?, ?, ?, ?,
			?
		)
		ON CONFLICT(ip) DO UPDATE SET
			mac = excluded.mac,
			hostname = excluded.hostname,
			vendor = excluded.vendor,
			type = excluded.type,
			web_ui = excluded.web_ui,
			risks = excluded.risks,
			label = excluded.label,
			notes = excluded.notes,
			"group" = excluded."group",
			custom_hostname = excluded.custom_hostname,
			custom_web_url = excluded.custom_web_url,
			custom_type = excluded.custom_type,
			web_port = excluded.web_port,
			web_scheme = excluded.web_scheme,
			probed = excluded.probed,
			detected_ssh_port = excluded.detected_ssh_port,
			ssh_override = excluded.ssh_override,
			ssh_override_port = excluded.ssh_override_port,
			assignment = excluded.assignment,
			network_name = excluded.network_name,
			first_seen = excluded.first_seen,
			last_seen = excluded.last_seen,
			response_time = excluded.response_time,
			address_history = excluded.address_history,
			is_online = excluded.is_online,
			linked_mac = excluded.linked_mac,
			notify_on_seen = excluded.notify_on_seen,
			ansible_managed = excluded.ansible_managed,
			os = excluded.os,
			os_version = excluded.os_version,
			os_family = excluded.os_family,
			custom_os = excluded.custom_os,
			custom_os_version = excluded.custom_os_version,
			custom_os_family = excluded.custom_os_family,
			ssid = excluded.ssid,
			ap_name = excluded.ap_name,
			radio_band = excluded.radio_band,
			channel = excluded.channel,
			wifi_standard = excluded.wifi_standard,
			signal = excluded.signal,
			signal_quality = excluded.signal_quality,
			rx_rate = excluded.rx_rate,
			tx_rate = excluded.tx_rate,
			rx_bytes = excluded.rx_bytes,
			tx_bytes = excluded.tx_bytes,
			association_uptime = excluded.association_uptime,
			unifi_model = excluded.unifi_model,
			vlan = excluded.vlan,
			unifi_name = CASE WHEN excluded.unifi_name != '' THEN excluded.unifi_name ELSE devices.unifi_name END,
			router_source = excluded.router_source,
			router_interface = excluded.router_interface,
			lease_expires = excluded.lease_expires,
			lease_lifetime = excluded.lease_lifetime,
			router_notes = excluded.router_notes,
			switch_name = excluded.switch_name,
			switch_host = excluded.switch_host,
			switch_port = excluded.switch_port,
			switch_vlan = excluded.switch_vlan,
			switch_link_state = excluded.switch_link_state,
			switch_link_speed = excluded.switch_link_speed,
			switch_duplex = excluded.switch_duplex,
			switch_poe_watts = excluded.switch_poe_watts,
			switch_updated_at = excluded.switch_updated_at,
			traffic_source = excluded.traffic_source,
			rx_rate_bps = excluded.rx_rate_bps,
			tx_rate_bps = excluded.tx_rate_bps,
			wan_rx_rate_bps = excluded.wan_rx_rate_bps,
			wan_tx_rate_bps = excluded.wan_tx_rate_bps,
			wan_rx_bytes = excluded.wan_rx_bytes,
			wan_tx_bytes = excluded.wan_tx_bytes,
			ips = CASE WHEN excluded.ips != '[]' AND excluded.ips != '' THEN excluded.ips ELSE devices.ips END
	`, device.IP, device.MAC, device.Hostname, device.Vendor, device.Type, boolToInt(device.WebUI), string(risksJSON),
		device.Label, device.Notes, device.Group, device.CustomHostname, device.CustomWebURL, device.CustomType,
		device.WebPort, device.WebScheme, boolToInt(device.Probed), device.DetectedSSHPort, device.SSHOverride, device.SSHOverridePort, device.Assignment, device.NetworkName,
		device.FirstSeen, device.LastSeen, device.ResponseTime, string(historyJSON), isOnline, device.LastSeen,
		device.LinkedMAC, boolToInt(device.NotifyOnSeen), boolToInt(device.AnsibleManaged),
		device.OS, device.OSVersion, device.OSFamily, device.CustomOS, device.CustomOSVersion, device.CustomOSFamily,
		device.SSID, device.APName, device.RadioBand, device.Channel, device.WiFiStandard, device.Signal, device.SignalQuality,
		device.RxRate, device.TxRate, device.RxBytes, device.TxBytes, device.AssociationUptime, device.UniFiModel, device.VLAN, device.UniFiName,
		device.RouterSource, device.RouterInterface, leaseExpiresVal, device.LeaseLifetime, device.RouterNotes,
		device.SwitchName, device.SwitchHost, device.SwitchPort, device.SwitchVLAN, device.SwitchLinkState, device.SwitchLinkSpeed, device.SwitchDuplex, device.SwitchPoEWatts, switchUpdatedAtVal,
		device.TrafficSource, device.RxRateBps, device.TxRateBps,
		device.WanRxRateBps, device.WanTxRateBps, device.WanRxBytes, device.WanTxBytes,
		string(ipsJSON))
	return err
}

// UpdateDeviceFields updates specific fields of a device
func (s *Storage) UpdateDeviceFields(ip string, label, notes, group, customHostname, customWebURL, customType, linkedMac, sshOverride *string, notifyOnSeen, ansibleManaged *bool, sshOverridePort *int, customOS, customOSVersion, customOSFamily, mac, vendor *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing := s.GetDeviceLocked(ip)
	if existing == nil {
		return fmt.Errorf("device not found: %s", ip)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Determine active parent MAC address (normalized)
	parentMAC := NormalizeMAC(existing.LinkedMAC)
	var normLinkedMAC string
	if linkedMac != nil {
		normLinkedMAC = NormalizeMAC(*linkedMac)
		parentMAC = normLinkedMAC
	}

	// 2. If parentMAC is set and valid, update parent's customizations!
	if parentMAC != "" {
		// Try to find the parent device IP
		var parentIP string
		if err := tx.QueryRow("SELECT ip FROM devices WHERE LOWER(REPLACE(mac, '-', ':')) = ? AND mac <> '' LIMIT 1", parentMAC).Scan(&parentIP); err != nil && err != sql.ErrNoRows {
			return err
		}

		if parentIP != "" {
			// Forward customizations directly to the parent device!
			parentQuery := `UPDATE devices SET `
			var parentArgs []interface{}
			var parentFields []string

			if label != nil {
				parentFields = append(parentFields, `label = ?`)
				parentArgs = append(parentArgs, *label)
			}
			if notes != nil {
				parentFields = append(parentFields, `notes = ?`)
				parentArgs = append(parentArgs, *notes)
			}
			if group != nil {
				parentFields = append(parentFields, `"group" = ?`)
				parentArgs = append(parentArgs, *group)
			}
			if customHostname != nil {
				parentFields = append(parentFields, `custom_hostname = ?`)
				parentArgs = append(parentArgs, *customHostname)
			}
			if customWebURL != nil {
				parentFields = append(parentFields, `custom_web_url = ?`)
				parentArgs = append(parentArgs, *customWebURL)
			}
			if customType != nil {
				parentFields = append(parentFields, `custom_type = ?`)
				parentArgs = append(parentArgs, *customType)
			}
			if notifyOnSeen != nil {
				parentFields = append(parentFields, `notify_on_seen = ?`)
				parentArgs = append(parentArgs, boolToInt(*notifyOnSeen))
			}
			if ansibleManaged != nil {
				parentFields = append(parentFields, `ansible_managed = ?`)
				parentArgs = append(parentArgs, boolToInt(*ansibleManaged))
			}
			if sshOverride != nil {
				parentFields = append(parentFields, `ssh_override = ?`)
				parentArgs = append(parentArgs, *sshOverride)
			}
			if sshOverridePort != nil {
				parentFields = append(parentFields, `ssh_override_port = ?`)
				parentArgs = append(parentArgs, *sshOverridePort)
			}
			if customOS != nil {
				parentFields = append(parentFields, `custom_os = ?`)
				parentArgs = append(parentArgs, *customOS)
			}
			if customOSVersion != nil {
				parentFields = append(parentFields, `custom_os_version = ?`)
				parentArgs = append(parentArgs, *customOSVersion)
			}
			if customOSFamily != nil {
				parentFields = append(parentFields, `custom_os_family = ?`)
				parentArgs = append(parentArgs, *customOSFamily)
			}

			if len(parentFields) > 0 {
				parentQuery += joinStrings(parentFields, ", ") + ` WHERE ip = ?`
				parentArgs = append(parentArgs, parentIP)
				if _, err := tx.Exec(parentQuery, parentArgs...); err != nil {
					return fmt.Errorf("failed to update linked parent device: %w", err)
				}
			}

			// Clear customizations on the child so it cleanly inherits them from the parent
			childQuery := `UPDATE devices SET label = '', notes = '', "group" = '', custom_hostname = '', custom_web_url = '', custom_type = '', notify_on_seen = 0, ansible_managed = 0, ssh_override = '', ssh_override_port = 0, custom_os = '', custom_os_version = '', custom_os_family = ''`
			var childArgs []interface{}
			if linkedMac != nil {
				childQuery += `, linked_mac = ?`
				childArgs = append(childArgs, normLinkedMAC)
			}
			childQuery += ` WHERE ip = ?`
			childArgs = append(childArgs, ip)
			if _, err := tx.Exec(childQuery, childArgs...); err != nil {
				return fmt.Errorf("failed to update linked child device: %w", err)
			}
			return tx.Commit()
		}
	}

	// 3. Otherwise, if not linked, update the child directly as normal
	query := `UPDATE devices SET `
	var args []interface{}
	var fields []string

	if label != nil {
		fields = append(fields, `label = ?`)
		args = append(args, *label)
	}
	if notes != nil {
		fields = append(fields, `notes = ?`)
		args = append(args, *notes)
	}
	if group != nil {
		fields = append(fields, `"group" = ?`)
		args = append(args, *group)
	}
	if customHostname != nil {
		fields = append(fields, `custom_hostname = ?`)
		args = append(args, *customHostname)
	}
	if customWebURL != nil {
		fields = append(fields, `custom_web_url = ?`)
		args = append(args, *customWebURL)
	}
	if customType != nil {
		fields = append(fields, `custom_type = ?`)
		args = append(args, *customType)
	}
	if linkedMac != nil {
		fields = append(fields, `linked_mac = ?`)
		args = append(args, normLinkedMAC)
	}
	if notifyOnSeen != nil {
		fields = append(fields, `notify_on_seen = ?`)
		args = append(args, boolToInt(*notifyOnSeen))
	}
	if ansibleManaged != nil {
		fields = append(fields, `ansible_managed = ?`)
		args = append(args, boolToInt(*ansibleManaged))
	}
	if sshOverride != nil {
		fields = append(fields, `ssh_override = ?`)
		args = append(args, *sshOverride)
	}
	if sshOverridePort != nil {
		fields = append(fields, `ssh_override_port = ?`)
		args = append(args, *sshOverridePort)
	}
	if customOS != nil {
		fields = append(fields, `custom_os = ?`)
		args = append(args, *customOS)
	}
	if customOSVersion != nil {
		fields = append(fields, `custom_os_version = ?`)
		args = append(args, *customOSVersion)
	}
	if customOSFamily != nil {
		fields = append(fields, `custom_os_family = ?`)
		args = append(args, *customOSFamily)
	}
	if mac != nil {
		cleanMAC := NormalizeMAC(*mac)
		fields = append(fields, `mac = ?`)
		args = append(args, cleanMAC)
	}
	if vendor != nil && *vendor != "" {
		fields = append(fields, `vendor = ?`)
		args = append(args, *vendor)
	}

	if len(fields) == 0 {
		return nil
	}

	query += joinStrings(fields, ", ") + ` WHERE ip = ?`
	args = append(args, ip)

	if _, err := tx.Exec(query, args...); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateDeviceCustomOS updates custom OS override fields by MAC address.
func (s *Storage) UpdateDeviceCustomOS(mac, customOS, customOSVersion, customOSFamily string) error {
	norm := NormalizeMAC(mac)
	if norm == "" {
		return fmt.Errorf("mac cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`
		UPDATE devices
		SET custom_os = ?, custom_os_version = ?, custom_os_family = ?
		WHERE LOWER(REPLACE(mac, '-', ':')) = ?
	`, customOS, customOSVersion, customOSFamily, norm)
	if err != nil {
		return err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("device with mac %s not found", mac)
	}
	return nil
}

// UpdateDeviceCustomOSByIP updates custom OS override fields by IP address.
func (s *Storage) UpdateDeviceCustomOSByIP(ip, customOS, customOSVersion, customOSFamily string) error {
	if strings.TrimSpace(ip) == "" {
		return fmt.Errorf("ip cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`
		UPDATE devices
		SET custom_os = ?, custom_os_version = ?, custom_os_family = ?
		WHERE ip = ?
	`, customOS, customOSVersion, customOSFamily, strings.TrimSpace(ip))
	if err != nil {
		return err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("device with ip %s not found", ip)
	}
	return nil
}

// UpdateDeviceMAC updates the MAC address and optional vendor of a device by IP.
func (s *Storage) UpdateDeviceMAC(ip, mac, vendor string) error {
	norm := NormalizeMAC(mac)
	if norm == "" {
		return fmt.Errorf("mac cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	if vendor != "" {
		_, err = s.db.Exec("UPDATE devices SET mac = ?, vendor = ? WHERE ip = ?", norm, vendor, strings.TrimSpace(ip))
	} else {
		_, err = s.db.Exec("UPDATE devices SET mac = ? WHERE ip = ?", norm, strings.TrimSpace(ip))
	}
	return err
}

// UpdateDeviceHostnameIfBlank updates the device's hostname only if it is currently empty.
func (s *Storage) UpdateDeviceHostnameIfBlank(target, hostname string, isIP bool) error {
	trimmed := strings.TrimSpace(hostname)
	if trimmed == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if isIP {
		ip := strings.TrimSpace(target)
		_, err := s.db.Exec(`
			UPDATE devices
			SET hostname = ?
			WHERE ip = ? AND (hostname IS NULL OR hostname = '')
		`, trimmed, ip)
		return err
	}

	norm := NormalizeMAC(target)
	if norm == "" {
		return fmt.Errorf("mac cannot be empty")
	}
	_, err := s.db.Exec(`
		UPDATE devices
		SET hostname = ?
		WHERE LOWER(REPLACE(mac, '-', ':')) = ? AND (hostname IS NULL OR hostname = '')
	`, trimmed, norm)
	return err
}

// DeleteDevice removes a device by IP
func (s *Storage) DeleteDevice(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec("DELETE FROM devices WHERE ip = ?", ip)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("device not found: %s", ip)
	}
	return nil
}

// ClearDevices removes all devices, or only those belonging to a specific network name.
func (s *Storage) ClearDevices(networkName string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var res sql.Result
	var err error

	if networkName == "" || strings.ToLower(networkName) == "all" {
		res, err = s.db.Exec("DELETE FROM devices")
	} else {
		res, err = s.db.Exec("DELETE FROM devices WHERE LOWER(network_name) = LOWER(?)", networkName)
	}

	if err != nil {
		return 0, err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}

	return affected, nil
}

// GetStats returns device statistics
func (s *Storage) GetStats() types.DeviceStats {
	stats := types.DeviceStats{
		Groups: make(map[string]int),
	}

	scanInterval := s.GetScanInterval()
	devices := s.GetDevices()
	for _, d := range devices {
		stats.Total++
		if d.IsOnline(scanInterval) {
			stats.Online++
		} else {
			stats.Offline++
		}
		if d.Group != "" {
			stats.Groups[d.Group]++
		}
	}

	return stats
}

// GetNewDevicesCount returns the count of devices discovered since the given time
func (s *Storage) GetNewDevicesCount(since time.Time) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM devices WHERE first_seen > ?", since).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

func (s *Storage) findByMACLocked(tx *sql.Tx, mac, excludeIP string) (string, *types.Device, error) {
	normMAC := NormalizeMAC(mac)
	if normMAC == "" {
		return "", nil, nil
	}
	wantV4 := isIPv4(excludeIP)
	rows, err := tx.Query(`SELECT `+deviceSelectColumns+`
		FROM devices
		WHERE LOWER(REPLACE(mac, '-', ':')) = ? AND ip != ?
		ORDER BY is_online DESC, length(ip) ASC, ip ASC, last_seen DESC, first_seen ASC
	`, normMAC, excludeIP)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()

	for rows.Next() {
		d, err := s.scanDevice(rows)
		if err == nil {
			if isIPv4(d.IP) == wantV4 {
				return d.IP, d, nil
			}
		}
	}
	if err := rows.Err(); err != nil {
		return "", nil, err
	}
	return "", nil, nil
}

func (s *Storage) findAnyByMACLocked(tx *sql.Tx, mac string) (*types.Device, error) {
	normMAC := NormalizeMAC(mac)
	if normMAC == "" {
		return nil, nil
	}
	row := tx.QueryRow(`SELECT `+deviceSelectColumns+`
		FROM devices
		WHERE LOWER(REPLACE(mac, '-', ':')) = ?
		ORDER BY is_online DESC, length(ip) ASC, ip ASC, last_seen DESC, first_seen ASC
		LIMIT 1
	`, normMAC)
	d, err := s.scanDevice(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return d, nil
}

func (s *Storage) attachIP(d *types.Device, ip, networkName string) {
	s.attachIPWithTime(d, ip, networkName, time.Time{})
}

func (s *Storage) attachIPWithTime(d *types.Device, ip, networkName string, seen time.Time) {
	if ip == "" {
		return
	}
	if networkName == "" {
		networkName = s.resolveNetworkNameLocked(ip)
	}
	if len(d.IPs) == 0 && d.IP != "" {
		d.IPs = []types.IPAttachment{{IP: d.IP, NetworkName: d.NetworkName, LastSeen: d.LastSeen, IsActive: true}}
	}
	for i, att := range d.IPs {
		if att.IP == ip {
			if networkName != "" && att.NetworkName != networkName {
				d.IPs[i].NetworkName = networkName
			}
			if !seen.IsZero() {
				d.IPs[i].LastSeen = seen
				d.IPs[i].MissedSweeps = 0
				d.IPs[i].IsActive = true
			}
			return
		}
	}
	newAtt := types.IPAttachment{
		IP:          ip,
		NetworkName: networkName,
		LastSeen:    seen,
		IsActive:    !seen.IsZero(),
	}
	d.IPs = append(d.IPs, newAtt)
}

func (s *Storage) syncAttachments(d *types.Device) {
	if len(d.IPs) == 0 && d.IP != "" {
		d.IPs = []types.IPAttachment{{IP: d.IP, NetworkName: d.NetworkName, LastSeen: d.LastSeen, IsActive: true}}
		return
	}
	foundPrimary := false
	for _, att := range d.IPs {
		if att.IP == d.IP {
			foundPrimary = true
			break
		}
	}
	if !foundPrimary && d.IP != "" {
		d.IPs = append([]types.IPAttachment{{IP: d.IP, NetworkName: d.NetworkName, LastSeen: d.LastSeen, IsActive: true}}, d.IPs...)
	}
}

func (s *Storage) mergeDuplicateDevice(target *types.Device, source *types.Device, now time.Time) {
	if source == nil {
		return
	}
	// Tier 1: User overrides preserved (target keeps its overrides, or inherits from source if target has not set them)
	if target.Label == "" && source.Label != "" {
		target.Label = source.Label
	}
	if target.Notes == "" && source.Notes != "" {
		target.Notes = source.Notes
	}
	if target.Group == "" && source.Group != "" {
		target.Group = source.Group
	}
	if target.CustomHostname == "" && source.CustomHostname != "" {
		target.CustomHostname = source.CustomHostname
	}
	if target.CustomWebURL == "" && source.CustomWebURL != "" {
		target.CustomWebURL = source.CustomWebURL
	}
	if target.CustomType == "" && source.CustomType != "" {
		target.CustomType = source.CustomType
	}
	if target.CustomOS == "" && source.CustomOS != "" {
		target.CustomOS = source.CustomOS
	}
	if target.CustomOSVersion == "" && source.CustomOSVersion != "" {
		target.CustomOSVersion = source.CustomOSVersion
	}
	if target.CustomOSFamily == "" && source.CustomOSFamily != "" {
		target.CustomOSFamily = source.CustomOSFamily
	}
	if target.SSHOverride == "" && source.SSHOverride != "" {
		target.SSHOverride = source.SSHOverride
	}
	if target.SSHOverridePort == 0 && source.SSHOverridePort != 0 {
		target.SSHOverridePort = source.SSHOverridePort
	}
	if !target.NotifyOnSeen && source.NotifyOnSeen {
		target.NotifyOnSeen = source.NotifyOnSeen
	}
	if !target.AnsibleManaged && source.AnsibleManaged {
		target.AnsibleManaged = source.AnsibleManaged
	}
	if target.LinkedMAC == "" && source.LinkedMAC != "" {
		target.LinkedMAC = source.LinkedMAC
	}

	// Tier 2: target's values take precedence; fall back to source if target is empty
	if target.Hostname == "" && source.Hostname != "" {
		target.Hostname = source.Hostname
	}
	if target.Vendor == "" && source.Vendor != "" {
		target.Vendor = source.Vendor
	}
	if target.Type == "" && source.Type != "" {
		target.Type = source.Type
	}
	if !target.WebUI && source.WebUI {
		target.WebUI = source.WebUI
	}
	if target.WebPort == 0 && source.WebPort != 0 {
		target.WebPort = source.WebPort
		target.WebScheme = source.WebScheme
	}
	if !target.Probed && source.Probed {
		target.Probed = source.Probed
		target.WebScheme = source.WebScheme
	}
	if len(target.Risks) == 0 && len(source.Risks) > 0 {
		target.Risks = source.Risks
	}
	if len(target.OpenPorts) == 0 && len(source.OpenPorts) > 0 {
		target.OpenPorts = source.OpenPorts
	}
	if len(target.OpenServices) == 0 && len(source.OpenServices) > 0 {
		target.OpenServices = source.OpenServices
	}
	if target.DetectedSSHPort == 0 && source.DetectedSSHPort != 0 {
		target.DetectedSSHPort = source.DetectedSSHPort
	}
	if target.OS == "" && source.OS != "" {
		target.OS = source.OS
		target.OSVersion = source.OSVersion
		target.OSFamily = source.OSFamily
	}
	if target.Assignment == "" && source.Assignment != "" {
		target.Assignment = source.Assignment
	}
	if target.SSID == "" && source.SSID != "" {
		target.SSID = source.SSID
	}
	if target.APName == "" && source.APName != "" {
		target.APName = source.APName
	}
	if target.RadioBand == "" && source.RadioBand != "" {
		target.RadioBand = source.RadioBand
	}
	if target.Channel == 0 && source.Channel != 0 {
		target.Channel = source.Channel
	}
	if target.WiFiStandard == "" && source.WiFiStandard != "" {
		target.WiFiStandard = source.WiFiStandard
	}
	if target.Signal == 0 && source.Signal != 0 {
		target.Signal = source.Signal
		target.SignalQuality = source.SignalQuality
	}
	if target.RxRate == 0 && source.RxRate != 0 {
		target.RxRate = source.RxRate
	}
	if target.TxRate == 0 && source.TxRate != 0 {
		target.TxRate = source.TxRate
	}
	if target.RxBytes == 0 && source.RxBytes != 0 {
		target.RxBytes = source.RxBytes
	}
	if target.TxBytes == 0 && source.TxBytes != 0 {
		target.TxBytes = source.TxBytes
	}
	if target.AssociationUptime == 0 && source.AssociationUptime != 0 {
		target.AssociationUptime = source.AssociationUptime
	}
	if target.UniFiModel == "" && source.UniFiModel != "" {
		target.UniFiModel = source.UniFiModel
	}
	if target.UniFiName == "" && source.UniFiName != "" {
		target.UniFiName = source.UniFiName
	}
	if target.VLAN == 0 && source.VLAN != 0 {
		target.VLAN = source.VLAN
	}
	if target.RouterSource == "" && source.RouterSource != "" {
		target.RouterSource = source.RouterSource
	}
	if target.RouterInterface == "" && source.RouterInterface != "" {
		target.RouterInterface = source.RouterInterface
	}
	if target.LeaseExpires.IsZero() && !source.LeaseExpires.IsZero() {
		target.LeaseExpires = source.LeaseExpires
	}
	if target.LeaseLifetime == 0 && source.LeaseLifetime != 0 {
		target.LeaseLifetime = source.LeaseLifetime
	}
	if target.RouterNotes == "" && source.RouterNotes != "" {
		target.RouterNotes = source.RouterNotes
	}
	if target.SwitchName == "" && source.SwitchName != "" {
		target.SwitchName = source.SwitchName
		target.SwitchHost = source.SwitchHost
		target.SwitchPort = source.SwitchPort
		target.SwitchVLAN = source.SwitchVLAN
		target.SwitchLinkState = source.SwitchLinkState
		target.SwitchLinkSpeed = source.SwitchLinkSpeed
		target.SwitchDuplex = source.SwitchDuplex
		target.SwitchPoEWatts = source.SwitchPoEWatts
		target.SwitchUpdatedAt = source.SwitchUpdatedAt
	}
	if target.TrafficSource == "" && source.TrafficSource != "" {
		target.TrafficSource = source.TrafficSource
		target.RxRateBps = source.RxRateBps
		target.TxRateBps = source.TxRateBps
		target.WanRxRateBps = source.WanRxRateBps
		target.WanTxRateBps = source.WanTxRateBps
		target.WanRxBytes = source.WanRxBytes
		target.WanTxBytes = source.WanTxBytes
	}
	if target.ResponseTime == nil && source.ResponseTime != nil {
		target.ResponseTime = source.ResponseTime
	}
	if target.LastDeepScanAt.IsZero() && !source.LastDeepScanAt.IsZero() {
		target.LastDeepScanAt = source.LastDeepScanAt
	}
	if target.FirstSeen.IsZero() || (!source.FirstSeen.IsZero() && source.FirstSeen.Before(target.FirstSeen)) {
		target.FirstSeen = source.FirstSeen
	}

	for _, att := range source.IPs {
		s.attachIP(target, att.IP, att.NetworkName)
	}
	s.attachIP(target, source.IP, source.NetworkName)
	s.syncAttachments(target)
}

func (s *Storage) addNewDeviceLocked(tx *sql.Tx, d *types.Device, now time.Time, activeIPs map[string]bool) (bool, bool, error) {
	isNew := true
	relocated := false
	scanInterval := s.GetScanInterval()

	// Check if this IP is already attached to an existing device (e.g. VIP or multi-network attachment)
	if d.IP != "" {
		// If another device had d.IP in its attached IPs, prune it immediately (e.g. DHCP churn / address reassignment)
		pruneRows, pErr := tx.Query(`SELECT ip, ips FROM devices WHERE ip != ? AND instr(ips, '"' || ? || '"') > 0`, d.IP, d.IP)
		if pErr != nil {
			return false, false, pErr
		}
		type toPrune struct {
			primaryIP string
			ips       []types.IPAttachment
		}
		var prunes []toPrune
		for pruneRows.Next() {
			var pIP, ipsJSON string
			if err := pruneRows.Scan(&pIP, &ipsJSON); err == nil {
				var atts []types.IPAttachment
				_ = json.Unmarshal([]byte(ipsJSON), &atts)
				updated := make([]types.IPAttachment, 0, len(atts))
				for _, a := range atts {
					if a.IP != d.IP {
						updated = append(updated, a)
					}
				}
				prunes = append(prunes, toPrune{primaryIP: pIP, ips: updated})
			}
		}
		if err := pruneRows.Err(); err != nil {
			pruneRows.Close()
			return false, false, err
		}
		pruneRows.Close()
		for _, p := range prunes {
			upJSON, _ := json.Marshal(p.ips)
			if _, err := tx.Exec("UPDATE devices SET ips = ? WHERE ip = ?", string(upJSON), p.primaryIP); err != nil {
				return false, false, err
			}
		}
	}

	if d.MAC != "" {
		oldIP, old, err := s.findByMACLocked(tx, d.MAC, d.IP)
		if err != nil {
			return false, false, err
		}
		if old != nil {
			isNew = false
			// Check if this is a relocation:
			// If oldIP and d.IP are in the same subnet, and oldIP did NOT answer the sweep (activeIPs != nil && !activeIPs[oldIP]):
			// then the device moved on the local subnet!
			isRelocation := false
			if activeIPs != nil {
				// Sweep batch context:
				// If oldIP and d.IP are in the same subnet and oldIP didn't answer -> moved on the local subnet!
				// If on different subnets: if oldIP was already marked offline in DB, it definitely moved.
				// If oldIP is still online on another subnet, it is a multi-network device until proven otherwise by sweep.
				if s.inSameSubnetLocked(d.IP, oldIP) {
					if !activeIPs[oldIP] {
						isRelocation = true
					}
				} else {
					if !old.IsOnline(scanInterval) {
						isRelocation = true
					}
				}
			} else {
				// No active sweep context: check if oldIP is offline in DB
				isRelocation = !old.IsOnline(scanInterval)
			}

			if isRelocation {
				// Relocation (same or cross subnet): retire oldIP to address history, promote d.IP
				// If old device was marked as a multi-IP gateway/unified record, check if oldIP was only one of its attachments
				hasRemainingAttachments := false
				for _, att := range old.IPs {
					if att.IP != oldIP && att.IP != "" {
						hasRemainingAttachments = true
						break
					}
				}
				if hasRemainingAttachments {
					// Don't treat a multi-IP device as relocated just because one IP didn't answer in a sweep!
					// Keep old device, attach d.IP, and merge.
					isRelocation = false
				}
			}

			if isRelocation {
				relocated = true
				// Relocation (same or cross subnet): retire oldIP to address history, promote d.IP
				d.AddressHistory = appendAddressChange(old.AddressHistory, oldIP, now)
				s.mergeDuplicateDevice(d, old, now)
				newIPs := make([]types.IPAttachment, 0, len(old.IPs))
				for _, att := range old.IPs {
					if att.IP != oldIP {
						newIPs = append(newIPs, att)
					}
				}
				d.IPs = newIPs
				s.attachIPWithTime(d, d.IP, d.NetworkName, now)
				s.syncAttachments(d)

				if _, err := tx.Exec("UPDATE device_presence_history SET ip = ? WHERE ip = ?", d.IP, oldIP); err != nil {
					return false, false, err
				}
				if _, err := tx.Exec("UPDATE OR IGNORE device_open_ports SET ip = ? WHERE ip = ?", d.IP, oldIP); err != nil {
					return false, false, err
				}
				if _, err := tx.Exec("DELETE FROM device_open_ports WHERE ip = ?", oldIP); err != nil {
					return false, false, err
				}
				if _, err := tx.Exec("DELETE FROM devices WHERE ip = ?", oldIP); err != nil {
					return false, false, err
				}
			} else {
				// Multi-IP unified device attachment (VIP or multi-network): both are active
				attachedIP := d.IP
				attachedMAC := d.MAC
				attachedHostname := d.Hostname
				s.mergeDuplicateDevice(old, d, now)
				s.attachIPWithTime(old, old.IP, old.NetworkName, old.LastSeen)
				s.attachIPWithTime(old, attachedIP, d.NetworkName, now)
				s.syncAttachments(old)
				if now.After(old.LastSeen) {
					old.LastSeen = now
				}
				*d = *old

				// Record presence event for attachedIP
				if _, err := tx.Exec(`
					INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
					VALUES (?, ?, ?, 'join', 0.0, ?)
				`, attachedIP, attachedMAC, attachedHostname, now); err != nil {
					return false, false, err
				}

				// Update old device in DB
				risksJSON, _ := json.Marshal(old.Risks)
				historyJSON, _ := json.Marshal(old.AddressHistory)
				ipsJSON, _ := json.Marshal(old.IPs)
				var leaseExpiresVal interface{}
				if !old.LeaseExpires.IsZero() {
					leaseExpiresVal = old.LeaseExpires
				}
				var switchUpdatedAtVal interface{}
				if !old.SwitchUpdatedAt.IsZero() {
					switchUpdatedAtVal = old.SwitchUpdatedAt
				}

				_, err = tx.Exec(`
					UPDATE devices SET
						hostname = ?, vendor = ?, type = ?, web_ui = ?, risks = ?,
						label = ?, notes = ?, "group" = ?, custom_hostname = ?, custom_web_url = ?,
						custom_type = ?, web_port = ?, web_scheme = ?, probed = ?, detected_ssh_port = ?,
						ssh_override = ?, ssh_override_port = ?, assignment = ?, network_name = ?,
						first_seen = ?, last_seen = ?, response_time = ?, address_history = ?,
						is_online = ?,
						linked_mac = ?, notify_on_seen = ?, ansible_managed = ?,
						os = ?, os_version = ?, os_family = ?, custom_os = ?, custom_os_version = ?, custom_os_family = ?,
						ssid = ?, ap_name = ?, radio_band = ?, channel = ?, wifi_standard = ?, signal = ?, signal_quality = ?,
						rx_rate = ?, tx_rate = ?, rx_bytes = ?, tx_bytes = ?, association_uptime = ?, unifi_model = ?, vlan = ?, unifi_name = ?,
						router_source = ?, router_interface = ?, lease_expires = ?, lease_lifetime = ?, router_notes = ?,
						switch_name = ?, switch_host = ?, switch_port = ?, switch_vlan = ?, switch_link_state = ?, switch_link_speed = ?, switch_duplex = ?, switch_poe_watts = ?, switch_updated_at = ?,
						traffic_source = ?, rx_rate_bps = ?, tx_rate_bps = ?, wan_rx_rate_bps = ?, wan_tx_rate_bps = ?, wan_rx_bytes = ?, wan_tx_bytes = ?,
						ips = ?
					WHERE ip = ?
				`, old.Hostname, old.Vendor, old.Type, boolToInt(old.WebUI), string(risksJSON),
					old.Label, old.Notes, old.Group, old.CustomHostname, old.CustomWebURL,
					old.CustomType, old.WebPort, old.WebScheme, boolToInt(old.Probed), old.DetectedSSHPort,
					old.SSHOverride, old.SSHOverridePort, old.Assignment, old.NetworkName,
					old.FirstSeen, old.LastSeen, old.ResponseTime, string(historyJSON),
					boolToInt(old.IsOnline(scanInterval)),
					old.LinkedMAC, boolToInt(old.NotifyOnSeen), boolToInt(old.AnsibleManaged),
					old.OS, old.OSVersion, old.OSFamily, old.CustomOS, old.CustomOSVersion, old.CustomOSFamily,
					old.SSID, old.APName, old.RadioBand, old.Channel, old.WiFiStandard, old.Signal, old.SignalQuality,
					old.RxRate, old.TxRate, old.RxBytes, old.TxBytes, old.AssociationUptime, old.UniFiModel, old.VLAN, old.UniFiName,
					old.RouterSource, old.RouterInterface, leaseExpiresVal, old.LeaseLifetime, old.RouterNotes,
					old.SwitchName, old.SwitchHost, old.SwitchPort, old.SwitchVLAN, old.SwitchLinkState, old.SwitchLinkSpeed, old.SwitchDuplex, old.SwitchPoEWatts, switchUpdatedAtVal,
					old.TrafficSource, old.RxRateBps, old.TxRateBps, old.WanRxRateBps, old.WanTxRateBps, old.WanRxBytes, old.WanTxBytes,
					string(ipsJSON),
					oldIP)
				return false, false, err
			}
		}
	}
	if d.FirstSeen.IsZero() {
		d.FirstSeen = now
	}
	d.LastSeen = now

	s.syncAttachments(d)
	risksJSON, _ := json.Marshal(d.Risks)
	historyJSON, _ := json.Marshal(d.AddressHistory)
	ipsJSON, _ := json.Marshal(d.IPs)
	isOnline := 0
	if d.IsOnline(scanInterval) {
		isOnline = 1
	}

	var leaseExpiresVal interface{}
	if !d.LeaseExpires.IsZero() {
		leaseExpiresVal = d.LeaseExpires
	}
	var switchUpdatedAtVal interface{}
	if !d.SwitchUpdatedAt.IsZero() {
		switchUpdatedAtVal = d.SwitchUpdatedAt
	}

	_, err := tx.Exec(`
		INSERT INTO devices (
			ip, mac, hostname, vendor, type, web_ui, risks, label, notes, "group",
			custom_hostname, custom_web_url, custom_type, web_port, web_scheme, probed, detected_ssh_port, ssh_override, ssh_override_port,
			assignment, network_name, first_seen, last_seen, response_time, address_history,
			is_online, missed_sweeps, last_presence_change, linked_mac, notify_on_seen, ansible_managed,
			os, os_version, os_family, custom_os, custom_os_version, custom_os_family,
			ssid, ap_name, radio_band, channel, wifi_standard, signal, signal_quality,
			rx_rate, tx_rate, rx_bytes, tx_bytes, association_uptime, unifi_model, vlan, unifi_name,
			router_source, router_interface, lease_expires, lease_lifetime, router_notes,
			switch_name, switch_host, switch_port, switch_vlan, switch_link_state, switch_link_speed, switch_duplex, switch_poe_watts, switch_updated_at,
			traffic_source, rx_rate_bps, tx_rate_bps,
			wan_rx_rate_bps, wan_tx_rate_bps, wan_rx_bytes, wan_tx_bytes,
			ips
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?,
			?, 0, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?,
			?, ?, ?, ?,
			?
		)
	`, d.IP, d.MAC, d.Hostname, d.Vendor, d.Type, boolToInt(d.WebUI), string(risksJSON),
		d.Label, d.Notes, d.Group, d.CustomHostname, d.CustomWebURL, d.CustomType,
		d.WebPort, d.WebScheme, boolToInt(d.Probed), d.DetectedSSHPort, d.SSHOverride, d.SSHOverridePort, d.Assignment, d.NetworkName,
		d.FirstSeen, d.LastSeen, d.ResponseTime, string(historyJSON), isOnline, d.LastSeen,
		d.LinkedMAC, boolToInt(d.NotifyOnSeen), boolToInt(d.AnsibleManaged),
		d.OS, d.OSVersion, d.OSFamily, d.CustomOS, d.CustomOSVersion, d.CustomOSFamily,
		d.SSID, d.APName, d.RadioBand, d.Channel, d.WiFiStandard, d.Signal, d.SignalQuality,
		d.RxRate, d.TxRate, d.RxBytes, d.TxBytes, d.AssociationUptime, d.UniFiModel, d.VLAN, d.UniFiName,
		d.RouterSource, d.RouterInterface, leaseExpiresVal, d.LeaseLifetime, d.RouterNotes,
		d.SwitchName, d.SwitchHost, d.SwitchPort, d.SwitchVLAN, d.SwitchLinkState, d.SwitchLinkSpeed, d.SwitchDuplex, d.SwitchPoEWatts, switchUpdatedAtVal,
		d.TrafficSource, d.RxRateBps, d.TxRateBps,
		d.WanRxRateBps, d.WanTxRateBps, d.WanRxBytes, d.WanTxBytes,
		string(ipsJSON))
	if err != nil {
		return false, false, err
	}

	if isNew {
		// Log an initial 'join' presence event for first-time discovery!
		_, err = tx.Exec(`
			INSERT INTO device_presence_history (ip, mac, hostname, event, duration, created_at)
			VALUES (?, ?, ?, 'join', 0.0, ?)
		`, d.IP, d.MAC, d.Hostname, now)
		if err != nil {
			return false, false, err
		}
	}
	return isNew, relocated, nil
}
