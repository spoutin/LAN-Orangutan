package scanner

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/spoutin/LAN-Orangutan/internal/config"
)

const (
	switchIfNameOID            = "1.3.6.1.2.1.31.1.1.1.1"
	switchIfOperStatusOID      = "1.3.6.1.2.1.2.2.1.8"
	switchIfHighSpeedOID       = "1.3.6.1.2.1.31.1.1.1.15"
	switchIfDuplexOID          = "1.3.6.1.2.1.10.7.2.1.19"
	switchBridgePortIfIndexOID = "1.3.6.1.2.1.17.1.4.1.2"
	switchBridgeFDBPortOID     = "1.3.6.1.2.1.17.4.3.1.2"
	switchQBridgeFDBPortOID    = "1.3.6.1.2.1.17.7.1.2.2.1.2"
	switchPSEIfIndexOID        = "1.3.6.1.2.1.105.1.1.1.2"
	switchPSEPowerOID          = "1.3.6.1.2.1.105.1.1.1.10"
)

// SwitchConnection is a current FDB-to-interface match. Task 4 maps it to
// storage.SwitchConnection to avoid coupling the scanner and storage packages.
type SwitchConnection struct {
	MAC        string
	SwitchName string
	SwitchHost string
	Port       string
	VLAN       int
	LinkState  string
	LinkSpeed  int
	Duplex     string
	PoEWatts   *float64
	UpdatedAt  time.Time
}

type switchWalker interface {
	Walk(context.Context, string) ([]gosnmp.SnmpPDU, error)
	Close() error
}

// FetchSwitchConnections reads each relevant table at most once and resolves
// learned MAC addresses without issuing any SNMP write request.
func FetchSwitchConnections(ctx context.Context, cfg config.SwitchConfig, vlanByMAC map[string]int) ([]SwitchConnection, error) {
	w, err := newSNMPV3SwitchWalker(cfg)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	return fetchSwitchConnections(ctx, cfg, vlanByMAC, w)
}

func fetchSwitchConnections(ctx context.Context, cfg config.SwitchConfig, vlanByMAC map[string]int, w switchWalker) ([]SwitchConnection, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ifNames, err := walkStringTable(ctx, w, switchIfNameOID)
	if err != nil {
		return nil, switchWalkError(cfg.ID, "interface names")
	}
	bridgeToIf, err := walkIntTable(ctx, w, switchBridgePortIfIndexOID)
	if err != nil {
		return nil, switchWalkError(cfg.ID, "bridge port map")
	}
	qbridge, qbridgeErr := walkFDBTable(ctx, w, switchQBridgeFDBPortOID, true)
	bridge, bridgeErr := walkFDBTable(ctx, w, switchBridgeFDBPortOID, false)
	if qbridgeErr != nil && bridgeErr != nil {
		return nil, switchWalkError(cfg.ID, "forwarding table")
	}

	operStatus, _ := walkIntTable(ctx, w, switchIfOperStatusOID)
	highSpeed, _ := walkIntTable(ctx, w, switchIfHighSpeedOID)
	duplex, _ := walkIntTable(ctx, w, switchIfDuplexOID)
	poeWatts := walkPoEWatts(ctx, w)

	requestedVLAN := make(map[string]int, len(vlanByMAC))
	for mac, vlan := range vlanByMAC {
		requestedVLAN[normalizeSwitchMAC(mac)] = vlan
	}

	candidates := make(map[string]struct{})
	for key := range qbridge {
		candidates[key.mac] = struct{}{}
	}
	for key := range bridge {
		candidates[key.mac] = struct{}{}
	}
	macs := make([]string, 0, len(candidates))
	for mac := range candidates {
		macs = append(macs, mac)
	}
	sort.Strings(macs)

	now := time.Now()
	connections := make([]SwitchConnection, 0, len(macs))
	for _, mac := range macs {
		bridgePort, vlan, ok := resolveBridgePort(mac, requestedVLAN, qbridge, bridge)
		if !ok || bridgePort == 0 {
			continue
		}
		ifIndex := bridgeToIf[bridgePort]
		if ifIndex == 0 {
			continue
		}
		port := ifNames[ifIndex]
		if port == "" {
			continue
		}
		connection := SwitchConnection{
			MAC: mac, SwitchName: cfg.ID, SwitchHost: cfg.Host, Port: port, VLAN: vlan,
			LinkState: linkState(operStatus[ifIndex]), LinkSpeed: highSpeed[ifIndex], Duplex: duplexState(duplex[ifIndex]),
			UpdatedAt: now,
		}
		if watts, ok := poeWatts[ifIndex]; ok {
			connection.PoEWatts = &watts
		}
		connections = append(connections, connection)
	}
	return connections, nil
}

func switchWalkError(switchID, table string) error {
	return fmt.Errorf("switch %q: unable to read %s", switchID, table)
}

type fdbKey struct {
	mac  string
	vlan int
}

func resolveBridgePort(mac string, requestedVLAN map[string]int, qbridge map[fdbKey]int, bridge map[fdbKey]int) (int, int, bool) {
	if vlan, known := requestedVLAN[mac]; known {
		if port := qbridge[fdbKey{mac: mac, vlan: vlan}]; port != 0 {
			return port, vlan, true
		}
	} else {
		var port, vlan int
		for key, candidate := range qbridge {
			if key.mac != mac || candidate == 0 {
				continue
			}
			if port != 0 && port != candidate {
				port = 0
				break
			}
			port, vlan = candidate, key.vlan
		}
		if port != 0 {
			return port, vlan, true
		}
	}
	var bridgePorts []int
	for key, port := range bridge {
		if key.mac == mac {
			bridgePorts = append(bridgePorts, port)
		}
	}
	ports := uniqueNonZeroPorts(bridgePorts)
	if len(ports) == 1 {
		return ports[0], 0, true
	}
	return 0, 0, false
}

func walkStringTable(ctx context.Context, w switchWalker, oid string) (map[int]string, error) {
	pdus, err := w.Walk(ctx, oid)
	if err != nil {
		return nil, err
	}
	result := make(map[int]string, len(pdus))
	for _, pdu := range pdus {
		if index, ok := oidIndex(pdu.Name, oid, 1); ok {
			if value, ok := pdu.Value.(string); ok {
				result[index[0]] = value
			} else if value, ok := pdu.Value.([]byte); ok {
				result[index[0]] = string(value)
			}
		}
	}
	return result, nil
}

func walkIntTable(ctx context.Context, w switchWalker, oid string) (map[int]int, error) {
	pdus, err := w.Walk(ctx, oid)
	if err != nil {
		return nil, err
	}
	result := make(map[int]int, len(pdus))
	for _, pdu := range pdus {
		if index, ok := oidIndex(pdu.Name, oid, 1); ok {
			if value, ok := snmpInt(pdu.Value); ok {
				result[index[0]] = value
			}
		}
	}
	return result, nil
}

func walkFDBTable(ctx context.Context, w switchWalker, oid string, vlanAware bool) (map[fdbKey]int, error) {
	pdus, err := w.Walk(ctx, oid)
	if err != nil {
		return nil, err
	}
	result := make(map[fdbKey]int, len(pdus))
	for _, pdu := range pdus {
		count := 6
		if vlanAware {
			count = 7
		}
		index, ok := oidIndex(pdu.Name, oid, count)
		port, portOK := snmpInt(pdu.Value)
		if !ok || !portOK {
			continue
		}
		vlan := 0
		if vlanAware {
			vlan = index[0]
			index = index[1:]
		}
		result[fdbKey{mac: bytesMAC(index), vlan: vlan}] = port
	}
	return result, nil
}

func walkPoEWatts(ctx context.Context, w switchWalker) map[int]float64 {
	indices, err := w.Walk(ctx, switchPSEIfIndexOID)
	if err != nil {
		return nil
	}
	powers, err := w.Walk(ctx, switchPSEPowerOID)
	if err != nil {
		return nil
	}
	byPSE := make(map[string]int, len(indices))
	for _, pdu := range indices {
		if index, ok := oidIndex(pdu.Name, switchPSEIfIndexOID, 2); ok {
			if ifIndex, ok := snmpInt(pdu.Value); ok {
				byPSE[indexKey(index)] = ifIndex
			}
		}
	}
	result := make(map[int]float64, len(powers))
	for _, pdu := range powers {
		if index, ok := oidIndex(pdu.Name, switchPSEPowerOID, 2); ok {
			if watts, ok := snmpInt(pdu.Value); ok && byPSE[indexKey(index)] != 0 {
				result[byPSE[indexKey(index)]] = float64(watts)
			}
		}
	}
	return result
}

func oidIndex(name, root string, count int) ([]int, bool) {
	name = strings.TrimPrefix(name, ".")
	root = strings.TrimPrefix(root, ".")
	parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(name, root), "."), ".")
	if len(parts) != count || strings.Join(parts, ".") == name {
		return nil, false
	}
	index := make([]int, count)
	for i, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 || value > 255 && count > 1 {
			return nil, false
		}
		index[i] = value
	}
	return index, true
}

func snmpInt(value any) (int, bool) {
	switch value := value.(type) {
	case int:
		return value, true
	case uint:
		return int(value), true
	case int32:
		return int(value), true
	case uint32:
		return int(value), true
	case int64:
		return int(value), true
	case uint64:
		return int(value), value <= uint64(^uint(0)>>1)
	default:
		return 0, false
	}
}

func bytesMAC(index []int) string {
	parts := make([]string, len(index))
	for i, value := range index {
		parts[i] = fmt.Sprintf("%02x", value)
	}
	return strings.Join(parts, ":")
}

func normalizeSwitchMAC(mac string) string {
	mac = strings.ToLower(strings.TrimSpace(mac))
	mac = strings.NewReplacer("-", ":", ".", "", " ", "").Replace(mac)
	if len(mac) == 12 && !strings.Contains(mac, ":") {
		return strings.Join([]string{mac[0:2], mac[2:4], mac[4:6], mac[6:8], mac[8:10], mac[10:12]}, ":")
	}
	return mac
}

func uniqueNonZeroPorts(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port != 0 {
			seen[port] = struct{}{}
		}
	}
	result := make([]int, 0, len(seen))
	for port := range seen {
		result = append(result, port)
	}
	return result
}

func indexKey(index []int) string { return strconv.Itoa(index[0]) + "." + strconv.Itoa(index[1]) }

func linkState(value int) string {
	if value == 1 {
		return "up"
	}
	if value == 2 {
		return "down"
	}
	return ""
}
func duplexState(value int) string {
	if value == 3 {
		return "full"
	}
	if value == 2 {
		return "half"
	}
	return ""
}

type gosnmpSwitchWalker struct{ client *gosnmp.GoSNMP }

func newSNMPV3SwitchWalker(cfg config.SwitchConfig) (switchWalker, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	client := snmpV3Client(cfg)
	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("switch %q: unable to connect", cfg.ID)
	}
	return gosnmpSwitchWalker{client: client}, nil
}

func snmpV3Client(cfg config.SwitchConfig) *gosnmp.GoSNMP {
	privacyProtocol := gosnmp.DES
	if strings.EqualFold(cfg.PrivacyProtocol, "AES") {
		privacyProtocol = gosnmp.AES
	}
	return &gosnmp.GoSNMP{
		Target: cfg.Host, Port: uint16(cfg.Port), Version: gosnmp.Version3, Context: context.Background(), Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
		MsgFlags: gosnmp.AuthPriv, SecurityModel: gosnmp.UserSecurityModel,
		SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: cfg.Username, AuthenticationProtocol: gosnmp.SHA, PrivacyProtocol: privacyProtocol, AuthenticationPassphrase: cfg.AuthPassword, PrivacyPassphrase: cfg.PrivacyPassword},
	}
}

func (w gosnmpSwitchWalker) Walk(ctx context.Context, oid string) ([]gosnmp.SnmpPDU, error) {
	w.client.Context = ctx
	return w.client.BulkWalkAll(oid)
}
func (w gosnmpSwitchWalker) Close() error { return w.client.Close() }
