package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/spoutin/LAN-Orangutan/internal/config"
)

const (
	ifNameOID            = "1.3.6.1.2.1.31.1.1.1.1"
	dot1dBasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2"
	dot1dTpFdbPort       = "1.3.6.1.2.1.17.4.3.1.2"
	dot1qTpFdbPort       = "1.3.6.1.2.1.17.7.1.2.2.1.2"
	optionalPoETable     = "optional-poe-table"
)

type fakeSwitchWalker struct {
	tables map[string][]gosnmp.SnmpPDU
	errs   map[string]error
	walks  *[]string
}

func (w fakeSwitchWalker) Walk(_ context.Context, oid string) ([]gosnmp.SnmpPDU, error) {
	if w.walks != nil {
		*w.walks = append(*w.walks, oid)
	}
	if err := w.errs[oid]; err != nil {
		return nil, err
	}
	return w.tables[oid], nil
}

func (fakeSwitchWalker) Close() error { return nil }

func pdu(oid string, value any) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Value: value}
}

func switchConfig() config.SwitchConfig {
	return config.SwitchConfig{
		ID: "switchy", Host: "10.0.0.2", Port: 161, Version: 3,
		Username: "monitor", SecurityLevel: "authPriv", AuthProtocol: "SHA", AuthPassword: "auth-secret",
		PrivacyProtocol: "AES", PrivacyPassword: "privacy-secret", TimeoutSeconds: 5,
	}
}

func TestSwitchResolvesPhysicalPortFromVLANForwardingTable(t *testing.T) {
	connections, err := fetchSwitchConnections(context.Background(), switchConfig(), map[string]int{"6C-4C-BC-29-E8-C1": 3}, fakeSwitchWalker{tables: map[string][]gosnmp.SnmpPDU{
		ifNameOID:            {pdu(ifNameOID+".71", "gi1/23")},
		dot1dBasePortIfIndex: {pdu(dot1dBasePortIfIndex+".71", 71)},
		dot1qTpFdbPort:       {pdu(dot1qTpFdbPort+".3.108.76.188.41.232.193", 71)},
	}})
	if err != nil {
		t.Fatalf("fetchSwitchConnections: %v", err)
	}
	if len(connections) != 1 {
		t.Fatalf("resolved %d connections, want 1", len(connections))
	}
	got := connections[0]
	if got.MAC != "6c:4c:bc:29:e8:c1" || got.Port != "gi1/23" || got.VLAN != 3 || got.SwitchName != "switchy" || got.SwitchHost != "10.0.0.2" {
		t.Fatalf("connection = %#v", got)
	}
}

func TestSwitchPrefersRequestedVLANOverOtherVLANForwardingEntries(t *testing.T) {
	connections, err := fetchSwitchConnections(context.Background(), switchConfig(), map[string]int{"6c:4c:bc:29:e8:c1": 3}, fakeSwitchWalker{tables: map[string][]gosnmp.SnmpPDU{
		ifNameOID:            {pdu(ifNameOID+".71", "gi1/23"), pdu(ifNameOID+".72", "gi1/24")},
		dot1dBasePortIfIndex: {pdu(dot1dBasePortIfIndex+".71", 71), pdu(dot1dBasePortIfIndex+".72", 72)},
		dot1qTpFdbPort: {
			pdu(dot1qTpFdbPort+".2.108.76.188.41.232.193", 72),
			pdu(dot1qTpFdbPort+".3.108.76.188.41.232.193", 71),
		},
	}})
	if err != nil {
		t.Fatalf("fetchSwitchConnections: %v", err)
	}
	if len(connections) != 1 || connections[0].Port != "gi1/23" || connections[0].VLAN != 3 {
		t.Fatalf("connections = %#v, want VLAN 3 gi1/23", connections)
	}
}

func TestSwitchIgnoresNonInventoryForwardingEntries(t *testing.T) {
	connections, err := fetchSwitchConnections(context.Background(), switchConfig(), map[string]int{"6c:4c:bc:29:e8:c1": 3}, fakeSwitchWalker{tables: map[string][]gosnmp.SnmpPDU{
		ifNameOID:            {pdu(ifNameOID+".71", "gi1/23"), pdu(ifNameOID+".72", "gi1/24")},
		dot1dBasePortIfIndex: {pdu(dot1dBasePortIfIndex+".71", 71), pdu(dot1dBasePortIfIndex+".72", 72)},
		dot1qTpFdbPort: {
			pdu(dot1qTpFdbPort+".3.108.76.188.41.232.193", 71),
			pdu(dot1qTpFdbPort+".3.0.17.34.51.68.85", 72),
		},
	}})
	if err != nil {
		t.Fatalf("fetchSwitchConnections: %v", err)
	}
	if len(connections) != 1 || connections[0].MAC != "6c:4c:bc:29:e8:c1" {
		t.Fatalf("connections = %#v, want only the inventory MAC", connections)
	}
}

func TestSwitchResolvesVLANAboveMACOctetRange(t *testing.T) {
	connections, err := fetchSwitchConnections(context.Background(), switchConfig(), map[string]int{"6c:4c:bc:29:e8:c1": 300}, fakeSwitchWalker{tables: map[string][]gosnmp.SnmpPDU{
		ifNameOID:            {pdu(ifNameOID+".71", "gi1/23")},
		dot1dBasePortIfIndex: {pdu(dot1dBasePortIfIndex+".71", 71)},
		dot1qTpFdbPort:       {pdu(dot1qTpFdbPort+".300.108.76.188.41.232.193", 71)},
	}})
	if err != nil {
		t.Fatalf("fetchSwitchConnections: %v", err)
	}
	if len(connections) != 1 || connections[0].VLAN != 300 || connections[0].Port != "gi1/23" {
		t.Fatalf("connections = %#v, want VLAN 300 gi1/23", connections)
	}
}

func TestSwitchRejectsInvalidMACOctets(t *testing.T) {
	connections, err := fetchSwitchConnections(context.Background(), switchConfig(), map[string]int{"6c:4c:bc:29:e8:c1": 0}, fakeSwitchWalker{tables: map[string][]gosnmp.SnmpPDU{
		ifNameOID:            {pdu(ifNameOID+".71", "gi1/23")},
		dot1dBasePortIfIndex: {pdu(dot1dBasePortIfIndex+".71", 71)},
		dot1qTpFdbPort:       {pdu(dot1qTpFdbPort+".300.256.76.188.41.232.193", 71)},
	}})
	if err != nil {
		t.Fatalf("fetchSwitchConnections: %v", err)
	}
	if len(connections) != 0 {
		t.Fatalf("connections = %#v, want invalid MAC entry ignored", connections)
	}
}

func TestSwitchFallsBackToBridgeFDBWhenQBridgeIsUnavailable(t *testing.T) {
	connections, err := fetchSwitchConnections(context.Background(), switchConfig(), map[string]int{"6c:4c:bc:29:e8:c1": 0}, fakeSwitchWalker{tables: map[string][]gosnmp.SnmpPDU{
		ifNameOID:            {pdu(ifNameOID+".71", "gi1/23")},
		dot1dBasePortIfIndex: {pdu(dot1dBasePortIfIndex+".71", 71)},
		dot1dTpFdbPort:       {pdu(dot1dTpFdbPort+".108.76.188.41.232.193", 71)},
	}, errs: map[string]error{dot1qTpFdbPort: errors.New("unsupported table")}})
	if err != nil {
		t.Fatalf("fetchSwitchConnections: %v", err)
	}
	if len(connections) != 1 || connections[0].Port != "gi1/23" || connections[0].VLAN != 0 {
		t.Fatalf("connections = %#v, want fallback gi1/23", connections)
	}
}

func TestSwitchIgnoresBridgePortZero(t *testing.T) {
	connections, err := fetchSwitchConnections(context.Background(), switchConfig(), map[string]int{"6c:4c:bc:29:e8:c1": 0}, fakeSwitchWalker{tables: map[string][]gosnmp.SnmpPDU{
		ifNameOID:      {pdu(ifNameOID+".71", "gi1/23")},
		dot1qTpFdbPort: {pdu(dot1qTpFdbPort+".3.108.76.188.41.232.193", 0)},
	}})
	if err != nil {
		t.Fatalf("fetchSwitchConnections: %v", err)
	}
	if len(connections) != 0 {
		t.Fatalf("connections = %#v, want no result for bridge port 0", connections)
	}
}

func TestSwitchRetainsPortChannelAndContinuesWithoutPoE(t *testing.T) {
	var walks []string
	connections, err := fetchSwitchConnections(context.Background(), switchConfig(), map[string]int{"6c:4c:bc:29:e8:c1": 0}, fakeSwitchWalker{tables: map[string][]gosnmp.SnmpPDU{
		ifNameOID:            {pdu(ifNameOID+".200", "Po2")},
		dot1dBasePortIfIndex: {pdu(dot1dBasePortIfIndex+".80", 200)},
		dot1dTpFdbPort:       {pdu(dot1dTpFdbPort+".108.76.188.41.232.193", 80)},
	}, errs: map[string]error{optionalPoETable: errors.New("unsupported table")}, walks: &walks})
	if err != nil {
		t.Fatalf("fetchSwitchConnections: %v", err)
	}
	if len(connections) != 1 || connections[0].Port != "Po2" || connections[0].PoEWatts != nil {
		t.Fatalf("connections = %#v, want port-channel without PoE", connections)
	}
	for _, oid := range walks {
		if strings.HasPrefix(oid, "1.3.6.1.2.1.105.") {
			t.Fatal("switch scanner must not poll an unavailable PoE watts table")
		}
	}
}

func TestSwitchClientUsesConfiguredAuthPrivProtocols(t *testing.T) {
	for _, privacy := range []struct {
		name string
		want gosnmp.SnmpV3PrivProtocol
	}{
		{name: "DES", want: gosnmp.DES},
		{name: "AES", want: gosnmp.AES},
	} {
		t.Run(privacy.name, func(t *testing.T) {
			cfg := switchConfig()
			cfg.PrivacyProtocol = privacy.name
			client := snmpV3Client(cfg)
			params, ok := client.SecurityParameters.(*gosnmp.UsmSecurityParameters)
			if !ok {
				t.Fatalf("SecurityParameters = %T, want UsmSecurityParameters", client.SecurityParameters)
			}
			if client.Version != gosnmp.Version3 || client.MsgFlags != gosnmp.AuthPriv || params.AuthenticationProtocol != gosnmp.SHA || params.PrivacyProtocol != privacy.want {
				t.Fatalf("client security = version %v, flags %v, auth %v, privacy %v", client.Version, client.MsgFlags, params.AuthenticationProtocol, params.PrivacyProtocol)
			}
		})
	}
}
