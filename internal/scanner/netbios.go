package scanner

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// netbiosTimeout bounds a single NetBIOS name query. A device on the LAN answers
// in milliseconds; one that is not listening should not stall the scan.
const netbiosTimeout = 500 * time.Millisecond

// netbiosNodeStatusRequest is the fixed "node status request" packet for the
// wildcard name "*", which asks a host to list its NetBIOS names. Windows
// machines answer it even with no reverse DNS entry, so it recovers a name a
// ping sweep alone would miss. It needs no elevated privileges (plain UDP).
var netbiosNodeStatusRequest = buildNodeStatusRequest()

func buildNodeStatusRequest() []byte {
	// The 16-byte NetBIOS name for a node status query is "*" followed by 15
	// null bytes, first-level encoded (each byte split into two nibbles, each
	// added to 'A'). 0x2A ('*') becomes "CK"; each 0x00 becomes "AA".
	encoded := "CK" + strings.Repeat("A", 30) // 32 characters

	buf := []byte{
		0x00, 0x00, // transaction id
		0x00, 0x00, // flags: standard query
		0x00, 0x01, // questions: 1
		0x00, 0x00, // answer records
		0x00, 0x00, // authority records
		0x00, 0x00, // additional records
		0x20, // question name length: 32
	}
	buf = append(buf, []byte(encoded)...)
	buf = append(buf,
		0x00,       // name terminator
		0x00, 0x21, // type: NBSTAT
		0x00, 0x01, // class: IN
	)
	return buf
}

// netbiosName asks a host at ip for its NetBIOS name. It returns "" on any
// timeout, error, or response without a usable workstation name.
func netbiosName(ctx context.Context, ip string) string {
	dialCtx, cancel := context.WithTimeout(ctx, netbiosTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "udp", net.JoinHostPort(ip, "137"))
	if err != nil {
		return ""
	}
	defer conn.Close()

	deadline := time.Now().Add(netbiosTimeout)
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(netbiosNodeStatusRequest); err != nil {
		return ""
	}

	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil {
		return ""
	}
	name, err := parseNodeStatusName(resp[:n])
	if err != nil {
		return ""
	}
	return name
}

// parseNodeStatusName extracts the machine's name from a NetBIOS node status
// response: the unique name carrying the workstation suffix (0x00).
func parseNodeStatusName(resp []byte) (string, error) {
	if len(resp) < 12 {
		return "", errors.New("short response")
	}
	ancount := int(resp[6])<<8 | int(resp[7])
	if ancount == 0 {
		return "", errors.New("no answer records")
	}

	// Skip the answer record's name, which is either a literal length-prefixed
	// name or a compression pointer (top two bits set).
	pos := 12
	if resp[pos]&0xC0 == 0xC0 {
		pos += 2
	} else {
		pos += 1 + int(resp[pos]) + 1 // length byte + encoded name + terminator
	}
	// Skip type(2) + class(2) + ttl(4) + rdlength(2).
	pos += 10
	if pos >= len(resp) {
		return "", errors.New("truncated before name list")
	}

	numNames := int(resp[pos])
	pos++
	for i := 0; i < numNames; i++ {
		if pos+18 > len(resp) {
			break
		}
		raw := resp[pos : pos+15]
		suffix := resp[pos+15]
		flags := uint16(resp[pos+16])<<8 | uint16(resp[pos+17])
		group := flags&0x8000 != 0

		// The workstation name is the unique (non-group) entry with suffix 0x00.
		if suffix == 0x00 && !group {
			if name := sanitizeNetBIOSName(raw); name != "" {
				return name, nil
			}
		}
		pos += 18
	}
	return "", errors.New("no workstation name")
}

// sanitizeNetBIOSName trims the padding NetBIOS uses and rejects a name with any
// non-printable byte, which would be a garbled or non-name entry.
func sanitizeNetBIOSName(raw []byte) string {
	s := strings.TrimRight(string(raw), " \x00")
	if s == "" {
		return ""
	}
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return ""
		}
	}
	return s
}

// fillWindowsNames looks up a NetBIOS name for every device that a scan left
// without a hostname, concurrently and with a bound. Windows machines commonly
// have no reverse DNS entry, so this recovers their names. A recovered name may
// also yield a better device type than the vendor alone.
//
// It always runs, not only under service detection: it is name resolution, the
// same category as the reverse DNS lookup the scan already does, and it only
// touches devices that have no name yet.
func fillWindowsNames(ctx context.Context, devices []types.Device) {
	sem := make(chan struct{}, serviceProbeConcurrency)
	var wg sync.WaitGroup

	for i := range devices {
		if devices[i].Hostname != "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(d *types.Device) {
			defer wg.Done()
			defer func() { <-sem }()

			name := netbiosName(ctx, d.IP)
			if name == "" {
				return
			}
			d.Hostname = name
			if t := Classify(d.Vendor, d.Hostname, nil); t != "" {
				d.Type = t
			}
		}(&devices[i])
	}

	wg.Wait()
}
