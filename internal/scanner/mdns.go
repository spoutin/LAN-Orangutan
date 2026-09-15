package scanner

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// mDNS (multicast DNS / DNS-SD) passive discovery: ask the network what services
// it offers and listen to what devices announce, so they reveal themselves
// without a sweep. It is hand-rolled to keep the binary dependency-free.
//
// The query sets the unicast-response bit, so answers come back to our own
// ephemeral port. That avoids binding UDP 5353, which the host's own responder
// (avahi on Linux, mDNSResponder on macOS) already holds. Devices that only
// multicast their reply are missed; most common ones honour the unicast bit.

const (
	mdnsListenWindow = 2 * time.Second
	typePTR          = 12
	typeA            = 1
	typeAAAA         = 28
	typeSRV          = 33
)

var errMalformedDNS = errors.New("malformed dns message")

// mdnsServiceQueries are the service types worth asking about, keyed by the
// value people care about. A single PTR query for a service type usually brings
// back the whole chain (PTR, SRV and A) in one packet.
var mdnsServiceQueries = []string{
	"_services._dns-sd._udp.local", // enumerate offered service types
	"_ipp._tcp.local", "_ipps._tcp.local", "_printer._tcp.local",
	"_airplay._tcp.local", "_raop._tcp.local", "_googlecast._tcp.local",
	"_spotify-connect._tcp.local", "_sonos._tcp.local",
	"_hap._tcp.local", "_ssh._tcp.local", "_smb._tcp.local",
	"_afpovertcp._tcp.local", "_companion-link._tcp.local",
	"_apple-mobdev2._tcp.local", "_http._tcp.local", "_workstation._tcp.local",
}

// mdnsServiceTypes maps the leading label of a service type to a device type.
var mdnsServiceTypes = map[string]string{
	"_ipp": TypePrinter, "_ipps": TypePrinter, "_printer": TypePrinter,
	"_pdl-datastream": TypePrinter,
	"_airplay":        TypeMediaPlayer, "_raop": TypeMediaPlayer,
	"_googlecast": TypeMediaPlayer, "_spotify-connect": TypeMediaPlayer,
	"_sonos": TypeMediaPlayer,
	"_hap":   TypeIoT, "_homekit": TypeIoT, "_hue": TypeIoT,
	"_ssh": TypeServer, "_sftp-ssh": TypeServer, "_smb": TypeServer,
	"_afpovertcp": TypeServer, "_nfs": TypeServer,
	"_apple-mobdev2": TypePhone, "_companion-link": TypePhone,
}

type ptrEntry struct{ service, instance string }

// DiscoverMDNS finds devices that advertise themselves over mDNS, returning each
// with the friendly name it announces and, where a service type reveals it, a
// device type. These have no MAC (mDNS does not carry one); merging by IP folds
// them into whatever an IP scan found for the same address.
func (s *Scanner) DiscoverMDNS(ctx context.Context) []types.Device {
	packets := queryMDNS(ctx)

	aRecords := map[string]string{} // host name -> IP
	srv := map[string]string{}      // service instance -> target host
	var ptrs []ptrEntry             // service type -> instance

	for _, pkt := range packets {
		parseMDNSInto(pkt, aRecords, srv, &ptrs)
	}
	return buildDevicesFromMDNS(aRecords, srv, ptrs)
}

// buildDevicesFromMDNS turns the parsed records into devices: each host with an
// address becomes a device, named by what it announced and typed either from a
// service it offers or, failing that, from its name.
func buildDevicesFromMDNS(aRecords, srv map[string]string, ptrs []ptrEntry) []types.Device {
	// Resolve service type down to the host that answers for it.
	instanceType := map[string]string{}
	for _, p := range ptrs {
		if dt := mdnsTypeForService(p.service); dt != "" {
			instanceType[p.instance] = dt
		}
	}
	hostType := map[string]string{}
	for instance, host := range srv {
		if dt := instanceType[instance]; dt != "" {
			hostType[host] = dt
		}
	}

	devices := make([]types.Device, 0, len(aRecords))
	for host, ip := range aRecords {
		name := cleanMDNSName(host)
		dt := hostType[host]
		if dt == "" {
			dt = Classify("", name, nil) // fall back to name-based typing
		}
		devices = append(devices, types.Device{IP: ip, Hostname: name, Type: dt})
	}
	return devices
}

func cleanMDNSName(host string) string {
	name := strings.TrimSuffix(host, ".")
	name = strings.TrimSuffix(name, ".local")
	return name
}

func mdnsTypeForService(service string) string {
	label := service
	if i := strings.IndexByte(service, '.'); i >= 0 {
		label = service[:i]
	}
	return mdnsServiceTypes[label]
}

// queryMDNS sends the service queries and collects response packets for a short
// window. Best effort: any failure returns whatever was gathered so far.
func queryMDNS(ctx context.Context) [][]byte {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	for _, name := range mdnsServiceQueries {
		_, _ = conn.WriteToUDP(buildMDNSQuery(name, typePTR), dst)
	}

	_ = conn.SetReadDeadline(time.Now().Add(mdnsListenWindow))
	var packets [][]byte
	buf := make([]byte, 9000)
	for {
		if ctx.Err() != nil {
			break
		}
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // deadline reached
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		packets = append(packets, pkt)
	}
	return packets
}

// buildMDNSQuery builds a single-question query. The class carries the
// unicast-response (QU) bit so answers return to our port.
func buildMDNSQuery(name string, qtype uint16) []byte {
	buf := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0} // header, one question
	buf = append(buf, encodeDNSName(name)...)
	buf = append(buf, byte(qtype>>8), byte(qtype))
	buf = append(buf, 0x80, 0x01) // class IN, unicast-response bit set
	return buf
}

func encodeDNSName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0x00)
}

// parseMDNSInto parses one response packet, folding its A, AAAA, PTR and SRV
// records into the shared maps. It is defensive: any malformation stops parsing
// that packet without a panic.
func parseMDNSInto(msg []byte, aRecords, srv map[string]string, ptrs *[]ptrEntry) {
	if len(msg) < 12 {
		return
	}
	qd := int(msg[4])<<8 | int(msg[5])
	total := (int(msg[6])<<8 | int(msg[7])) + (int(msg[8])<<8 | int(msg[9])) + (int(msg[10])<<8 | int(msg[11]))

	off := 12
	for i := 0; i < qd; i++ {
		_, no, err := decodeDNSName(msg, off)
		if err != nil || no+4 > len(msg) {
			return
		}
		off = no + 4 // type + class
	}

	for i := 0; i < total; i++ {
		name, no, err := decodeDNSName(msg, off)
		if err != nil {
			return
		}
		off = no
		if off+10 > len(msg) {
			return
		}
		rtype := uint16(msg[off])<<8 | uint16(msg[off+1])
		rdlen := int(msg[off+8])<<8 | int(msg[off+9])
		off += 10
		if off+rdlen > len(msg) {
			return
		}
		rdata := msg[off : off+rdlen]

		switch rtype {
		case typeA:
			if len(rdata) == 4 {
				aRecords[name] = net.IP(rdata).String()
			}
		case typeAAAA:
			if len(rdata) == 16 {
				if _, ok := aRecords[name]; !ok { // prefer an IPv4 answer
					aRecords[name] = net.IP(rdata).String()
				}
			}
		case typePTR:
			if target, _, err := decodeDNSName(msg, off); err == nil {
				*ptrs = append(*ptrs, ptrEntry{service: name, instance: target})
			}
		case typeSRV:
			if rdlen > 6 {
				if target, _, err := decodeDNSName(msg, off+6); err == nil {
					srv[name] = target
				}
			}
		}
		off += rdlen
	}
}

// decodeDNSName reads a DNS name at off, following compression pointers with a
// jump limit so a malformed message cannot loop forever. It returns the name and
// the offset in the record stream immediately after the name.
func decodeDNSName(msg []byte, off int) (string, int, error) {
	var labels []string
	next := -1
	jumps := 0

	for {
		if off < 0 || off >= len(msg) {
			return "", 0, errMalformedDNS
		}
		b := msg[off]
		if b == 0x00 {
			off++
			break
		}
		if b&0xC0 == 0xC0 { // compression pointer
			if off+1 >= len(msg) {
				return "", 0, errMalformedDNS
			}
			if next == -1 {
				next = off + 2 // the record continues after the pointer
			}
			jumps++
			if jumps > 20 {
				return "", 0, errMalformedDNS
			}
			off = int(b&0x3F)<<8 | int(msg[off+1])
			continue
		}
		length := int(b)
		off++
		if off+length > len(msg) {
			return "", 0, errMalformedDNS
		}
		labels = append(labels, string(msg[off:off+length]))
		off += length
	}

	name := strings.Join(labels, ".")
	if next != -1 {
		return name, next, nil
	}
	return name, off, nil
}
