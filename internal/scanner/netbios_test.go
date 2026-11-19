package scanner

import "testing"

func TestBuildNodeStatusRequest(t *testing.T) {
	req := netbiosNodeStatusRequest
	// 12-byte header + 1 length + 32 encoded + 1 terminator + 2 type + 2 class.
	if len(req) != 50 {
		t.Fatalf("request length = %d, want 50", len(req))
	}
	if req[5] != 0x01 {
		t.Errorf("questions field = %d, want 1", req[5])
	}
	if req[12] != 0x20 {
		t.Errorf("name length = %#x, want 0x20", req[12])
	}
	// The wildcard "*" encodes to "CK" followed by 30 'A's.
	if got := string(req[13:15]); got != "CK" {
		t.Errorf("encoded name starts with %q, want \"CK\"", got)
	}
	// Type NBSTAT (0x0021), class IN (0x0001) at the tail.
	tail := req[len(req)-4:]
	if tail[0] != 0x00 || tail[1] != 0x21 || tail[2] != 0x00 || tail[3] != 0x01 {
		t.Errorf("tail = % x, want 00 21 00 01", tail)
	}
}

// buildNodeStatusResponse crafts a minimal but valid node status response
// advertising the given (name, suffix, group) entries.
func buildNodeStatusResponse(entries []struct {
	name   string
	suffix byte
	group  bool
}) []byte {
	resp := []byte{
		0x00, 0x00, // txid
		0x84, 0x00, // flags: response
		0x00, 0x00, // questions
		0x00, 0x01, // answers: 1
		0x00, 0x00, // authority
		0x00, 0x00, // additional
	}
	// Answer name: literal, echoing the query name (0x20 + 32 + 0x00).
	resp = append(resp, 0x20)
	resp = append(resp, []byte("CK")...)
	for i := 0; i < 30; i++ {
		resp = append(resp, 'A')
	}
	resp = append(resp, 0x00)
	// type, class, ttl, rdlength (rdlength value is not validated by the parser).
	resp = append(resp, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// name list
	resp = append(resp, byte(len(entries)))
	for _, e := range entries {
		nameField := make([]byte, 15)
		copy(nameField, e.name)
		for i := len(e.name); i < 15; i++ {
			nameField[i] = ' '
		}
		resp = append(resp, nameField...)
		resp = append(resp, e.suffix)
		var flags uint16
		if e.group {
			flags |= 0x8000
		}
		resp = append(resp, byte(flags>>8), byte(flags))
	}
	return resp
}

func TestParseNodeStatusName(t *testing.T) {
	// A typical Windows response: the domain/group name plus the workstation.
	resp := buildNodeStatusResponse([]struct {
		name   string
		suffix byte
		group  bool
	}{
		{"WORKGROUP", 0x00, true},     // group, must be ignored
		{"DESKTOP-AB12", 0x00, false}, // the workstation name we want
		{"DESKTOP-AB12", 0x20, false}, // server service, wrong suffix
	})
	got, err := parseNodeStatusName(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "DESKTOP-AB12" {
		t.Errorf("name = %q, want DESKTOP-AB12", got)
	}
}

func TestParseNodeStatusName_NoWorkstation(t *testing.T) {
	resp := buildNodeStatusResponse([]struct {
		name   string
		suffix byte
		group  bool
	}{
		{"WORKGROUP", 0x00, true}, // only a group name
	})
	if _, err := parseNodeStatusName(resp); err == nil {
		t.Error("expected an error when there is no unique workstation name")
	}
}

func TestParseNodeStatusName_ShortOrEmpty(t *testing.T) {
	if _, err := parseNodeStatusName([]byte{0x00, 0x01}); err == nil {
		t.Error("expected an error for a short response")
	}
	// A response with zero answers.
	noans := make([]byte, 12)
	if _, err := parseNodeStatusName(noans); err == nil {
		t.Error("expected an error when there are no answer records")
	}
}

func TestSanitizeNetBIOSName(t *testing.T) {
	if got := sanitizeNetBIOSName([]byte("MYPC           ")); got != "MYPC" {
		t.Errorf("padding not trimmed: %q", got)
	}
	if got := sanitizeNetBIOSName([]byte{'A', 0x01, 'B'}); got != "" {
		t.Errorf("control character not rejected: %q", got)
	}
	if got := sanitizeNetBIOSName([]byte("               ")); got != "" {
		t.Errorf("all-spaces should be empty, got %q", got)
	}
}

func TestParseNodeStatusName_TruncatedAndMultiLabelNoPanic(t *testing.T) {
	// Exactly 12 bytes with ancount = 1 previously panicked reading resp[12].
	headerOnly := []byte{
		0x00, 0x00, 0x84, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	}
	if _, err := parseNodeStatusName(headerOnly); err == nil {
		t.Error("expected error for 12-byte response with ancount=1")
	}

	// Truncated label claiming 32 bytes when none follow.
	truncLabel := append(append([]byte{}, headerOnly...), 0x20)
	if _, err := parseNodeStatusName(truncLabel); err == nil {
		t.Error("expected error for truncated label")
	}

	// Truncated compression pointer (only 1 byte).
	truncPtr := append(append([]byte{}, headerOnly...), 0xC0)
	if _, err := parseNodeStatusName(truncPtr); err == nil {
		t.Error("expected error for truncated compression pointer")
	}

	// Valid multi-label answer name followed by workstation entry.
	multiLabel := append([]byte{}, headerOnly...)
	multiLabel = append(multiLabel, 0x03, 'a', 'b', 'c', 0x02, 'd', 'e', 0x00)
	multiLabel = append(multiLabel, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	multiLabel = append(multiLabel, 0x01)
	multiLabel = append(multiLabel, []byte("HOST-MULTI     ")...)
	multiLabel = append(multiLabel, 0x00, 0x00, 0x00)

	got, err := parseNodeStatusName(multiLabel)
	if err != nil {
		t.Fatalf("parseNodeStatusName multi-label unexpected error: %v", err)
	}
	if got != "HOST-MULTI" {
		t.Errorf("got %q, want HOST-MULTI", got)
	}
}
