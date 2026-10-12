package logging

import (
	"strings"
	"testing"
)

func TestLogBuffer_AddAndQuery(t *testing.T) {
	buf := NewBuffer(5)

	buf.Add("info", "starting discovery sweep on 10.0.0.0/24")
	buf.Add("error", "service scan failed for 10.5.5.143: connection refused")
	buf.Add("info", "completed discovery sweep on 10.0.0.0/24")
	buf.Add("warn", "rate limited on 10.0.1.0/24")

	all := buf.GetEntries("", "", 10)
	if len(all) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(all))
	}
	// Newest first
	if all[0].Level != "warn" {
		t.Errorf("newest entry level = %q, want warn", all[0].Level)
	}

	// Filter by search query
	search143 := buf.GetEntries("10.5.5.143", "", 10)
	if len(search143) != 1 {
		t.Fatalf("expected 1 match for 10.5.5.143, got %d", len(search143))
	}
	if !strings.Contains(search143[0].Message, "connection refused") {
		t.Errorf("unexpected message: %s", search143[0].Message)
	}

	// Filter by level
	errorsOnly := buf.GetEntries("", "error", 10)
	if len(errorsOnly) != 1 || errorsOnly[0].Level != "error" {
		t.Fatalf("expected 1 error entry, got %+v", errorsOnly)
	}
}

func TestLogBuffer_WriterInference(t *testing.T) {
	buf := NewBuffer(10)
	_, _ = buf.Write([]byte("2026/10/12 08:00:00 [scan] starting discovery sweep on 10.5.5.0/24\n"))
	_, _ = buf.Write([]byte("2026/10/12 08:00:01 [scan] service scan failed for 10.5.5.143: connection refused\n"))

	entries := buf.GetEntries("", "", 10)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Level != "error" {
		t.Errorf("expected level 'error', got %q", entries[0].Level)
	}
	if entries[1].Level != "info" {
		t.Errorf("expected level 'info', got %q", entries[1].Level)
	}
}

func TestLogBuffer_CapacityEviction(t *testing.T) {
	buf := NewBuffer(3)
	buf.Add("info", "msg 1")
	buf.Add("info", "msg 2")
	buf.Add("info", "msg 3")
	buf.Add("info", "msg 4")

	entries := buf.GetEntries("", "", 10)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries after eviction, got %d", len(entries))
	}
	// Oldest ("msg 1") should have been evicted; newest ("msg 4") is first
	if entries[0].Message != "msg 4" {
		t.Errorf("expected newest 'msg 4', got %q", entries[0].Message)
	}
	if entries[2].Message != "msg 2" {
		t.Errorf("expected oldest remaining 'msg 2', got %q", entries[2].Message)
	}
}
