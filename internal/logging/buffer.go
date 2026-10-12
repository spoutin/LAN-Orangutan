package logging

import (
	"strings"
	"sync"
	"time"
)

// LogEntry represents a single timestamped log event
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"` // "info", "warn", "error"
	Message   string    `json:"message"`
}

// Buffer holds an in-memory ring buffer of recent log entries
type Buffer struct {
	mu       sync.RWMutex
	capacity int
	entries  []LogEntry
}

// GlobalBuffer is the system-wide in-memory log buffer
var GlobalBuffer = NewBuffer(1000)

// NewBuffer creates a new in-memory log buffer with specified capacity
func NewBuffer(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = 1000
	}
	return &Buffer{
		capacity: capacity,
		entries:  make([]LogEntry, 0, capacity),
	}
}

// Add appends a log entry to the buffer, evicting oldest if capacity is reached
func (b *Buffer) Add(level, message string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
	}
	if len(b.entries) >= b.capacity {
		b.entries = b.entries[1:]
	}
	b.entries = append(b.entries, entry)
}

// Write implements io.Writer so the buffer can capture output from standard log package
func (b *Buffer) Write(p []byte) (n int, err error) {
	line := strings.TrimSpace(string(p))
	if line != "" {
		level := "info"
		lower := strings.ToLower(line)
		if strings.Contains(lower, "failed") || strings.Contains(lower, "error") || strings.Contains(lower, "fatal") {
			level = "error"
		} else if strings.Contains(lower, "warn") || strings.Contains(lower, "warning") || strings.Contains(lower, "skipped") {
			level = "warn"
		}
		b.Add(level, line)
	}
	return len(p), nil
}

// GetEntries returns log entries matching query and level, newest first
func (b *Buffer) GetEntries(q, level string, limit int) []LogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if limit <= 0 || limit > len(b.entries) {
		limit = len(b.entries)
	}

	q = strings.ToLower(strings.TrimSpace(q))
	level = strings.ToLower(strings.TrimSpace(level))

	var matches []LogEntry
	for i := len(b.entries) - 1; i >= 0; i-- {
		e := b.entries[i]
		if level != "" && level != "all" {
			if level == "error" && e.Level != "error" {
				continue
			}
			if level == "warn" && e.Level != "warn" && e.Level != "error" {
				continue
			}
		}
		if q != "" && !strings.Contains(strings.ToLower(e.Message), q) {
			continue
		}
		matches = append(matches, e)
		if len(matches) >= limit {
			break
		}
	}
	return matches
}
