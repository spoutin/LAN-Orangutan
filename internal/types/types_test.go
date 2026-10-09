package types

import (
	"testing"
	"time"
)

func TestIsRecentUsesTwoScanIntervals(t *testing.T) {
	interval := time.Hour
	device := Device{LastSeen: time.Now().Add(-119 * time.Minute)}
	if !device.IsRecent(interval) {
		t.Fatal("device seen within two scan intervals is not recent")
	}
	device.LastSeen = time.Now().Add(-121 * time.Minute)
	if device.IsRecent(interval) {
		t.Fatal("device seen beyond two scan intervals is recent")
	}
}
