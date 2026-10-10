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

func TestIsOnlineUsesThreeIntervals(t *testing.T) {
	interval := 35 * time.Minute // 7 networks * 5 minutes
	device := Device{LastSeen: time.Now().Add(-100 * time.Minute)}
	if !device.IsOnline(interval) {
		t.Fatal("device seen within three cycle intervals is not online")
	}
	device.LastSeen = time.Now().Add(-106 * time.Minute)
	if device.IsOnline(interval) {
		t.Fatal("device seen beyond three cycle intervals is online")
	}
}
