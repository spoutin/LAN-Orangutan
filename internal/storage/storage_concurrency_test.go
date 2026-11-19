package storage

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// TestConcurrentReadDuringMerge guards against the data race where a reader of
// GetDevices touches device fields while a scan merge mutates the same structs.
// It must stay race-clean: run the package with -race.
func TestConcurrentReadDuringMerge(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := mergeDevicesForTest(s, []types.Device{{IP: "10.0.0.1", Hostname: "a"}}); err != nil {
		t.Fatal(err)
	}

	const iterations = 2000
	var wg sync.WaitGroup

	// Reader: mimic the web handler reading fields after GetDevices returns.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			for _, d := range s.GetDevices() {
				_ = d.Hostname + d.MAC + d.Vendor
			}
		}
	}()

	// Writer: mimic a scan merging new data for the same IP.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = mergeDevicesForTest(s, []types.Device{{IP: "10.0.0.1", Hostname: "bbbbbbbb", MAC: "cc", Vendor: "dd"}})
		}
	}()

	wg.Wait()
}

func TestConcurrent_ProcessMissing_UpdateFields_ValidateToken(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "devices.json"), filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	now := time.Now()
	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("10.50.0.%d", i)
		mac := fmt.Sprintf("00:11:22:33:50:%02x", i)
		if err := s.UpdateDevice(&types.Device{
			IP:        ip,
			MAC:       mac,
			Hostname:  fmt.Sprintf("host-%d", i),
			FirstSeen: now.Add(-time.Hour),
			LastSeen:  now,
		}); err != nil {
			t.Fatalf("seed %s: %v", ip, err)
		}
	}

	rawToken := "orangutan_test_token_1234567890"
	if _, err := s.CreateAPIToken("ci-token", rawToken); err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	const workers = 6
	const iters = 25
	var wg sync.WaitGroup
	errCh := make(chan error, workers*iters)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				switch id % 3 {
				case 0:
					if _, err := s.ProcessMissingDevices([]string{"10.50.0.0/24"}, []string{"10.50.0.1"}, 5*time.Minute); err != nil {
						errCh <- fmt.Errorf("ProcessMissingDevices: %w", err)
					}
				case 1:
					lbl := fmt.Sprintf("lbl-%d-%d", id, i)
					if err := s.UpdateDeviceFields("10.50.0.1", &lbl, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil); err != nil {
						errCh <- fmt.Errorf("UpdateDeviceFields: %w", err)
					}
				case 2:
					ok, err := s.ValidateAndTouchAPIToken(rawToken)
					if err != nil || !ok {
						errCh <- fmt.Errorf("ValidateAndTouchAPIToken: ok=%v err=%v", ok, err)
					}
				}
			}
		}(w)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}
