package notification

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

func TestFormatDeepScanCutoffSlackMessage(t *testing.T) {
	got := FormatDeepScanCutoffSlackMessage("Office", "10.20.0.0/24", 7, 3)
	for _, want := range []string{
		"Office", "10.20.0.0/24", "03:00-06:00 Eastern", "7 completed", "3 skipped",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("message %q does not contain %q", got, want)
		}
	}
}

func TestFormatRemoteScannerFailureSlackMessage(t *testing.T) {
	msg := FormatRemoteScannerFailureSlackMessage("opnsense (10.0.0.1)", "10.0.0.0/24", "nmap: not found", true)
	for _, want := range []string{
		"Remote Scanner Failure",
		"opnsense (10.0.0.1)",
		"10.0.0.0/24",
		"nmap: not found",
		"pkg install nmap",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not contain %q", msg, want)
		}
	}

	genericMsg := FormatRemoteScannerFailureSlackMessage("openwrt (10.5.5.1)", "10.5.5.0/24", "connection refused", false)
	for _, want := range []string{
		"Remote Scanner Failure",
		"openwrt (10.5.5.1)",
		"10.5.5.0/24",
		"connection refused",
		"SSH connectivity",
	} {
		if !strings.Contains(genericMsg, want) {
			t.Errorf("message %q does not contain %q", genericMsg, want)
		}
	}
}

func TestFormatRemoteScannerRecoverySlackMessage(t *testing.T) {
	msg := FormatRemoteScannerRecoverySlackMessage("opnsense (10.0.0.1)", "10.0.4.0/24")
	for _, want := range []string{
		"Remote Scanner Recovered",
		"opnsense (10.0.0.1)",
		"10.0.4.0/24",
		"succeeded",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not contain %q", msg, want)
		}
	}
}

func TestFormatRouterAPIFailureAndRecoverySlackMessage(t *testing.T) {
	msg := FormatRouterAPIFailureSlackMessage("OpenWrt", "10.5.5.1", "401 Unauthorized")
	for _, want := range []string{
		"Router API Failure",
		"OpenWrt",
		"10.5.5.1",
		"401 Unauthorized",
		"DHCP lease & host discovery failed",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("failure msg %q does not contain %q", msg, want)
		}
	}

	recovery := FormatRouterAPIRecoverySlackMessage("OpenWrt", "10.5.5.1")
	for _, want := range []string{
		"Router API Recovered",
		"OpenWrt",
		"10.5.5.1",
		"DHCP telemetry resumed",
	} {
		if !strings.Contains(recovery, want) {
			t.Errorf("recovery msg %q does not contain %q", recovery, want)
		}
	}
}

func TestFormatConsolidatedSlackMessageWithMoves(t *testing.T) {
	newDevs := []types.Device{
		{IP: "10.0.0.15", MAC: "aa:bb:cc:11:22:33", Hostname: "printer", Vendor: "HP"},
	}
	movedDevs := []types.DeviceMoveEvent{
		{
			MAC:            "aa:bb:cc:44:55:66",
			Hostname:       "laptop-roam",
			Label:          "Personal Laptop",
			OldIP:          "192.168.1.50",
			OldNetworkName: "Home LAN",
			NewIP:          "172.16.0.22",
			NewNetworkName: "Guest",
		},
	}
	msg := FormatConsolidatedSlackMessageWithMoves("Guest", "172.16.0.0/24", newDevs, nil, movedDevs)

	for _, want := range []string{
		"1 New Device(s) Discovered",
		"printer",
		"1 Device(s) Moved / Relocated",
		"Personal Laptop",
		"Home LAN",
		"192.168.1.50",
		"Guest",
		"172.16.0.22",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not contain %q", msg, want)
		}
	}
}

func TestValidateWebhookURL(t *testing.T) {
	valid := []string{
		"https://hooks.slack.com/services/T000/B000/XXXX",
		"http://example.com/webhook",
	}
	for _, u := range valid {
		if err := ValidateWebhookURL(u); err != nil {
			t.Errorf("ValidateWebhookURL(%q) unexpected error: %v", u, err)
		}
	}

	invalid := []string{
		"",
		"not-a-url",
		"file:///etc/passwd",
		"ftp://example.com/hook",
		"gopher://127.0.0.1:70/",
		"https://",
		"http://localhost/hook",
		"http://sub.localhost:8080/hook",
		"http://127.0.0.1/hook",
		"http://127.0.1.1:8080/hook",
		"http://[::1]/hook",
		"http://[::ffff:127.0.0.1]/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://10.0.0.1/hook",
		"http://172.16.0.1/hook",
		"http://192.168.1.1/hook",
		"http://0.0.0.0/hook",
		"http://[fc00::1]/hook",
		"http://[fe80::1]/hook",
	}
	for _, u := range invalid {
		err := ValidateWebhookURL(u)
		if err == nil {
			t.Errorf("ValidateWebhookURL(%q) = nil, want error", u)
		} else if !errors.Is(err, ErrInvalidWebhookURL) {
			t.Errorf("ValidateWebhookURL(%q) error %v should wrap ErrInvalidWebhookURL", u, err)
		}
	}
}

func TestSendSlackNotificationRejectsSSRFAndRedirects(t *testing.T) {
	// Public SendSlackNotification must reject loopback/metadata URLs before dialing.
	for _, target := range []string{
		"http://127.0.0.1:1/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://localhost:8080/hook",
		"file:///etc/passwd",
	} {
		err := SendSlackNotification(target, "test")
		if !errors.Is(err, ErrInvalidWebhookURL) {
			t.Errorf("SendSlackNotification(%q) = %v, want ErrInvalidWebhookURL", target, err)
		}
	}

	// Dial-time check must reject hostnames that resolve to private/loopback IPs (DNS rebinding).
	dialer := newWebhookDialer(func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	})
	_, err := dialer(context.Background(), "tcp", "rebind.example.com:443")
	if !errors.Is(err, ErrInvalidWebhookURL) {
		t.Fatalf("dialer on rebinding host = %v, want ErrInvalidWebhookURL", err)
	}

	// Redirects must be disabled and never followed.
	var targetHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/secret", http.StatusFound)
			return
		}
		if r.URL.Path == "/secret" {
			targetHits.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newWebhookHTTPClient(true)
	err = sendSlackNotificationWithClient(srv.URL+"/redirect", "hello", client, true)
	if err == nil {
		t.Fatal("expected redirect response to return an error, got nil")
	}
	if targetHits.Load() != 0 {
		t.Errorf("redirect target was requested %d times, want 0", targetHits.Load())
	}
}

func TestSendSlackNotification_SuccessAndErrorStatuses(t *testing.T) {
	var gotMethod, gotContentType, gotText string
	var statusCode atomic.Int32
	statusCode.Store(http.StatusOK)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		var payload map[string]string
		_ = json.Unmarshal(body, &payload)
		gotText = payload["text"]
		w.WriteHeader(int(statusCode.Load()))
	}))
	defer srv.Close()

	client := newWebhookHTTPClient(true)
	if err := sendSlackNotificationWithClient(srv.URL, "hello slack", client, true); err != nil {
		t.Fatalf("unexpected error on 200 OK: %v", err)
	}
	if gotMethod != http.MethodPost || gotContentType != "application/json" || gotText != "hello slack" {
		t.Fatalf("unexpected request: method=%q ct=%q text=%q", gotMethod, gotContentType, gotText)
	}

	statusCode.Store(http.StatusInternalServerError)
	err := sendSlackNotificationWithClient(srv.URL, "fail", client, true)
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected status 500 error, got %v", err)
	}
}

func TestFormatConsolidatedSlackMessage_SeenDevicesAndFallbacks(t *testing.T) {
	newDevs := []types.Device{
		{IP: "10.0.0.10", MAC: "00:11:22:33:44:01", CustomHostname: "custom-box"},
		{IP: "10.0.0.11", MAC: "00:11:22:33:44:02"}, // falls back to Unknown Device / Unknown
	}
	seenDevs := []types.Device{
		{IP: "10.0.0.20", MAC: "00:11:22:33:44:03", Label: "Home NAS", Vendor: "Synology"},
		{IP: "10.0.0.21", MAC: "00:11:22:33:44:04"}, // falls back to Unknown Device / Unknown
	}

	msg := FormatConsolidatedSlackMessage("Core", "10.0.0.0/24", newDevs, seenDevs)
	for _, want := range []string{
		"Network Sweep Report [Core]",
		"10.0.0.0/24",
		"2 New Device(s) Discovered",
		"custom-box",
		"Unknown Device",
		"_Vendor:_ Unknown",
		"2 Tracked Device(s) Online",
		"Home NAS",
		"Synology",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("FormatConsolidatedSlackMessage missing %q in:\n%s", want, msg)
		}
	}

	moved := []types.DeviceMoveEvent{
		{
			MAC:   "00:11:22:33:44:05",
			OldIP: "10.0.0.50",
			NewIP: "10.0.1.50",
		},
	}
	msgWithMoves := FormatConsolidatedSlackMessageWithMoves("Core", "10.0.0.0/24", newDevs, seenDevs, moved)
	for _, want := range []string{
		"2 Tracked Device(s) Online",
		"Home NAS",
		"1 Device(s) Moved / Relocated",
		"*Device* moved from Previous Network (`10.0.0.50`) ➔ New Network (`10.0.1.50`)",
	} {
		if !strings.Contains(msgWithMoves, want) {
			t.Errorf("FormatConsolidatedSlackMessageWithMoves missing %q in:\n%s", want, msgWithMoves)
		}
	}
}
