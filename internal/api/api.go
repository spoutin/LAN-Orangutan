// Package api implements the REST API endpoints
package api

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/logging"
	"github.com/spoutin/LAN-Orangutan/internal/network"
	"github.com/spoutin/LAN-Orangutan/internal/notification"
	"github.com/spoutin/LAN-Orangutan/internal/remotescan"
	"github.com/spoutin/LAN-Orangutan/internal/scanner"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// Handler handles API requests
type Handler struct {
	store   *storage.Storage
	cfg     *config.Config
	scanner *scanner.Scanner
	// fetchSwitchConnections and sibling discovery/router hooks are injectable so
	// scan-pipeline tests do not hit live networks, SNMP devices, or routers.
	fetchSwitchConnections func(context.Context, config.SwitchConfig, map[string]int) ([]scanner.SwitchConnection, error)
	fetchUniFiClients      func(context.Context, config.UniFiConfig) ([]types.Device, error)
	fetchOPNsenseNetFlow   func(context.Context, config.OPNsenseConfig) (map[string]*types.NetFlowDeviceStats, error)
	fetchOpenWrtNlbwmon    func(context.Context, config.OpenWrtConfig) (map[string]*types.NetFlowDeviceStats, error)
	fetchOpenWrtDHCP       func(context.Context, config.OpenWrtConfig) ([]types.Device, []types.Device, error)
	fetchOPNsenseDHCP      func(context.Context, config.OPNsenseConfig) ([]types.Device, []types.Device, []types.Device, error)
	discoverIPv6           func(context.Context) []types.Device
	discoverMDNS           func(context.Context) []types.Device
	enrichWithServices     func(context.Context, []types.Device)
	sendSlackNotification  func(string, string) error
	trafficCollector       *TrafficCollector

	// jobMu guards job, which holds the most recent background scan. Only one
	// scan runs at a time.
	jobMu sync.Mutex
	job   *scanJob

	// scanCtx is the parent of every scan job's context, so cancelling it at
	// shutdown stops any scan in flight. scanWG tracks the running scan
	// goroutines and bgWG tracks background loops and async notifications so
	// shutdown can drain everything cleanly before closing storage.
	closeOnce   sync.Once
	closeCtx    context.Context
	closeCancel context.CancelFunc
	scanCtx     context.Context
	scanWG      sync.WaitGroup
	bgWG        sync.WaitGroup
	nightlyMu   sync.Mutex
	now         func() time.Time

	alertMu        sync.Mutex
	failedGateways map[string]bool

	muxOnce sync.Once
	mux     *http.ServeMux
}

// NewHandler creates a new API handler
func NewHandler(store *storage.Storage, cfg *config.Config) *Handler {
	s := scanner.New(cfg.Scanning.MinScanInterval, cfg.Scanning.EnableServiceDetection, cfg.Scanning.EnablePortScan, cfg.Scanning.PortScanRange)
	if cfg.RemoteScanners.Enable {
		s.SetRemoteRunner(remotescan.NewRunner(cfg.RemoteScanners))
	}
	closeCtx, closeCancel := context.WithCancel(context.Background())
	h := &Handler{
		store:                  store,
		cfg:                    cfg,
		scanner:                s,
		closeCtx:               closeCtx,
		closeCancel:            closeCancel,
		scanCtx:                closeCtx,
		fetchSwitchConnections: scanner.FetchSwitchConnections,
		fetchUniFiClients:      scanner.FetchUniFiClients,
		fetchOPNsenseNetFlow:   scanner.FetchOPNsenseNetFlow,
		fetchOpenWrtNlbwmon:    scanner.FetchOpenWrtNlbwmon,
		fetchOpenWrtDHCP:       scanner.FetchOpenWrtDHCP,
		fetchOPNsenseDHCP:      scanner.FetchOPNsenseDHCP,
		discoverIPv6:           s.DiscoverIPv6,
		discoverMDNS:           s.DiscoverMDNS,
		enrichWithServices:     scanner.EnrichWithServices,
		sendSlackNotification:  notification.SendSlackNotification,
		now:                    time.Now,
		failedGateways:         make(map[string]bool),
		trafficCollector:       NewTrafficCollector(store, cfg),
	}
	h.mux = h.routes()
	return h
}

// SetScanContext sets the parent context for all scan jobs. Cancelling it stops
// any scan in flight, so call it with the server's shutdown context before
// starting the server.
func (h *Handler) SetScanContext(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	if h.closeCtx == nil {
		h.scanCtx = ctx
		return
	}
	mergedCtx, cancel := context.WithCancel(ctx)
	context.AfterFunc(h.closeCtx, cancel)
	h.scanCtx = mergedCtx
}

// bgContext derives a context for background loops that cancels when either ctx
// or Handler.Close() fires.
func (h *Handler) bgContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	if h.closeCtx != nil {
		stop := context.AfterFunc(h.closeCtx, cancel)
		return runCtx, func() {
			stop()
			cancel()
		}
	}
	return runCtx, cancel
}

// WaitForScans blocks until any running scan or background goroutine has
// returned. Call it at shutdown, after the scan context has been cancelled, so
// a scan or background loop is not left half-written before closing storage.
func (h *Handler) WaitForScans() {
	h.scanWG.Wait()
	h.bgWG.Wait()
}

// Close cancels background loops, closes any remote SSH connections, and waits
// for scan and background goroutines to drain cleanly.
func (h *Handler) Close() error {
	h.closeOnce.Do(func() {
		if h.closeCancel != nil {
			h.closeCancel()
		}
	})
	var closeErr error
	if r := h.scanner.GetRemoteRunner(); r != nil {
		if closer, ok := r.(interface{ Close() error }); ok {
			closeErr = closer.Close()
		}
	}
	h.scanWG.Wait()
	h.bgWG.Wait()
	return closeErr
}

// gatewayForTarget returns the remote gateway name responsible for target, or "local" if not offloaded.
func (h *Handler) gatewayForTarget(target string) string {
	if r := h.scanner.GetRemoteRunner(); r != nil && r.HasRemoteScannerForTarget(target) {
		return r.GetGatewayForTarget(target)
	}
	return "local"
}

const (
	maxJSONBodyBytes = 1 << 20 // 1 MiB
	maxLogsLimit     = 1000
)

// decodeJSONBody enforces a strict size limit on JSON request bodies and
// writes a 413 or 400 error response if decoding fails.
func (h *Handler) decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			h.error(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		h.error(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	return true
}

type statusProbeWriter struct {
	header http.Header
	code   int
}

func (p *statusProbeWriter) Header() http.Header         { return p.header }
func (p *statusProbeWriter) WriteHeader(statusCode int)  { p.code = statusCode }
func (p *statusProbeWriter) Write(b []byte) (int, error) { return len(b), nil }

func (h *Handler) ensureMux() *http.ServeMux {
	h.muxOnce.Do(func() {
		if h.mux == nil {
			h.mux = h.routes()
		}
	})
	return h.mux
}

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/devices", h.handleDevices)
	mux.HandleFunc("POST /api/devices/clear", h.handleDevicesClear)
	mux.HandleFunc("GET /api/devices/clear", h.handleMethodNotAllowed)
	mux.HandleFunc("PUT /api/devices/clear", h.handleMethodNotAllowed)
	mux.HandleFunc("DELETE /api/devices/clear", h.handleMethodNotAllowed)
	mux.HandleFunc("GET /api/devices/{ip}/traffic", h.handleDeviceTraffic)
	mux.HandleFunc("POST /api/devices/{ip}/facts", h.handleDeviceFacts)
	mux.HandleFunc("PUT /api/devices/{ip}/facts", h.handleDeviceFacts)
	mux.HandleFunc("POST /api/devices/{ip}/deep-scan", h.handleDeviceDeepScan)
	mux.HandleFunc("GET /api/devices/{ip}", h.handleDevice)
	mux.HandleFunc("POST /api/devices/{ip}", h.handleDevice)
	mux.HandleFunc("PUT /api/devices/{ip}", h.handleDevice)
	mux.HandleFunc("DELETE /api/devices/{ip}", h.handleDevice)
	mux.HandleFunc("GET /api/device", h.handleDevice)
	mux.HandleFunc("POST /api/device", h.handleDevice)
	mux.HandleFunc("PUT /api/device", h.handleDevice)
	mux.HandleFunc("DELETE /api/device", h.handleDevice)
	mux.HandleFunc("GET /api/networks", h.handleNetworks)
	mux.HandleFunc("POST /api/scan", h.handleScan)
	mux.HandleFunc("POST /api/scan/start", h.handleScanStart)
	mux.HandleFunc("GET /api/scan/progress", h.handleScanProgress)
	mux.HandleFunc("POST /api/scan/cancel", h.handleScanCancel)
	mux.HandleFunc("GET /api/scan/continuous", h.handleScanContinuous)
	mux.HandleFunc("POST /api/scan/continuous", h.handleScanContinuous)
	mux.HandleFunc("GET /api/tailscale", h.handleTailscale)
	mux.HandleFunc("POST /api/tailscale/connect", h.handleTailscaleConnect)
	mux.HandleFunc("POST /api/tailscale/disconnect", h.handleTailscaleDisconnect)
	mux.HandleFunc("GET /api/stats", h.handleStats)
	mux.HandleFunc("GET /api/status", h.handleStatus)
	mux.HandleFunc("GET /api/settings", h.handleSettings)
	mux.HandleFunc("POST /api/settings", h.handleSettings)
	mux.HandleFunc("GET /api/settings/notifications", h.handleSettingsNotifications)
	mux.HandleFunc("POST /api/settings/notifications", h.handleSettingsNotifications)
	mux.HandleFunc("POST /api/settings/notifications/test", h.handleSettingsNotificationsTest)
	mux.HandleFunc("GET /api/scans/history", h.handleScansHistory)
	mux.HandleFunc("GET /api/scans/events", h.handleScansEvents)
	mux.HandleFunc("GET /api/logs", h.handleLogs)
	mux.HandleFunc("GET /api/tokens", h.handleTokens)
	mux.HandleFunc("POST /api/tokens", h.handleTokens)
	mux.HandleFunc("DELETE /api/tokens/{id}", h.handleTokenDelete)
	mux.HandleFunc("POST /api/tokens/{id}", h.handleTokenDelete)
	return mux
}

func (h *Handler) handleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	h.error(w, http.StatusMethodNotAllowed, "method not allowed")
}

// ServeHTTP implements http.Handler
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set JSON content type for all API responses
	w.Header().Set("Content-Type", "application/json")

	// CSRF protection for mutating requests
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
		contentType := r.Header.Get("Content-Type")
		xRequestedWith := r.Header.Get("X-Requested-With")

		mediaType, _, err := mime.ParseMediaType(contentType)
		isJSON := err == nil && mediaType == "application/json"
		if !isJSON && xRequestedWith != "XMLHttpRequest" {
			h.error(w, http.StatusForbidden, "CSRF protection: requires Content-Type: application/json or X-Requested-With header")
			return
		}
	}

	req := r
	if len(r.URL.Path) > len("/api/") && strings.HasSuffix(r.URL.Path, "/") {
		rCopy := *r
		urlCopy := *r.URL
		urlCopy.Path = strings.TrimSuffix(urlCopy.Path, "/")
		rCopy.URL = &urlCopy
		req = &rCopy
	}

	mux := h.ensureMux()
	handler, pattern := mux.Handler(req)
	if pattern == "" {
		probe := &statusProbeWriter{header: make(http.Header)}
		handler.ServeHTTP(probe, req)
		if probe.code == http.StatusMethodNotAllowed {
			if allow := probe.header.Get("Allow"); allow != "" {
				w.Header().Set("Allow", allow)
			}
			h.error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h.error(w, http.StatusNotFound, "endpoint not found")
		return
	}
	mux.ServeHTTP(w, req)
}

func (h *Handler) handleDeviceDeepScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ip := r.PathValue("ip")
	device := h.store.GetDevice(ip)
	if device == nil {
		h.error(w, http.StatusNotFound, "device not found")
		return
	}
	h.jobMu.Lock()
	defer h.jobMu.Unlock()
	if h.job != nil && h.job.isRunning() {
		h.job.adopt()
		h.success(w, h.job.snapshot(h.cfg, h.store))
		return
	}
	networks, err := h.resolveScanTargets("all")
	if err != nil {
		h.error(w, http.StatusBadRequest, err.Error())
		return
	}
	cidr := findSubnetForIP(device.IP, networks)
	if cidr == "" {
		h.error(w, http.StatusBadRequest, "device is not in a configured scan network")
		return
	}
	h.job = h.startScanJobWithDeadline([]string{cidr}, false, scanModeDeep, time.Time{}, nil, []types.Device{*device})
	h.success(w, h.job.snapshot(h.cfg, h.store))
}

// handleDeviceFacts updates device OS, version, and optional MAC facts by MAC or IP address
func (h *Handler) handleDeviceFacts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	target := r.PathValue("ip")

	var req struct {
		MAC       string `json:"mac"`
		Hostname  string `json:"hostname"`
		OS        string `json:"os"`
		OSVersion string `json:"os_version"`
		OSFamily  string `json:"os_family"`
	}
	if !h.decodeJSONBody(w, r, &req) {
		return
	}

	trimmedTarget := strings.TrimSpace(target)
	var dev *types.Device
	var isIP bool

	if net.ParseIP(trimmedTarget) != nil {
		isIP = true
		dev = h.store.GetDevice(trimmedTarget)
	} else {
		cleanMAC := storage.NormalizeMAC(trimmedTarget)
		dev = h.store.GetDeviceByMAC(cleanMAC)
	}

	if dev == nil {
		if isIP {
			h.error(w, http.StatusNotFound, fmt.Sprintf("device with IP %s not found", target))
		} else {
			h.error(w, http.StatusNotFound, fmt.Sprintf("device with MAC %s not found", target))
		}
		return
	}

	// Update MAC address if provided in request body
	if req.MAC != "" {
		newMAC := storage.NormalizeMAC(req.MAC)
		if newMAC != "" {
			vendor := scanner.GetMACVendor(newMAC)
			_ = h.store.UpdateDeviceMAC(dev.IP, newMAC, vendor)
		}
	}

	// Update hostname if blank
	if req.Hostname != "" {
		_ = h.store.UpdateDeviceHostnameIfBlank(trimmedTarget, req.Hostname, isIP)
	}

	// Update custom OS facts
	if isIP {
		if err := h.store.UpdateDeviceCustomOSByIP(dev.IP, req.OS, req.OSVersion, req.OSFamily); err != nil {
			h.error(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else {
		cleanMAC := storage.NormalizeMAC(trimmedTarget)
		if err := h.store.UpdateDeviceCustomOS(cleanMAC, req.OS, req.OSVersion, req.OSFamily); err != nil {
			h.error(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	updated := h.store.GetDevice(dev.IP)
	h.success(w, updated)
}

// handleTokens handles GET and POST for /api/tokens
func (h *Handler) handleTokens(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tokens, err := h.store.ListAPITokens()
		if err != nil {
			h.error(w, http.StatusInternalServerError, err.Error())
			return
		}
		if tokens == nil {
			tokens = []*types.APIToken{}
		}
		h.success(w, tokens)

	case http.MethodPost:
		var req struct {
			Name string `json:"name"`
		}
		if !h.decodeJSONBody(w, r, &req) {
			return
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = "API Token"
		}

		// Generate random token string
		secretBytes := make([]byte, 24)
		if _, err := rand.Read(secretBytes); err != nil {
			h.error(w, http.StatusInternalServerError, "failed to generate random token")
			return
		}
		rawToken := "ora_" + hex.EncodeToString(secretBytes)

		tokenRec, err := h.store.CreateAPIToken(name, rawToken)
		if err != nil {
			h.error(w, http.StatusInternalServerError, err.Error())
			return
		}

		h.success(w, map[string]interface{}{
			"id":           tokenRec.ID,
			"name":         tokenRec.Name,
			"token_prefix": tokenRec.TokenPrefix,
			"created_at":   tokenRec.CreatedAt,
			"token":        rawToken,
		})

	default:
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleTokenDelete handles DELETE /api/tokens/{id}
func (h *Handler) handleTokenDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		h.error(w, http.StatusBadRequest, "invalid token ID")
		return
	}
	if err := h.store.DeleteAPIToken(id); err != nil {
		h.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.success(w, map[string]string{"message": "token deleted"})
}

// handleDevices handles GET /api/devices
func (h *Handler) handleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	devices := h.store.GetDevices()

	if r.URL.Query().Get("format") == "csv" {
		h.writeDevicesCSV(w, devices)
		return
	}

	h.success(w, devices)
}

// writeDevicesCSV sends the device list as a downloadable CSV file.
//
// The columns match `orangutan export`, so a file saved from the browser and
// one saved from the command line are interchangeable.
func (h *Handler) writeDevicesCSV(w http.ResponseWriter, devices map[string]*types.Device) {
	sorted := make([]*types.Device, 0, len(devices))
	for _, d := range devices {
		sorted = append(sorted, d)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].IP < sorted[j].IP })

	// Set before writing: headers are ignored once the body has started.
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="devices.csv"`)

	cw := csv.NewWriter(w)
	defer cw.Flush()

	_ = cw.Write([]string{
		"IP Address", "MAC Address", "Hostname", "Vendor", "Label",
		"Notes", "Group", "First Seen", "Last Seen", "Status",
	})

	scanInterval := time.Duration(h.cfg.Scanning.ScanInterval) * time.Second
	for _, d := range sorted {
		status := "offline"
		if d.IsOnline(scanInterval) {
			status = "online"
		}
		_ = cw.Write(types.SanitizeCSVRow([]string{
			d.IP, d.MAC, d.Hostname, scanner.ResolveVendor(d.Vendor, d.MAC), d.Label, d.Notes, d.Group,
			d.FirstSeen.Format("2006-01-02 15:04:05"),
			d.LastSeen.Format("2006-01-02 15:04:05"),
			status,
		}))
	}
}

// handleDevice handles GET/POST/DELETE /api/device
func (h *Handler) handleDevice(w http.ResponseWriter, r *http.Request) {
	pathIP := r.PathValue("ip")
	switch r.Method {
	case http.MethodGet:
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			ip = pathIP
		}
		if ip == "" {
			h.error(w, http.StatusBadRequest, "ip parameter required")
			return
		}
		device := h.store.GetDevice(ip)
		if device == nil {
			h.error(w, http.StatusNotFound, "device not found")
			return
		}
		h.success(w, device)

	case http.MethodPost, http.MethodPut:
		var req struct {
			IP              string  `json:"ip"`
			MAC             *string `json:"mac"`
			Label           *string `json:"label"`
			Notes           *string `json:"notes"`
			Group           *string `json:"group"`
			CustomHostname  *string `json:"custom_hostname"`
			CustomWebURL    *string `json:"custom_web_url"`
			CustomType      *string `json:"custom_type"`
			LinkedMAC       *string `json:"linked_mac"`
			NotifyOnSeen    *bool   `json:"notify_on_seen"`
			AnsibleManaged  *bool   `json:"ansible_managed"`
			SSHOverride     *string `json:"ssh_override"`
			SSHOverridePort *int    `json:"ssh_override_port"`
			CustomOS        *string `json:"custom_os"`
			CustomOSVersion *string `json:"custom_os_version"`
			CustomOSFamily  *string `json:"custom_os_family"`
		}
		if !h.decodeJSONBody(w, r, &req) {
			return
		}

		// Get IP from query or path if not in body
		ip := req.IP
		if ip == "" {
			ip = r.URL.Query().Get("ip")
		}
		if ip == "" {
			ip = pathIP
		}
		if ip == "" {
			h.error(w, http.StatusBadRequest, "ip required")
			return
		}

		if req.SSHOverride != nil {
			if *req.SSHOverride != types.SSHOverrideAuto && *req.SSHOverride != types.SSHOverrideAvailable && *req.SSHOverride != types.SSHOverrideUnavailable {
				h.error(w, http.StatusBadRequest, "ssh_override must be auto, available, or unavailable")
				return
			}
			if *req.SSHOverride == types.SSHOverrideAvailable && (req.SSHOverridePort == nil || *req.SSHOverridePort < 1 || *req.SSHOverridePort > 65535) {
				h.error(w, http.StatusBadRequest, "ssh_override_port must be between 1 and 65535 when SSH is available")
				return
			}
		}

		var resolvedVendor *string
		if req.MAC != nil {
			cleanMAC := storage.NormalizeMAC(*req.MAC)
			req.MAC = &cleanMAC
			if cleanMAC != "" {
				v := scanner.GetMACVendor(cleanMAC)
				if v != "" {
					resolvedVendor = &v
				}
			}
		}

		if err := h.store.UpdateDeviceFields(ip, req.Label, req.Notes, req.Group, req.CustomHostname, req.CustomWebURL, req.CustomType, req.LinkedMAC, req.SSHOverride, req.NotifyOnSeen, req.AnsibleManaged, req.SSHOverridePort, req.CustomOS, req.CustomOSVersion, req.CustomOSFamily, req.MAC, resolvedVendor); err != nil {
			h.error(w, http.StatusNotFound, err.Error())
			return
		}
		h.success(w, map[string]string{"message": "device updated"})

	case http.MethodDelete:
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			ip = pathIP
		}
		if ip == "" {
			h.error(w, http.StatusBadRequest, "ip parameter required")
			return
		}
		if err := h.store.DeleteDevice(ip); err != nil {
			h.error(w, http.StatusNotFound, err.Error())
			return
		}
		h.success(w, map[string]string{"message": "device deleted"})

	default:
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleNetworks handles GET /api/networks
func (h *Handler) handleNetworks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	networks, err := network.DetectNetworks()
	if err != nil {
		h.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	compiled := network.WithConfigured(networks, network.Filter{Configured: h.cfg.Scanning.Networks, Excluded: h.cfg.Scanning.ExcludeNetworks, OnlyConfigured: h.cfg.Scanning.OnlyConfiguredNetworks})

	// Override FriendlyName using our custom network names configuration
	for i, n := range compiled {
		if name, ok := h.cfg.Scanning.NetworkNames[n.CIDR]; ok {
			compiled[i].FriendlyName = name
		}
	}

	h.success(w, compiled)
}

// extendWriteDeadline widens the per-request HTTP write deadline for long-running
// synchronous endpoints without relaxing the server's default WriteTimeout.
func extendWriteDeadline(w http.ResponseWriter, d time.Duration) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(d))
}

// handleScan handles POST /api/scan
func (h *Handler) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	cidr := r.URL.Query().Get("network")
	if cidr == "" {
		h.error(w, http.StatusBadRequest, "network parameter required")
		return
	}
	// "all" scans every detected network, matching the CLI's behaviour
	if strings.EqualFold(cidr, "all") {
		extendWriteDeadline(w, 15*time.Minute)
		h.scanAllNetworks(w, r)
		return
	}

	// Validate CIDR
	if !network.ValidateCIDR(cidr) {
		h.error(w, http.StatusBadRequest, "invalid CIDR format")
		return
	}

	// Check rate limit
	lastScan := h.store.GetLastScan(cidr)
	canScan, waitTime := h.scanner.CheckRateLimit(lastScan)
	if !canScan {
		h.error(w, http.StatusTooManyRequests,
			"rate limited, wait "+waitTime.Round(time.Second).String())
		return
	}

	extendWriteDeadline(w, 6*time.Minute)

	result, err := h.executeNetworkSweep(r.Context(), cidr)
	if err != nil {
		h.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.success(w, result)
}

// networkScanSummary reports the outcome of scanning a single network as part
// of a scan-all request.
type networkScanSummary struct {
	Network        string  `json:"network"`
	NetworkName    string  `json:"network_name,omitempty"`
	Status         string  `json:"status"` // scanned, skipped or failed
	DeviceCount    int     `json:"device_count"`
	Duration       float64 `json:"duration"`
	Error          string  `json:"error,omitempty"`
	IsSupplemental bool    `json:"is_supplemental,omitempty"`
}

// scanAllResult aggregates the per-network outcomes of a scan-all request.
type scanAllResult struct {
	Success      bool                 `json:"success"`
	Networks     []networkScanSummary `json:"networks"`
	NetworkCount int                  `json:"network_count"`
	ScannedCount int                  `json:"scanned_count"`
	DeviceCount  int                  `json:"device_count"`
	Timestamp    time.Time            `json:"timestamp"`
}

// scanAllNetworks scans every detected network. A network that is rate limited
// or fails is reported in the response rather than failing the whole request,
// so one bad interface cannot mask results from the others.
func (h *Handler) scanAllNetworks(w http.ResponseWriter, r *http.Request) {
	detected, err := network.DetectNetworks()
	if err != nil {
		h.error(w, http.StatusInternalServerError, "failed to detect networks: "+err.Error())
		return
	}
	detected = network.WithConfigured(detected, network.Filter{Configured: h.cfg.Scanning.Networks, Excluded: h.cfg.Scanning.ExcludeNetworks, OnlyConfigured: h.cfg.Scanning.OnlyConfiguredNetworks})
	if len(detected) == 0 {
		h.error(w, http.StatusNotFound, "no networks detected")
		return
	}

	result := scanAllResult{
		Networks:     make([]networkScanSummary, 0, len(detected)),
		NetworkCount: len(detected),
		Timestamp:    time.Now(),
	}

	for _, n := range detected {
		summary := networkScanSummary{Network: n.CIDR}

		lastScan := h.store.GetLastScan(n.CIDR)
		if canScan, waitTime := h.scanner.CheckRateLimit(lastScan); !canScan {
			summary.Status = "skipped"
			summary.Error = "rate limited, wait " + waitTime.Round(time.Second).String()
			result.Networks = append(result.Networks, summary)
			continue
		}

		scan, err := h.executeNetworkSweep(r.Context(), n.CIDR)
		if err != nil {
			summary.Status = "failed"
			summary.Error = err.Error()
			result.Networks = append(result.Networks, summary)
			continue
		}

		summary.Status = "scanned"
		summary.DeviceCount = scan.DeviceCount
		summary.Duration = scan.Duration
		result.Networks = append(result.Networks, summary)
		result.ScannedCount++
		result.DeviceCount += scan.DeviceCount
	}

	// Supplemental sources, once for the whole request. IPv6 neighbors (an IPv6
	// subnet cannot be swept) enrich devices by MAC rather than being listed per
	// address, so they go through MergeIPv6Neighbors. mDNS announcements merge as
	// an ordinary secondary source.
	discoverIPv6 := h.discoverIPv6
	if discoverIPv6 == nil && h.scanner != nil {
		discoverIPv6 = h.scanner.DiscoverIPv6
	}
	if discoverIPv6 != nil {
		if ipv6 := discoverIPv6(r.Context()); len(ipv6) > 0 {
			if err := h.store.MergeIPv6Neighbors(ipv6); err == nil {
				result.Networks = append(result.Networks, networkScanSummary{
					Network: "IPv6 neighbors", Status: "scanned", DeviceCount: len(ipv6), IsSupplemental: true,
				})
			}
		}
	}
	discoverMDNS := h.discoverMDNS
	if discoverMDNS == nil && h.scanner != nil {
		discoverMDNS = h.scanner.DiscoverMDNS
	}
	if discoverMDNS != nil {
		if mdns := discoverMDNS(r.Context()); len(mdns) > 0 {
			if err := h.store.MergeSupplemental(mdns); err == nil {
				result.Networks = append(result.Networks, networkScanSummary{
					Network: "mDNS", Status: "scanned", DeviceCount: len(mdns), IsSupplemental: true,
				})
			}
		}
	}

	// Only a request where nothing at all could be scanned counts as a failure.
	result.Success = result.ScannedCount > 0
	h.success(w, result)
}

// resolveScanTargets turns the network parameter into the list of networks to
// scan. "all" expands to every detected network, matching the CLI.
func (h *Handler) resolveScanTargets(cidr string) ([]string, error) {
	if !strings.EqualFold(cidr, "all") {
		if !network.ValidateCIDR(cidr) {
			return nil, errors.New("invalid CIDR format")
		}
		return []string{cidr}, nil
	}

	detected, err := network.DetectNetworks()
	if err != nil {
		return nil, errors.New("failed to detect networks: " + err.Error())
	}
	detected = network.WithConfigured(detected, network.Filter{Configured: h.cfg.Scanning.Networks, Excluded: h.cfg.Scanning.ExcludeNetworks, OnlyConfigured: h.cfg.Scanning.OnlyConfiguredNetworks})
	if len(detected) == 0 {
		return nil, errors.New("no networks detected")
	}

	networks := make([]string, 0, len(detected))
	for _, n := range detected {
		networks = append(networks, n.CIDR)
	}
	return networks, nil
}

// handleScanStart handles POST /api/scan/start, which begins a scan in the
// background and returns immediately. Scanning a large network takes minutes,
// so the UI starts a job and polls /api/scan/progress rather than holding a
// request open for the duration.
func (h *Handler) handleScanStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	cidr := r.URL.Query().Get("network")
	if cidr == "" {
		h.error(w, http.StatusBadRequest, "network parameter required")
		return
	}
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = scanModeQuick
	}
	if mode != scanModeQuick && mode != scanModeDeep && mode != scanModeBoth {
		h.error(w, http.StatusBadRequest, "mode must be quick, deep, or both")
		return
	}

	networks, err := h.resolveScanTargets(cidr)
	if err != nil {
		h.error(w, http.StatusBadRequest, err.Error())
		return
	}

	h.jobMu.Lock()
	defer h.jobMu.Unlock()

	if h.job != nil && h.job.isRunning() {
		// A scan is already running, most often the background scanner. Rather
		// than rejecting the user's click with a 409, attach to that scan and
		// adopt it as user-initiated so the progress overlay follows it and the
		// user gets the fresh results it is already producing.
		h.job.adopt()
		h.success(w, h.job.snapshot(h.cfg, h.store))
		return
	}

	h.job = h.startScanJob(networks, false, mode)
	h.success(w, h.job.snapshot(h.cfg, h.store))
}

// handleScanProgress handles GET /api/scan/progress.
func (h *Handler) handleScanProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	h.jobMu.Lock()
	job := h.job
	h.jobMu.Unlock()

	if job == nil {
		h.success(w, scanProgress{Status: "idle", Percent: percentUnknown})
		return
	}
	h.success(w, job.snapshot(h.cfg, h.store))
}

// handleScanCancel handles POST /api/scan/cancel.
func (h *Handler) handleScanCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	h.jobMu.Lock()
	job := h.job
	h.jobMu.Unlock()

	if job == nil || !job.isRunning() {
		h.error(w, http.StatusConflict, "no scan is running")
		return
	}

	job.cancel()
	h.success(w, map[string]string{"message": "scan cancelled"})
}

// handleScanContinuous reports (GET) or sets (POST) whether the server keeps
// re-scanning the networks on its own. The choice is persisted so it survives a
// restart, letting a user scan once and sit on the snapshot without editing the
// config or restarting.
func (h *Handler) handleScanContinuous(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.success(w, map[string]bool{"enabled": h.store.ContinuousScanEnabled(h.cfg.Scanning.ContinuousScan)})
	case http.MethodPost:
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if !h.decodeJSONBody(w, r, &body) {
			return
		}
		if err := h.store.SetContinuousScan(body.Enabled); err != nil {
			h.error(w, http.StatusInternalServerError, "could not save setting: "+err.Error())
			return
		}
		// Turning it on kicks off a scan right away, so the user sees fresh
		// results instead of waiting up to a full interval for the next tick.
		// Runs in the background; the one-scan-at-a-time guard and the
		// per-network rate limit keep it from piling up or hammering.
		if body.Enabled {
			h.bgWG.Add(1)
			go func() {
				defer h.bgWG.Done()
				if h.scanCtx != nil && h.scanCtx.Err() != nil {
					return
				}
				h.runBackgroundScan()
			}()
		}
		h.success(w, map[string]bool{"enabled": body.Enabled})
	default:
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// executeNetworkSweep runs a single-CIDR discovery sweep, updates error/alert
// state, enriches gateway MACs, merges devices, handles notifications (or
// accumulates onto an active scan job), and records scan timing metadata.
func (h *Handler) executeNetworkSweep(ctx context.Context, cidr string) (*types.ScanResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	result, err := h.scanner.Scan(ctx, cidr)
	if err != nil {
		h.notifyRemoteScannerFailure(cidr, cidr, err)
		h.store.SetNetworkScanError(cidr, err.Error())
		return nil, err
	}
	if !result.Success {
		h.notifyRemoteScannerFailure(cidr, cidr, errors.New(result.Error))
		h.store.SetNetworkScanError(cidr, result.Error)
		return nil, errors.New(result.Error)
	}
	h.notifyRemoteScannerSuccess(cidr, cidr)
	h.store.ClearNetworkScanError(cidr)

	// Enrich any self-scanned gateway host (which remote Nmap returns with no MAC)
	h.enrichGatewayMACs(cidr, result.Devices)

	newDevs, seenDevs, movedDevs, err := h.store.MergeDevicesWithMoves(result.Devices)
	if err != nil {
		return nil, errors.New("failed to save devices")
	}

	h.jobMu.Lock()
	activeJob := h.job
	h.jobMu.Unlock()

	if activeJob != nil && activeJob.isRunning() {
		var newIPs []string
		for _, d := range newDevs {
			newIPs = append(newIPs, d.IP)
		}
		var seenIPs []string
		for _, d := range seenDevs {
			seenIPs = append(seenIPs, d.IP)
		}
		activeJob.accumulate(newIPs, seenIPs)
	} else {
		h.dispatchNotificationsWithMoves(cidr, newDevs, seenDevs, movedDevs)
	}

	h.store.SetLastScan(cidr, time.Now())
	// Remember how long this took so the next scan of the same network can show
	// a progress estimate based on real measured time.
	h.store.SetLastDuration(cidr, result.Duration)

	return result, nil
}

// scanNetwork scans a single network and merges the results into storage.
func (h *Handler) scanNetwork(ctx context.Context, cidr string) (*types.ScanResult, error) {
	return h.executeNetworkSweep(ctx, cidr)
}

// enrichGatewayMACs populates known gateway MAC addresses for self-scanned edge router hosts
// that report no MAC address because local ARP does not produce Ethernet frames for self-traffic.
func (h *Handler) enrichGatewayMACs(cidr string, devices []types.Device) {
	if h.cfg == nil || len(devices) == 0 {
		return
	}
	var gwHost string
	if sc, ok := h.cfg.RemoteScanners.FindScannerForCIDR(cidr); ok && sc != nil && sc.Host != "" {
		gwHost = sc.Host
	}

	for i := range devices {
		if devices[i].MAC != "" {
			continue
		}
		// Check if this device IP matches the remote scanner's host IP
		if gwHost != "" && devices[i].IP == gwHost {
			if existing := h.store.GetDevice(gwHost); existing != nil && existing.MAC != "" {
				devices[i].MAC = existing.MAC
				if devices[i].Vendor == "" {
					devices[i].Vendor = existing.Vendor
				}
				continue
			}
		}
		// Also check if any existing device record in store holds devices[i].IP in its ips attachments
		if existing := h.store.GetDevice(devices[i].IP); existing != nil && existing.MAC != "" {
			devices[i].MAC = existing.MAC
			if devices[i].Vendor == "" {
				devices[i].Vendor = existing.Vendor
			}
		}
	}
}

// handleTailscale handles GET /api/tailscale
func (h *Handler) handleTailscale(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	status := network.GetTailscaleStatus()
	h.success(w, status)
}

// handleTailscaleConnect handles POST /api/tailscale/connect.
//
// It is behind the same authentication and CSRF checks as every other mutating
// endpoint. A successful call may still report that the machine needs to sign
// in, in which case the response carries a login URL.
func (h *Handler) handleTailscaleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	result, err := network.ConnectTailscale()
	if err != nil {
		h.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	h.success(w, result)
}

// handleTailscaleDisconnect handles POST /api/tailscale/disconnect.
func (h *Handler) handleTailscaleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if err := network.DisconnectTailscale(); err != nil {
		h.error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	h.success(w, map[string]string{"message": "disconnected"})
}

// handleStats handles GET /api/stats
func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	stats := h.store.GetStats()
	h.success(w, stats)
}

// handleStatus handles GET /api/status
func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	status := map[string]interface{}{
		"server":    "running",
		"timestamp": time.Now().Format(time.RFC3339),
		"config": map[string]interface{}{
			"port":        h.cfg.Server.Port,
			"bind":        h.cfg.Server.BindAddress,
			"api_enabled": h.cfg.Server.EnableAPI,
		},
	}
	h.success(w, status)
}

// handleSettings handles GET/POST /api/settings
func (h *Handler) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settings := map[string]interface{}{
			"theme":          h.cfg.UI.Theme,
			"scan_interval":  h.cfg.Scanning.ScanInterval,
			"retention_days": h.cfg.Storage.RetentionDays,
		}
		h.success(w, settings)

	case http.MethodPost:
		// Settings update would require config file write
		// For now, return not implemented
		h.error(w, http.StatusNotImplemented, "settings update not yet implemented")

	default:
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// success sends a successful JSON response
func (h *Handler) success(w http.ResponseWriter, data interface{}) {
	resp := types.APIResponse{
		Success: true,
		Data:    data,
	}
	json.NewEncoder(w).Encode(resp)
}

// error sends an error JSON response
func (h *Handler) error(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	resp := types.APIResponse{
		Success: false,
		Error:   message,
	}
	json.NewEncoder(w).Encode(resp)
}

// handleScansHistory handles GET /api/scans/history
func (h *Handler) handleScansHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	dateStr := r.URL.Query().Get("date")
	scanType := r.URL.Query().Get("type")
	query := r.URL.Query().Get("q")

	history, err := h.store.GetScanHistoryFiltered(dateStr, scanType, query)
	if err != nil {
		h.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.success(w, history)
}

// handleScansEvents handles GET /api/scans/events
func (h *Handler) handleScansEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	mac := r.URL.Query().Get("mac")
	ip := r.URL.Query().Get("ip")
	q := r.URL.Query().Get("q")

	events, err := h.store.GetPresenceEventsFiltered(mac, ip, q)
	if err != nil {
		h.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.success(w, events)
}

// handleDeviceTraffic handles GET /api/devices/{mac_or_ip}/traffic
func (h *Handler) handleDeviceTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	identifier := strings.TrimSpace(r.PathValue("ip"))
	if identifier == "" {
		h.error(w, http.StatusBadRequest, "device identifier required")
		return
	}

	mac := identifier
	// If it contains a dot, resolve device by IP to get its MAC
	if strings.Contains(identifier, ".") {
		dev := h.store.GetDevice(identifier)
		if dev != nil && dev.MAC != "" {
			mac = dev.MAC
		}
	}

	timeRange := r.URL.Query().Get("range")
	if timeRange != "1h" && timeRange != "24h" && timeRange != "7d" {
		timeRange = "24h"
	}

	series, err := h.store.GetDeviceTrafficSeries(mac, timeRange)
	if err != nil {
		h.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	if series != nil {
		isOpnsenseNet := len(h.cfg.OPNsense.Networks) > 0 && network.ContainsIP(h.cfg.OPNsense.Networks, series.IP)
		isOpenWrtNet := false
		for _, wrt := range h.cfg.AllOpenWrts() {
			if wrt.Enable && wrt.TrafficMonitoring && len(wrt.Networks) > 0 && network.ContainsIP(wrt.Networks, series.IP) {
				isOpenWrtNet = true
				break
			}
		}

		if isOpenWrtNet {
			// Device is on an OpenWrt network: strictly OpenWrt telemetry
			if series.Source == "opnsense" {
				series.Source = "openwrt"
			}
		} else if isOpnsenseNet {
			// Device is on an OPNsense network: strictly OPNsense telemetry
			if series.Source == "openwrt" {
				series.Source = "opnsense"
			}
		} else {
			// Device is outside all configured firewall networks: zero out WAN telemetry
			series.Current.WanRxRateBytesSec = 0
			series.Current.WanTxRateBytesSec = 0
			series.Current.WanRxBytesTotal = 0
			series.Current.WanTxBytesTotal = 0
			if series.Source == "opnsense" || series.Source == "openwrt" {
				series.Source = ""
			}
		}
	}

	h.success(w, series)
}

// handleLogs handles GET /api/logs
func (h *Handler) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	q := r.URL.Query().Get("q")
	level := r.URL.Query().Get("level")
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
		if limit > maxLogsLimit {
			limit = maxLogsLimit
		}
	}
	entries := logging.GlobalBuffer.GetEntries(q, level, limit)
	h.success(w, entries)
}

// handleDevicesClear handles POST /api/devices/clear
func (h *Handler) handleDevicesClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Network string `json:"network"`
	}
	if !h.decodeJSONBody(w, r, &req) {
		return
	}

	affected, err := h.store.ClearDevices(req.Network)
	if err != nil {
		h.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.success(w, map[string]interface{}{
		"success":  true,
		"affected": affected,
	})
}

// handleSettingsNotifications handles GET and POST for /api/settings/notifications
func (h *Handler) handleSettingsNotifications(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := h.store.GetNetworkNotifications()
		if err != nil {
			h.error(w, http.StatusInternalServerError, err.Error())
			return
		}
		h.success(w, list)

	case http.MethodPost:
		var req struct {
			NetworkCIDR  string `json:"network_cidr"`
			SlackWebhook string `json:"slack_webhook"`
			Enabled      bool   `json:"enabled"`
		}
		if !h.decodeJSONBody(w, r, &req) {
			return
		}
		if req.NetworkCIDR == "" {
			h.error(w, http.StatusBadRequest, "network_cidr required")
			return
		}
		if req.SlackWebhook != "" {
			if err := notification.ValidateWebhookURL(req.SlackWebhook); err != nil {
				h.error(w, http.StatusBadRequest, err.Error())
				return
			}
		}

		if err := h.store.SaveNetworkNotification(req.NetworkCIDR, req.SlackWebhook, req.Enabled); err != nil {
			h.error(w, http.StatusInternalServerError, err.Error())
			return
		}
		h.success(w, map[string]string{"message": "notification setting saved"})

	default:
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleSettingsNotificationsTest handles POST for /api/settings/notifications/test
func (h *Handler) handleSettingsNotificationsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		SlackWebhook string `json:"slack_webhook"`
	}
	if !h.decodeJSONBody(w, r, &req) {
		return
	}
	if req.SlackWebhook == "" {
		h.error(w, http.StatusBadRequest, "slack_webhook required")
		return
	}
	if err := notification.ValidateWebhookURL(req.SlackWebhook); err != nil {
		h.error(w, http.StatusBadRequest, err.Error())
		return
	}

	err := h.sendSlackNotification(req.SlackWebhook, "🔔 *LAN-Orangutan Webhook Test!* Webhook verified successfully.")
	if err != nil {
		if errors.Is(err, notification.ErrInvalidWebhookURL) {
			h.error(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("webhook test notification failed: %v", err)
		h.error(w, http.StatusBadGateway, "failed to send test notification")
		return
	}

	h.success(w, map[string]string{"message": "test notification sent successfully"})
}

// dispatchNotifications posts a consolidated network sweep report to Slack
func (h *Handler) dispatchNotifications(cidr string, newDevices []types.Device, seenDevices []types.Device) {
	h.dispatchNotificationsWithMoves(cidr, newDevices, seenDevices, nil)
}

func (h *Handler) dispatchNotificationsWithMoves(cidr string, newDevices []types.Device, seenDevices []types.Device, movedDevices []types.DeviceMoveEvent) {
	if len(newDevices) == 0 && len(seenDevices) == 0 && len(movedDevices) == 0 {
		return
	}

	// Fetch notification config for this CIDR
	n, err := h.store.GetNetworkNotification(cidr)
	if err != nil || n == nil || n.SlackWebhook == "" || !n.Enabled {
		return
	}

	// Format beautiful message
	networkName := cidr
	if name, ok := h.cfg.Scanning.NetworkNames[cidr]; ok && name != "" {
		networkName = name
	}

	text := notification.FormatConsolidatedSlackMessageWithMoves(networkName, cidr, newDevices, seenDevices, movedDevices)

	// Post to Slack asynchronously
	sendFn := h.sendSlackNotification
	if sendFn == nil {
		sendFn = notification.SendSlackNotification
	}
	h.bgWG.Add(1)
	go func(webhook, msg string) {
		defer h.bgWG.Done()
		_ = sendFn(webhook, msg)
	}(n.SlackWebhook, text)
}

func (h *Handler) getEffectiveSlackWebhook(networkCIDR string) string {
	if networkCIDR != "" {
		conf, err := h.store.GetNetworkNotification(networkCIDR)
		if err == nil && conf != nil && conf.Enabled && conf.SlackWebhook != "" {
			return conf.SlackWebhook
		}
	}
	all, err := h.store.GetNetworkNotifications()
	if err == nil {
		for _, n := range all {
			if n.Enabled && n.SlackWebhook != "" {
				return n.SlackWebhook
			}
		}
	}
	return ""
}

func (h *Handler) getEffectiveSlackWebhooks(networkCIDRs []string) []string {
	var webhooks []string
	seen := make(map[string]bool)
	for _, cidr := range networkCIDRs {
		conf, sErr := h.store.GetNetworkNotification(cidr)
		if sErr == nil && conf != nil && conf.Enabled && conf.SlackWebhook != "" && !seen[conf.SlackWebhook] {
			seen[conf.SlackWebhook] = true
			webhooks = append(webhooks, conf.SlackWebhook)
		}
	}
	if len(webhooks) == 0 {
		if fallback := h.getEffectiveSlackWebhook(""); fallback != "" {
			webhooks = append(webhooks, fallback)
		}
	}
	return webhooks
}

func (h *Handler) notifyRemoteScannerFailure(networkCIDR string, target string, err error) {
	if err == nil {
		return
	}
	var rErr *remotescan.RemoteScannerError
	var gateway string
	var isMissingNmap bool
	var errorMsg string

	if errors.As(err, &rErr) {
		gateway = rErr.Gateway
		isMissingNmap = rErr.IsMissingNmap
		errorMsg = rErr.Err.Error()
	} else if r := h.scanner.GetRemoteRunner(); r != nil && r.HasRemoteScannerForTarget(target) {
		gateway = r.GetGatewayForTarget(target)
		errorMsg = err.Error()
		if strings.Contains(strings.ToLower(errorMsg), "not found") || strings.Contains(strings.ToLower(errorMsg), "no such file") {
			isMissingNmap = true
		}
	} else {
		gateway = "scanner"
		errorMsg = err.Error()
		if strings.Contains(strings.ToLower(errorMsg), "not found") || strings.Contains(strings.ToLower(errorMsg), "no such file") {
			isMissingNmap = true
		}
	}

	debounceKey := fmt.Sprintf("%s:%s", gateway, networkCIDR)
	h.alertMu.Lock()
	if h.failedGateways == nil {
		h.failedGateways = make(map[string]bool)
	}
	if h.failedGateways[debounceKey] {
		// Already alerted for this failure incident; suppress repeats until recovery
		h.alertMu.Unlock()
		return
	}
	h.failedGateways[debounceKey] = true
	h.alertMu.Unlock()

	webhook := h.getEffectiveSlackWebhook(networkCIDR)
	if webhook == "" {
		return
	}

	msg := notification.FormatRemoteScannerFailureSlackMessage(gateway, target, errorMsg, isMissingNmap)
	_ = h.sendSlackNotification(webhook, msg)
}

func (h *Handler) notifyRemoteScannerSuccess(networkCIDR string, target string) {
	var gateway string
	if r := h.scanner.GetRemoteRunner(); r != nil && r.HasRemoteScannerForTarget(target) {
		gateway = r.GetGatewayForTarget(target)
	} else {
		gateway = "scanner"
	}

	debounceKey := fmt.Sprintf("%s:%s", gateway, networkCIDR)
	h.alertMu.Lock()
	if h.failedGateways == nil || !h.failedGateways[debounceKey] {
		h.alertMu.Unlock()
		return
	}
	delete(h.failedGateways, debounceKey)
	h.alertMu.Unlock()

	webhook := h.getEffectiveSlackWebhook(networkCIDR)
	if webhook == "" {
		return
	}

	msg := notification.FormatRemoteScannerRecoverySlackMessage(gateway, target)
	_ = h.sendSlackNotification(webhook, msg)
}

func (h *Handler) notifyRouterAPIFailure(routerType string, routerID string, networkCIDRs []string, err error) {
	if err == nil {
		return
	}
	debounceKey := fmt.Sprintf("router:%s:%s", routerType, routerID)
	h.alertMu.Lock()
	if h.failedGateways == nil {
		h.failedGateways = make(map[string]bool)
	}
	if h.failedGateways[debounceKey] {
		h.alertMu.Unlock()
		return
	}
	h.failedGateways[debounceKey] = true
	h.alertMu.Unlock()

	webhooks := h.getEffectiveSlackWebhooks(networkCIDRs)
	if len(webhooks) == 0 {
		return
	}

	msg := notification.FormatRouterAPIFailureSlackMessage(routerType, routerID, err.Error())
	for _, wh := range webhooks {
		_ = h.sendSlackNotification(wh, msg)
	}
}

func (h *Handler) notifyRouterAPISuccess(routerType string, routerID string, networkCIDRs []string) {
	debounceKey := fmt.Sprintf("router:%s:%s", routerType, routerID)
	h.alertMu.Lock()
	if h.failedGateways == nil || !h.failedGateways[debounceKey] {
		h.alertMu.Unlock()
		return
	}
	delete(h.failedGateways, debounceKey)
	h.alertMu.Unlock()

	webhooks := h.getEffectiveSlackWebhooks(networkCIDRs)
	if len(webhooks) == 0 {
		return
	}

	msg := notification.FormatRouterAPIRecoverySlackMessage(routerType, routerID)
	for _, wh := range webhooks {
		_ = h.sendSlackNotification(wh, msg)
	}
}
