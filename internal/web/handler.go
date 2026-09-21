// Package web handles the web UI and static assets
package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/auth"
	"github.com/spoutin/LAN-Orangutan/internal/config"
	"github.com/spoutin/LAN-Orangutan/internal/network"
	"github.com/spoutin/LAN-Orangutan/internal/scanner"
	"github.com/spoutin/LAN-Orangutan/internal/storage"
	"github.com/spoutin/LAN-Orangutan/internal/types"
)

//go:embed static/*
var staticFS embed.FS

//go:embed templates/*
var templateFS embed.FS

// Handler handles web requests
type Handler struct {
	store     *storage.Storage
	cfg       *config.Config
	auth      *auth.Authenticator
	version   string
	templates *template.Template
	staticFS  http.Handler
}

// NetworkView holds network info and device statistics for rendering
type NetworkView struct {
	types.Network
	DeviceCount   int
	IsScanning    bool
	IsCompleted   bool
	LastScanUnix  int64
	LastScanAgo   string
	SlackWebhook  string
	NotifyEnabled bool
}

// PageData holds data passed to templates
type PageData struct {
	Title        string
	Theme        string
	Version      string
	Devices      []*DeviceView
	Networks     []NetworkView
	Tailscale    types.TailscaleStatus
	Stats        types.DeviceStats
	Groups       []string
	CurrentGroup string
	Error        string

	// AuthEnabled reports whether a password is configured, so pages can show
	// a sign out link only when there is a session to end.
	AuthEnabled bool

	// MinPasswordLength is shown on the setup page and enforced by the browser.
	MinPasswordLength int

	// LastScanAgo and LastScanAt describe when the device list was last
	// refreshed. Both are empty when nothing has been scanned yet.
	LastScanAgo string
	LastScanAt  string

	// NetworkWarning explains that this instance cannot see the local network,
	// which happens in a container without host networking. Empty when fine.
	NetworkWarning string

	// LastScanUnix lets the page keep the relative time ticking without a
	// reload. A server-rendered "1 min ago" would otherwise still claim one
	// minute an hour later, which is the very confusion the footer exists to
	// prevent.
	LastScanUnix int64

	// Flagged is how many devices expose a risky service, and Moved how many
	// have changed IP. They fill the dashboard summary strip with information
	// worth glancing at rather than empty space.
	Flagged int
	Moved   int

	// ContinuousScan reports whether the server re-scans on its own. When true
	// the dashboard shows a "live" cue so the last-scan time does not read as
	// stale data when it is actually being kept current.
	ContinuousScan bool

	// ScanRunning reports whether a network scan is currently running
	ScanRunning bool
}

// DeviceView is a device with computed display properties
type DeviceView struct {
	*types.Device
	Status       string
	StatusClass  string
	StatusTip    string
	TimeAgo      string
	LastSeenUnix int64

	// Vendor shadows the stored value so it can be resolved for records that
	// predate the built-in manufacturer database.
	Vendor string

	// Type shadows the stored value so a device recorded before classification
	// existed still shows a type, inferred from its vendor and hostname now.
	Type string
}

// NewHandler creates a new web handler
func NewHandler(store *storage.Storage, cfg *config.Config, authn *auth.Authenticator, version string) *Handler {
	// Parse templates with custom functions
	funcMap := template.FuncMap{
		"timeAgo":  timeAgo,
		"lower":    strings.ToLower,
		"typeIcon": typeIcon,
	}

	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html"))

	// Create static file server
	staticSub, _ := staticSubFS()
	staticHandler := newStaticHandler(staticSub)

	return &Handler{
		store:     store,
		cfg:       cfg,
		auth:      authn,
		version:   version,
		templates: tmpl,
		staticFS:  staticHandler,
	}
}

// StaticHandler serves the embedded static assets.
//
// Exposed separately so the server can leave static files unauthenticated,
// which the login page needs in order to style itself.
func (h *Handler) StaticHandler() http.Handler {
	return h.staticFS
}

// HandleSetup renders the first run page and creates the initial password.
//
// onPasswordSet persists the new hash. It is supplied by the caller so this
// package does not need to know where credentials live.
func (h *Handler) HandleSetup(onPasswordSet func(hash string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Once a password exists there is nothing to set up, and this page must
		// not become a way to overwrite it.
		if !h.auth.NeedsSetup() {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		switch r.Method {
		case http.MethodGet:
			h.renderSetup(w, "", http.StatusOK)

		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				h.renderSetup(w, "Could not read that submission. Please try again.", http.StatusBadRequest)
				return
			}

			password := r.FormValue("password")
			if password != r.FormValue("confirm") {
				h.renderSetup(w, "Those passwords do not match.", http.StatusBadRequest)
				return
			}

			if err := auth.ValidatePassword(password); err != nil {
				h.renderSetup(w, err.Error(), http.StatusBadRequest)
				return
			}

			hash, err := h.auth.SetPassword(password)
			if err != nil {
				h.renderSetup(w, err.Error(), http.StatusBadRequest)
				return
			}

			if err := onPasswordSet(hash); err != nil {
				// The password is live in memory but could not be saved, so it
				// would vanish on restart. Say so rather than pretend.
				h.renderSetup(w,
					"Your password was set, but could not be saved: "+err.Error(),
					http.StatusInternalServerError)
				return
			}

			// Sign the user straight in rather than bouncing them to a login
			// form for the password they just typed twice.
			if token, ok := h.auth.StartSession(); ok {
				h.auth.SetCookie(w, r, token)
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// renderSetup draws the first run page, optionally with an error message.
func (h *Handler) renderSetup(w http.ResponseWriter, message string, status int) {
	data := PageData{
		Title:             "Welcome - LAN Orangutan",
		Theme:             h.cfg.UI.Theme,
		Error:             message,
		MinPasswordLength: auth.MinPasswordLength,
	}

	var buf bytes.Buffer
	if err := h.templates.ExecuteTemplate(&buf, "setup.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

// HandleLogin renders the sign in form and processes submissions.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	// Send first run visitors to setup rather than a login form for a password
	// that does not exist yet.
	if h.auth.NeedsSetup() {
		http.Redirect(w, r, auth.SetupPath, http.StatusSeeOther)
		return
	}

	// With no password configured there is nothing to sign in to.
	if !h.auth.Enabled() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.renderLogin(w, "")

	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			h.renderLogin(w, "Could not read that submission. Please try again.")
			return
		}

		if h.auth.LockedOut(r.RemoteAddr) {
			h.renderLogin(w, "Too many failed attempts. Please wait a few minutes and try again.")
			return
		}

		token, ok := h.auth.Login(r.RemoteAddr, r.FormValue("password"))
		if !ok {
			h.renderLogin(w, "Incorrect password.")
			return
		}

		h.auth.SetCookie(w, r, token)
		http.Redirect(w, r, "/", http.StatusSeeOther)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleLogout ends the current session.
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	h.auth.Logout(r)
	h.auth.ClearCookie(w, r)
	http.Redirect(w, r, auth.LoginPath, http.StatusSeeOther)
}

// renderLogin draws the sign in page, optionally with an error message.
func (h *Handler) renderLogin(w http.ResponseWriter, message string) {
	data := PageData{
		Title: "Sign in - LAN Orangutan",
		Theme: h.cfg.UI.Theme,
		Error: message,
	}

	var buf bytes.Buffer
	if err := h.templates.ExecuteTemplate(&buf, "login.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// A failed attempt is not a successful page load; say so for any client
	// that pays attention to the status code.
	if message != "" {
		w.WriteHeader(http.StatusUnauthorized)
	}
	buf.WriteTo(w)
}

// ServeHTTP implements http.Handler
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Static files
	if strings.HasPrefix(path, "/static/") {
		h.staticFS.ServeHTTP(w, r)
		return
	}

	// Routes
	switch path {
	case "/", "/index.html":
		h.handleIndex(w, r)
	case "/scans", "/scans.html":
		h.handleScans(w, r)
	case "/settings", "/settings.html":
		h.handleSettings(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleIndex renders the main dashboard
func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Get devices
	devices := h.store.GetDevices()

	// Convert to view models
	var deviceViews []*DeviceView
	groupSet := make(map[string]bool)
	var flagged, moved int

	for _, d := range devices {
		if d.LinkedMAC != "" {
			continue // Skip linked children, keeping the main dashboard clean!
		}
		if len(d.Risks) > 0 {
			flagged++
		}
		if len(d.AddressHistory) > 0 {
			moved++
		}
		// Devices recorded by an older version have no vendor stored, so look it
		// up now rather than showing "Unknown" until a rescan.
		resolvedVendor := scanner.ResolveVendor(d.Vendor, d.MAC)

		dv := &DeviceView{
			Device:       d,
			TimeAgo:      timeAgo(d.LastSeen),
			LastSeenUnix: d.LastSeen.Unix(),
			Vendor:       resolvedVendor,
			Type:         d.Type,
		}
		// Backfill a type for records that predate classification, from the same
		// vendor and hostname the row already shows. Port evidence is not
		// available here, so this is the default path, not the opt-in probe.
		if dv.Type == "" {
			dv.Type = scanner.Classify(resolvedVendor, d.Hostname, nil)
		}

		scanInterval := time.Duration(h.cfg.Scanning.ScanInterval) * time.Second
		if d.IsRecent(scanInterval) {
			dv.Status = "online"
			dv.StatusClass = "status-online"
			dv.StatusTip = fmt.Sprintf("Online (active on network within the last %s)", formatDurationFriendly(scanInterval+getBuffer(scanInterval)))
		} else if d.IsOnline(scanInterval) {
			dv.Status = "seen"
			dv.StatusClass = "status-seen"
			dv.StatusTip = fmt.Sprintf("Seen recently (active on network within the last %s)", formatDurationFriendly(3*scanInterval))
		} else {
			dv.Status = "offline"
			dv.StatusClass = "status-offline"
			dv.StatusTip = fmt.Sprintf("Offline (no activity seen for over %s)", formatDurationFriendly(3*scanInterval))
		}

		deviceViews = append(deviceViews, dv)

		if d.Group != "" {
			groupSet[d.Group] = true
		}
	}

	// Sort by IP
	sort.Slice(deviceViews, func(i, j int) bool {
		return ipToLong(deviceViews[i].IP) < ipToLong(deviceViews[j].IP)
	})

	// Get groups
	var groups []string
	for g := range groupSet {
		groups = append(groups, g)
	}
	sort.Strings(groups)

	// Get networks and count active devices per network
	networks, _ := network.DetectNetworks()
	networks = network.WithConfigured(networks, network.Filter{Configured: h.cfg.Scanning.Networks, Excluded: h.cfg.Scanning.ExcludeNetworks, OnlyConfigured: h.cfg.Scanning.OnlyConfiguredNetworks})

	scanInterval := time.Duration(h.cfg.Scanning.ScanInterval) * time.Second
	networkCounts := make(map[string]int)
	for _, d := range devices {
		if d.IsOnline(scanInterval) && d.NetworkName != "" {
			networkCounts[strings.ToLower(d.NetworkName)]++
		}
	}

	currentScanning := h.store.GetCurrentScanningNetwork()

	var networkViews []NetworkView
	for _, n := range networks {
		if name, ok := h.cfg.Scanning.NetworkNames[n.CIDR]; ok {
			n.FriendlyName = name
		}
		friendlyLower := strings.ToLower(n.FriendlyName)

		// Get last scan info
		lastScanTime := h.store.GetLastScan(n.CIDR)
		var lastScanUnix int64
		var lastScanAgo string
		if !lastScanTime.IsZero() {
			lastScanUnix = lastScanTime.Unix()
			lastScanAgo = timeAgo(lastScanTime)
		}

		isScanning := currentScanning == n.CIDR
		isCompleted := h.store.IsNetworkCompletedInCurrentRun(n.CIDR)

		networkViews = append(networkViews, NetworkView{
			Network:      n,
			DeviceCount:  networkCounts[friendlyLower],
			IsScanning:   isScanning,
			IsCompleted:  isCompleted,
			LastScanUnix: lastScanUnix,
			LastScanAgo:  lastScanAgo,
		})
	}

	// Get Tailscale status
	tailscale := network.GetTailscaleStatus()

	// Get stats
	stats := h.store.GetStats()

	scanRunning := h.store.IsScanRunning()

	data := PageData{
		Title:          "LAN Orangutan",
		Theme:          h.cfg.UI.Theme,
		Devices:        deviceViews,
		Networks:       networkViews,
		Tailscale:      tailscale,
		Stats:          stats,
		Groups:         groups,
		AuthEnabled:    h.auth.Enabled(),
		Flagged:        flagged,
		Moved:          moved,
		Version:        h.version,
		ContinuousScan: h.store.ContinuousScanEnabled(h.cfg.Scanning.ContinuousScan),
		ScanRunning:    scanRunning,
	}

	data.NetworkWarning = network.IsolationWarning(networks)

	// The table is only as current as the last scan. Say so, so that a "last
	// seen" time is read against when the data was actually gathered.
	if lastScan := h.store.GetMostRecentScan(); !lastScan.IsZero() {
		data.LastScanAgo = timeAgo(lastScan)
		data.LastScanAt = lastScan.Format("Jan 2, 2006 at 3:04 PM")
		data.LastScanUnix = lastScan.Unix()
	}

	// Buffer the template output to avoid superfluous WriteHeader on error
	var buf bytes.Buffer
	if err := h.templates.ExecuteTemplate(&buf, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// handleSettings renders the settings page
func (h *Handler) handleSettings(w http.ResponseWriter, r *http.Request) {
	// Get Tailscale status
	tailscale := network.GetTailscaleStatus()

	// Get stats
	stats := h.store.GetStats()

	// Get networks
	networks, _ := network.DetectNetworks()
	networks = network.WithConfigured(networks, network.Filter{Configured: h.cfg.Scanning.Networks, Excluded: h.cfg.Scanning.ExcludeNetworks, OnlyConfigured: h.cfg.Scanning.OnlyConfiguredNetworks})

	notifs, _ := h.store.GetNetworkNotifications()
	notifMap := make(map[string]types.NetworkNotification)
	for _, n := range notifs {
		notifMap[n.NetworkCIDR] = n
	}

	var networkViews []NetworkView
	for _, n := range networks {
		if name, ok := h.cfg.Scanning.NetworkNames[n.CIDR]; ok {
			n.FriendlyName = name
		}
		
		slackWebhook := ""
		notifyEnabled := false
		if conf, exists := notifMap[n.CIDR]; exists {
			slackWebhook = conf.SlackWebhook
			notifyEnabled = conf.Enabled
		}

		networkViews = append(networkViews, NetworkView{
			Network:       n,
			SlackWebhook:  slackWebhook,
			NotifyEnabled: notifyEnabled,
		})
	}

	data := PageData{
		Title:       "Settings - LAN Orangutan",
		Theme:       h.cfg.UI.Theme,
		Version:     h.version,
		Tailscale:   tailscale,
		Stats:       stats,
		Networks:    networkViews,
		AuthEnabled: h.auth.Enabled(),
	}

	// Buffer the template output to avoid superfluous WriteHeader on error
	var buf bytes.Buffer
	if err := h.templates.ExecuteTemplate(&buf, "settings.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// handleScans renders the scans page
func (h *Handler) handleScans(w http.ResponseWriter, r *http.Request) {
	// Get Tailscale status
	tailscale := network.GetTailscaleStatus()

	// Get stats
	stats := h.store.GetStats()

	data := PageData{
		Title:       "Scans - LAN Orangutan",
		Theme:       h.cfg.UI.Theme,
		Version:     h.version,
		Tailscale:   tailscale,
		Stats:       stats,
		AuthEnabled: h.auth.Enabled(),
	}

	// Buffer the template output to avoid superfluous WriteHeader on error
	var buf bytes.Buffer
	if err := h.templates.ExecuteTemplate(&buf, "scans.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// timeAgo returns a human-readable time difference
func timeAgo(t time.Time) string {
	if t.IsZero() {
		return "never"
	}

	diff := time.Since(t)

	switch {
	case diff < time.Minute:
		return "just now"
	case diff < time.Hour:
		mins := int(diff.Minutes())
		if mins == 1 {
			return "1 min ago"
		}
		return fmt.Sprintf("%d min ago", mins)
	case diff < 24*time.Hour:
		hours := int(diff.Hours())
		if hours == 1 {
			return "1 hr ago"
		}
		return fmt.Sprintf("%d hr ago", hours)
	case diff < 7*24*time.Hour:
		days := int(diff.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	default:
		return t.Format("Jan 2, 2006")
	}
}

// ipToLong converts an IP string to a sortable integer
func ipToLong(ip string) int64 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0x7FFFFFFFFFFFFFFF
	}

	var result int64
	for i, p := range parts {
		var n int
		for _, c := range p {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		result |= int64(n) << (24 - 8*i)
	}
	return result
}

func formatDurationFriendly(d time.Duration) string {
	if d == time.Hour {
		return "hour"
	}
	if d == 24*time.Hour {
		return "day"
	}
	if d.Minutes() < 120 {
		mins := int(d.Minutes())
		if mins == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", mins)
	}
	hours := int(d.Hours())
	if hours == 1 {
		return "1 hour"
	}
	return fmt.Sprintf("%d hours", hours)
}

func getBuffer(scanInterval time.Duration) time.Duration {
	buffer := scanInterval / 5
	if buffer < 2*time.Minute {
		buffer = 2 * time.Minute
	}
	return buffer
}
