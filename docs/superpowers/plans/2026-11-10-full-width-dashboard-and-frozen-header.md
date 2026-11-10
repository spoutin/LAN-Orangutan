# Full-Width Dashboard, Frozen Header, and Pinned Scan Status Footer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the LAN-Orangutan dashboard into a full-width device inventory table with a frozen header hierarchy, move the network list to the Scans tab, add "Scan All" to the dashboard toolbar, and dock a live scan status footer at the bottom of the viewport.

**Architecture:** 
1. Remove `.sidebar-networks` from `index.html` and move the network list and per-network controls to `scans.html`.
2. Move the "Scan All" button and mode selector into the `.section-actions` toolbar on `index.html`.
3. Configure sticky positioning in `style.css` so the top nav, toolbar, and table headers stay pinned, preserving wide-screen stat-strip docking while letting stats scroll off naturally on mobile.
4. Render a fixed bottom status footer on `index.html` displaying live scan activity and network last-scan chips, wired up via `scan-refresh.js` with a mobile minimize toggle.

**Tech Stack:** Go (html/template, net/http), Vanilla JavaScript (ES6+), Modern CSS (Flexbox, Sticky positioning, CSS custom properties), Node.js test runner (`node --test`).

**Spec:** `docs/superpowers/specs/2026-11-10-full-width-dashboard-and-frozen-header-design.md`

## Global Constraints
- Single Go binary with embedded static files and templates (`internal/web/templates/`, `internal/web/static/`).
- Zero external client-side runtime dependencies (no React/Vue/jQuery).
- Preserves theme switching (Light / Dark / Accent colors) and `localStorage` preferences.
- Responsive across desktop (>1100px), tablet (768px-1024px), and mobile (<768px).

## Review Focus
- **Mobile Viewport Sandwich:** Ensure sticky elements do not take over >40% of mobile screen height (<768px).
- **Column Header Alignment:** Ensure sticky `thead` stays aligned with column widths when columns are drag-resized or window resized.
- **Scroll Bleed-Through:** Ensure sticky bars have opaque backgrounds so underlying table text does not show through.
- **Live Scan Status Accuracy:** Ensure the bottom footer updates dynamically during scans and returns to idle state without requiring page reload.
- **Scan All Button Functionality:** Verify triggering Quick, Deep, or Both from the new toolbar location initiates scans as expected.

---

### Task 1: Scans View Configured Networks Integration

**Files:**
- Modify: `internal/web/templates/scans.html`
- Modify: `internal/web/handler.go`
- Test: `internal/web/handler_test.go`
- Test: `internal/web/static/scans-view.test.js`

**Interfaces:**
- Consumes: `Handler.HandleScans` template data containing `Networks` slice and `Tailscale` status.
- Produces: Rendered `#configured-networks` section on `/scans` with per-network scan triggers and Tailscale widget.

- [ ] **Step 1: Write failing handler test for `/scans` Configured Networks**

Add test in `internal/web/handler_test.go`:
```go
func TestScansPageRendersConfiguredNetworks(t *testing.T) {
	h, _ := newTestHandler(t, testPassword)
	rec := httptest.NewRecorder()
	h.HandleScans(rec, httptest.NewRequest(http.MethodGet, "/scans", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scans page status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Configured Networks") {
		t.Error("scans page should contain Configured Networks heading")
	}
	if !strings.Contains(body, `class="network-list"`) {
		t.Error("scans page should contain network-list container")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/web -run TestScansPageRendersConfiguredNetworks`  
Expected: FAIL (missing "Configured Networks" / `network-list`)

- [ ] **Step 3: Update `scans.html` to render Configured Networks and Tailscale widget**

In `internal/web/templates/scans.html`, add the "Configured Networks" section above or alongside "Execution History" with:
- Network items (`.sidebar-net-item` / `.network-card`) displaying friendly name, CIDR, device count, scan mode selector, and scan action button.
- Tailscale status item with connect/disconnect actions.
- Ensure the template has access to `.Networks` and `.Tailscale` via `handler.go` if not already passed.

- [ ] **Step 4: Run Go test to verify it passes**

Run: `go test -v ./internal/web -run TestScansPageRendersConfiguredNetworks`  
Expected: PASS

- [ ] **Step 5: Add JS test in `scans-view.test.js` verifying network action helpers**

Add test in `internal/web/static/scans-view.test.js` checking that network elements on the scans view have valid action data attributes.

- [ ] **Step 6: Run JS tests**

Run: `node --test internal/web/static/*.test.js`  
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/web/templates/scans.html internal/web/handler.go internal/web/handler_test.go internal/web/static/scans-view.test.js
git commit -m "feat(web): add configured networks section to scans view"
```

---

### Task 2: Dashboard Full-Width Layout & Toolbar "Scan All" Control

**Files:**
- Modify: `internal/web/templates/index.html`
- Modify: `internal/web/static/style.css`
- Test: `internal/web/handler_test.go`

**Interfaces:**
- Consumes: `.section-actions` toolbar on `/`
- Produces: Full-width devices table without `.sidebar-networks`, and toolbar `.btn-scan-all` with `.scan-mode-select`.

- [ ] **Step 1: Write failing handler test for Dashboard layout and toolbar**

Add test in `internal/web/handler_test.go`:
```go
func TestDashboardFullWidthLayoutAndScanAllToolbar(t *testing.T) {
	h, _ := newTestHandler(t, testPassword)
	rec := httptest.NewRecorder()
	h.HandleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("index page status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, `class="sidebar-networks"`) {
		t.Error("index page should no longer contain sidebar-networks")
	}
	if !strings.Contains(body, `btn-scan-all`) {
		t.Error("index page toolbar should contain btn-scan-all")
	}
	if !strings.Contains(body, `data-network="all"`) {
		t.Error("btn-scan-all should target all networks")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/web -run TestDashboardFullWidthLayoutAndScanAllToolbar`  
Expected: FAIL

- [ ] **Step 3: Modify `index.html` and `style.css`**

- Remove `.sidebar-networks` from `internal/web/templates/index.html`.
- Move `.btn-scan-all` and `.scan-mode-select` into `.section-actions` (right next to `.auto-refresh` / Continuous Scan toggle).
- In `internal/web/static/style.css`, update `.dashboard-layout` to remove the 2-column split so `.dashboard-content` uses 100% width. Update toolbar styling to align the scan mode select and Scan All button neatly.

- [ ] **Step 4: Run Go test to verify it passes**

Run: `go test -v ./internal/web -run TestDashboardFullWidthLayoutAndScanAllToolbar`  
Expected: PASS

- [ ] **Step 5: Run all web tests**

Run: `go test -v ./internal/web`  
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/web/templates/index.html internal/web/static/style.css internal/web/handler_test.go
git commit -m "feat(web): flatten dashboard to full width and move scan all to toolbar"
```

---

### Task 3: Frozen Top Header Hierarchy & Scroll Stacking

**Files:**
- Modify: `internal/web/static/style.css`
- Modify: `internal/web/static/app.js`
- Test: `internal/web/static/app-scroll.test.js` (or DOM verification test)

**Interfaces:**
- Consumes: `.header`, `.stat-strip-holder`, `.section-header`, `table#devices-table thead`.
- Produces: Layered sticky positioning where table rows scroll beneath pinned header tiers.

- [ ] **Step 1: Write CSS test / assertion for sticky positioning rules**

Create or add a test in `internal/web/static/scroll-dock.test.js` validating the sticky hierarchy CSS properties and z-indexes:
- `.header`: `position: sticky`, `top: 0`, `z-index: 100`
- `.stat-strip-holder`: opaque background, handles docking
- `.section-header` / table container: sticky positioning beneath header
- `thead th`: `position: sticky`, opaque background `var(--bg-card)` or `var(--bg-secondary)`

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test internal/web/static/*.test.js`  
Expected: FAIL (missing new sticky classes/assertions)

- [ ] **Step 3: Implement sticky hierarchy in `style.css`**

- Set `.section-header` and `.table-toolbar` to sticky below `.header` (accounting for header height).
- Set `table#devices-table thead th` to `position: sticky; top: var(--table-header-top); z-index: 70; background: var(--bg-card);`.
- Ensure wide-screen (`>= 1100px`) `initStatDock` in `app.js` continues to glide `.stat-strip` into `.header`.
- In `@media (max-width: 768px)`:
  - Keep `.stat-strip-holder` as `position: static` (scrolls off).
  - Pin only `.header` and compact search bar.

- [ ] **Step 4: Run JS and Go tests**

Run: `node --test internal/web/static/*.test.js && go test -v ./internal/web`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/web/static/style.css internal/web/static/app.js internal/web/static/*.test.js
git commit -m "feat(ui): implement frozen sticky header and table column hierarchy"
```

---

### Task 4: Pinned Scan Status Footer (Option A)

**Files:**
- Modify: `internal/web/templates/index.html`
- Modify: `internal/web/static/style.css`
- Modify: `internal/web/static/scan-refresh.js`
- Test: `internal/web/static/scan-footer.test.js`
- Test: `internal/web/handler_test.go`

**Interfaces:**
- Consumes: `/api/scan/progress` data from `scan-refresh.js`.
- Produces: `#scan-status-footer` DOM element pinned at viewport bottom, with live updates and minimize toggle.

- [ ] **Step 1: Write failing test for scan footer markup and refresh logic**

In `internal/web/static/scan-footer.test.js`:
- Test `renderScanStatusFooter(state)` returns formatted active scan status (pulsing dot, network name, mode) when scanning.
- Test `renderScanStatusFooter(state)` returns idle summary and relative last scan times per network when idle.
- Test minimize toggle state toggles `.minimized` class and stores setting in `localStorage`.

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test internal/web/static/scan-footer.test.js`  
Expected: FAIL

- [ ] **Step 3: Implement footer in `index.html`, `style.css`, and `scan-refresh.js`**

- In `index.html`: Add `#scan-status-footer` at bottom of `<body>` with active indicator, network last-scan ticker chips, link to `/scans`, and minimize button.
- In `style.css`: Style `.scan-status-footer` fixed at `bottom: 0`, height 36px, z-index 95, background `var(--bg-card)` with top border `var(--border)`. Add `.minimized` state styling.
- In `scan-refresh.js`: Export and call `updateScanStatusFooter(status)` during background refresh ticks, updating the footer live with active scan progress and relative times.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test internal/web/static/scan-footer.test.js`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/web/templates/index.html internal/web/static/style.css internal/web/static/scan-refresh.js internal/web/static/scan-footer.test.js
git commit -m "feat(ui): add pinned scan status footer with live telemetry and mobile minimize"
```

---

### Task 5: Integration Verification & Polish

**Files:**
- Modify: All relevant files for polish / bug fixes
- Test: Full test suite

- [ ] **Step 1: Run all backend tests**

Run: `go test -v ./internal/web`  
Expected: PASS

- [ ] **Step 2: Run all frontend unit tests**

Run: `node --test internal/web/static/*.test.js`  
Expected: PASS

- [ ] **Step 3: Verify build**

Run: `go build -o /dev/null ./cmd/orangutan`  
Expected: SUCCESS (compiles cleanly)

- [ ] **Step 4: Final verification and commit**

```bash
git status
git commit -m "chore: complete full-width dashboard, frozen header, and scan footer integration"
```
