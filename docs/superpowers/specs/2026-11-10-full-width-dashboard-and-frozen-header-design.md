# Design: Full-Width Dashboard, Frozen Header, and Pinned Scan Status Footer

**Date:** 2026-11-10  
**Status:** Approved  
**Author:** AI & Human Collaborator  

---

## 1. Intent & Context

LAN-Orangutan displays discovered network inventory and telemetry in a primary table on the Dashboard. Currently, the dashboard is split horizontally by a left-hand sidebar listing all configured networks (`.sidebar-networks`), which consumes horizontal space on desktop and awkwardly stacks vertically above the table on mobile devices.

The goal of this design is to:
1. Move the network list and individual network scan actions to the **Scans** page (`/scans`), freeing up the dashboard for a full-width device inventory table.
2. Relocate the manual **Scan All** control (with Quick / Deep / Both mode selector) into the dashboard's top action toolbar, keeping one-click network sweeps accessible without navigating away from the device list.
3. Freeze everything above the table rows (top navigation bar, stats summary, search/filter toolbar, and table column headers) so the user never loses filter/search context while scrolling through large inventories.
4. Provide a dedicated, sticky **Scan Status Footer** at the bottom of the dashboard that displays active scan progress and per-network last scan times, with a hideable/minimizable toggle on mobile to protect vertical screen real estate.

---

## 2. Goals, Non-Goals & Anti-Goals

### Goals
* **Full-Width Inventory Table:** Remove `.sidebar-networks` from `/` (`index.html`), allowing the devices table to utilize the full container width.
* **Consolidated Network Management on Scans Page:** Move the interactive network list (with per-network Quick/Deep scan triggers, device counts, and Tailscale status) into `/scans` (`scans.html`) alongside the Live Scan Progress card and Execution History.
* **Dashboard "Scan All" Toolbar Control:** Place the "Scan All" button and scan mode selector (`Quick`, `Deep`, `Both`) in the `.section-actions` toolbar on `/` directly adjacent to the Continuous Scan toggle.
* **Frozen Top Header:** Keep the global header (`.header`), summary stats strip (`.stat-strip-holder`), toolbar controls (`.section-header`), and table column headers (`<thead>`) fixed (`position: sticky`) as the user scrolls down the devices table.
* **Preserve Desktop Stat-Strip Docking:** Preserve the existing desktop behavior (`initStatDock` on screens $\ge 1100\text{px}$) where the stats strip glides into the header on scroll, saving ~50px of vertical space.
* **Mobile Viewport Protection:** On mobile screens ($< 768\text{px}$), allow `.stat-strip` to scroll off naturally rather than sticking, keeping only the essential header/search bar and table header frozen to prevent sandwiching the viewport.
* **Bottom Scan Status Footer (Option A):** Dock a sleek status footer at the bottom of the viewport showing:
  * Currently active scan (network name, scan type/mode, running spinner/indicator).
  * Last scan timestamps for configured networks (horizontal ticker chips).
  * Quick navigation link to `/scans`.
  * Minimize/Hide toggle `[_]` that collapses the footer into an ultra-compact grab handle on mobile.
* **Preserve Existing Table Capabilities:** Ensure drag-to-resize columns, column sorting, search filtering, and device detail modals continue to function properly without CSS clipping or alignment bugs.

### Non-Goals
* Redesigning the REST API or scanner daemon backend (all needed scan state is already exposed via `/api/scan/progress` and page template data).
* Changing how Nmap, OPNsense, OpenWrt, or SNMP switch discovery operate.
* Replacing the dedicated scan history and presence timeline features on `/scans`.

### Anti-Goals
* Breaking table column resize handles or horizontal scrolling when many columns are enabled.
* Consuming excessive vertical screen space on mobile phones.

---

## 3. Architecture & UI Design

### 3.1 Relocating Networks Sidebar to `/scans`
* **Dashboard (`index.html`):**
  * Remove `.sidebar-networks`.
  * Move `.btn-scan-all` and `.scan-mode-select` into `.section-actions` toolbar next to `#continuous-scan-toggle`.
  * Flatten `.dashboard-layout` so `.dashboard-content` spans 100% width.
* **Scans View (`scans.html`):**
  * Add a dedicated "Configured Networks" section containing the list of configured networks with friendly names, CIDRs, last scan timestamps, device counts, individual scan triggers (`Quick`, `Deep`, `Both`), and Tailscale connection controls.
  * Ensure the JS handlers (`startSelectedScan`, `disconnectTailscale`, `connectTailscale`) function cleanly on `/scans`.

### 3.2 Frozen Top Header & Column Headers
* **Header Hierarchy:**
  1. `.header`: Sticky at `top: 0`, z-index 100.
  2. `.stat-strip-holder`: Sticky below `.header` (or docked into `.header` on $\ge 1100\text{px}$ via `initStatDock`).
  3. `.section-header` / `.table-toolbar`: Sticky below stat strip/header, z-index 80.
  4. `table#devices-table thead`: Sticky below toolbar, z-index 70.
* **Responsive Scrolling:**
  * On mobile ($< 768\text{px}$), `.stat-strip-holder` scrolls off naturally. Only `.header`, the compact search input, and table headers remain sticky.
  * Backgrounds and borders are opaque (`var(--bg-secondary)`, `var(--bg-card)`) to eliminate text bleed-through when scrolling.

### 3.3 Docked Bottom Scan Status Footer
* **Component Placement:** Pinned at `bottom: 0`, full width, `position: fixed`, z-index 95.
* **Desktop Presentation:**
  * Height ~34px–38px, background `var(--bg-card)` with top border `var(--border)`.
  * Left: Active scan badge (pulsing indicator + network name + scan mode). If idle, displays "All networks idle" with last complete scan time.
  * Center: Inline ticker showing each network and its relative last scan time (e.g. `IoT: 3m ago`, `LAN: 12m ago`).
  * Right: "View Scans →" link and a Minimize/Hide toggle `[_]`.
* **Mobile Presentation (< 768px):**
  * Default: Compact strip with horizontal scrolling for network chips.
  * Tapping the minimize toggle slides the footer down into a minimal 18px grab handle labeled "▲ Scans". Tapping restores it.
* **Live Telemetry & Sync:**
  * Seamlessly hooks into `scan-refresh.js` and `/api/scan/progress` to reflect live running scans and last-scanned times dynamically without page reload.

---

## 4. Implementation Decisions & Builder Calls
* **Desktop docking preservation:** `initStatDock` in `app.js` is preserved so wide screens enjoy zero vertical penalty from the stats strip.
* **Mobile vertical space management:** The stats strip will not be sticky on screens $< 768\text{px}$, leaving ample space for the devices table.
* **Scan All position:** Located in the `.section-actions` toolbar on the dashboard.
