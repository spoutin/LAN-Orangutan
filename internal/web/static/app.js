// Theme

// applyTheme switches the theme with transitions turned off for the switch, so
// every element changes at the same instant. Left on, some elements fade over
// their own transition while others (the page background) snap immediately,
// which reads as the page changing in pieces.
function applyTheme(theme) {
    const root = document.documentElement;
    // Do this synchronously with forced reflows rather than on an animation
    // frame: requestAnimationFrame does not fire in a background tab, which
    // would leave transitions disabled if the tab lost focus mid-switch.
    root.classList.add('theme-switching');
    void root.offsetWidth;                 // commit "transitions off"
    root.setAttribute('data-theme', theme);
    void root.offsetWidth;                 // commit the new theme instantly
    root.classList.remove('theme-switching'); // restore transitions for hover
    localStorage.setItem('theme', theme);
    syncThemeRadios(theme);
    updateThemeToggle(theme);
}

// Keep the Settings page's Light/Dark/Auto radios showing the theme that is
// actually applied. Without this they are checked from the server's config
// default, so a browser that pinned Light/Dark with the header button would
// still show "Auto" selected and leave the user unable to tell what is active
// (or to re-pick a value that already looks chosen). A no-op on pages without
// the radios (the dashboard).
function syncThemeRadios(theme) {
    document.querySelectorAll('input[name="theme"]').forEach(function (radio) {
        radio.checked = radio.value === theme;
    });
}

// Icons and labels for the header theme button, one per state. The icon always
// changes on click, so cycling into Auto is visibly different even when Auto
// happens to match the current system look (a sun for light, a moon for dark, a
// monitor for "follow the system"). Feather-style strokes, currentColor so they
// sit on the header in either theme.
const THEME_TOGGLE = {
    light: {
        title: 'Theme: Light — click for Dark',
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>'
    },
    dark: {
        title: 'Theme: Dark — click for Auto',
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>'
    },
    auto: {
        title: 'Theme: Auto (follows your system) — click for Light',
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>'
    }
};

// Point the header button(s) at the state the given theme will land on, so the
// icon and tooltip always describe what is actually active.
function updateThemeToggle(theme) {
    const state = THEME_TOGGLE[theme] ? theme : 'auto';
    document.querySelectorAll('.theme-toggle').forEach(function (btn) {
        btn.innerHTML = THEME_TOGGLE[state].icon;
        btn.setAttribute('title', THEME_TOGGLE[state].title);
        btn.setAttribute('aria-label', THEME_TOGGLE[state].title);
    });
}

// The header button cycles light -> dark -> auto -> light, matching the three
// choices on the settings page so the two controls can never disagree. The icon
// changes on every click (see updateThemeToggle), so landing on Auto is always
// a visible change even when Auto looks like the current system theme.
function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'light' ? 'dark' : current === 'dark' ? 'auto' : 'light';
    applyTheme(next);
}

// Initialize theme
(function() {
    const saved = localStorage.getItem('theme');
    if (saved) {
        document.documentElement.setAttribute('data-theme', saved);
        // Reflect the real (localStorage) choice in the Settings radios, which
        // the server rendered from the config default and would otherwise show
        // a value the browser is not actually using.
        syncThemeRadios(saved);
    }
    // Point the header button at whatever is actually active (the saved choice,
    // or the server's config default when nothing is saved).
    updateThemeToggle(document.documentElement.getAttribute('data-theme') || 'auto');
})();

// Accent colour. Blue is the default. Orange is the stylesheet's base and
// carries no attribute; every other accent (including blue) sets data-accent,
// which the stylesheet turns into the accent for both light and dark. The
// choice is stored so it applies on every page and every visit.
function applyAccent(name) {
    name = name || 'blue';
    if (name === 'orange') {
        document.documentElement.removeAttribute('data-accent');
    } else {
        document.documentElement.setAttribute('data-accent', name);
    }
    localStorage.setItem('accent', name);
}

// setAccent is called from the settings swatches: apply and mark the active one.
function setAccent(name) {
    applyAccent(name);
    document.querySelectorAll('.accent-swatch').forEach(function(sw) {
        sw.classList.toggle('active', sw.dataset.accent === name);
    });
}

(function() {
    applyAccent(localStorage.getItem('accent'));
    // Mark the active swatch on the settings page once it has rendered.
    document.addEventListener('DOMContentLoaded', function() {
        const current = localStorage.getItem('accent') || 'blue';
        document.querySelectorAll('.accent-swatch').forEach(function(sw) {
            sw.classList.toggle('active', sw.dataset.accent === current);
        });
    });
})();

// Toast notifications
function showToast(message, type = 'info', duration = 3000) {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.className = 'toast ' + type + ' show';
    setTimeout(() => toast.classList.remove('show'), duration);
}

// API helper
async function api(action, params = {}, method = 'GET') {
    let url = `/api/${action}`;
    const options = { method };
    if (method === 'GET') {
        const queryParams = Object.keys(params).map(key => `${key}=${encodeURIComponent(params[key])}`).join('&');
        if (queryParams) url += `?${queryParams}`;
    } else {
        options.headers = { 'Content-Type': 'application/json' };
        options.body = JSON.stringify(params);
    }
    try {
        const response = await fetch(url, options);
        const text = await response.text();
        if (!response.ok) {
            // Try to parse error from response body
            try {
                const errData = JSON.parse(text);
                if (response.status === 429) {
                    throw new Error(errData.error || 'Rate limited - please wait before scanning again');
                }
                throw new Error(errData.error || `HTTP error: ${response.status}`);
            } catch (parseErr) {
                if (parseErr.message.includes('Rate limited') || parseErr.message.includes('rate limited')) {
                    throw parseErr;
                }
                throw new Error(`HTTP error: ${response.status}`);
            }
        }
        if (!text) throw new Error('Empty response');
        return JSON.parse(text);
    } catch (error) {
        console.error('API error:', error);
        throw error;
    }
}

// Network scanning
//
// Scans run in the background on the server and the page polls for progress.
// A large network takes minutes, which is far too long to hold a request open.
const SCAN_POLL_MS = 1000;

function formatSeconds(total) {
    const s = Math.max(0, Math.round(total));
    return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
}

function showScanProgress(p) {
    const panel = document.getElementById('scan-progress');
    if (!panel) return;
    panel.style.display = 'flex';

    const title = document.getElementById('scan-title');
    const cancelBtn = document.getElementById('scan-cancel');

    const isFinished = p.status === 'done' || p.status === 'cancelled' || p.status === 'failed';

    if (p.status === 'done') {
        if (title) title.textContent = 'Scan Complete!';
        if (cancelBtn) {
            cancelBtn.textContent = 'Close';
            cancelBtn.onclick = function() {
                hideScanProgress();
                refreshAfterScan();
            };
        }
    } else if (p.status === 'failed') {
        if (title) title.textContent = 'Scan Failed';
        if (cancelBtn) {
            cancelBtn.textContent = 'Close';
            cancelBtn.onclick = function() {
                hideScanProgress();
                refreshAfterScan();
            };
        }
    } else if (p.status === 'cancelled') {
        if (title) title.textContent = 'Scan Cancelled';
        if (cancelBtn) {
            cancelBtn.textContent = 'Close';
            cancelBtn.onclick = function() {
                hideScanProgress();
                refreshAfterScan();
            };
        }
    } else {
        if (title) {
            if (p.port_scan_active) {
                title.textContent = 'Probing Services & Ports...';
            } else {
                let currentName = p.current_network_name ? `${p.current_network_name} (${p.current_network})` : p.current_network;
                title.textContent = p.current_network ? `Scanning ${currentName}` : 'Starting scan...';
            }
        }
        if (cancelBtn) {
            cancelBtn.textContent = 'Cancel';
            cancelBtn.onclick = cancelScan;
        }
    }

    // percent is -1 when the network has never been scanned and there is no
    // timing history to estimate from. Show a sweeping bar rather than a
    // made-up number.
    const bar = document.getElementById('scan-bar');
    const fill = document.getElementById('scan-bar-fill');
    const known = p.percent >= 0 || isFinished || p.port_scan_active;
    if (bar) bar.classList.toggle('indeterminate', !known);
    if (fill) {
        if (isFinished) {
            fill.style.width = '100%';
        } else if (p.port_scan_active) {
            const pct = p.port_scan_total > 0 ? (p.port_scan_complete / p.port_scan_total) * 100 : 0;
            fill.style.width = `${Math.min(100, Math.round(pct))}%`;
        } else {
            fill.style.width = known ? `${Math.min(100, p.percent)}%` : '';
        }
    }

    const detail = document.getElementById('scan-detail');
    if (detail) {
        if (isFinished) {
            detail.textContent = `Completed in ${formatSeconds(p.elapsed)}`;
        } else if (p.port_scan_active) {
            detail.textContent = `Probed ${p.port_scan_complete} of ${p.port_scan_total} active devices`;
        } else {
            const parts = [];
            if (p.network_count > 1) parts.push(`Network ${p.network_index} of ${p.network_count}`);
            if (p.current_network) {
                let currentName = p.current_network_name ? `${p.current_network_name} (${p.current_network})` : p.current_network;
                parts.push(currentName);
            }
            detail.textContent = parts.join(' · ');
        }
    }

    // The running total gets its own line. Appended to the line above it wrapped
    // mid-sentence once more than one network was involved.
    //
    // Only claim a count once there is one: nmap reports nothing until its
    // sweep finishes, so a permanent "0 devices found" reads as a failed scan
    // rather than an unfinished one.
    const count = document.getElementById('scan-count');
    if (count) {
        let countText = '';
        if (p.device_count > 0) {
            countText = `${p.device_count} device${p.device_count === 1 ? '' : 's'} found`;
            if (p.new_device_count > 0) {
                countText += ` (${p.new_device_count} new)`;
            }
        } else if (isFinished) {
            countText = 'No devices found';
        }
        count.textContent = countText;
    }

    const eta = document.getElementById('scan-eta');
    if (eta) {
        if (isFinished) {
            eta.textContent = '';
        } else if (p.port_scan_active) {
            const pct = p.port_scan_total > 0 ? (p.port_scan_complete / p.port_scan_total) * 100 : 0;
            eta.textContent = `${formatSeconds(p.elapsed)} elapsed · ${Math.round(pct)}%`;
        } else {
            eta.textContent = known && p.remaining != null
                ? `~${formatSeconds(p.remaining)} left · ${Math.round(p.percent)}%`
                : `${formatSeconds(p.elapsed)} elapsed`;
        }
    }

    // Set expectations explicitly while there is nothing to report yet.
    const hint = document.getElementById('scan-hint');
    if (hint) {
        if (p.error) {
            hint.textContent = p.error;
            hint.style.color = '#ef4444';
        } else {
            hint.style.color = '';
            hint.textContent = p.device_count > 0 || isFinished
                ? ''
                : 'Checking every address on the network. Devices are listed once the sweep finishes.';
        }
    }

    // Dynamic completed subnets list
    let detailsContainer = document.getElementById('scan-details-container');
    let detailsList = document.getElementById('scan-details-list');

    // Create container dynamically if it doesn't exist
    if (!detailsContainer && panel) {
        detailsContainer = document.createElement('div');
        detailsContainer.id = 'scan-details-container';
        detailsContainer.className = 'scan-details-container';

        const header = document.createElement('div');
        header.className = 'scan-details-header';
        header.textContent = 'Completed Subnets:';
        detailsContainer.appendChild(header);

        detailsList = document.createElement('div');
        detailsList.id = 'scan-details-list';
        detailsList.className = 'scan-details-list';
        detailsContainer.appendChild(detailsList);

        panel.appendChild(detailsContainer);
    }

    if (detailsContainer && detailsList) {
        if (p.networks && p.networks.length > 0) {
            detailsContainer.style.display = 'block';
            let rowsHtml = p.networks.map(n => {
                const nameLabel = n.network_name ? `${n.network_name} (${n.network})` : n.network;
                const statusBadge = `<span class="scan-status-badge ${n.status}">${n.status}</span>`;
                const durationText = n.duration ? `in ${formatSeconds(n.duration)}` : '';
                return `
                    <div class="scan-detail-row">
                        <span class="scan-detail-network">${nameLabel}</span>
                        <span class="scan-detail-status">${statusBadge}</span>
                        <span class="scan-detail-summary">${n.device_count} found ${durationText}</span>
                    </div>
                `;
            }).join('');

            if (p.port_scan_active) {
                const statusBadge = `<span class="scan-status-badge running">scanning</span>`;
                rowsHtml += `
                    <div class="scan-detail-row port-scan-row">
                        <span class="scan-detail-network">🔌 Active Port Prober</span>
                        <span class="scan-detail-status">${statusBadge}</span>
                        <span class="scan-detail-summary">${p.port_scan_complete}/${p.port_scan_total} probed</span>
                    </div>
                `;
            } else if (p.port_scan_total > 0) {
                const statusBadge = `<span class="scan-status-badge scanned">scanned</span>`;
                rowsHtml += `
                    <div class="scan-detail-row port-scan-row">
                        <span class="scan-detail-network">🔌 Active Port Prober</span>
                        <span class="scan-detail-status">${statusBadge}</span>
                        <span class="scan-detail-summary">${p.port_scan_total} probed</span>
                    </div>
                `;
            }

            detailsList.innerHTML = rowsHtml;
        } else {
            detailsContainer.style.display = 'none';
        }
    }
}

function hideScanProgress() {
    const panel = document.getElementById('scan-progress');
    if (panel) panel.style.display = 'none';
}

async function cancelScan() {
    try {
        await api('scan/cancel', {}, 'POST');
        showToast('Scan cancelled', 'warning');
    } catch (e) {
        showToast('Could not cancel: ' + e.message, 'error');
    }
}

// Reports the outcome of a finished job. Networks that were rate limited or
// failed are surfaced rather than being hidden behind a success message.
function reportScanOutcome(p) {
    const scanned = (p.networks || []).filter(n => n.status === 'scanned');
    if (p.status === 'cancelled') {
        showToast('Scan cancelled', 'warning');
        if (scanned.length) setTimeout(refreshAfterScan, 1000);
        return;
    }
    if (scanned.length === 0) {
        const reason = (p.networks || []).find(n => n.error)?.error;
        showToast(reason ? 'Scan failed: ' + reason : 'No networks could be scanned', 'warning');
        return;
    }
    const where = p.network_count > 1 ? ` across ${scanned.length} network${scanned.length === 1 ? '' : 's'}` : '';
    showToast(`Found ${p.device_count} device${p.device_count === 1 ? '' : 's'}${where}`, 'success');
    setTimeout(refreshAfterScan, 1000);
}

// refreshAfterScan brings in the newly discovered devices without throwing away
// the user's scroll position, search text or filters.
async function refreshAfterScan() {
    if (!(await refreshInPlace())) location.reload();
}

// Follows a scan that is already running until it stops. Scans live on the
// server, not in the page, so this is used both by the page that starts one and
// by any page loaded while one is already in progress.
async function followScan() {
    while (true) {
        await new Promise(r => setTimeout(r, SCAN_POLL_MS));
        const progress = (await api('scan/progress')).data;
        // Stop when the scan ends, or when the current job is an automatic
        // background scan: the user's scan has finished and the background
        // scanner has taken the single job slot, so there is nothing of the
        // user's left to follow. Automatic scans never own the overlay.
        if (progress.status !== 'running' || progress.automatic) {
            if (!progress.automatic && (progress.status === 'done' || progress.status === 'cancelled' || progress.status === 'failed')) {
                showScanProgress(progress);
            } else {
                hideScanProgress();
                if (!progress.automatic) reportScanOutcome(progress);
            }
            return;
        }
        showScanProgress(progress);
    }
}

async function runScan(target) {
    try {
        const started = await api(`scan/start?network=${encodeURIComponent(target)}`, {}, 'POST');
        showScanProgress(started.data);
        await followScan();
    } catch (e) {
        hideScanProgress();
        const isRateLimit = e.message.toLowerCase().includes('rate limit');
        showToast(isRateLimit ? e.message : 'Scan failed: ' + e.message, isRateLimit ? 'warning' : 'error');
    }
}

// Picks up a scan that was started before this page was loaded, for instance
// when the user starts a scan and then moves to the settings page. Without
// this, the scan carries on invisibly and the page never notices it finish.
async function resumeScanIfRunning() {
    try {
        const progress = (await api('scan/progress')).data;
        // Only resume a scan the user started. An automatic background scan
        // must not pop the progress overlay (with its Cancel button) on its
        // own; its results simply appear on the next refresh.
        if (progress && progress.status === 'running' && !progress.automatic) {
            showScanProgress(progress);
            await followScan();
        }
    } catch (e) {
        // No scan has ever run, or this page cannot ask. Nothing to show.
    }
}

resumeScanIfRunning();

async function scanNetwork(cidr) {
    await runScan(cidr);
}

async function scanAllNetworks() {
    await runScan('all');
}

// Device filtering
// Filter set by clicking a summary chip ("flagged" / "moved"), or null.
let statChipFilter = null;
let activeNetworkFilters = [];

// Toggle the chip filter: a second click on the same chip clears it.
function applyStatChipFilter(kind) {
    statChipFilter = statChipFilter === kind ? null : kind;
    filterDevices();
    if (statChipFilter) {
        document.querySelector('.table-container')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

function toggleNetworkDropdownFilter(val) {
    const allCheckbox = document.getElementById('network-filter-all');
    const checkboxes = document.querySelectorAll('.network-filter-checkbox');
    const btn = document.getElementById('network-filter-btn');

    if (!allCheckbox || !btn) return;

    if (val === 'all') {
        if (allCheckbox.checked) {
            checkboxes.forEach(cb => cb.checked = false);
            activeNetworkFilters = [];
            btn.textContent = 'All Networks';
        } else {
            // Force 'All' to stay checked if clicked while already checked or if nothing else is selected
            allCheckbox.checked = true;
        }
    } else {
        allCheckbox.checked = false;
        activeNetworkFilters = [];
        checkboxes.forEach(cb => {
            if (cb.checked) {
                activeNetworkFilters.push(cb.value);
            }
        });

        if (activeNetworkFilters.length === 0) {
            allCheckbox.checked = true;
            btn.textContent = 'All Networks';
        } else {
            // Collect selected friendly names
            const friendlyNames = Array.from(checkboxes)
                .filter(cb => cb.checked)
                .map(cb => cb.nextElementSibling.textContent);

            if (friendlyNames.length <= 2) {
                btn.textContent = friendlyNames.join(', ');
            } else {
                btn.textContent = `${friendlyNames.length} Networks`;
            }
        }
    }

    filterDevices();
}

function filterDevices() {
    // Reflect the active chip filter on the chips, which an auto-refresh may
    // have just swapped out from under us.
    document.querySelectorAll('.stat-chip-filter').forEach(chip =>
        chip.classList.toggle('active', !!statChipFilter && chip.dataset.filter === statChipFilter));

    // Restore active states on network filter checkboxes after an auto-refresh
    const allCheckbox = document.getElementById('network-filter-all');
    const checkboxes = document.querySelectorAll('.network-filter-checkbox');
    const btn = document.getElementById('network-filter-btn');

    if (allCheckbox && btn) {
        if (activeNetworkFilters.length === 0) {
            allCheckbox.checked = true;
            checkboxes.forEach(cb => cb.checked = false);
            btn.textContent = 'All Networks';
        } else {
            allCheckbox.checked = false;
            const friendlyNames = [];
            checkboxes.forEach(cb => {
                const isActive = activeNetworkFilters.includes(cb.value);
                cb.checked = isActive;
                if (isActive) {
                    friendlyNames.push(cb.nextElementSibling.textContent);
                }
            });

            if (friendlyNames.length <= 2) {
                btn.textContent = friendlyNames.join(', ');
            } else {
                btn.textContent = `${friendlyNames.length} Networks`;
            }
        }
    }

    const search = (document.getElementById('device-search')?.value || '').toLowerCase();
    const statusFilter = document.getElementById('device-filter')?.value || 'all';
    const groupFilter = document.getElementById('group-filter')?.value || 'all';

    let visible = 0;
    document.querySelectorAll('.device-row').forEach(row => {
        const text = [row.dataset.ip, row.dataset.hostname, row.dataset.customHostname || '', row.dataset.customWebUrl || '', row.dataset.mac, row.dataset.vendor, row.dataset.label, row.dataset.type, row.dataset.network || '', row.dataset.assignment || ''].join(' ').toLowerCase();
        const status = row.dataset.status;
        const group = row.dataset.group || '';
        const network = (row.dataset.network || '').toLowerCase();

        const matchSearch = !search || text.includes(search);
        const matchStatus = statusFilter === 'all' ||
            (statusFilter === 'online' && (status === 'online' || status === 'recent')) ||
            (statusFilter === 'offline' && status === 'offline');
        const matchGroup = groupFilter === 'all' || group === groupFilter;
        const matchChip = !statChipFilter ||
            (statChipFilter === 'moved' && row.dataset.moved === '1') ||
            (statChipFilter === 'flagged' && row.dataset.flagged === '1');
        const matchNetwork = activeNetworkFilters.length === 0 || activeNetworkFilters.includes(network);

        const show = matchSearch && matchStatus && matchGroup && matchChip && matchNetwork;
        row.style.display = show ? '' : 'none';
        if (show) visible++;
    });

    const countEl = document.getElementById('device-count');
    if (countEl) countEl.textContent = `Showing ${visible} device${visible === 1 ? '' : 's'}`;
}

// Device editing
async function editDevice(ip) {
    const modal = document.getElementById('edit-modal');
    const row = document.querySelector(`.device-row[data-ip="${CSS.escape(ip)}"]`);
    if (!modal || !row) return;

    // 1. Populate General Read-Only Stats (Left Panel)
    const ipDisplay = document.getElementById('detail-ip');
    if (ipDisplay) ipDisplay.textContent = ip;

    const macDisplay = document.getElementById('detail-mac');
    if (macDisplay) {
        const macVal = row.dataset.macOriginal || row.dataset.mac || '-';
        macDisplay.textContent = macVal.toUpperCase();
    }

    const vendorDisplay = document.getElementById('detail-vendor');
    if (vendorDisplay) vendorDisplay.textContent = row.dataset.vendorOriginal || 'Unknown';

    const firstSeenDisplay = document.getElementById('detail-firstseen');
    if (firstSeenDisplay) {
        const dateVal = new Date(row.dataset.firstseen);
        firstSeenDisplay.textContent = isNaN(dateVal.getTime()) ? row.dataset.firstseen : dateVal.toLocaleString();
    }

    const lastSeenDisplay = document.getElementById('detail-lastseen');
    if (lastSeenDisplay) {
        const dateVal = new Date(row.dataset.lastseenDisplay);
        lastSeenDisplay.textContent = isNaN(dateVal.getTime()) ? row.dataset.lastseenDisplay : dateVal.toLocaleString();
    }

    const responseTimeDisplay = document.getElementById('detail-responsetime');
    if (responseTimeDisplay) responseTimeDisplay.textContent = row.dataset.responsetime || 'N/A';

    // 2. Populate Edit Form Fields (Right Panel)
    document.getElementById('edit-ip').value = ip;
    const ipDispInput = document.getElementById('edit-ip-display');
    if (ipDispInput) ipDispInput.value = ip;
    document.getElementById('edit-label').value = row.dataset.labelOriginal || '';
    document.getElementById('edit-custom-hostname').value = row.dataset.customHostnameOriginal || '';
    document.getElementById('edit-custom-web-url').value = row.dataset.customWebUrlOriginal || '';
    document.getElementById('edit-custom-type').value = row.dataset.customTypeOriginal || '';
    document.getElementById('edit-notes').value = row.dataset.notes || '';

    // 3. Fetch and Render Device Presence Events (Left Panel Timeline)
    const timelineEl = document.getElementById('detail-timeline');
    if (timelineEl) {
        timelineEl.innerHTML = '<div class="timeline-loading">Loading activity history...</div>';
        try {
            const macVal = row.dataset.macOriginal || row.dataset.mac || '';
            const res = await fetch(`/api/scans/events?mac=${encodeURIComponent(macVal)}`);
            const result = await res.json();
            if (result.success && result.data && result.data.length > 0) {
                timelineEl.innerHTML = result.data.map(event => {
                    const dateVal = new Date(event.created_at);
                    const ago = relativeTime(Math.floor(dateVal.getTime() / 1000));
                    let detailText = '';
                    if (event.event === 'leave') {
                        detailText = `went offline (was connected for ${formatSeconds(event.duration)})`;
                    } else if (event.event === 'return') {
                        detailText = `reconnected (was gone for ${formatSeconds(event.duration)})`;
                    } else if (event.event === 'join') {
                        detailText = `joined network for the first time`;
                    }
                    const badgeClass = event.event === 'join' ? 'join' : (event.event === 'leave' ? 'leave' : 'return');
                    return `
                        <div class="timeline-event-item" style="display:flex; flex-direction:column; gap:4px; padding:8px; border-bottom:1px solid var(--border); font-size:0.85rem;">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <span class="scan-status-badge ${badgeClass}" style="padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 0.7rem; text-transform: uppercase;">${event.event}</span>
                                <span style="color:var(--text-muted); font-size:0.75rem;">${ago}</span>
                            </div>
                            <div style="color:var(--text); margin-top:2px;">${detailText}</div>
                        </div>
                    `;
                }).join('');
            } else {
                timelineEl.innerHTML = '<div class="timeline-empty" style="padding:16px; color:var(--text-muted); font-size:0.85rem; text-align:center;">No logged activity events for this device.</div>';
            }
        } catch (e) {
            timelineEl.innerHTML = '<div class="timeline-error" style="padding:16px; color:#ef4444; font-size:0.85rem; text-align:center;">Failed to load activity logs.</div>';
        }
    }

    modal.style.display = 'flex';
}

function closeModal() {
    const modal = document.getElementById('edit-modal');
    if (modal) modal.style.display = 'none';
}

async function saveDevice() {
    const ip = document.getElementById('edit-ip').value;
    const label = document.getElementById('edit-label').value;
    const custom_hostname = document.getElementById('edit-custom-hostname').value;
    const custom_web_url = document.getElementById('edit-custom-web-url').value;
    const custom_type = document.getElementById('edit-custom-type').value;
    const group = document.getElementById('edit-group').value;
    const notes = document.getElementById('edit-notes').value;
    try {
        const result = await api('device', { ip, label, custom_hostname, custom_web_url, custom_type, group, notes }, 'POST');
        if (result.success) {
            showToast('Device updated', 'success');
            closeModal();
            // Keep the user where they were; editing a device halfway down a
            // long list should not jump back to the top.
            if (!(await refreshInPlace())) location.reload();
        } else {
            showToast(result.error || 'Failed to update device', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

async function deleteDevice(ip) {
    if (!confirm(`Delete device ${ip}?`)) return;
    try {
        const response = await fetch(`/api/device?ip=${encodeURIComponent(ip)}`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' }
        });
        const result = await response.json();
        if (result.success) {
            showToast('Device deleted', 'success');
            document.querySelector(`.device-row[data-ip="${CSS.escape(ip)}"]`)?.remove();
            filterDevices(); // Update count
        } else {
            showToast(result.error || 'Failed to delete', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

async function updateDeviceGroup(select) {
    const ip = select.dataset.ip;
    const group = select.value;
    try {
        const result = await api('device', { ip, group }, 'POST');
        if (result.success) {
            showToast('Group updated', 'success');
            // Update data attribute, then re-apply the current filters so a row
            // moved out of the active group filter stops showing (and the
            // "Showing N devices" count stays honest) without waiting for the
            // next refresh.
            const row = select.closest('.device-row');
            if (row) row.dataset.group = group;
            filterDevices();
        } else {
            showToast(result.error || 'Failed to update', 'error');
        }
    } catch (e) {
        showToast('Failed to update group', 'error');
    }
}

// Copy to clipboard.
//
// The async Clipboard API (navigator.clipboard) is only exposed in a secure
// context: HTTPS, or localhost. On a phone opening the dashboard over plain
// http on the LAN (http://<pi-ip>:291) it is not available, so we fall back to
// the legacy execCommand path. That is how most people reach a self-hosted
// instance, so the fallback is the common case, not an edge one.
function copyToClipboard(text, event) {
    const ok = () => showCopied(event);
    const fail = () => showToast('Failed to copy', 'error');
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(ok).catch(() => {
            if (legacyCopy(text)) ok(); else fail();
        });
    } else if (legacyCopy(text)) {
        ok();
    } else {
        fail();
    }
}

// The floating "Copied!" note at the tap/cursor point.
function showCopied(event) {
    const feedback = document.createElement('div');
    feedback.className = 'copy-feedback';
    feedback.textContent = 'Copied!';
    document.body.appendChild(feedback);
    // .copy-feedback is position: fixed, so it is placed in viewport
    // coordinates (clientX/clientY). pageX/pageY include the scroll offset,
    // which pushed the note far below the viewport once the page was scrolled
    // down (e.g. the IPv6 rows), so it never showed there. A synthetic event
    // may lack coordinates, so fall back to the centre of the screen.
    //
    // Centre the note on the tap, then clamp it inside the viewport keeping a
    // comfortable margin from every edge. On a phone the values are right
    // aligned in their cards, so the tap lands near the right edge; without a
    // real margin the note sits flush against (or off) the screen edge, which
    // is what looked wrong. Measured after append for its real size.
    const pad = 16;
    const w = feedback.offsetWidth;
    const x = event && event.clientX ? event.clientX : window.innerWidth / 2;
    const y = event && event.clientY ? event.clientY : 40;
    const left = Math.max(pad, Math.min(x - w / 2, window.innerWidth - w - pad));
    const top = Math.max(pad, y - 30);
    feedback.style.left = left + 'px';
    feedback.style.top = top + 'px';
    setTimeout(() => feedback.remove(), 800);
}

// Legacy clipboard copy for non-secure contexts (plain-http LAN access from a
// phone). Uses a hidden, selectable field and document.execCommand('copy'),
// which is deprecated but is the only clipboard path available without HTTPS
// and still works across current mobile and desktop browsers. The Range-based
// selection is what makes it work on iOS Safari, where textarea.select() alone
// does not. Returns whether the copy succeeded, and restores any prior page
// selection so the user's own text selection is left untouched.
function legacyCopy(text) {
    let ok = false;
    const field = document.createElement('textarea');
    field.value = text;
    field.contentEditable = 'true';
    field.readOnly = false;
    field.style.position = 'fixed';
    field.style.top = '-1000px';
    field.style.opacity = '0';
    document.body.appendChild(field);
    const selection = window.getSelection();
    const previous = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null;
    try {
        const range = document.createRange();
        range.selectNodeContents(field);
        selection.removeAllRanges();
        selection.addRange(range);
        field.setSelectionRange(0, text.length);
        ok = document.execCommand('copy');
    } catch (e) {
        ok = false;
    }
    document.body.removeChild(field);
    if (selection) {
        selection.removeAllRanges();
        if (previous) selection.addRange(previous);
    }
    return ok;
}

// Export devices
function exportDevices(format) {
    const rows = document.querySelectorAll('.device-row');
    const devices = [];

    rows.forEach(row => {
        if (row.style.display !== 'none') {
            devices.push({
                ip: row.dataset.ip,
                hostname: row.querySelector('.hostname-cell')?.textContent?.trim() || '',
                mac: row.dataset.mac?.toUpperCase() || '',
                vendor: row.querySelector('.vendor-cell')?.textContent?.trim() || '',
                label: row.dataset.labelOriginal || '',
                group: row.dataset.group || '',
                status: row.dataset.status || ''
            });
        }
    });

    let content, filename, type;

    if (format === 'csv') {
        const headers = ['IP', 'Hostname', 'MAC', 'Vendor', 'Label', 'Group', 'Status'];
        const csvRows = [headers.join(',')];
        devices.forEach(d => {
            csvRows.push([d.ip, d.hostname, d.mac, d.vendor, d.label, d.group, d.status]
                .map(v => `"${(v || '').replace(/"/g, '""')}"`)
                .join(','));
        });
        content = csvRows.join('\n');
        filename = 'devices.csv';
        type = 'text/csv';
    } else {
        content = JSON.stringify(devices, null, 2);
        filename = 'devices.json';
        type = 'application/json';
    }

    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);

    toggleDropdown('export-menu');
    showToast(`Exported ${devices.length} devices`, 'success');
}

// Dropdown toggle
function toggleDropdown(id) {
    const menu = document.getElementById(id);
    if (menu) {
        menu.classList.toggle('show');
        // Close on click outside
        if (menu.classList.contains('show')) {
            setTimeout(() => {
                document.addEventListener('click', function closeDropdown(e) {
                    if (!menu.contains(e.target)) {
                        menu.classList.remove('show');
                        document.removeEventListener('click', closeDropdown);
                    }
                });
            }, 0);
        }
    }
}

// Table sorting
let sortColumn = null;
let sortAsc = true;

// compareRows orders two device rows by the active column and direction. Split
// out so the sort can be re-applied after an auto-refresh without re-toggling
// the direction.
function compareRows(a, b, column) {
    let valA, valB;

    switch (column) {
        case 'ip':
            // Sort IP addresses numerically
            valA = a.dataset.ip.split('.').map(n => n.padStart(3, '0')).join('');
            valB = b.dataset.ip.split('.').map(n => n.padStart(3, '0')).join('');
            break;
        case 'hostname':
            valA = a.dataset.hostname || 'zzz';
            valB = b.dataset.hostname || 'zzz';
            break;
        case 'mac':
            valA = a.dataset.mac || 'zzz';
            valB = b.dataset.mac || 'zzz';
            break;
        case 'vendor':
            valA = a.dataset.vendor || 'zzz';
            valB = b.dataset.vendor || 'zzz';
            break;
        case 'status':
            const order = { online: 0, recent: 1, offline: 2 };
            valA = order[a.dataset.status] ?? 3;
            valB = order[b.dataset.status] ?? 3;
            break;
        case 'lastseen':
            valA = parseInt(a.dataset.lastseen) || 0;
            valB = parseInt(b.dataset.lastseen) || 0;
            break;
        default:
            valA = a.dataset[column] || '';
            valB = b.dataset[column] || '';
    }

    if (valA < valB) return sortAsc ? -1 : 1;
    if (valA > valB) return sortAsc ? 1 : -1;
    return 0;
}

// applyCurrentSort reorders the rows in the DOM to match the active sort. It
// does nothing when no column is sorted, so a freshly loaded (server-ordered)
// table is left as the server sent it.
function applyCurrentSort() {
    if (!sortColumn) return;
    const tbody = document.getElementById('devices-tbody');
    if (!tbody) return;
    const rows = Array.from(tbody.querySelectorAll('.device-row'));
    rows.sort((a, b) => compareRows(a, b, sortColumn));
    rows.forEach(row => tbody.appendChild(row));
}

// updateSortIndicator shows which column is sorted and in which direction. The
// arrow flips between ascending and descending; every other column shows the
// neutral glyph. The header row is not replaced on refresh, so this only needs
// to run when the sort itself changes.
function updateSortIndicator() {
    document.querySelectorAll('.table th[data-sort]').forEach(th => {
        const icon = th.querySelector('.sort-icon');
        if (th.dataset.sort === sortColumn) {
            th.classList.add('sorted');
            if (icon) icon.textContent = sortAsc ? '↑' : '↓';
        } else {
            th.classList.remove('sorted');
            if (icon) icon.textContent = '↕';
        }
    });
}

function sortTable(column) {
    if (sortColumn === column) {
        sortAsc = !sortAsc;
    } else {
        sortColumn = column;
        sortAsc = true;
    }
    applyCurrentSort();
    updateSortIndicator();
}

// Auto-refresh
//
// Refreshing must never disturb what the user is doing. Reloading the page
// would reset the scroll position, empty the search box, drop the status and
// group filters and undo any sorting, every thirty seconds. Instead the page is
// fetched in the background and only the parts that carry data are swapped in.
const AUTO_REFRESH_MS = 30000;
let autoRefreshInterval = null;

// refreshInPlace replaces the device table, the summary cards and the scan
// footer with fresh copies from the server.
//
// The markup comes from the server rather than being rebuilt here, so there is
// only ever one definition of how a device row looks.
//
// Returns false if the refresh could not be applied, which usually means the
// session has ended and the response was the login page.
async function refreshInPlace() {
    let doc;
    try {
        const response = await fetch(location.href, { credentials: 'same-origin' });
        if (!response.ok) return false;
        doc = new DOMParser().parseFromString(await response.text(), 'text/html');
    } catch (e) {
        return false;
    }

    const freshRows = doc.getElementById('devices-tbody');
    if (!freshRows) return false;

    document.getElementById('devices-tbody')?.replaceWith(freshRows);

    for (const selector of ['.stat-strip', '.table-footer', '#device-count', '#scan-time-top']) {
        const current = document.querySelector(selector);
        const replacement = doc.querySelector(selector);
        if (current && replacement) current.replaceWith(replacement);
    }

    // The search box, filter dropdowns and column sort are deliberately left
    // alone, so re-apply what they currently say to the rows that just arrived.
    // Without re-sorting, a live-refreshing table would jump back to server
    // order every interval, quietly undoing the user's chosen sort.
    updateRelativeTimes();
    filterDevices();
    applyCurrentSort();
    // Let the scroll-dock re-measure in case the new strip is a different height.
    window.dispatchEvent(new Event('devices-refreshed'));
    return true;
}

function startAutoRefresh() {
    if (autoRefreshInterval) return;
    autoRefreshInterval = setInterval(async () => {
        // If the refresh could not be applied the session has probably ended.
        // Reload so the user is taken to the login page rather than left
        // looking at a table that has quietly stopped updating.
        if (!(await refreshInPlace())) location.reload();
    }, AUTO_REFRESH_MS);
}

// Continuous scan is the single control for "live vs snapshot". When on, the
// server keeps scanning AND the browser auto-refreshes to show it AND the "Live"
// cue appears; when off, everything is a static snapshot. Binding the view to
// this one setting removes the confusing "scanning but frozen" combination.
// The initial state is rendered into the toggle by the server.
let continuousScan = !!(document.getElementById('continuous-scan-toggle') &&
    document.getElementById('continuous-scan-toggle').classList.contains('active'));

function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
}

// Bring the view (auto-refresh polling and the "Live" cue) in line with the
// current continuous-scan state.
function applyContinuousScanState() {
    document.documentElement.classList.toggle('live-view', continuousScan);
    if (continuousScan) startAutoRefresh();
    else stopAutoRefresh();
}

// toggleContinuousScan switches the server's background scanner on or off at
// runtime. The choice is persisted server-side, so it survives a restart and
// lets a user scan once and sit on the snapshot.
async function toggleContinuousScan() {
    const toggle = document.getElementById('continuous-scan-toggle');
    if (!toggle) return;
    const next = !continuousScan;
    try {
        const res = await api('scan/continuous', { enabled: next }, 'POST');
        if (!res || !res.success) throw new Error((res && res.error) || 'request failed');
    } catch (e) {
        showToast('Could not change continuous scan: ' + e.message, 'error');
        return;
    }
    continuousScan = next;
    toggle.classList.toggle('active', next);
    toggle.setAttribute('aria-checked', next ? 'true' : 'false');
    applyContinuousScanState();
    showToast(next
        ? 'Continuous scan on: the server keeps scanning your networks and the view updates automatically.'
        : 'Continuous scan off: showing a static snapshot. Click Scan All whenever you want a fresh one.',
        'info', 5000);
}

// Start the view in whatever state the server reports.
applyContinuousScanState();

// Keyboard support for the toolbar switch (role="switch" tabindex="0").
document.addEventListener('keydown', e => {
    const sw = e.target.closest && e.target.closest('.toggle-switch[role="switch"]');
    if (sw && (e.key === 'Enter' || e.key === ' ')) {
        e.preventDefault();
        sw.click();
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', e => {
    // Ignore if typing in input
    if (e.target.matches('input, textarea, select')) return;

    switch (e.key.toLowerCase()) {
        case '/':
            e.preventDefault();
            document.getElementById('device-search')?.focus();
            break;
        case 'r':
            refreshAfterScan();
            break;
        case 't':
            toggleTheme();
            break;
        // Escape is handled by a dedicated listener below so it also works
        // while focus is inside a modal input, where this handler bails out.
    }
});

// Close modal on backdrop click
document.addEventListener('click', e => {
    if (e.target.classList.contains('modal')) closeModal();
});

// Close modal on Escape
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeModal();
});

// --- Relative times ---------------------------------------------------
//
// "3 min ago" is rendered once by the server. Left alone it freezes, so a page
// open for an hour still claims three minutes, which is exactly the false
// impression these timestamps exist to prevent. Anything carrying a
// data-relative-time attribute (a unix timestamp) is rewritten periodically.

function relativeTime(unixSeconds) {
    const diff = Math.floor(Date.now() / 1000) - unixSeconds;

    if (diff < 0) return 'just now';
    if (diff < 60) return 'just now';

    const minutes = Math.floor(diff / 60);
    if (minutes < 60) return minutes === 1 ? '1 min ago' : `${minutes} min ago`;

    const hours = Math.floor(diff / 3600);
    if (hours < 24) return hours === 1 ? '1 hr ago' : `${hours} hr ago`;

    const days = Math.floor(diff / 86400);
    if (days < 7) return days === 1 ? '1 day ago' : `${days} days ago`;

    // Older than a week, show the date instead, matching the server format.
    return new Date(unixSeconds * 1000).toLocaleDateString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric'
    });
}

function updateRelativeTimes() {
    document.querySelectorAll('[data-relative-time]').forEach(el => {
        const ts = parseInt(el.dataset.relativeTime, 10);
        if (!isNaN(ts) && ts > 0) {
            el.textContent = relativeTime(ts);
        }
    });
}

updateRelativeTimes();
setInterval(updateRelativeTimes, 30000);

// --- Tailscale control ------------------------------------------------

// connectTailscale brings the machine up on its tailnet.
//
// If the machine still needs to sign in, the server returns a login URL
// instead of connecting, which is shown as a link rather than trying to
// automate the browser sign-in.
async function connectTailscale() {
    const msg = document.getElementById('tailscale-message');
    if (msg) msg.textContent = 'Connecting...';
    try {
        const result = await api('tailscale/connect', {}, 'POST');
        const data = result.data || {};

        if (data.login_url) {
            if (msg) {
                // Build the link with the DOM rather than innerHTML so the URL
                // cannot inject markup.
                msg.textContent = 'Tailscale needs you to sign in: ';
                const a = document.createElement('a');
                a.href = data.login_url;
                a.target = '_blank';
                a.rel = 'noopener';
                a.textContent = 'open sign in';
                msg.appendChild(a);
                msg.appendChild(document.createTextNode('. Finish it, then refresh this page.'));
            }
            return;
        }

        showToast('Tailscale connected', 'success');
        setTimeout(() => location.reload(), 1000);
    } catch (e) {
        if (msg) msg.textContent = '';
        showToast('Could not connect: ' + e.message, 'error');
    }
}

// disconnectTailscale takes the machine off its tailnet, after warning that
// this can cut the connection the user is reaching the dashboard through.
async function disconnectTailscale() {
    const warning =
        'Disconnect Tailscale?\n\n' +
        'If you are reaching this dashboard over Tailscale, disconnecting will ' +
        'cut your connection and you will need local access to reconnect.';
    if (!confirm(warning)) return;

    try {
        await api('tailscale/disconnect', {}, 'POST');
        showToast('Tailscale disconnected', 'warning');
        setTimeout(() => location.reload(), 1000);
    } catch (e) {
        showToast('Could not disconnect: ' + e.message, 'error');
    }
}

// Summary strip scroll-dock: as the page scrolls and the strip's top reaches
// the header, add .strip-docked to <body>. CSS then lifts the strip to
// position: fixed in the header band (transparent + light). It snaps in the
// instant it touches, so the glass bar is never painted over the header.
//
// The whole thing is driven by a class on <body> and matched by CSS selector;
// the strip is never moved or held in a variable, so an auto-refresh that swaps
// the strip element out cannot break it. The holder reserves the strip's height
// (via --strip-h) so the page never jumps. No-ops on narrow screens and reduced
// motion.
(function initStatDock() {
    const holder = document.querySelector('.stat-strip-holder');
    const header = document.querySelector('.header');
    if (!holder || !header) return;

    const wide = window.matchMedia('(min-width: 1100px)');
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)');
    const brand = header.querySelector('.header-brand');
    const nav = header.querySelector('.header-nav');
    let touchAt = Infinity;

    // Bound the docked strip to the space between the logo and the nav, so it
    // can never slide under either. The nav widens when a "Sign out" link is
    // present (auth enabled) and shifts with the monitor width, so measure it
    // live rather than assuming a fixed layout.
    function measureDockBounds() {
        if (!brand || !nav) return;
        const gap = 20;
        const left = Math.round(brand.getBoundingClientRect().right + gap);
        const right = Math.round(window.innerWidth - nav.getBoundingClientRect().left + gap);
        document.documentElement.style.setProperty('--dock-left', Math.max(0, left) + 'px');
        document.documentElement.style.setProperty('--dock-right', Math.max(0, right) + 'px');
    }

    function measure() {
        // Reserve exactly the strip's height, and find the scroll offset at
        // which the holder's top reaches the header's bottom (the touch point).
        // Re-query the strip so a refreshed one is always measured.
        const strip = holder.querySelector('.stat-strip');
        if (strip) holder.style.setProperty('--strip-h', strip.offsetHeight + 'px');
        touchAt = Math.max(0, holder.getBoundingClientRect().top + window.scrollY - header.offsetHeight);
        measureDockBounds();
    }

    // Drop the least-critical pieces from the docked strip only as far as
    // needed to keep it on one line inside its band: the scanned/Live line
    // first, then the chips. Driven by the real overflow (scrollWidth beyond
    // the band's clientWidth), so it adapts to any monitor width and nav size
    // instead of guessing a breakpoint.
    function fitDock() {
        const strip = holder.querySelector('.stat-strip');
        if (!strip) return;
        document.body.classList.remove('dock-hide-scan', 'dock-hide-meta');
        if (strip.scrollWidth > strip.clientWidth + 1) document.body.classList.add('dock-hide-scan');
        if (strip.scrollWidth > strip.clientWidth + 1) document.body.classList.add('dock-hide-meta');
    }

    let wasDocked = false;
    function onScroll() {
        const docked = wide.matches && !reduce.matches && window.scrollY >= touchAt;
        document.body.classList.toggle('strip-docked', docked);
        if (docked && !wasDocked) fitDock();
        if (!docked) document.body.classList.remove('dock-hide-scan', 'dock-hide-meta');
        wasDocked = docked;
    }

    function remeasure() {
        // Only re-measure the reserve while undocked; a docked holder is a fixed
        // reserve. The dock bounds, though, must track the header at any width.
        if (!document.body.classList.contains('strip-docked')) measure();
        else measureDockBounds();
        onScroll();
        if (document.body.classList.contains('strip-docked')) fitDock();
    }

    measure();
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', remeasure);
    // An auto-refresh can swap in a strip of a different height (e.g. a flagged
    // chip appears), so re-measure the reserve and touch point after each one.
    window.addEventListener('devices-refreshed', remeasure);
})();

// Back-to-top button: a floating orangutan that appears once the page is
// scrolled past a threshold and smoothly returns to the top when clicked.
(function initScrollTop() {
    const btn = document.getElementById('scroll-top');
    if (!btn) return;

    const THRESHOLD = 300;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)');

    // Sit the button in the bottom-right corner, always clear of the vertical
    // scrollbar. That scrollbar has real width on Linux/Windows (~15px) and
    // zero width on overlay-scrollbar systems like macOS, so measure it
    // (innerWidth includes it, clientWidth does not) and add it to the inset.
    // This keeps the button off the scrollbar on every platform and view.
    function place() {
        const scrollbar = Math.max(0, window.innerWidth - document.documentElement.clientWidth);
        btn.style.left = 'auto';
        btn.style.right = (18 + scrollbar) + 'px';
    }

    function onScroll() {
        btn.classList.toggle('visible', window.scrollY > THRESHOLD);
    }

    place();
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', place);
    window.addEventListener('devices-refreshed', place);

    btn.addEventListener('click', () => {
        window.scrollTo({ top: 0, behavior: reduce.matches ? 'auto' : 'smooth' });
    });
})();

// Instant tooltips for truncated table cells (hostname, vendor, label). The
// native `title` attribute waits ~1s before showing (and resets to that delay
// when "cold"), so those cells use this instead: one shared element at the body
// level, shown the moment the pointer enters a cell whose text is actually
// clipped. Positioned in fixed coordinates so the cell's overflow never clips it.
(function initCellTips() {
    const table = document.getElementById('devices-table');
    if (!table) return;

    const tip = document.createElement('div');
    tip.id = 'cell-tip';
    tip.setAttribute('role', 'tooltip');
    document.body.appendChild(tip);

    const SELECTOR = '.hostname-cell, .vendor-cell, .label-cell, .ip-cell, .mac-cell';

    function isClipped(cell) {
        return cell.scrollWidth > cell.clientWidth + 1;
    }

    function show(cell) {
        const text = (cell.textContent || '').trim();
        if (!text || !isClipped(cell)) return;

        // Match the cell's own text exactly so the reveal reads as the same text
        // un-truncating in place rather than a separate label.
        const cs = getComputedStyle(cell);
        const c = cell.getBoundingClientRect();
        tip.textContent = text;
        tip.style.fontFamily = cs.fontFamily;
        tip.style.fontSize = cs.fontSize;
        tip.style.fontWeight = cs.fontWeight;
        tip.style.fontStyle = cs.fontStyle;
        tip.style.letterSpacing = cs.letterSpacing;
        tip.style.color = cs.color;
        tip.style.paddingLeft = cs.paddingLeft;
        tip.style.paddingRight = cs.paddingRight;
        tip.style.height = Math.round(c.height) + 'px';
        tip.classList.add('show');

        // Overlay the cell and grow to the right; nudge left only if the full
        // value would run off the right edge of the window.
        const t = tip.getBoundingClientRect();
        let left = c.left;
        if (left + t.width > window.innerWidth - 6) {
            left = Math.max(6, window.innerWidth - t.width - 6);
        }
        tip.style.left = Math.round(left) + 'px';
        tip.style.top = Math.round(c.top) + 'px';
    }

    function hide() {
        tip.classList.remove('show');
    }

    // Delegated hover. mouseover/mouseout bubble, so they cover cells added by
    // an auto-refresh too. Only hide when the pointer truly leaves the cell.
    table.addEventListener('mouseover', function (e) {
        const cell = e.target.closest(SELECTOR);
        if (cell) show(cell);
    });
    table.addEventListener('mouseout', function (e) {
        const cell = e.target.closest(SELECTOR);
        if (cell && !cell.contains(e.relatedTarget)) hide();
    });
    // A stale tooltip must not linger over new content.
    window.addEventListener('scroll', hide, { passive: true });
})();

// Click-to-copy for value cells (IP, MAC, hostname, vendor). Driven by a
// data-copy attribute and event delegation rather than an inline onclick, so a
// value that contains quotes (a vendor name, say) can never break out of the
// handler, and rows added by an auto-refresh are covered automatically. Empty
// values (a placeholder like "Unknown") carry data-copy="" and are skipped.
(function initCopyCells() {
    const table = document.getElementById('devices-table');
    if (!table) return;
    table.addEventListener('click', function (e) {
        const cell = e.target.closest('td[data-copy]');
        if (!cell) return;
        const value = cell.getAttribute('data-copy');
        if (value) copyToClipboard(value, e);
    });
})();

// Clickable summary chips: clicking "N flagged" or "N moved" filters the device
// list to just those devices (and a second click clears it). Delegated on the
// document so it keeps working after an auto-refresh swaps the strip, and while
// the strip is docked in the header.
(function initStatChipFilters() {
    document.addEventListener('click', function (e) {
        const chip = e.target.closest && e.target.closest('.stat-chip-filter[data-filter]');
        if (chip) applyStatChipFilter(chip.dataset.filter);
    });
    document.addEventListener('keydown', function (e) {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        const chip = e.target.closest && e.target.closest('.stat-chip-filter[data-filter]');
        if (chip) { e.preventDefault(); applyStatChipFilter(chip.dataset.filter); }
    });
})();

// Instant tooltips for small indicators carrying a data-tip attribute (moved,
// risk, web-interface, notes). One shared bubble at the body level shown the
// moment the pointer enters the element, so there is no native `title` delay.
// Delegated on the document, so it also covers rows added by an auto-refresh.
(function initHintTips() {
    let tip = null;
    function ensure() {
        if (!tip) {
            tip = document.createElement('div');
            tip.id = 'hint-tip';
            tip.setAttribute('role', 'tooltip');
            document.body.appendChild(tip);
        }
        return tip;
    }
    function show(el) {
        const text = el.getAttribute('data-tip');
        if (!text) return;
        const t = ensure();
        t.textContent = text;
        t.classList.add('show');
        const r = el.getBoundingClientRect();
        const tr = t.getBoundingClientRect();
        let left = r.left + r.width / 2 - tr.width / 2;
        left = Math.max(6, Math.min(left, window.innerWidth - tr.width - 6));
        let top = r.top - tr.height - 8;      // above the icon by default
        if (top < 6) top = r.bottom + 8;       // drop below when no room above
        t.style.left = Math.round(left) + 'px';
        t.style.top = Math.round(top) + 'px';
    }
    function hide() {
        if (tip) tip.classList.remove('show');
    }
    document.addEventListener('mouseover', function (e) {
        const el = e.target.closest && e.target.closest('[data-tip]');
        if (el) show(el);
    });
    document.addEventListener('mouseout', function (e) {
        const el = e.target.closest && e.target.closest('[data-tip]');
        if (el && !el.contains(e.relatedTarget)) hide();
    });
    window.addEventListener('scroll', hide, { passive: true });
})();

(function initResizableColumns() {
    const table = document.getElementById('devices-table');
    if (!table) return;

    const storageKey = 'lan-orangutan-col-widths';

    // Apply saved widths
    function applySavedWidths() {
        try {
            const saved = localStorage.getItem(storageKey);
            if (!saved) return;
            const widths = JSON.parse(saved);
            Object.keys(widths).forEach(className => {
                const elements = table.querySelectorAll('.' + className);
                elements.forEach(el => {
                    el.style.width = widths[className];
                });
            });
        } catch (e) {
            console.error('Failed to apply column widths', e);
        }
    }

    // Initialize drag handles
    function initHandles() {
        const headers = table.querySelectorAll('thead th');
        headers.forEach((th, i) => {
            // No resize handle on the status and action columns
            if (th.classList.contains('col-status') || th.classList.contains('col-actions')) return;

            // Remove existing handle if any
            const existing = th.querySelector('.col-resize-handle');
            if (existing) existing.remove();

            const handle = document.createElement('div');
            handle.className = 'col-resize-handle';
            th.appendChild(handle);

            let startX, startWidth;

            handle.addEventListener('mousedown', function (e) {
                e.preventDefault();
                startX = e.pageX;
                startWidth = th.offsetWidth;
                handle.classList.add('resizing');

                function onMouseMove(e) {
                    const width = startWidth + (e.pageX - startX);
                    // Minimum width constraint
                    const minWidth = 40;
                    const finalWidth = Math.max(minWidth, width) + 'px';

                    // Apply the width to all cells in this column (by matching class name)
                    const colClass = Array.from(th.classList).find(c => c.startsWith('col-'));
                    if (colClass) {
                        const cells = table.querySelectorAll('.' + colClass);
                        cells.forEach(cell => {
                            cell.style.width = finalWidth;
                        });
                    }
                }

                function onMouseUp() {
                    handle.classList.remove('resizing');
                    document.removeEventListener('mousemove', onMouseMove);
                    document.removeEventListener('mouseup', onMouseUp);

                    // Save new widths of all columns
                    const widths = {};
                    table.querySelectorAll('thead th').forEach(h => {
                        const colClass = Array.from(h.classList).find(c => c.startsWith('col-'));
                        if (colClass && h.style.width) {
                            widths[colClass] = h.style.width;
                        }
                    });
                    localStorage.setItem(storageKey, JSON.stringify(widths));
                }

                document.addEventListener('mousemove', onMouseMove);
                document.addEventListener('mouseup', onMouseUp);
            });
        });
    }

    // Run on boot
    applySavedWidths();
    initHandles();

    // Re-apply widths and recreate handles after in-place auto refreshes
    window.addEventListener('devices-refreshed', function() {
        applySavedWidths();
        initHandles();
    });
})();

// Scans Page Live Updates & Timeline Rendering
async function initScansPage() {
    await refreshScansData();
    // Poll every 5 seconds
    setInterval(refreshScansData, 5000);
}

async function refreshScansData() {
    try {
        const historyRes = await fetch('/api/scans/history');
        const historyData = await historyRes.json();
        if (historyData.success) {
            renderScanHistory(historyData.data);
        }

        const eventsRes = await fetch('/api/scans/events');
        const eventsData = await eventsRes.json();
        if (eventsData.success) {
            renderPresenceTimeline(eventsData.data);
        }

        // Also update live progress if visible
        const progressRes = await fetch('/api/scan/progress');
        const progressData = await progressRes.json();
        if (progressData.success) {
            renderLiveProgressCard(progressData.data);
        }
    } catch (e) {
        console.error('Failed to refresh scans page data', e);
    }
}

function renderLiveProgressCard(progress) {
    const card = document.getElementById('live-progress-card');
    if (!card) return;

    if (progress.status === 'running') {
        let pct = progress.percent;
        if (pct < 0) pct = 0;
        let html = `
            <div class="progress-header" style="display: flex; justify-content: space-between; align-items: center;">
                <h3>Scanning ${progress.current_network_name || progress.current_network || ''}</h3>
                <span class="badge badge-running" style="background: var(--accent); color: white; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: bold; animation: pulse 1.5s infinite;">Running</span>
            </div>
            <div class="scan-bar" style="margin: 1rem 0; height: 12px; background: var(--bg-card-hover); border-radius: 6px; overflow: hidden;">
                <div class="scan-bar-fill" style="width: ${pct}%; height: 100%; background: var(--accent); transition: width 0.4s ease;"></div>
            </div>
            <div class="progress-meta" style="display: flex; justify-content: space-between; font-size: 0.9rem; color: var(--text-muted);">
                <span>Network ${progress.network_index} of ${progress.network_count}</span>
                <span>${pct.toFixed(0)}% Complete</span>
            </div>
        `;

        if (progress.port_scan_active) {
            let portPct = (progress.port_scan_complete / progress.port_scan_total) * 100;
            if (isNaN(portPct)) portPct = 0;
            html += `
                <div class="port-progress" style="margin-top: 1rem; border-top: 1px solid var(--border); padding-top: 1rem;">
                    <div style="display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 0.5rem;">
                        <span>Port Prober (Stage 2)</span>
                        <span>${progress.port_scan_complete}/${progress.port_scan_total} hosts done (${portPct.toFixed(0)}%)</span>
                    </div>
                    <div class="scan-bar" style="height: 6px; background: var(--bg-card-hover); border-radius: 3px; overflow: hidden;">
                        <div class="scan-bar-fill" style="width: ${portPct}%; height: 100%; background: var(--accent); transition: width 0.4s ease;"></div>
                    </div>
                </div>
            `;
        }

        card.innerHTML = html;
        card.style.display = 'block';
    } else {
        card.innerHTML = `
            <div style="text-align: center; color: var(--text-muted); padding: 1.5rem 0;">
                <p>Scanner is currently idle</p>
                <button class="btn btn-primary" style="margin-top: 1rem;" onclick="startScan('all')">Run Manual Scan</button>
            </div>
        `;
    }
}

function renderScanHistory(history) {
    const tbody = document.getElementById('scan-history-tbody');
    if (!tbody) return;

    if (!history || history.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No scan history recorded yet</td></tr>`;
        return;
    }

    tbody.innerHTML = history.map(row => {
        const date = new Date(row.timestamp);
        const dateStr = date.toLocaleString();
        const successBadge = row.success 
            ? `<span class="badge badge-success" style="background: rgba(44, 158, 107, 0.15); color: #2c9e6b; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: bold; font-size: 0.8rem;">Success</span>` 
            : `<span class="badge badge-failed" style="background: rgba(224, 132, 44, 0.15); color: #e0842c; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: bold; font-size: 0.8rem;" title="${row.error || ''}">Failed</span>`;
        
        return `
            <tr>
                <td style="padding: 0.8rem; border-bottom: 1px solid var(--border);">${dateStr}</td>
                <td style="padding: 0.8rem; border-bottom: 1px solid var(--border);"><strong>${row.network}</strong></td>
                <td style="padding: 0.8rem; border-bottom: 1px solid var(--border);">${successBadge}</td>
                <td style="padding: 0.8rem; border-bottom: 1px solid var(--border);"><span style="color: var(--accent); font-weight: bold;">${row.devices_online}</span></td>
                <td style="padding: 0.8rem; border-bottom: 1px solid var(--border);"><span style="color: #2c9e6b; font-weight: bold;">+${row.devices_joined}</span></td>
                <td style="padding: 0.8rem; border-bottom: 1px solid var(--border);"><span style="color: #2f7fd4; font-weight: bold;">+${row.devices_returned}</span></td>
                <td style="padding: 0.8rem; border-bottom: 1px solid var(--border);"><span style="color: #e0842c; font-weight: bold;">-${row.devices_left}</span></td>
                <td style="padding: 0.8rem; border-bottom: 1px solid var(--border);">${row.duration.toFixed(1)}s</td>
            </tr>
        `;
    }).join('');
}

function renderPresenceTimeline(events) {
    const container = document.getElementById('presence-timeline');
    if (!container) return;

    if (!events || events.length === 0) {
        container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 2rem 0;">No presence changes recorded yet</div>`;
        return;
    }

    container.innerHTML = events.map(evt => {
        const date = new Date(evt.created_at);
        const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const dateStr = date.toLocaleDateString([], { month: 'short', day: 'numeric' });
        
        let icon = '';
        let color = '';
        let bg = '';
        let description = '';

        if (evt.event === 'join') {
            icon = '✦';
            color = '#2c9e6b';
            bg = 'rgba(44, 158, 107, 0.1)';
            description = `joined the network for the first time`;
        } else if (evt.event === 'return') {
            icon = '✓';
            color = '#2f7fd4';
            bg = 'rgba(47, 127, 212, 0.1)';
            const durStr = formatEventDuration(evt.duration);
            description = `returned (offline for ${durStr})`;
        } else if (evt.event === 'leave') {
            icon = '✗';
            color = '#e0842c';
            bg = 'rgba(224, 132, 44, 0.1)';
            const durStr = formatEventDuration(evt.duration);
            description = `went offline (online session: ${durStr})`;
        }

        const name = evt.hostname || evt.mac || 'Unknown Device';

        return `
            <div class="timeline-item" style="display: flex; gap: 1rem; margin-bottom: 1.5rem; position: relative;">
                <div class="timeline-badge" style="width: 32px; height: 32px; border-radius: 50%; background: ${bg}; color: ${color}; display: flex; align-items: center; justify-content: center; font-weight: bold; flex-shrink: 0; border: 1px solid ${color};">
                    ${icon}
                </div>
                <div class="timeline-content" style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; flex-grow: 1; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                    <div class="timeline-header" style="font-size: 0.95rem; margin-bottom: 0.25rem;">
                        <strong>${name}</strong> <span style="color: var(--text-muted); font-size: 0.85rem;">(${evt.ip})</span> ${description}
                    </div>
                    <div class="timeline-time" style="font-size: 0.8rem; color: var(--text-muted);">${dateStr} at ${timeStr}</div>
                </div>
            </div>
        `;
    }).join('');
}

function formatEventDuration(seconds) {
    if (seconds < 60) return `${seconds.toFixed(0)}s`;
    const minutes = seconds / 60;
    if (minutes < 60) return `${minutes.toFixed(0)}m`;
    const hours = minutes / 60;
    if (hours < 24) return `${hours.toFixed(1)}h`;
    const days = hours / 24;
    return `${days.toFixed(1)}d`;
}
