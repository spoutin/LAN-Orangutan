(function (root, factory) {
    const utils = factory();
    if (typeof module === 'object' && module.exports) module.exports = utils;
    root.escapeHtml = utils.escapeHtml;
    root.sanitizeHttpUrl = utils.sanitizeHttpUrl;
    root.htmlUtils = utils;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function sanitizeHttpUrl(url) {
        if (!url || typeof url !== 'string') return '';
        const trimmed = url.trim();
        if (!trimmed) return '';
        try {
            const parsed = new URL(trimmed, 'http://localhost');
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                return trimmed;
            }
        } catch (_) {
            return '';
        }
        return '';
    }

    function renderTokenRowHtml(token) {
        const id = escapeHtml(String(token.id ?? ''));
        const name = escapeHtml(token.name || '');
        const prefix = escapeHtml(token.token_prefix || '');
        const createdDate = escapeHtml(token.createdDate || '');
        const lastUsed = escapeHtml(token.lastUsed || 'Never');
        return `
            <tr style="border-bottom: 1px solid var(--border);">
                <td style="padding: 0.75rem 0.5rem; font-weight: 500;">${name}</td>
                <td style="padding: 0.75rem 0.5rem;"><code style="background: var(--bg-main); padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.85rem;">${prefix}…</code></td>
                <td style="padding: 0.75rem 0.5rem; color: var(--text-muted); font-size: 0.85rem;">${createdDate}</td>
                <td style="padding: 0.75rem 0.5rem; color: var(--text-muted); font-size: 0.85rem;">${lastUsed}</td>
                <td style="padding: 0.75rem 0.5rem; text-align: right;">
                    <button type="button" class="btn btn-danger btn-sm js-delete-token" data-token-id="${id}" data-token-name="${name}">Revoke</button>
                </td>
            </tr>
        `;
    }

    function renderLinkedChildRowHtml(child, parentIP) {
        const childStr = String(child || '');
        const ipMatch = childStr.match(/\(([^()]+)\)\s*$/);
        const childIP = ipMatch ? ipMatch[1] : '';
        return `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 4px 0; border-bottom: 1px dashed var(--border);">
                <div style="display: flex; align-items: center; gap: 6px;">
                    <span style="color: var(--success); font-weight: bold;">🔗</span>
                    <span>${escapeHtml(childStr)}</span>
                </div>
                ${childIP ? `<button type="button" class="btn-text danger js-unlink-child" data-child-ip="${escapeHtml(childIP)}" data-parent-ip="${escapeHtml(parentIP || '')}" style="font-size: 0.75rem; background: none; border: none; color: #ef4444; cursor: pointer; padding: 2px 6px;">Unlink Alias</button>` : ''}
            </div>
        `;
    }

    function renderParentDeviceOptionHtml(dev) {
        const mac = String(dev?.mac || '');
        const name = dev?.label || dev?.custom_hostname || dev?.hostname || mac;
        const escapedValue = escapeHtml(`${name} [${mac.toUpperCase()}]`);
        const escapedMac = escapeHtml(mac);
        return `<option value="${escapedValue}" data-mac="${escapedMac}"></option>`;
    }

    function renderLiveProgressCardHtml(progress, helpers = {}) {
        const formatSeconds = typeof helpers.formatSeconds === 'function'
            ? helpers.formatSeconds
            : (s => `${Number(s) || 0}s`);

        if (!progress || progress.status !== 'running') {
            return `
                <div style="text-align: center; color: var(--text-muted); padding: 1.5rem 0;">
                    <p>Scanner is currently idle</p>
                    <div class="scan-control" style="margin-top: 1rem;">
                        <select class="scan-mode-select" aria-label="Scan type"><option value="quick">Quick scan</option><option value="deep">Deep scan</option><option value="both">Both stages</option></select>
                        <button class="btn btn-primary js-start-selected-scan" data-network="all">Run scan</button>
                    </div>
                </div>
            `;
        }

        const isDeep = progress.stage === 'deep';
        const networkPct = typeof progress.percent === 'number' && progress.percent >= 0 ? progress.percent : null;
        const portTotal = Number(progress.port_scan_total) || 0;
        const portComplete = Number(progress.port_scan_complete) || 0;
        const portPct = portTotal > 0 ? (portComplete / portTotal) * 100 : 0;
        const eta = progress.remaining != null ? formatSeconds(progress.remaining) : 'Estimating...';
        const phaseTitle = isDeep ? 'Stage 2 · Service discovery' : 'Stage 1 · Device discovery';
        const currentTarget = isDeep
            ? (progress.current_network || 'Preparing service scan')
            : (progress.current_network_name || progress.current_network || 'Preparing scan');
        const activeCount = Array.isArray(progress.active_networks) ? progress.active_networks.length : 0;
        const parallelSubtitle = !isDeep && activeCount > 1 ? `${activeCount} networks scanning in parallel · ` : '';
        const detailText = isDeep
            ? `${portComplete} of ${portTotal} known hosts checked`
            : `${parallelSubtitle}Network ${Number(progress.network_index) || 1} of ${Number(progress.network_count) || 1}`;

        const activeBadges = !isDeep && activeCount > 1
            ? `<div class="scan-network-checklist">${progress.active_networks.map(net =>
                `<div class="scan-network-row active"><span>●</span><strong>${escapeHtml(net)}</strong><em>scanning</em></div>`
            ).join('')}</div>`
            : '';

        const deepChecklist = isDeep && Array.isArray(progress.deep_networks) && progress.deep_networks.length
            ? `<div class="scan-network-checklist">${progress.deep_networks.map(network => {
                const complete = Number(network.complete) || 0;
                const total = Number(network.total) || 0;
                const activeCountNet = Number(network.active) || 0;
                const state = complete >= total ? 'complete' : activeCountNet > 0 ? 'active' : 'queued';
                const marker = state === 'complete' ? '✓' : state === 'active' ? '●' : '○';
                const active = activeCountNet > 0 ? ` · ${activeCountNet} active` : '';
                return `<div class="scan-network-row ${state}"><span>${marker}</span><strong>${escapeHtml(network.network)}</strong><em>${complete} / ${total}${active}</em></div>`;
            }).join('')}</div>`
            : '';

        const fillWidth = Math.max(0, Math.min(100, Number(isDeep ? portPct : (networkPct ?? 0)) || 0));
        const remainingAttr = progress.remaining != null ? escapeHtml(String(progress.remaining)) : '';
        const elapsedVal = Number(progress.elapsed) || 0;

        let html = `
            <div class="scan-progress-card">
              <div class="scan-progress-topline">
                <span class="scan-phase-badge">${escapeHtml(phaseTitle)}</span>
                <span class="scan-eta">ETA <span id="scan-eta-live" data-seconds="${remainingAttr}">${escapeHtml(eta)}</span></span>
              </div>
              <div class="scan-progress-title">${isDeep ? 'Service scan across selected networks' : `Scanning <strong>${escapeHtml(currentTarget)}</strong>`}</div>
              <div class="scan-progress-detail">${escapeHtml(detailText)}</div>
              <div class="scan-progress-track">
                <div class="scan-progress-fill" style="width: ${fillWidth}%"></div>
              </div>
              <div class="scan-progress-footer">
                <span>${isDeep ? `${portPct.toFixed(0)}% of service scan` : networkPct == null ? 'Measuring current scan speed...' : `${networkPct.toFixed(0)}% of full scan`}</span>
                <span><span id="scan-elapsed-live" data-seconds="${elapsedVal}">${escapeHtml(formatSeconds(elapsedVal))}</span> elapsed</span>
              </div>${deepChecklist}${activeBadges}`;

        if (progress.last_port_scan_host?.ip) {
            const host = progress.last_port_scan_host;
            const ports = host.error
                ? host.error
                : (Array.isArray(host.open_ports) && host.open_ports.length ? `Open: ${host.open_ports.join(', ')}` : 'No open ports found');
            html += `<div class="scan-latest-result"><span>Latest result</span><strong>${escapeHtml(host.hostname || host.ip)}</strong><code>${escapeHtml(host.ip)}</code><em>${escapeHtml(ports)}</em></div>`;
        }
        html += `</div>`;
        return html;
    }

    function renderPresenceStreamItemHtml(evt, opts = {}) {
        const name = evt?.hostname || evt?.mac || 'Unknown Device';
        const ip = evt?.ip || '';
        const dayTitle = opts.dayTitle || '';
        const timeStr = opts.timeStr || '';
        const relativeTime = opts.relativeTime || '';
        const fullTimeStr = opts.fullTimeStr || '';
        const durPill = opts.durPill || '';

        let badgeText = '';
        let dotClass = 'timeline-dot-join';
        let pillClass = 'timeline-pill-join';
        if (evt?.event === 'join') {
            badgeText = '✦ Joined';
            dotClass = 'timeline-dot-join';
            pillClass = 'timeline-pill-join';
        } else if (evt?.event === 'return') {
            badgeText = '↺ Returned';
            dotClass = 'timeline-dot-return';
            pillClass = 'timeline-pill-return';
        } else if (evt?.event === 'leave') {
            badgeText = '✗ Went offline';
            dotClass = 'timeline-dot-leave';
            pillClass = 'timeline-pill-leave';
        }

        return `
            <div class="timeline-stream-item" data-ip="${escapeHtml(ip)}" title="${escapeHtml(name)} (${escapeHtml(ip)}) on ${escapeHtml(dayTitle)} at ${escapeHtml(timeStr)}">
                <span class="timeline-stream-dot ${dotClass}"></span>
                <div class="timeline-stream-main">
                    <strong style="color: var(--accent);">${escapeHtml(name)}</strong>
                    <code style="color: var(--text-muted); font-size: 0.78rem;">${escapeHtml(ip)}</code>
                    <span class="timeline-pill ${pillClass}">${escapeHtml(badgeText)}</span>
                </div>
                <div class="timeline-stream-meta">
                    ${durPill}
                    <span title="${escapeHtml(fullTimeStr)}">${escapeHtml(relativeTime)}</span>
                </div>
            </div>
        `;
    }

    function buildPresenceDetailTextHtml(event, formatSecondsFn) {
        const formatSeconds = typeof formatSecondsFn === 'function' ? formatSecondsFn : (s => `${Number(s) || 0}s`);
        const safeNet = event?.network_name ? `<strong>${escapeHtml(event.network_name)}</strong>` : '';
        const dur = escapeHtml(formatSeconds(event?.duration));
        if (event?.event === 'leave') {
            const netText = safeNet ? ` on ${safeNet}` : '';
            return `went offline${netText} (was connected for ${dur})`;
        }
        if (event?.event === 'return') {
            const netText = safeNet ? ` on ${safeNet}` : '';
            return `reconnected${netText} (was gone for ${dur})`;
        }
        if (event?.event === 'join') {
            const netText = safeNet ? ` ${safeNet}` : '';
            return `joined${netText} network for the first time`;
        }
        return '';
    }

    function safeEventBadgeClass(eventName) {
        if (eventName === 'join') return 'join';
        if (eventName === 'leave') return 'leave';
        return 'return';
    }

    function renderTimelineEventItemHtml(event, ago, formatSecondsFn) {
        const detailText = buildPresenceDetailTextHtml(event, formatSecondsFn);
        const badgeClass = safeEventBadgeClass(event?.event);
        return `
            <div class="timeline-event-item" style="display:flex; flex-direction:column; gap:4px; padding:8px; border-bottom:1px solid var(--border); font-size:0.85rem;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span class="scan-status-badge ${badgeClass}" style="padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 0.7rem; text-transform: uppercase;">${escapeHtml(event?.event || '')}</span>
                    <span style="color:var(--text-muted); font-size:0.75rem;">${escapeHtml(ago)}</span>
                </div>
                <div style="color:var(--text); margin-top:2px;">${detailText}</div>
            </div>
        `;
    }

    function renderDetailedHistoryEventHtml(event, ago, formatSecondsFn) {
        const detailText = buildPresenceDetailTextHtml(event, formatSecondsFn);
        const badgeClass = safeEventBadgeClass(event?.event);
        const createdStr = escapeHtml(event?.createdStr || '');
        const ip = escapeHtml(event?.ip || '');
        const macPart = event?.mac ? `, MAC: ${escapeHtml(String(event.mac).toUpperCase())}` : '';
        return `
            <div class="timeline-event-item" style="display:flex; flex-direction:column; gap:4px; padding:12px 8px; border-bottom:1px solid var(--border); font-size:0.9rem;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span class="scan-status-badge ${badgeClass}" style="padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; text-transform: uppercase;">${escapeHtml(event?.event || '')}</span>
                    <span style="color:var(--text-muted); font-size:0.8rem;">${escapeHtml(ago)}</span>
                </div>
                <div style="color:var(--text); margin-top:4px;">${detailText}</div>
                <div style="color:var(--text-muted); font-size:0.75rem; margin-top:2px;">
                    Logged on ${createdStr} (IP: ${ip}${macPart})
                </div>
            </div>
        `;
    }

    function renderPresenceTooltipHtml(session, durText, formatTimeFn, opts = {}) {
        const formatTime = typeof formatTimeFn === 'function' ? formatTimeFn : (d => d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
        const fontSize = opts.fontSize || '0.75rem';
        const titleSize = opts.titleSize || '0.8rem';
        const includeIP = !!opts.includeIP;
        const startStr = escapeHtml(formatTime(session.start));
        const endStr = session.isCurrent ? (opts.currentEndLabel || 'Present') : escapeHtml(formatTime(session.end));
        const ipHtml = includeIP && session.ip
            ? `<span style="display: block; color: var(--text-muted); font-size: 0.75rem; margin-top: 4px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 4px;">IP Address: ${escapeHtml(session.ip)}</span>`
            : '';
        const netMargin = includeIP && session.ip ? 'margin-top: 2px;' : 'margin-top: 4px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 4px;';
        const netHtml = session.networkName
            ? `<span style="display: block; color: var(--text-muted); font-size: 0.75rem; ${netMargin}">Network: ${escapeHtml(session.networkName)}</span>`
            : '';

        return `
            <div class="presence-tooltip">
                <strong style="color: var(--success); font-size: ${titleSize}; display: block; margin-bottom: 4px;">🟩 ${session.isCurrent ? 'Active Online Session' : 'Completed Session'}</strong>
                <span style="display: block; margin-bottom: 2px; font-size: ${fontSize};"><strong>Start:</strong> ${startStr}</span>
                <span style="display: block; margin-bottom: 2px; font-size: ${fontSize};"><strong>End:</strong> ${endStr}</span>
                <span style="display: block; margin-bottom: 2px; font-size: ${fontSize};"><strong>Duration:</strong> ${escapeHtml(durText)}</span>
                ${ipHtml}
                ${netHtml}
            </div>
        `;
    }

    return {
        escapeHtml,
        sanitizeHttpUrl,
        renderTokenRowHtml,
        renderLinkedChildRowHtml,
        renderParentDeviceOptionHtml,
        renderLiveProgressCardHtml,
        renderPresenceStreamItemHtml,
        renderTimelineEventItemHtml,
        renderDetailedHistoryEventHtml,
        renderPresenceTooltipHtml,
    };
});
