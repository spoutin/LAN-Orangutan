(function (root, factory) {
    const mod = factory();
    if (typeof module === 'object' && module.exports) module.exports = mod;
    root.deviceOperationState = mod;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    function shouldSyncSidebarForm({ hasUnsavedChanges, isFormFocused }) {
        return !hasUnsavedChanges && !isFormFocused;
    }

    function isElementProtectedFromTimeUpdate(el) {
        if (!el) return true;
        if (typeof el.closest === 'function' && (el.closest('.deep-scan-progress') || el.closest('.scanning'))) {
            return true;
        }
        return false;
    }

    function formatLastDeepScan(isoDateString, isScanning) {
        if (isScanning) {
            return {
                html: '<span class="deep-scan-progress"><svg class="spinner-svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/></svg>Scanning services...</span>',
                hasRelativeTime: false,
                unix: null,
            };
        }
        if (!isoDateString) {
            return {
                html: 'Never',
                hasRelativeTime: false,
                unix: null,
            };
        }
        const scannedAt = new Date(isoDateString);
        if (isNaN(scannedAt.getTime())) {
            return {
                html: 'Never',
                hasRelativeTime: false,
                unix: null,
            };
        }
        const unix = Math.floor(scannedAt.getTime() / 1000);
        return {
            html: `${scannedAt.toLocaleString()} · <span class="scan-time-relative" data-relative-time="${unix}"></span>`,
            hasRelativeTime: true,
            unix: unix,
        };
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    const networkPalette = ['blue', 'pink', 'amber', 'purple', 'cyan', 'emerald', 'orange', 'indigo'];

    function getNetworkColorKey(networkName) {
        if (!networkName || typeof networkName !== 'string') return 'neutral';
        const s = networkName.toLowerCase().trim();
        if (!s) return 'neutral';

        if (s.includes('dmz') || s.includes('untrusted') || s.includes('external')) return 'pink';
        if (s.includes('iot') || s.includes('camera') || s.includes('smart') || s.includes('sensor')) return 'amber';
        if (s.includes('guest') || s.includes('visitor')) return 'purple';
        if (s.includes('tailscale') || s.includes('vpn') || s.includes('wireguard') || s.includes('wg')) return 'cyan';
        if (s.includes('mgmt') || s.includes('manage') || s.includes('server') || s.includes('infra')) return 'emerald';
        if (s.includes('lan') || s.includes('home') || s.includes('internal') || s.includes('corp') || s.includes('main')) return 'blue';

        let hash = 0;
        for (let i = 0; i < s.length; i++) {
            hash = (hash << 5) - hash + s.charCodeAt(i);
            hash |= 0;
        }
        const index = Math.abs(hash) % networkPalette.length;
        return networkPalette[index];
    }

    function formatSidebarIPDisplay(data) {
        if (!data) return { isHTML: false, text: '—' };
        let ips = [];
        if (Array.isArray(data.ips)) {
            ips = data.ips;
        } else if (data.ipsJson && typeof data.ipsJson === 'string') {
            try { ips = JSON.parse(data.ipsJson); } catch (_) {}
        }

        if (Array.isArray(ips) && ips.length > 1) {
            const html = ips.map(att => {
                const net = att.network_name || att.networkName || data.network || 'LAN';
                const colorKey = getNetworkColorKey(net);
                return `<div style="font-family: var(--font-mono);">${escapeHtml(att.ip)} <span class="network-badge net-${colorKey}" style="margin-left:4px; font-size:0.7rem;">${escapeHtml(net)}</span></div>`;
            }).join('');
            return { isHTML: true, html };
        }

        return { isHTML: false, text: data.ip || '—' };
    }

    function ipToComparable(ip) {
        if (!ip) return '999.999.999.999';
        if (ip.includes('.')) {
            return ip.split('.').map(n => n.padStart(3, '0')).join('.');
        }
        return ip;
    }

    function ipInCIDR(ip, cidr) {
        if (!ip || !cidr || !cidr.includes('/')) return false;
        const parts = cidr.split('/');
        const prefix = parts[0];
        const bits = parseInt(parts[1], 10);
        if (isNaN(bits) || bits < 0 || bits > 32) return false;
        const ipParts = ip.split('.');
        const prefixParts = prefix.split('.');
        if (ipParts.length !== 4 || prefixParts.length !== 4) return false;
        const ipNum = ipParts.reduce((acc, octet) => ((acc << 8) + (parseInt(octet, 10) || 0)) >>> 0, 0) >>> 0;
        const prefixNum = prefixParts.reduce((acc, octet) => ((acc << 8) + (parseInt(octet, 10) || 0)) >>> 0, 0) >>> 0;
        const mask = bits === 0 ? 0 : ((0xFFFFFFFF << (32 - bits)) >>> 0);
        return (ipNum & mask) === (prefixNum & mask);
    }

    function isAttachmentMatchingFilters(att, normalizedFilters) {
        if (!att || !normalizedFilters || normalizedFilters.length === 0) return false;
        const net = (att.network_name || att.networkName || '').toLowerCase().trim();
        for (const filter of normalizedFilters) {
            if (filter === net) return true;
            if (filter.includes('/') && ipInCIDR(att.ip, filter)) return true;
        }
        return false;
    }

    function parseAttachments(data) {
        if (!data) return [];
        if (Array.isArray(data.ips)) {
            return data.ips;
        }
        if (data.ipsJson && typeof data.ipsJson === 'string') {
            try {
                const parsed = JSON.parse(data.ipsJson);
                if (Array.isArray(parsed)) return parsed;
            } catch (_) {}
        }
        if (data.ip) {
            return [{ ip: data.ip, network_name: data.network || '' }];
        }
        return [];
    }

    function getEffectiveRowIP(data, activeNetworkFilters) {
        if (!data) return '';
        const fallbackIP = data.ip || '';
        const attachments = parseAttachments(data);

        if (!activeNetworkFilters || activeNetworkFilters.length === 0) {
            if (attachments.length === 0) return fallbackIP;
            const sorted = [...attachments].sort((a, b) => ipToComparable(a.ip).localeCompare(ipToComparable(b.ip)));
            return sorted[0].ip || fallbackIP;
        }

        if (attachments.length === 0) {
            return fallbackIP;
        }

        const normalizedFilters = activeNetworkFilters.map(f => (f || '').toLowerCase().trim());
        const matching = attachments.filter(att => isAttachmentMatchingFilters(att, normalizedFilters));

        if (matching.length === 0) {
            const sorted = [...attachments].sort((a, b) => ipToComparable(a.ip).localeCompare(ipToComparable(b.ip)));
            return sorted[0].ip || fallbackIP;
        }

        matching.sort((a, b) => ipToComparable(a.ip).localeCompare(ipToComparable(b.ip)));
        return matching[0].ip || fallbackIP;
    }

    function getOrderedAttachments(data, activeNetworkFilters) {
        const attachments = parseAttachments(data);
        if (attachments.length <= 1) {
            return attachments;
        }
        if (!activeNetworkFilters || activeNetworkFilters.length === 0) {
            return [...attachments].sort((a, b) => ipToComparable(a.ip).localeCompare(ipToComparable(b.ip)));
        }

        const normalizedFilters = activeNetworkFilters.map(f => (f || '').toLowerCase().trim());
        const matching = [];
        const nonMatching = [];

        attachments.forEach(att => {
            if (isAttachmentMatchingFilters(att, normalizedFilters)) {
                matching.push(att);
            } else {
                nonMatching.push(att);
            }
        });

        matching.sort((a, b) => ipToComparable(a.ip).localeCompare(ipToComparable(b.ip)));
        nonMatching.sort((a, b) => ipToComparable(a.ip).localeCompare(ipToComparable(b.ip)));
        return [...matching, ...nonMatching];
    }

    function resolveDeviceRow(target, doc) {
        if (!target) return null;
        if (typeof target === 'string') {
            const d = doc || (typeof document !== 'undefined' ? document : null);
            return d ? d.querySelector(`.device-row[data-ip="${target}"]`) : null;
        }
        if (target.classList && target.classList.contains('device-row')) {
            return target;
        }
        if (target.classList && target.classList.contains('device-subrow')) {
            if (target.previousElementSibling && target.previousElementSibling.classList && target.previousElementSibling.classList.contains('device-row')) {
                return target.previousElementSibling;
            }
            const ip = target.dataset?.ip;
            const d = doc || (typeof document !== 'undefined' ? document : null);
            return (ip && d) ? d.querySelector(`.device-row[data-ip="${ip}"]`) : null;
        }
        if (typeof target.closest === 'function') {
            const mainRow = target.closest('.device-row');
            if (mainRow) return mainRow;
            const sub = target.closest('.device-subrow');
            if (sub) {
                if (sub.previousElementSibling && sub.previousElementSibling.classList && sub.previousElementSibling.classList.contains('device-row')) {
                    return sub.previousElementSibling;
                }
                const ip = sub.dataset?.ip;
                const d = doc || (typeof document !== 'undefined' ? document : null);
                return (ip && d) ? d.querySelector(`.device-row[data-ip="${ip}"]`) : null;
            }
        }
        return null;
    }

    function findSubrowForDeviceRow(row, doc) {
        if (!row) return null;
        if (row.nextElementSibling && row.nextElementSibling.classList && row.nextElementSibling.classList.contains('device-subrow')) {
            return row.nextElementSibling;
        }
        const ip = row.dataset?.ip;
        const d = doc || (typeof document !== 'undefined' ? document : null);
        return (ip && d) ? d.querySelector(`.device-subrow[data-ip="${ip}"]`) : null;
    }

    return {
        shouldSyncSidebarForm,
        isElementProtectedFromTimeUpdate,
        formatLastDeepScan,
        formatSidebarIPDisplay,
        ipToComparable,
        getEffectiveRowIP,
        getOrderedAttachments,
        getNetworkColorKey,
        resolveDeviceRow,
        findSubrowForDeviceRow,
    };
});
