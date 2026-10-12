function formatRelativeTime(date, now = Date.now()) {
    if (!date) return '';
    const d = date instanceof Date ? date : new Date(date);
    if (isNaN(d.getTime())) return '';
    const diffSec = Math.max(0, Math.floor((now - d.getTime()) / 1000));
    if (diffSec < 60) return 'just now';
    const mins = Math.floor(diffSec / 60);
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
}

function isSameDay(d1, d2) {
    if (!d1 || !d2) return false;
    const a = d1 instanceof Date ? d1 : new Date(d1);
    const b = d2 instanceof Date ? d2 : new Date(d2);
    return a.getFullYear() === b.getFullYear() &&
           a.getMonth() === b.getMonth() &&
           a.getDate() === b.getDate();
}

function filterScanHistoryRows(rows, { selectedDay = null, showAll = false, typeFilter = 'all', query = '' } = {}) {
    if (!rows) return [];
    const q = (query || '').toLowerCase().trim();
    return rows.filter(row => {
        const rowDate = new Date(row.timestamp);
        if (!showAll && selectedDay && !isSameDay(rowDate, selectedDay)) {
            return false;
        }
        if (typeFilter === 'sweep' && row.scan_type && row.scan_type !== 'sweep') {
            return false;
        }
        if (typeFilter === 'deep' && row.scan_type !== 'deep') {
            return false;
        }
        if (q) {
            const netMatch = row.network && row.network.toLowerCase().includes(q);
            const errMatch = row.error && row.error.toLowerCase().includes(q);
            const devMatch = row.devices_found && row.devices_found.some(d =>
                (d.ip && d.ip.toLowerCase().includes(q)) ||
                (d.hostname && d.hostname.toLowerCase().includes(q)) ||
                (d.mac && d.mac.toLowerCase().includes(q))
            );
            if (!netMatch && !errMatch && !devMatch) return false;
        }
        return true;
    });
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { formatRelativeTime, isSameDay, filterScanHistoryRows };
}
