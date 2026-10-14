// Pure JS & SVG helper for traffic telemetry formatting and charts

function formatBandwidth(bytesPerSec) {
    const val = Number(bytesPerSec);
    if (isNaN(val) || val <= 0) return '0 B/s';
    if (val < 1024) return `${Math.round(val)} B/s`;
    if (val < 1024 * 1024) return `${(val / 1024).toFixed(1)} KB/s`;
    if (val < 1024 * 1024 * 1024) return `${(val / (1024 * 1024)).toFixed(1)} MB/s`;
    return `${(val / (1024 * 1024 * 1024)).toFixed(2)} GB/s`;
}

function formatTrafficBytes(bytes) {
    const val = Number(bytes);
    if (isNaN(val) || val <= 0) return '0 B';
    if (val < 1024) return `${Math.round(val)} B`;
    if (val < 1024 * 1024) return `${(val / 1024).toFixed(1)} KB`;
    if (val < 1024 * 1024 * 1024) return `${(val / (1024 * 1024)).toFixed(1)} MB`;
    return `${(val / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function calculateTrafficStats(series) {
    if (!series || series.length === 0) {
        return { peakRx: 0, peakTx: 0, avgRx: 0, avgTx: 0, totalRx: 0, totalTx: 0 };
    }
    let peakRx = 0, peakTx = 0, sumRx = 0, sumTx = 0;
    for (const pt of series) {
        const rx = Number(pt.rx_rate) || 0;
        const tx = Number(pt.tx_rate) || 0;
        if (rx > peakRx) peakRx = rx;
        if (tx > peakTx) peakTx = tx;
        sumRx += rx;
        sumTx += tx;
    }
    const count = series.length;
    return {
        peakRx,
        peakTx,
        avgRx: Math.round(sumRx / count),
        avgTx: Math.round(sumTx / count),
        totalRx: sumRx,
        totalTx: sumTx,
    };
}

function renderTrafficChartSVG(series, { width = 700, height = 240, margin = { top: 20, right: 30, bottom: 30, left: 65 } } = {}) {
    if (!series || series.length === 0) {
        return `<svg viewBox="0 0 ${width} ${height}" class="traffic-svg" xmlns="http://www.w3.org/2000/svg">
            <rect width="100%" height="100%" fill="transparent"/>
            <text x="${width / 2}" y="${height / 2}" fill="var(--text-muted, #888)" text-anchor="middle" font-size="13">No traffic samples recorded in this window</text>
        </svg>`;
    }

    const plotW = width - margin.left - margin.right;
    const plotH = height - margin.top - margin.bottom;

    let maxRate = 1024; // Minimum 1 KB/s scale
    for (const pt of series) {
        const rx = Number(pt.rx_rate) || 0;
        const tx = Number(pt.tx_rate) || 0;
        if (rx > maxRate) maxRate = rx;
        if (tx > maxRate) maxRate = tx;
    }
    // Round maxRate up for cleaner axis
    maxRate = Math.ceil(maxRate * 1.15);

    const count = series.length;
    const xStep = count > 1 ? plotW / (count - 1) : plotW;

    // Build SVG paths for Rx and Tx
    let rxLine = '';
    let txLine = '';
    let rxArea = `M ${margin.left} ${margin.top + plotH}`;
    let txArea = `M ${margin.left} ${margin.top + plotH}`;

    series.forEach((pt, i) => {
        const x = margin.left + i * xStep;
        const rxVal = Number(pt.rx_rate) || 0;
        const txVal = Number(pt.tx_rate) || 0;
        const rxY = margin.top + plotH - (rxVal / maxRate) * plotH;
        const txY = margin.top + plotH - (txVal / maxRate) * plotH;

        if (i === 0) {
            rxLine += `M ${x} ${rxY}`;
            txLine += `M ${x} ${txY}`;
            rxArea += ` L ${x} ${rxY}`;
            txArea += ` L ${x} ${txY}`;
        } else {
            rxLine += ` L ${x} ${rxY}`;
            txLine += ` L ${x} ${txY}`;
            rxArea += ` L ${x} ${rxY}`;
            txArea += ` L ${x} ${txY}`;
        }
    });

    const lastX = margin.left + (count - 1) * xStep;
    rxArea += ` L ${lastX} ${margin.top + plotH} Z`;
    txArea += ` L ${lastX} ${margin.top + plotH} Z`;

    // Gridlines and labels
    const gridY1 = margin.top;
    const gridY2 = margin.top + plotH / 2;
    const gridY3 = margin.top + plotH;

    const labelTop = formatBandwidth(maxRate);
    const labelMid = formatBandwidth(maxRate / 2);

    const firstTime = series[0] && series[0].timestamp ? new Date(series[0].timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
    const lastTime = series[count - 1] && series[count - 1].timestamp ? new Date(series[count - 1].timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';

    return `<svg viewBox="0 0 ${width} ${height}" class="traffic-svg" xmlns="http://www.w3.org/2000/svg">
        <defs>
            <linearGradient id="rxGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="#10b981" stop-opacity="0.35"/>
                <stop offset="100%" stop-color="#10b981" stop-opacity="0.02"/>
            </linearGradient>
            <linearGradient id="txGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.30"/>
                <stop offset="100%" stop-color="#3b82f6" stop-opacity="0.02"/>
            </linearGradient>
        </defs>

        <!-- Grid Lines -->
        <line x1="${margin.left}" y1="${gridY1}" x2="${margin.left + plotW}" y2="${gridY1}" stroke="var(--border-subtle, #333)" stroke-dasharray="3 3"/>
        <line x1="${margin.left}" y1="${gridY2}" x2="${margin.left + plotW}" y2="${gridY2}" stroke="var(--border-subtle, #333)" stroke-dasharray="3 3"/>
        <line x1="${margin.left}" y1="${gridY3}" x2="${margin.left + plotW}" y2="${gridY3}" stroke="var(--border, #444)"/>

        <!-- Y Axis Labels -->
        <text x="${margin.left - 8}" y="${gridY1 + 4}" fill="var(--text-muted, #888)" text-anchor="end" font-size="11">${labelTop}</text>
        <text x="${margin.left - 8}" y="${gridY2 + 4}" fill="var(--text-muted, #888)" text-anchor="end" font-size="11">${labelMid}</text>
        <text x="${margin.left - 8}" y="${gridY3 + 4}" fill="var(--text-muted, #888)" text-anchor="end" font-size="11">0</text>

        <!-- Area Fills -->
        <path d="${rxArea}" fill="url(#rxGrad)"/>
        <path d="${txArea}" fill="url(#txGrad)"/>

        <!-- Lines -->
        <path d="${rxLine}" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        <path d="${txLine}" fill="none" stroke="#3b82f6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>

        <!-- X Axis Labels -->
        <text x="${margin.left}" y="${height - 8}" fill="var(--text-muted, #888)" text-anchor="start" font-size="11">${firstTime}</text>
        <text x="${margin.left + plotW}" y="${height - 8}" fill="var(--text-muted, #888)" text-anchor="end" font-size="11">${lastTime}</text>
    </svg>`;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        formatBandwidth,
        formatTrafficBytes,
        calculateTrafficStats,
        renderTrafficChartSVG,
    };
}
