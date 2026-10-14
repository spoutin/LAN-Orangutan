const test = require('node:test');
const assert = require('node:assert/strict');
const {
    formatBandwidth,
    formatTrafficBytes,
    calculateTrafficStats,
    renderTrafficChartSVG,
} = require('./traffic-chart.js');

test('formatBandwidth formats B/s, KB/s, MB/s, and GB/s cleanly', () => {
    assert.equal(formatBandwidth(0), '0 B/s');
    assert.equal(formatBandwidth(-10), '0 B/s');
    assert.equal(formatBandwidth(500), '500 B/s');
    assert.equal(formatBandwidth(1536), '1.5 KB/s');
    assert.equal(formatBandwidth(1048576 * 2.5), '2.5 MB/s');
    assert.equal(formatBandwidth(1073741824 * 1.25), '1.25 GB/s');
});

test('formatTrafficBytes formats bytes into human-readable units', () => {
    assert.equal(formatTrafficBytes(0), '0 B');
    assert.equal(formatTrafficBytes(850), '850 B');
    assert.equal(formatTrafficBytes(1024 * 400), '400.0 KB');
    assert.equal(formatTrafficBytes(1048576 * 35), '35.0 MB');
    assert.equal(formatTrafficBytes(1073741824 * 4.8), '4.80 GB');
});

test('calculateTrafficStats returns peak, average, and totals', () => {
    const series = [
        { rx_rate: 1000, tx_rate: 200 },
        { rx_rate: 5000, tx_rate: 800 },
        { rx_rate: 3000, tx_rate: 500 },
    ];
    const stats = calculateTrafficStats(series);
    assert.equal(stats.peakRx, 5000);
    assert.equal(stats.peakTx, 800);
    assert.equal(stats.avgRx, 3000); // 9000 / 3
    assert.equal(stats.avgTx, 500);  // 1500 / 3
});

test('renderTrafficChartSVG renders empty state message on empty series', () => {
    const svg = renderTrafficChartSVG([]);
    assert.match(svg, /No traffic samples recorded/);
});

test('renderTrafficChartSVG renders valid paths and gradients for data series', () => {
    const series = [
        { timestamp: '2026-10-14T10:00:00Z', rx_rate: 100000, tx_rate: 20000 },
        { timestamp: '2026-10-14T10:01:00Z', rx_rate: 250000, tx_rate: 50000 },
        { timestamp: '2026-10-14T10:02:00Z', rx_rate: 180000, tx_rate: 30000 },
    ];
    const svg = renderTrafficChartSVG(series);
    assert.match(svg, /<svg/);
    assert.match(svg, /id="rxGrad"/);
    assert.match(svg, /id="txGrad"/);
    assert.match(svg, /stroke="#10b981"/);
    assert.match(svg, /stroke="#3b82f6"/);
});
