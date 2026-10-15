const test = require('node:test');
const assert = require('node:assert/strict');
const {
    completedNetworkKeys,
    automaticScanFailureMessage,
    scannedSubnetCount,
    formatScanCompletionSummary,
    formatRefreshCountdown,
    formatRefreshTooltip
} = require('./scan-refresh.js');

test('completed network keys include completed quick scan results', () => {
    assert.deepEqual(completedNetworkKeys({
        networks: [{ network: '10.0.0.0/24', status: 'scanned' }]
    }), ['quick:10.0.0.0/24:scanned']);
});

test('completed network keys wait for all deep probes in a network', () => {
    assert.deepEqual(completedNetworkKeys({
        deep_networks: [
            { network: '10.0.0.0/24', total: 4, complete: 3, active: 1 },
            { network: '10.1.0.0/24', total: 2, complete: 2, active: 0 }
        ]
    }), ['deep:10.1.0.0/24']);
});

test('automatic scan failure message returns null when automatic scan succeeds', () => {
    assert.equal(automaticScanFailureMessage({
        automatic: true,
        networks: [{ network: '10.0.0.0/24', status: 'scanned' }]
    }), null);
});

test('automatic scan failure message formats warning when network fails', () => {
    assert.equal(automaticScanFailureMessage({
        automatic: true,
        networks: [
            { network: '10.5.5.0/24', network_name: 'black', status: 'failed', error: 'stat /var/secrets/openwwrt.key: no such file or directory' },
            { network: '10.0.4.0/24', network_name: 'SemiPrivate', status: 'scanned' }
        ]
    }), 'Scan failed for black: stat /var/secrets/openwwrt.key: no such file or directory');
});

test('scannedSubnetCount excludes supplemental sources', () => {
    assert.equal(scannedSubnetCount({
        scanned_network_count: 2,
        networks: [
            { network: '10.0.0.0/24', status: 'scanned' },
            { network: '10.5.5.0/24', status: 'scanned' },
            { network: 'mDNS', status: 'scanned', is_supplemental: true },
            { network: 'switchy SNMP', status: 'scanned', is_supplemental: true }
        ]
    }), 2);
});

test('formatScanCompletionSummary formats correct device and subnet count', () => {
    assert.equal(formatScanCompletionSummary({
        network_count: 7,
        scanned_network_count: 7,
        device_count: 91,
        networks: [
            { network: '10.0.0.0/24', status: 'scanned' },
            { network: '10.5.5.0/24', status: 'scanned' },
            { network: 'mDNS', status: 'scanned', is_supplemental: true },
            { network: 'switchy SNMP', status: 'scanned', is_supplemental: true }
        ]
    }), 'Found 91 devices across 7 networks');
});

test('formatScanCompletionSummary explains partial completion when a network was skipped', () => {
    assert.equal(formatScanCompletionSummary({
        network_count: 7,
        scanned_network_count: 6,
        device_count: 101,
        networks: [
            { network: '10.5.5.0/24', network_name: 'black', status: 'skipped', error: 'rate limited, wait 10s' },
            { network: '10.0.0.0/24', status: 'scanned' },
            { network: '10.0.1.0/24', status: 'scanned' },
            { network: '10.0.3.0/24', status: 'scanned' },
            { network: '10.0.4.0/24', status: 'scanned' },
            { network: '192.168.1.0/24', status: 'scanned' },
            { network: '192.168.111.0/24', status: 'scanned' },
            { network: 'mDNS', status: 'scanned', is_supplemental: true }
        ]
    }), 'Found 101 devices across 6 of 7 networks (1 skipped: rate limited, wait 10s)');
});

test('formatScanCompletionSummary identifies failed networks', () => {
    assert.equal(formatScanCompletionSummary({
        network_count: 2,
        scanned_network_count: 1,
        device_count: 5,
        networks: [
            { network: '10.0.0.0/24', status: 'scanned' },
            { network: '10.5.5.0/24', status: 'failed', error: 'SSH connection refused' }
        ]
    }), 'Found 5 devices across 1 of 2 networks (1 failed: 10.5.5.0/24)');
});

test('formatScanCompletionSummary reports single network scan failure', () => {
    assert.equal(formatScanCompletionSummary({
        network_count: 1,
        scanned_network_count: 0,
        device_count: 0,
        networks: [
            { network: '10.5.5.0/24', status: 'failed', error: 'SSH connection refused' }
        ]
    }), 'Scan failed for 10.5.5.0/24: SSH connection refused');
});

test('formatRefreshCountdown shows countdown seconds when active', () => {
    assert.equal(formatRefreshCountdown({ continuousScan: true, isRefreshing: false, secondsRemaining: 24 }), 'refresh in 24s');
    assert.equal(formatRefreshCountdown({ continuousScan: true, isRefreshing: false, secondsRemaining: 1 }), 'refresh in 1s');
});

test('formatRefreshCountdown shows refreshing when in-flight or 0s remaining', () => {
    assert.equal(formatRefreshCountdown({ continuousScan: true, isRefreshing: true, secondsRemaining: 10 }), 'refreshing...');
    assert.equal(formatRefreshCountdown({ continuousScan: true, isRefreshing: false, secondsRemaining: 0 }), 'refreshing...');
});

test('formatRefreshCountdown shows paused when continuousScan is false', () => {
    assert.equal(formatRefreshCountdown({ continuousScan: false, isRefreshing: false, secondsRemaining: 20 }), 'refresh paused');
});

test('formatRefreshTooltip formats comprehensive breakdown when live', () => {
    const fixedNow = 1700000030000; // ms
    const tooltip = formatRefreshTooltip({
        continuousScan: true,
        isScanRunning: false,
        lastScanUnix: 1700000000, // 30s ago
        nextScanUnix: 1700000270, // in 240s (4m)
        lastRefreshTimeMs: 1700000020000, // 10s ago
        nextRefreshTimeMs: 1700000050000, // in 20s
        nowMs: fixedNow
    });

    assert.match(tooltip, /Network Scan:/);
    assert.match(tooltip, /Last scan: 30s ago/);
    assert.match(tooltip, /Next scan: in ~4m/);
    assert.match(tooltip, /Dashboard Refresh:/);
    assert.match(tooltip, /Last updated: 10s ago/);
    assert.match(tooltip, /Next refresh: in 20s/);
});

test('formatRefreshTooltip reports in progress when scan is currently running', () => {
    const fixedNow = 1700000030000;
    const tooltip = formatRefreshTooltip({
        continuousScan: true,
        isScanRunning: true,
        lastScanUnix: 1700000000,
        nextScanUnix: 0,
        lastRefreshTimeMs: 1700000025000,
        nextRefreshTimeMs: 1700000055000,
        nowMs: fixedNow
    });

    assert.match(tooltip, /Next scan: In progress\.\.\./);
});

test('formatRefreshTooltip reports paused when continuousScan is false', () => {
    const fixedNow = 1700000030000;
    const tooltip = formatRefreshTooltip({
        continuousScan: false,
        isScanRunning: false,
        lastScanUnix: 1700000000,
        nextScanUnix: 0,
        lastRefreshTimeMs: 1700000010000,
        nextRefreshTimeMs: 0,
        nowMs: fixedNow
    });

    assert.match(tooltip, /Next scan: Paused \(manual only\)/);
    assert.match(tooltip, /Next refresh: Paused/);
});




