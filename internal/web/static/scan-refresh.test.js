const test = require('node:test');
const assert = require('node:assert/strict');
const { completedNetworkKeys, automaticScanFailureMessage, scannedSubnetCount, formatScanCompletionSummary } = require('./scan-refresh.js');

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



