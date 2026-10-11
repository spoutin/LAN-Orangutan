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


