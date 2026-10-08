const test = require('node:test');
const assert = require('node:assert/strict');
const { completedNetworkKeys } = require('./scan-refresh.js');

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
