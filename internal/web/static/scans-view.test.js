const test = require('node:test');
const assert = require('node:assert/strict');
const { formatRelativeTime, isSameDay, filterScanHistoryRows, parseNetworkScanTarget } = require('./scans-view.js');

test('formatRelativeTime formats accurate relative times', () => {
    const now = 1700000000000;
    assert.equal(formatRelativeTime(new Date(now - 10 * 1000), now), 'just now');
    assert.equal(formatRelativeTime(new Date(now - 5 * 60 * 1000), now), '5m ago');
    assert.equal(formatRelativeTime(new Date(now - 3 * 3600 * 1000), now), '3h ago');
    assert.equal(formatRelativeTime(new Date(now - 48 * 3600 * 1000), now), '2d ago');
    assert.equal(formatRelativeTime(null, now), '');
    assert.equal(formatRelativeTime('invalid-date', now), '');
});

test('isSameDay accurately compares dates', () => {
    const d1 = new Date('2026-10-12T09:15:00Z');
    const d2 = new Date('2026-10-12T22:30:00Z');
    const d3 = new Date('2026-10-11T23:59:00Z');

    assert.equal(isSameDay(d1, d2), true);
    assert.equal(isSameDay(d1, d3), false);
    assert.equal(isSameDay(null, d1), false);
});

test('filterScanHistoryRows filters by day, scan type, and search query', () => {
    const today = new Date('2026-10-12T12:00:00Z');
    const rows = [
        {
            id: 1,
            network: '10.0.0.0/24',
            scan_type: 'sweep',
            status: 'success',
            timestamp: '2026-10-12T08:00:00Z',
            devices_found: [{ ip: '10.0.0.5', hostname: 'my-desktop' }]
        },
        {
            id: 2,
            network: '10.5.5.0/24',
            scan_type: 'deep',
            status: 'warning',
            timestamp: '2026-10-12T09:30:00Z',
            devices_found: [{ ip: '10.5.5.142', hostname: 'proxmox' }]
        },
        {
            id: 3,
            network: '10.0.0.0/24',
            scan_type: 'sweep',
            status: 'success',
            timestamp: '2026-10-11T14:00:00Z',
            devices_found: [{ ip: '10.0.0.5' }]
        }
    ];

    // Day filter (only today)
    const todayRows = filterScanHistoryRows(rows, { selectedDay: today, showAll: false });
    assert.equal(todayRows.length, 2);
    assert.equal(todayRows[0].id, 1);
    assert.equal(todayRows[1].id, 2);

    // Show all
    const allRows = filterScanHistoryRows(rows, { selectedDay: today, showAll: true });
    assert.equal(allRows.length, 3);

    // Type filter: deep only
    const deepRows = filterScanHistoryRows(rows, { showAll: true, typeFilter: 'deep' });
    assert.equal(deepRows.length, 1);
    assert.equal(deepRows[0].id, 2);

    // Search filter: 'proxmox'
    const searchRows = filterScanHistoryRows(rows, { showAll: true, query: 'proxmox' });
    assert.equal(searchRows.length, 1);
    assert.equal(searchRows[0].id, 2);

    // Search filter: '10.0.0'
    const netSearch = filterScanHistoryRows(rows, { showAll: true, query: '10.0.0' });
    assert.equal(netSearch.length, 2);
});

test('parseNetworkScanTarget parses network and mode from control elements', () => {
    const btn = {
        getAttribute: (attr) => attr === 'data-network' ? '10.0.0.0/24' : null,
        closest: (sel) => ({
            querySelector: (q) => q === '.scan-mode-select' ? { value: 'deep' } : null
        })
    };
    const target = parseNetworkScanTarget(btn);
    assert.deepEqual(target, { network: '10.0.0.0/24', mode: 'deep' });

    assert.equal(parseNetworkScanTarget(null), null);
});

test('isSameDay returns false for invalid dates and scansView helpers are preserved when loaded with app.js', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const vm = require('node:vm');

    assert.equal(isSameDay(new Date('invalid'), new Date('2026-10-12T00:00:00Z')), false);
    assert.equal(isSameDay(new Date('2026-10-12T00:00:00Z'), new Date('invalid')), false);

    // Default scan mode falls back to 'quick' when .scan-mode-select is absent
    const btnNoSelect = {
        getAttribute: (attr) => attr === 'data-network' ? '10.0.0.0/24' : null,
        closest: () => ({ querySelector: () => null }),
    };
    assert.deepEqual(parseNetworkScanTarget(btnNoSelect), { network: '10.0.0.0/24', mode: 'quick' });

    // Loading scans-view.js followed by app.js preserves the canonical global helpers
    const noop = () => {};
    const makeClassList = () => ({ add: noop, remove: noop, toggle: () => false, contains: () => false });
    const document = {
        documentElement: { classList: makeClassList(), style: { setProperty: noop }, getAttribute: () => null, setAttribute: noop, offsetWidth: 0 },
        body: { classList: makeClassList(), appendChild: noop },
        getElementById: () => null,
        querySelector: () => null,
        querySelectorAll: () => [],
        createElement: () => ({ style: {}, classList: makeClassList(), setAttribute: noop, appendChild: noop }),
        addEventListener: noop,
        removeEventListener: noop,
    };
    const sandbox = {
        console, Math, Number, String, Boolean, Array, Object, Map, Set, Date, JSON, RegExp, Error, URL,
        encodeURIComponent, decodeURIComponent, parseInt, parseFloat, isNaN, isFinite,
        CSS: { escape: s => String(s) },
        localStorage: { getItem: () => null, setItem: noop, removeItem: noop },
        matchMedia: () => ({ matches: false, addEventListener: noop }),
        fetch: async () => ({ ok: true, text: async () => '{}', json: async () => ({ success: true, data: {} }) }),
        setInterval: () => 1,
        clearInterval: noop,
        setTimeout: () => 1,
        clearTimeout: noop,
        Event: class Event { constructor(type) { this.type = type; } },
        document,
        addEventListener: noop,
        removeEventListener: noop,
        dispatchEvent: noop,
    };
    sandbox.window = sandbox;
    sandbox.globalThis = sandbox;
    sandbox.self = sandbox;

    const htmlSrc = fs.readFileSync(path.join(__dirname, 'html-utils.js'), 'utf8');
    vm.runInNewContext(htmlSrc, sandbox, { filename: 'html-utils.js' });

    const scansViewSrc = fs.readFileSync(path.join(__dirname, 'scans-view.js'), 'utf8');
    vm.runInNewContext(scansViewSrc, sandbox, { filename: 'scans-view.js' });
    const canonicalIsSameDay = sandbox.isSameDay;
    const canonicalFormatRelativeTime = sandbox.formatRelativeTime;

    const appSrc = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
    vm.runInNewContext(appSrc, sandbox, { filename: 'app.js' });

    assert.equal(typeof sandbox.isSameDay, 'function');
    assert.equal(typeof sandbox.formatRelativeTime, 'function');
    assert.equal(sandbox.isSameDay, canonicalIsSameDay);
    assert.equal(sandbox.formatRelativeTime, canonicalFormatRelativeTime);
});


