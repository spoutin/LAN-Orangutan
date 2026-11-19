const test = require('node:test');
const assert = require('node:assert/strict');
const {
    formatScanFooterStatus,
    formatScanFooterTicker,
    toggleScanFooterMinimized
} = require('./scan-refresh.js');

test('formatScanFooterStatus returns active scanning state when progress indicates active scan', () => {
    const progress = {
        scanning: true,
        current_network_name: 'Home-LAN',
        current_network: '10.0.0.0/24',
        mode: 'quick'
    };
    const status = formatScanFooterStatus(progress);
    assert.equal(status.isScanning, true);
    assert.equal(status.text, 'Scanning: Home-LAN (10.0.0.0/24)');
    assert.equal(status.mode, 'quick');
});

test('formatScanFooterStatus returns idle state when no scan running', () => {
    const progress = {
        scanning: false,
        last_scan_ago: '5m ago'
    };
    const status = formatScanFooterStatus(progress);
    assert.equal(status.isScanning, false);
    assert.equal(status.text, 'All networks idle');
    assert.equal(status.detail, 'scanned 5m ago');
});

test('formatScanFooterTicker formats chips for each network', () => {
    const networks = [
        { friendly_name: 'Home-LAN', cidr: '10.0.0.0/24', last_scan_ago: '2m ago', is_scanning: true },
        { friendly_name: 'IoT', cidr: '10.0.20.0/24', last_scan_ago: '15m ago', is_scanning: false }
    ];
    const chips = formatScanFooterTicker(networks);
    assert.equal(chips.length, 2);
    assert.equal(chips[0].name, 'Home-LAN');
    assert.equal(chips[0].statusText, 'scanning...');
    assert.equal(chips[0].isScanning, true);
    assert.equal(chips[1].name, 'IoT');
    assert.equal(chips[1].statusText, '15m ago');
    assert.equal(chips[1].isScanning, false);
});

test('toggleScanFooterMinimized toggles minimized class and updates localStorage', () => {
    const store = {};
    const mockStorage = {
        getItem: (k) => store[k] || null,
        setItem: (k, v) => { store[k] = String(v); }
    };
    let hasClass = false;
    const mockEl = {
        classList: {
            toggle: (cls, force) => {
                hasClass = (typeof force === 'boolean') ? force : !hasClass;
                return hasClass;
            },
            contains: (cls) => hasClass
        }
    };

    // First toggle: minimizes
    const res1 = toggleScanFooterMinimized(mockEl, mockStorage);
    assert.equal(res1, true);
    assert.equal(hasClass, true);
    assert.equal(mockStorage.getItem('scan-footer-minimized'), 'true');

    // Second toggle: restores
    const res2 = toggleScanFooterMinimized(mockEl, mockStorage);
    assert.equal(res2, false);
    assert.equal(hasClass, false);
    assert.equal(mockStorage.getItem('scan-footer-minimized'), 'false');
});

function makeFooterAppContext() {
    const fs = require('node:fs');
    const path = require('node:path');
    const vm = require('node:vm');

    const makeClassList = (initial = []) => {
        const set = new Set(initial);
        return {
            add: (...cls) => cls.forEach(c => set.add(c)),
            remove: (...cls) => cls.forEach(c => set.delete(c)),
            toggle: (c, force) => {
                if (force === undefined) {
                    if (set.has(c)) { set.delete(c); return false; }
                    set.add(c); return true;
                }
                if (force) set.add(c); else set.delete(c);
                return !!force;
            },
            contains: c => set.has(c),
        };
    };

    const storageMap = new Map();
    const localStorage = {
        getItem: k => storageMap.has(k) ? storageMap.get(k) : null,
        setItem: (k, v) => storageMap.set(k, String(v)),
        removeItem: k => storageMap.delete(k),
    };

    const makeEl = (id, classes = [], extra = {}) => ({
        id,
        classList: makeClassList(classes),
        style: {},
        dataset: {},
        textContent: '',
        innerHTML: '',
        disabled: false,
        setAttribute: () => {},
        querySelector: () => null,
        querySelectorAll: () => [],
        ...extra,
    });

    const dot = makeEl(null, ['scan-status-dot']);
    const label = makeEl('scan-status-label');
    const detail = makeEl('scan-status-detail');

    const chip1Time = makeEl(null, ['ticker-net-time']);
    const chip1Btn = makeEl(null, ['btn-ticker-scan']);
    const chip1 = makeEl(null, ['scan-ticker-chip'], {
        dataset: { cidr: '10.0.0.0/24' },
        querySelector: sel => sel === '.ticker-net-time' ? chip1Time : (sel === '.btn-ticker-scan' ? chip1Btn : null),
    });

    const chip2Time = makeEl(null, ['ticker-net-time']);
    const chip2Btn = makeEl(null, ['btn-ticker-scan']);
    const chip2 = makeEl(null, ['scan-ticker-chip'], {
        dataset: { cidr: '10.0.20.0/24' },
        querySelector: sel => sel === '.ticker-net-time' ? chip2Time : (sel === '.btn-ticker-scan' ? chip2Btn : null),
    });

    const footer = makeEl('scan-status-footer', [], {
        querySelector: sel => {
            if (sel === '.scan-status-dot') return dot;
            if (sel === '.scan-ticker-chip[data-cidr="10\\.0\\.0\\.0\\/24"]' || sel === '.scan-ticker-chip[data-cidr="10.0.0.0/24"]') return chip1;
            if (sel === '.scan-ticker-chip[data-cidr="10\\.0\\.20\\.0\\/24"]' || sel === '.scan-ticker-chip[data-cidr="10.0.20.0/24"]') return chip2;
            return null;
        },
        querySelectorAll: sel => {
            if (sel === '.scan-ticker-chip.scanning') {
                return [chip1, chip2].filter(c => c.classList.contains('scanning'));
            }
            return [];
        },
    });

    // Replaceable slots for refreshInPlace()
    const slots = new Map();
    const registerSlot = (selector, id) => {
        const current = makeEl(id, [], {
            marker: 'old',
            replaceWith(replacement) {
                slots.set(selector, replacement);
            },
        });
        slots.set(selector, current);
    };
    for (const sel of ['#devices-tbody', '.stat-strip', '.table-footer', '#device-count', '#scan-time-top', '.scan-control-compact', '.btn-scan-all', '#scan-status-footer', '#configured-networks-section']) {
        registerSlot(sel, sel.startsWith('#') ? sel.slice(1) : null);
    }
    // Preserve footer reference initially and allow replacement during refreshInPlace
    slots.set('#scan-status-footer', Object.assign(footer, {
        marker: 'old',
        replaceWith(replacement) {
            slots.set('#scan-status-footer', replacement);
        },
    }));

    const freshDocSlots = new Map();
    for (const sel of slots.keys()) {
        freshDocSlots.set(sel, makeEl(sel.startsWith('#') ? sel.slice(1) : null, [], { marker: 'new' }));
    }

    const dispatchedWindowEvents = [];
    const document = {
        readyState: 'complete',
        documentElement: { classList: makeClassList(), style: { setProperty: () => {} }, getAttribute: () => null, setAttribute: () => {}, offsetWidth: 0 },
        body: { classList: makeClassList(), appendChild: () => {} },
        activeElement: null,
        getElementById(id) {
            if (id === 'scan-status-label') return label;
            if (id === 'scan-status-detail') return detail;
            return slots.get('#' + id) || null;
        },
        querySelector(sel) {
            return slots.get(sel) || null;
        },
        querySelectorAll: () => [],
        createElement: () => makeEl(null),
        addEventListener: () => {},
        removeEventListener: () => {},
    };

    class MockDOMParser {
        parseFromString() {
            return {
                getElementById: (id) => freshDocSlots.get('#' + id) || null,
                querySelector: (sel) => freshDocSlots.get(sel) || null,
            };
        }
    }

    const sandbox = {
        console,
        Math,
        Number,
        String,
        Boolean,
        Array,
        Object,
        Map,
        Set,
        Date,
        JSON,
        RegExp,
        Error,
        URL,
        encodeURIComponent,
        decodeURIComponent,
        parseInt,
        parseFloat,
        isNaN,
        isFinite,
        CSS: { escape: s => String(s).replace(/([^\w-])/g, '\\$1') },
        localStorage,
        matchMedia: () => ({ matches: false, addEventListener: () => {} }),
        DOMParser: MockDOMParser,
        fetch: async (url) => {
            if (String(url).includes('/api/')) {
                return { ok: true, text: async () => JSON.stringify({ success: true, data: { status: 'idle' } }), json: async () => ({ success: true, data: { status: 'idle' } }) };
            }
            return { ok: true, text: async () => '<html></html>', json: async () => ({ success: true, data: {} }) };
        },
        setInterval: () => 1,
        clearInterval: () => {},
        setTimeout: () => 1,
        clearTimeout: () => {},
        Event: class Event { constructor(type) { this.type = type; } },
        document,
        innerWidth: 1280,
        scrollY: 0,
        location: { href: 'http://localhost/', reload: () => {} },
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: (evt) => dispatchedWindowEvents.push(evt.type),
    };
    sandbox.window = sandbox;
    sandbox.globalThis = sandbox;
    sandbox.self = sandbox;

    for (const file of ['html-utils.js', 'scan-refresh.js', 'scans-view.js', 'app.js']) {
        const src = fs.readFileSync(path.join(__dirname, file), 'utf8');
        vm.runInNewContext(src, sandbox, { filename: file });
    }

    return { sandbox, footer, dot, label, detail, chip1, chip1Time, chip1Btn, chip2, chip2Time, chip2Btn, slots, localStorage, dispatchedWindowEvents };
}

test('updateScanStatusFooter updates running sweep, deep scan, and idle DOM state', () => {
    const ctx = makeFooterAppContext();

    // Active sweep
    ctx.sandbox.updateScanStatusFooter({
        status: 'running',
        stage: 'sweep',
        current_network_name: 'Home-LAN',
        current_network: '10.0.0.0/24',
        percent: 42,
        networks: [
            { network: '10.0.0.0/24', status: 'scanning', last_scan_ago: '1m ago' },
            { network: '10.0.20.0/24', status: 'scanned', last_scan_ago: '15m ago' },
        ],
    });
    assert.equal(ctx.dot.classList.contains('active'), true);
    assert.equal(ctx.label.textContent, 'Scanning: Home-LAN');
    assert.equal(ctx.detail.textContent, '(42%)');
    assert.equal(ctx.chip1.classList.contains('scanning'), true);
    assert.equal(ctx.chip1Time.textContent, 'scanning...');
    assert.equal(ctx.chip1Btn.disabled, true);
    assert.equal(ctx.chip2.classList.contains('scanning'), false);
    assert.equal(ctx.chip2Time.textContent, '15m ago');
    assert.equal(ctx.chip2Btn.disabled, true);

    // Active deep stage
    ctx.sandbox.updateScanStatusFooter({
        status: 'running',
        stage: 'deep',
        current_network: '10.0.20.0/24',
        percent: 80,
    });
    assert.equal(ctx.label.textContent, 'Services: 10.0.20.0/24');
    assert.equal(ctx.detail.textContent, '(80%)');

    // Idle state clears active dot & chip spinning state
    ctx.sandbox.updateScanStatusFooter({
        status: 'idle',
        last_scan_ago: 'just now',
    });
    assert.equal(ctx.dot.classList.contains('active'), false);
    assert.equal(ctx.label.textContent, 'All networks idle');
    assert.equal(ctx.detail.textContent, 'scanned just now');
    assert.equal(ctx.chip1.classList.contains('scanning'), false);
    assert.equal(ctx.chip1Btn.disabled, false);
});

test('toggleScanFooter toggles minimized state and persists across refreshInPlace', async () => {
    const ctx = makeFooterAppContext();

    ctx.sandbox.toggleScanFooter();
    assert.equal(ctx.footer.classList.contains('minimized'), true);
    assert.equal(ctx.localStorage.getItem('scan-footer-minimized'), 'true');

    const ok = await ctx.sandbox.refreshInPlace();
    assert.equal(ok, true);

    // Toolbar, footer, and configured-networks section were swapped for fresh nodes
    for (const sel of ['#devices-tbody', '.stat-strip', '.btn-scan-all', '#scan-status-footer', '#configured-networks-section']) {
        assert.equal(ctx.slots.get(sel).marker, 'new', `expected ${sel} to be replaced in refreshInPlace`);
    }
    assert.equal(
        ctx.slots.get('#scan-status-footer').classList.contains('minimized'),
        true,
        'expected minimized state to be restored onto refreshed footer'
    );
    assert.equal(ctx.dispatchedWindowEvents.includes('devices-refreshed'), true);
});


