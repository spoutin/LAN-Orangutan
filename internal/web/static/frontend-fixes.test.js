const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function loadAppContext(extraElements = {}, extraQuery = null) {
    const docListeners = new Map();
    const winListeners = new Map();
    const elements = new Map(Object.entries(extraElements));

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

    const document = {
        documentElement: {
            classList: makeClassList(),
            style: { setProperty: () => {} },
            getAttribute: () => null,
            setAttribute: () => {},
            offsetWidth: 0,
        },
        body: {
            classList: makeClassList(),
            appendChild: () => {},
        },
        activeElement: null,
        getElementById(id) {
            return elements.get(id) || null;
        },
        querySelector(sel) {
            if (extraQuery && extraQuery.querySelector) {
                const hit = extraQuery.querySelector(sel);
                if (hit !== undefined) return hit;
            }
            return null;
        },
        querySelectorAll(sel) {
            if (extraQuery && extraQuery.querySelectorAll) {
                const hit = extraQuery.querySelectorAll(sel);
                if (hit !== undefined) return hit;
            }
            if (sel === '.modal') {
                return [...elements.values()].filter(el => el.classList && el.classList.contains('modal'));
            }
            if (sel === '.dropdown-menu.show') {
                return [...elements.values()].filter(el =>
                    el.classList && el.classList.contains('dropdown-menu') && el.classList.contains('show')
                );
            }
            return [];
        },
        createElement() {
            return {
                style: {},
                classList: makeClassList(),
                setAttribute: () => {},
                appendChild: () => {},
            };
        },
        addEventListener(type, fn) {
            if (!docListeners.has(type)) docListeners.set(type, new Set());
            docListeners.get(type).add(fn);
        },
        removeEventListener(type, fn) {
            docListeners.get(type)?.delete(fn);
        },
        dispatchEvent(evt) {
            for (const fn of [...(docListeners.get(evt.type) || [])]) {
                fn(evt);
            }
        },
    };

    let nextTimerId = 1;
    const activeIntervals = new Set();
    const clearedIntervals = [];
    const queuedTimeouts = [];

    const windowObj = {
        document,
        innerWidth: 1280,
        scrollY: 0,
        location: { href: 'http://localhost/', reload: () => {} },
        addEventListener(type, fn) {
            if (!winListeners.has(type)) winListeners.set(type, new Set());
            winListeners.get(type).add(fn);
        },
        removeEventListener(type, fn) {
            winListeners.get(type)?.delete(fn);
        },
        dispatchEvent() {},
    };

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
        localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
        matchMedia: () => ({ matches: false, addEventListener: () => {} }),
        fetch: async () => ({
            ok: true,
            text: async () => JSON.stringify({ success: true, data: {} }),
            json: async () => ({ success: true, data: {} }),
        }),
        setInterval(fn, ms) {
            const id = nextTimerId++;
            activeIntervals.add(id);
            return id;
        },
        clearInterval(id) {
            if (id != null) {
                activeIntervals.delete(id);
                clearedIntervals.push(id);
            }
        },
        setTimeout(fn) {
            const id = nextTimerId++;
            queuedTimeouts.push({ id, fn });
            return id;
        },
        clearTimeout() {},
        Event: class Event { constructor(type) { this.type = type; } },
        document,
        window: windowObj,
        globalThis: null,
    };
    sandbox.globalThis = sandbox;
    sandbox.self = windowObj;

    for (const file of ['html-utils.js', 'device-operation-state.js', 'scans-view.js', 'app.js']) {
        const src = fs.readFileSync(path.join(__dirname, file), 'utf8');
        vm.runInNewContext(src, sandbox, { filename: file });
    }

    return {
        sandbox,
        document,
        docListeners,
        activeIntervals,
        clearedIntervals,
        flushTimeouts() {
            while (queuedTimeouts.length > 0) {
                const { fn } = queuedTimeouts.shift();
                fn();
            }
        },
        makeClassList,
    };
}

test('toggleNetworkDropdownFilter, filterDevices, and updateRowMultiIPPresentation filter rows and reorder multi-IP cells', () => {
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

    const makeRow = (dataset, subrow, multiCells = null) => ({
        dataset,
        style: { display: '' },
        classList: makeClassList(['device-row']),
        querySelector(sel) {
            if (!multiCells) return null;
            if (sel === '.multi-ip-cell') return multiCells.ipCell;
            if (sel === '.multi-network-cell') return multiCells.netCell;
            if (sel === '.col-ip.ip-cell') return multiCells.copyCell;
            return null;
        },
        _subrow: subrow,
    });

    const sub1 = { dataset: { ip: '10.0.0.10' }, style: { display: '' }, classList: makeClassList(['device-subrow']) };
    const sub2 = { dataset: { ip: '10.0.0.2' }, style: { display: '' }, classList: makeClassList(['device-subrow']) };
    const multiCells = {
        ipCell: { innerHTML: '' },
        netCell: { innerHTML: '' },
        copyCell: { dataset: { copy: '10.0.0.10' } },
    };

    const row1 = makeRow({
        ip: '10.0.0.10',
        ips: '10.0.0.10,10.0.20.10',
        ipsJson: JSON.stringify([
            { ip: '10.0.0.10', network_name: 'Core' },
            { ip: '10.0.20.10', network_name: 'IoT' },
        ]),
        hostname: 'nas-box',
        mac: '00:11:22:33:44:10',
        vendor: 'Synology',
        label: 'NAS',
        type: 'Server',
        network: 'Core',
        networks: 'core,iot',
        status: 'online',
        group: 'Storage',
        lastseen: '200',
    }, sub1, multiCells);

    const row2 = makeRow({
        ip: '10.0.0.2',
        hostname: 'camera-front',
        mac: '00:11:22:33:44:02',
        vendor: 'Axis',
        label: 'Front Cam',
        type: 'IoT',
        network: 'IoT',
        networks: 'iot',
        status: 'offline',
        group: 'Security',
        lastseen: '100',
        flagged: '1',
    }, sub2);

    const rows = [row1, row2];
    const subrows = [sub1, sub2];
    const tbody = {
        children: [row1, sub1, row2, sub2],
        appendChild(el) {
            const idx = this.children.indexOf(el);
            if (idx >= 0) this.children.splice(idx, 1);
            this.children.push(el);
        },
        querySelectorAll(sel) {
            if (sel === '.device-row') return rows;
            return [];
        },
        querySelector(sel) {
            const m = sel.match(/^\.device-subrow\[data-ip="(.+)"\]$/);
            if (!m) return null;
            const ip = m[1].replace(/\\/g, '');
            return subrows.find(s => s.dataset.ip === ip) || null;
        },
    };

    const allCheckbox = { checked: true };
    const cbCore = { value: 'core', checked: false, nextElementSibling: { textContent: 'Core' } };
    const cbIoT = { value: 'iot', checked: false, nextElementSibling: { textContent: 'IoT' } };
    const filterBtn = { textContent: 'All Networks' };
    const searchInput = { value: '' };
    const statusSelect = { value: 'all' };
    const groupSelect = { value: 'all' };
    const countEl = { textContent: '' };

    const ctx = loadAppContext({
        'devices-tbody': tbody,
        'network-filter-all': allCheckbox,
        'network-filter-btn': filterBtn,
        'device-search': searchInput,
        'device-filter': statusSelect,
        'group-filter': groupSelect,
        'device-count': countEl,
    }, {
        querySelector(sel) {
            const m = sel.match(/^\.device-subrow\[data-ip="(.+)"\]$/);
            if (m) {
                const ip = m[1].replace(/\\/g, '');
                return subrows.find(s => s.dataset.ip === ip) || null;
            }
            return undefined;
        },
        querySelectorAll(sel) {
            if (sel === '.network-filter-checkbox') return [cbCore, cbIoT];
            if (sel === '.device-row') return rows;
            if (sel === '.stat-chip-filter') return [];
            return undefined;
        },
    });

    // Search filter hides non-matching row and its subrow
    searchInput.value = 'synology';
    ctx.sandbox.filterDevices();
    assert.equal(row1.style.display, '');
    assert.equal(sub1.style.display, '');
    assert.equal(row2.style.display, 'none');
    assert.equal(sub2.style.display, 'none');
    assert.equal(countEl.textContent, 'Showing 1 device');

    // Clear search and filter by IoT network via dropdown
    searchInput.value = '';
    cbIoT.checked = true;
    ctx.sandbox.toggleNetworkDropdownFilter('iot');
    assert.equal(allCheckbox.checked, false);
    assert.equal(filterBtn.textContent, 'IoT');
    assert.equal(row1.style.display, '');
    assert.equal(row2.style.display, '');
    assert.equal(countEl.textContent, 'Showing 2 devices');

    // Multi-IP presentation promotes matching IoT attachment (10.0.20.10) to top
    assert.match(multiCells.ipCell.innerHTML, /^<div class="ip-row">10\.0\.20\.10<\/div>/);
    assert.match(multiCells.netCell.innerHTML, /^<span class="network-badge net-amber">IoT<\/span>/);
    assert.equal(multiCells.copyCell.dataset.copy, '10.0.20.10');

    // Resetting to 'all' restores button label and default checkbox state
    allCheckbox.checked = true;
    ctx.sandbox.toggleNetworkDropdownFilter('all');
    assert.equal(filterBtn.textContent, 'All Networks');
    assert.equal(cbIoT.checked, false);
});

test('sortTable orders device rows and keeps subrows paired, and resetDeviceSort restores default order', () => {
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

    const rowA = { dataset: { ip: '10.0.0.10', hostname: 'alpha', lastseen: '100' }, classList: makeClassList(['device-row']) };
    const subA = { dataset: { ip: '10.0.0.10' }, classList: makeClassList(['device-subrow']) };
    const rowB = { dataset: { ip: '10.0.0.2', hostname: 'zeta', lastseen: '300' }, classList: makeClassList(['device-row']) };
    const subB = { dataset: { ip: '10.0.0.2' }, classList: makeClassList(['device-subrow']) };

    const allSubrows = [subA, subB];
    const tbody = {
        children: [rowA, subA, rowB, subB],
        appendChild(el) {
            const idx = this.children.indexOf(el);
            if (idx >= 0) this.children.splice(idx, 1);
            this.children.push(el);
        },
        querySelectorAll(sel) {
            if (sel === '.device-row') return this.children.filter(c => c.classList.contains('device-row'));
            return [];
        },
        querySelector(sel) {
            const m = sel.match(/^\.device-subrow\[data-ip="(.+)"\]$/);
            if (!m) return null;
            const ip = m[1].replace(/\\/g, '');
            return allSubrows.find(s => s.dataset.ip === ip) || null;
        },
    };

    const ipIcon = { textContent: '↕' };
    const hostIcon = { textContent: '↕' };
    const thIP = { dataset: { sort: 'ip' }, classList: makeClassList(), querySelector: () => ipIcon };
    const thHost = { dataset: { sort: 'hostname' }, classList: makeClassList(), querySelector: () => hostIcon };
    const resetBtn = { classList: makeClassList(['hidden']) };

    const ctx = loadAppContext({
        'devices-tbody': tbody,
        'reset-device-sort': resetBtn,
    }, {
        querySelectorAll(sel) {
            if (sel === '.table th[data-sort]') return [thIP, thHost];
            return undefined;
        },
    });

    // Sort by IP ascending: 10.0.0.2 then 10.0.0.10, each followed by its subrow
    ctx.sandbox.sortTable('ip');
    assert.deepEqual(tbody.children.map(el => el.dataset.ip), ['10.0.0.2', '10.0.0.2', '10.0.0.10', '10.0.0.10']);
    assert.equal(thIP.classList.contains('sorted'), true);
    assert.equal(ipIcon.textContent, '↑');
    assert.equal(hostIcon.textContent, '↕');
    assert.equal(resetBtn.classList.contains('hidden'), false);

    // Clicking IP again toggles descending
    ctx.sandbox.sortTable('ip');
    assert.deepEqual(tbody.children.map(el => el.dataset.ip), ['10.0.0.10', '10.0.0.10', '10.0.0.2', '10.0.0.2']);
    assert.equal(ipIcon.textContent, '↓');

    // Reset restores initial default order [10.0.0.10, 10.0.0.2]
    ctx.sandbox.resetDeviceSort();
    assert.deepEqual(tbody.children.map(el => el.dataset.ip), ['10.0.0.10', '10.0.0.10', '10.0.0.2', '10.0.0.2']);
    assert.equal(thIP.classList.contains('sorted'), false);
    assert.equal(ipIcon.textContent, '↕');
    assert.equal(resetBtn.classList.contains('hidden'), true);
});

test('renderLiveProgressCard clears progressClock interval when scan stops running', () => {
    const card = { innerHTML: '', style: { display: 'none' }, addEventListener: () => {} };
    const ctx = loadAppContext({ 'live-progress-card': card });

    const beforeCount = ctx.activeIntervals.size;
    ctx.sandbox.renderLiveProgressCard({ status: 'running', network_index: 1, network_count: 1 });
    assert.equal(ctx.activeIntervals.size, beforeCount + 1, 'expected progressClock interval to start while running');

    ctx.sandbox.renderLiveProgressCard({ status: 'idle' });
    assert.equal(ctx.activeIntervals.size, beforeCount, 'expected progressClock interval to be cleared when idle');

    ctx.sandbox.renderLiveProgressCard({ status: 'running', network_index: 1, network_count: 1 });
    assert.equal(ctx.activeIntervals.size, beforeCount + 1);
    ctx.sandbox.renderLiveProgressCard(null);
    assert.equal(ctx.activeIntervals.size, beforeCount, 'expected progressClock interval to be cleared when null');
});

test('toggleDropdown does not leak document click listeners on repeated toggles', () => {
    const makeClassList = (initial = []) => {
        const set = new Set(initial);
        return {
            add: (...cls) => cls.forEach(c => set.add(c)),
            remove: (...cls) => cls.forEach(c => set.delete(c)),
            toggle: c => { if (set.has(c)) { set.delete(c); return false; } set.add(c); return true; },
            contains: c => set.has(c),
        };
    };

    const menu = {
        id: 'export-menu',
        classList: makeClassList(['dropdown-menu']),
        contains: () => false,
        closest: () => null,
    };
    const ctx = loadAppContext({ 'export-menu': menu });
    const baseClickListeners = ctx.docListeners.get('click')?.size || 0;

    for (let i = 0; i < 5; i++) {
        ctx.sandbox.toggleDropdown('export-menu');
        ctx.flushTimeouts();
        ctx.sandbox.toggleDropdown('export-menu');
        ctx.flushTimeouts();
    }

    assert.equal(menu.classList.contains('show'), false);
    assert.equal(
        ctx.docListeners.get('click')?.size || 0,
        baseClickListeners,
        'expected no leaked document click listeners after toggling dropdown open and closed'
    );
});

test('closeModal, backdrop click, and Escape close all modals', () => {
    const modalIds = [
        'edit-modal',
        'history-modal',
        'service-details-modal',
        'error-details-modal',
        'logs-modal',
        'traffic-modal',
        'scan-detail-modal',
        'token-create-modal',
        'token-created-modal',
    ];
    const modals = {};
    for (const id of modalIds) {
        modals[id] = {
            id,
            style: { display: 'none' },
            classList: { contains: c => c === 'modal' },
        };
    }

    const ctx = loadAppContext(modals);

    // closeModal() without args closes any open modal
    for (const id of modalIds) {
        modals[id].style.display = 'flex';
        ctx.sandbox.closeModal();
        assert.equal(modals[id].style.display, 'none', `expected closeModal() to close #${id}`);
    }

    // Escape key closes any open modal
    for (const id of modalIds) {
        modals[id].style.display = 'flex';
        ctx.document.dispatchEvent({
            type: 'keydown',
            key: 'Escape',
            target: { closest: () => null, matches: () => false },
            stopImmediatePropagation: () => {},
        });
        assert.equal(modals[id].style.display, 'none', `expected Escape to close #${id}`);
    }

    // Clicking backdrop closes that modal
    for (const id of modalIds) {
        modals[id].style.display = 'flex';
        ctx.document.dispatchEvent({ type: 'click', target: modals[id] });
        assert.equal(modals[id].style.display, 'none', `expected backdrop click to close #${id}`);
    }
});

test('shared JS helpers are consolidated without duplicate definitions across modules', () => {
    const readStatic = name => fs.readFileSync(path.join(__dirname, name), 'utf8');

    const osPres = readStatic('os-presentation.js');
    const devOpState = readStatic('device-operation-state.js');
    const appJs = readStatic('app.js');

    assert.equal(/\bfunction\s+escapeHtml\b/.test(osPres), false, 'os-presentation.js must not duplicate escapeHtml');
    assert.equal(/\bfunction\s+escapeHtml\b/.test(devOpState), false, 'device-operation-state.js must not duplicate escapeHtml');
    assert.equal(/\bfunction\s+escapeHtml\b/.test(appJs), false, 'app.js must not duplicate escapeHtml');
    assert.equal(/all\.filter\(row\s*=>/.test(appJs), false, 'app.js must not duplicate filterScanHistoryRows logic');
    assert.equal(/target\.closest\('\.device-subrow'\)\?\.previousElementSibling/.test(appJs), false, 'app.js must not duplicate resolveDeviceRow logic');
});
