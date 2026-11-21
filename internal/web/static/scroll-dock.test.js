const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function makeClassList(initial = []) {
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
}

function makeStyle() {
    const props = new Map();
    return {
        setProperty: (k, v) => props.set(k, String(v)),
        getPropertyValue: (k) => props.get(k) || '',
    };
}

function loadScrollDockApp({
    innerWidth = 1280,
    clientWidth = 1280,
    scrollY = 0,
    wideMatches = true,
    reduceMatches = false,
    headerHeight = 64,
    secHeaderHeight = 54,
    toolbarHeight = 38,
    scanFooterHeight = 38,
    scanFooterMinimized = false,
    hasScanFooter = true,
    saveBarVisible = false,
    saveBarHeight = 48,
    holderTop = 200,
    stripHeight = 44,
    stripScrollWidth = 600,
    stripClientWidth = 600,
} = {}) {
    const winListeners = new Map();
    const docListeners = new Map();
    const btnListeners = new Map();
    const scrollCalls = [];

    const rootStyle = makeStyle();
    const holderStyle = makeStyle();

    const brandEl = { getBoundingClientRect: () => ({ right: 220 }) };
    const navEl = { getBoundingClientRect: () => ({ left: 900 }) };
    const headerEl = {
        offsetHeight: headerHeight,
        querySelector: (sel) => sel === '.header-brand' ? brandEl : (sel === '.header-nav' ? navEl : null),
    };
    const secHeaderEl = { offsetHeight: secHeaderHeight };
    const toolbarEl = { offsetHeight: toolbarHeight };
    const scanFooterEl = hasScanFooter ? {
        offsetHeight: scanFooterMinimized ? 26 : scanFooterHeight,
        classList: makeClassList(scanFooterMinimized ? ['scan-status-footer', 'minimized'] : ['scan-status-footer']),
        querySelector: () => null,
        querySelectorAll: () => [],
    } : null;
    const saveBarEl = {
        style: makeStyle(),
        offsetHeight: saveBarHeight,
        classList: makeClassList(saveBarVisible ? ['sidebar-save-bar'] : ['sidebar-save-bar', 'hidden']),
    };
    const stripEl = {
        offsetHeight: stripHeight,
        get scrollWidth() { return stripScrollWidth; },
        get clientWidth() { return stripClientWidth; },
    };
    const holderEl = {
        style: holderStyle,
        querySelector: (sel) => sel === '.stat-strip' ? stripEl : null,
        getBoundingClientRect: () => ({ top: holderTop }),
    };
    const scrollTopBtn = {
        style: makeStyle(),
        classList: makeClassList(),
        addEventListener: (type, fn) => {
            if (!btnListeners.has(type)) btnListeners.set(type, new Set());
            btnListeners.get(type).add(fn);
        },
        click: () => {
            for (const fn of btnListeners.get('click') || []) fn();
        },
    };

    const document = {
        readyState: 'complete',
        documentElement: {
            classList: makeClassList(),
            style: rootStyle,
            clientWidth,
            getAttribute: () => null,
            setAttribute: () => {},
            offsetWidth: 0,
        },
        body: {
            classList: makeClassList(),
            appendChild: () => {},
        },
        getElementById: (id) => {
            if (id === 'scroll-top') return scrollTopBtn;
            if (id === 'scan-status-footer') return scanFooterEl;
            if (id === 'sb-save-bar') return saveBarEl;
            return null;
        },
        querySelector: (sel) => {
            switch (sel) {
                case '.header': return headerEl;
                case '.section-header': return secHeaderEl;
                case '.table-toolbar': return toolbarEl;
                case '.stat-strip-holder': return holderEl;
                default: return null;
            }
        },
        querySelectorAll: () => [],
        createElement: () => ({ style: makeStyle(), classList: makeClassList(), setAttribute: () => {}, appendChild: () => {} }),
        addEventListener: (type, fn) => {
            if (!docListeners.has(type)) docListeners.set(type, new Set());
            docListeners.get(type).add(fn);
        },
        removeEventListener: (type, fn) => docListeners.get(type)?.delete(fn),
    };

    const windowObj = {
        document,
        innerWidth,
        scrollY,
        location: { href: 'http://localhost/', reload: () => {} },
        matchMedia: (q) => ({
            matches: q.includes('min-width') ? wideMatches : reduceMatches,
            addEventListener: () => {},
        }),
        scrollTo: (opts) => scrollCalls.push(opts),
        addEventListener: (type, fn) => {
            if (!winListeners.has(type)) winListeners.set(type, new Set());
            winListeners.get(type).add(fn);
        },
        removeEventListener: (type, fn) => winListeners.get(type)?.delete(fn),
        dispatchEvent: (evt) => {
            for (const fn of [...(winListeners.get(evt.type) || [])]) fn(evt);
        },
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
        matchMedia: windowObj.matchMedia,
        fetch: async () => ({ ok: true, text: async () => '{}', json: async () => ({}) }),
        setInterval: () => 1,
        clearInterval: () => {},
        setTimeout: () => 1,
        clearTimeout: () => {},
        Event: class Event { constructor(type) { this.type = type; } },
        document,
        window: windowObj,
        globalThis: null,
    };
    sandbox.globalThis = sandbox;
    sandbox.self = windowObj;

    for (const file of ['html-utils.js', 'scans-view.js', 'app.js']) {
        const src = fs.readFileSync(path.join(__dirname, file), 'utf8');
        vm.runInNewContext(src, sandbox, { filename: file });
    }

    return {
        window: windowObj,
        document,
        rootStyle,
        holderStyle,
        headerEl,
        toolbarEl,
        scanFooterEl,
        saveBarEl,
        scrollTopBtn,
        scrollCalls,
        sandbox,
        setStripOverflow(overflowing) {
            stripScrollWidth = overflowing ? 900 : 600;
            stripClientWidth = 600;
        },
        Event: sandbox.Event,
    };
}

test('initStickyHeader measures header, section-header, and toolbar offsets and updates on resize', () => {
    const app = loadScrollDockApp({ headerHeight: 70, secHeaderHeight: 50, toolbarHeight: 40 });

    assert.equal(app.rootStyle.getPropertyValue('--header-h'), '70px');
    assert.equal(app.rootStyle.getPropertyValue('--section-header-h'), '50px');
    assert.equal(app.rootStyle.getPropertyValue('--table-toolbar-h'), '40px');
    assert.equal(app.rootStyle.getPropertyValue('--table-thead-top'), '160px');

    app.headerEl.offsetHeight = 80;
    app.toolbarEl.offsetHeight = 45;
    app.window.dispatchEvent(new app.Event('resize'));

    assert.equal(app.rootStyle.getPropertyValue('--header-h'), '80px');
    assert.equal(app.rootStyle.getPropertyValue('--table-toolbar-h'), '45px');
    assert.equal(app.rootStyle.getPropertyValue('--table-thead-top'), '175px');
});

test('initScrollTop accounts for scrollbar width, toggles .visible on scroll, and scrolls smoothly on click', () => {
    const app = loadScrollDockApp({ innerWidth: 1280, clientWidth: 1265, scrollY: 0 });

    // Scrollbar is 1280 - 1265 = 15px, so right offset is 18 + 15 = 33px
    assert.equal(app.scrollTopBtn.style.left, 'auto');
    assert.equal(app.scrollTopBtn.style.right, '33px');
    assert.equal(app.scrollTopBtn.classList.contains('visible'), false);

    app.window.scrollY = 350;
    app.window.dispatchEvent(new app.Event('scroll'));
    assert.equal(app.scrollTopBtn.classList.contains('visible'), true);

    app.scrollTopBtn.click();
    assert.equal(app.scrollCalls.length, 1);
    assert.equal(app.scrollCalls[0].top, 0);
    assert.equal(app.scrollCalls[0].behavior, 'smooth');

    app.window.scrollY = 100;
    app.window.dispatchEvent(new app.Event('scroll'));
    assert.equal(app.scrollTopBtn.classList.contains('visible'), false);
});

test('initStatDock docks stat strip past touchAt and hides overflowing pieces when needed', () => {
    const app = loadScrollDockApp({
        innerWidth: 1280,
        headerHeight: 64,
        holderTop: 200,
        stripHeight: 44,
    });
    app.setStripOverflow(true);

    // touchAt = 200 + 0 - 64 = 136
    assert.equal(app.holderStyle.getPropertyValue('--strip-h'), '44px');
    assert.equal(app.rootStyle.getPropertyValue('--dock-left'), '240px'); // 220 + 20
    assert.equal(app.rootStyle.getPropertyValue('--dock-right'), '400px'); // 1280 - 900 + 20
    assert.equal(app.document.body.classList.contains('strip-docked'), false);

    app.window.scrollY = 140;
    app.window.dispatchEvent(new app.Event('scroll'));
    assert.equal(app.document.body.classList.contains('strip-docked'), true);
    assert.equal(app.document.body.classList.contains('dock-hide-scan'), true);
    assert.equal(app.document.body.classList.contains('dock-hide-meta'), true);

    app.window.scrollY = 50;
    app.window.dispatchEvent(new app.Event('scroll'));
    assert.equal(app.document.body.classList.contains('strip-docked'), false);
    assert.equal(app.document.body.classList.contains('dock-hide-scan'), false);
    assert.equal(app.document.body.classList.contains('dock-hide-meta'), false);
});

test('initStickyHeader and initScrollTop adjust --scan-footer-h and #scroll-top bottom offset for scan footer and save bar', () => {
    const app = loadScrollDockApp({ scanFooterHeight: 38, saveBarVisible: false });
    assert.equal(app.rootStyle.getPropertyValue('--scan-footer-h'), '38px');
    assert.equal(app.scrollTopBtn.style.bottom, '54px');

    // Minimizing the scan footer shrinks --scan-footer-h to 26px and lowers #scroll-top
    app.scanFooterEl.classList.add('minimized');
    app.scanFooterEl.offsetHeight = 26;
    app.sandbox.toggleScanFooter();
    // After toggleScanFooter() toggles minimized off then back on or syncs state:
    // Verify explicit minimized state syncs properly
    app.scanFooterEl.classList.add('minimized');
    app.scanFooterEl.offsetHeight = 26;
    app.window.dispatchEvent(new app.Event('resize'));
    assert.equal(app.rootStyle.getPropertyValue('--scan-footer-h'), '26px');
    assert.equal(app.scrollTopBtn.style.bottom, '42px');

    // Showing the floating save bar lifts #scroll-top clear of it
    app.saveBarEl.classList.remove('hidden');
    app.window.dispatchEvent(new app.Event('resize'));
    assert.equal(parseInt(app.scrollTopBtn.style.bottom, 10) >= 90, true);
});

test('initStickyHeader sets --scan-footer-h to 0px when scan footer is absent', () => {
    const app = loadScrollDockApp({ hasScanFooter: false });
    assert.equal(app.rootStyle.getPropertyValue('--scan-footer-h'), '0px');
    assert.equal(app.scrollTopBtn.style.bottom, '16px');
});
