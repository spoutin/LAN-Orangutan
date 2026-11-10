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

test('app.js includes scan toolbar and footer in refresh in place selectors', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const appJs = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');

    assert.match(appJs, /['"]\.btn-scan-all['"]/);
    assert.match(appJs, /['"]#scan-status-footer['"]/);
    assert.match(appJs, /['"]#configured-networks-section['"]/);
});

test('style.css ensures floating save bar sits above bottom scan footer', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const css = fs.readFileSync(path.join(__dirname, 'style.css'), 'utf8');

    assert.match(css, /\.sidebar-save-bar\s*\{[^}]*bottom:\s*calc/);
});

test('style.css ensures minimized scan footer stays on screen without translateY offscreen transform', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const css = fs.readFileSync(path.join(__dirname, 'style.css'), 'utf8');

    assert.doesNotMatch(css, /\.scan-status-footer\.minimized\s*\{[^}]*translateY/);
    assert.match(css, /\.scan-status-footer\.minimized\s*\{[^}]*height:\s*\d+px/);
});


