const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('style.css defines sticky hierarchy for frozen header and table thead', () => {
    const cssPath = path.join(__dirname, 'style.css');
    const css = fs.readFileSync(cssPath, 'utf8');

    // Header sticky top 0 with high z-index
    assert.match(css, /\.header\s*\{[^}]*position:\s*sticky/);
    assert.match(css, /\.header\s*\{[^}]*top:\s*0/);

    // Section header / toolbar sticky
    assert.match(css, /\.section-header\s*\{[^}]*position:\s*sticky/);

    // Table thead th sticky
    assert.match(css, /#devices-table\s+thead\s+th\s*\{[^}]*position:\s*sticky/);
});

test('style.css prevents scroll flicker with border-collapse separate and unclipped table container', () => {
    const cssPath = path.join(__dirname, 'style.css');
    const css = fs.readFileSync(cssPath, 'utf8');

    assert.match(css, /\.table\s*\{[^}]*border-collapse:\s*separate/);
    assert.doesNotMatch(css, /\.table-container\s*\{[^}]*overflow:\s*clip/);
});

