const test = require('node:test');
const assert = require('node:assert/strict');
const { formatOSDisplay, formatOSName, formatOSVersion } = require('./os-presentation.js');

test('formatOSDisplay renders Linux icon and Ubuntu version', () => {
    const res = formatOSDisplay({ os: 'Ubuntu Linux', os_version: '22.04', os_family: 'Linux' });
    assert.match(res.html, /svg class="os-icon"/);
    assert.match(res.html, /Ubuntu 22\.04/);
});

test('formatOSDisplay prioritizes custom_os override', () => {
    const res = formatOSDisplay({ os: 'Linux', os_version: '5.15', os_family: 'Linux', custom_os: 'Debian 12' });
    assert.match(res.html, /Debian 12/);
});

test('formatOSDisplay falls back to plain text for esoteric OS without icon', () => {
    const res = formatOSDisplay({ os: 'Plan9', os_version: '4th Edition', os_family: 'Plan9' });
    assert.equal(res.html, 'Plan9 4th Edition');
});

test('formatOSDisplay returns dash for unprobed device', () => {
    const res = formatOSDisplay({ os: '', os_version: '', os_family: '' });
    assert.equal(res.html, '—');
});

test('formatOSName returns OS name with icon without version', () => {
    const res = formatOSName({ os: 'Ubuntu Linux', os_version: '22.04', os_family: 'Linux' });
    assert.match(res.html, /svg class="os-icon"/);
    assert.match(res.html, /Ubuntu/);
    assert.doesNotMatch(res.html, /22\.04/);
});

test('formatOSName prioritizes custom_os override', () => {
    const res = formatOSName({ os: 'Linux', os_version: '5.15', os_family: 'Linux', custom_os: 'Debian' });
    assert.match(res.html, /svg class="os-icon"/);
    assert.match(res.html, /Debian/);
});

test('formatOSName returns dash for unprobed device', () => {
    const res = formatOSName({ os: '', os_version: '', os_family: '' });
    assert.equal(res.html, '—');
    assert.equal(res.text, '—');
    assert.equal(formatOSName(null).html, '—');
});

test('formatOSVersion returns only version or dash', () => {
    assert.equal(formatOSVersion({ os_version: '22.04' }), '22.04');
    assert.equal(formatOSVersion({ osVersion: '11' }), '11');
    assert.equal(formatOSVersion({ os_version: '   ' }), '—');
    assert.equal(formatOSVersion({ os_version: '' }), '—');
    assert.equal(formatOSVersion(null), '—');
});

