const test = require('node:test');
const assert = require('node:assert/strict');
const {
    resolveEffectiveDeviceName,
    shouldDisplayUniFiCard,
    formatUniFiName
} = require('./unifi-presentation.js');

test('resolveEffectiveDeviceName prioritizes custom hostname override', () => {
    const data = {
        customHostname: 'My Override',
        hostname: 'dns-name',
        unifiName: 'UniFi Name'
    };
    assert.equal(resolveEffectiveDeviceName(data), 'My Override');
});

test('resolveEffectiveDeviceName prioritizes normal hostname over unifi name when no custom override', () => {
    const data = {
        hostname: 'dns-name',
        unifiName: 'UniFi Name'
    };
    assert.equal(resolveEffectiveDeviceName(data), 'dns-name');
});

test('resolveEffectiveDeviceName falls back to unifi name when normal hostname is empty', () => {
    const data = {
        hostname: '',
        unifiName: 'UniFi Name'
    };
    assert.equal(resolveEffectiveDeviceName(data), 'UniFi Name');
});

test('resolveEffectiveDeviceName falls back to empty string when no names available', () => {
    const data = {};
    assert.equal(resolveEffectiveDeviceName(data), '');
});

test('shouldDisplayUniFiCard shows card when unifiName is present even without ssid', () => {
    assert.equal(shouldDisplayUniFiCard({ unifiName: 'Living Room Switch' }), true);
    assert.equal(shouldDisplayUniFiCard({ ssid: 'Home-WiFi' }), true);
    assert.equal(shouldDisplayUniFiCard({ apName: 'AP-1' }), true);
    assert.equal(shouldDisplayUniFiCard({}), false);
});

test('formatUniFiName returns trimmed name or dash', () => {
    assert.equal(formatUniFiName({ unifiName: '  Office AP  ' }), 'Office AP');
    assert.equal(formatUniFiName({ unifiName: '' }), '—');
    assert.equal(formatUniFiName({}), '—');
});
