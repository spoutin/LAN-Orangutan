const test = require('node:test');
const assert = require('node:assert/strict');
const {
  shouldSyncSidebarForm,
  isElementProtectedFromTimeUpdate,
  formatLastDeepScan,
  formatSidebarIPDisplay,
} = require('./device-operation-state.js');

test('shouldSyncSidebarForm rejects sync when user has unsaved edits', () => {
  assert.equal(shouldSyncSidebarForm({ hasUnsavedChanges: true, isFormFocused: false }), false);
  assert.equal(shouldSyncSidebarForm({ hasUnsavedChanges: true, isFormFocused: true }), false);
});

test('shouldSyncSidebarForm rejects sync when user is actively focused on form input', () => {
  assert.equal(shouldSyncSidebarForm({ hasUnsavedChanges: false, isFormFocused: true }), false);
});

test('shouldSyncSidebarForm permits sync when form is clean and unfocused', () => {
  assert.equal(shouldSyncSidebarForm({ hasUnsavedChanges: false, isFormFocused: false }), true);
});

test('isElementProtectedFromTimeUpdate protects elements inside scanning containers', () => {
  const insideSpinner = {
    closest: selector => (selector === '.deep-scan-progress' ? {} : null),
  };
  const insideScanning = {
    closest: selector => (selector === '.scanning' ? {} : null),
  };
  const normalElement = {
    closest: () => null,
  };

  assert.equal(isElementProtectedFromTimeUpdate(insideSpinner), true);
  assert.equal(isElementProtectedFromTimeUpdate(insideScanning), true);
  assert.equal(isElementProtectedFromTimeUpdate(normalElement), false);
  assert.equal(isElementProtectedFromTimeUpdate(null), true);
});

test('formatLastDeepScan returns spinner markup and no relative-time attribute when scanning', () => {
  const result = formatLastDeepScan('2026-10-09T18:00:00Z', true);
  assert.equal(result.hasRelativeTime, false);
  assert.match(result.html, /class="deep-scan-progress"/);
  assert.match(result.html, /Scanning services\.\.\./);
  assert.doesNotMatch(result.html, /data-relative-time/);
});

test('formatLastDeepScan returns timestamp with relative-time child when not scanning', () => {
  const result = formatLastDeepScan('2026-10-09T18:00:00Z', false);
  assert.equal(result.hasRelativeTime, true);
  assert.equal(typeof result.unix, 'number');
  assert.match(result.html, /data-relative-time=/);
  assert.doesNotMatch(result.html, /class="deep-scan-progress"/);
});

test('formatLastDeepScan returns Never when timestamp is missing or invalid', () => {
  assert.deepEqual(formatLastDeepScan('', false), {
    html: 'Never',
    hasRelativeTime: false,
    unix: null,
  });
  assert.deepEqual(formatLastDeepScan(null, false), {
    html: 'Never',
    hasRelativeTime: false,
    unix: null,
  });
  assert.deepEqual(formatLastDeepScan('invalid-date', false), {
    html: 'Never',
    hasRelativeTime: false,
    unix: null,
  });
});

test('formatSidebarIPDisplay safely handles string ips from DOM dataset without crashing', () => {
  // Case from bug report: data.ips is a string "192.168.1.50" from dataset
  const res = formatSidebarIPDisplay({ ip: '192.168.1.50', ips: '192.168.1.50' });
  assert.equal(res.isHTML, false);
  assert.equal(res.text, '192.168.1.50');
});

test('formatSidebarIPDisplay renders multi-IP HTML when ips is an array with > 1 items', () => {
  const res = formatSidebarIPDisplay({
    ip: '10.0.0.10',
    ips: [
      { ip: '10.0.0.10', network_name: 'Home LAN' },
      { ip: '10.0.0.20', network_name: 'Home LAN' },
    ],
  });
  assert.equal(res.isHTML, true);
  assert.match(res.html, /10\.0\.0\.10/);
  assert.match(res.html, /10\.0\.0\.20/);
  assert.match(res.html, /Home LAN/);
});

test('formatSidebarIPDisplay renders multi-IP HTML when ipsJson string contains > 1 items', () => {
  const res = formatSidebarIPDisplay({
    ip: '10.0.0.10',
    ips: '10.0.0.10,10.0.0.20',
    ipsJson: '[{"ip":"10.0.0.10","network_name":"Home LAN"},{"ip":"10.0.0.20","network_name":"Home LAN"}]',
  });
  assert.equal(res.isHTML, true);
  assert.match(res.html, /10\.0\.0\.10/);
  assert.match(res.html, /10\.0\.0\.20/);
});

test('formatSidebarIPDisplay falls back to dash for empty device data', () => {
  const res = formatSidebarIPDisplay({});
  assert.equal(res.isHTML, false);
  assert.equal(res.text, '—');
});
