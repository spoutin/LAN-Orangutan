const test = require('node:test');
const assert = require('node:assert/strict');
const {
  shouldSyncSidebarForm,
  isElementProtectedFromTimeUpdate,
  formatLastDeepScan,
  formatSidebarIPDisplay,
  ipToComparable,
  getEffectiveRowIP,
  getOrderedAttachments,
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

test('ipToComparable formats IPv4 into zero-padded comparable string', () => {
  assert.equal(ipToComparable('10.0.0.1'), '010.000.000.001');
  assert.equal(ipToComparable('10.0.4.1'), '010.000.004.001');
  assert.equal(ipToComparable('10.0.0.1') < ipToComparable('10.0.4.1'), true);
});

test('getEffectiveRowIP selects matching subnet IP when network filter is active', () => {
  const dataset = {
    ip: '10.0.4.1',
    ipsJson: '[{"ip":"10.0.4.1","network_name":"VLAN 4"},{"ip":"10.0.0.1","network_name":"Home LAN"}]',
  };

  // When filtered on Home LAN, the row's effective sort IP must be 10.0.0.1 (not 10.0.4.1)
  assert.equal(getEffectiveRowIP(dataset, ['home lan']), '10.0.0.1');

  // When filtered on CIDR '10.0.0.0/24', must match 10.0.0.1 via CIDR containment
  assert.equal(getEffectiveRowIP(dataset, ['10.0.0.0/24']), '10.0.0.1');

  // When filtered on VLAN 4, returns 10.0.4.1
  assert.equal(getEffectiveRowIP(dataset, ['vlan 4']), '10.0.4.1');

  // When All Networks (empty active filter), sorts based on lowest IP (10.0.0.1)
  assert.equal(getEffectiveRowIP(dataset, []), '10.0.0.1');

  // When filter doesn't match, falls back to lowest IP
  assert.equal(getEffectiveRowIP(dataset, ['tailscale']), '10.0.0.1');
});

test('getOrderedAttachments orders matching subnet attachments first when filtered', () => {
  const dataset = {
    ip: '10.0.4.1',
    ipsJson: '[{"ip":"10.0.4.1","network_name":"VLAN 4"},{"ip":"10.0.0.1","network_name":"Home LAN"}]',
  };

  // When filtered on Home LAN, Home LAN (10.0.0.1) attachment moves to index 0
  const ordered = getOrderedAttachments(dataset, ['home lan']);
  assert.equal(ordered.length, 2);
  assert.equal(ordered[0].ip, '10.0.0.1');
  assert.equal(ordered[0].network_name, 'Home LAN');
  assert.equal(ordered[1].ip, '10.0.4.1');
  assert.equal(ordered[1].network_name, 'VLAN 4');

  // When filtered on CIDR '10.0.0.0/24', 10.0.0.1 moves to index 0
  const orderedCIDR = getOrderedAttachments(dataset, ['10.0.0.0/24']);
  assert.equal(orderedCIDR[0].ip, '10.0.0.1');

  // When All Networks (empty filter), attachments are ordered by lowest IP first
  const original = getOrderedAttachments(dataset, []);
  assert.equal(original[0].ip, '10.0.0.1');
  assert.equal(original[1].ip, '10.0.4.1');
});

test('effective IP ordering compares correctly with or without network filter', () => {
  const rowA = {
    ip: '10.0.4.1',
    ipsJson: '[{"ip":"10.0.4.1","network_name":"VLAN 4"},{"ip":"10.0.0.1","network_name":"Home LAN"}]',
  };
  const rowB = {
    ip: '10.0.0.15',
    ipsJson: '[{"ip":"10.0.0.15","network_name":"Home LAN"}]',
  };

  // Even without network filter: rowA's lowest IP is 10.0.0.1, so rowA comes BEFORE rowB (10.0.0.15)!
  const noFilterA = ipToComparable(getEffectiveRowIP(rowA, []));
  const noFilterB = ipToComparable(getEffectiveRowIP(rowB, []));
  assert.equal(noFilterA < noFilterB, true);

  // With Home LAN filter: rowA effective IP is 10.0.0.1, so rowA still comes BEFORE rowB (10.0.0.15)!
  const filteredA = ipToComparable(getEffectiveRowIP(rowA, ['home lan']));
  const filteredB = ipToComparable(getEffectiveRowIP(rowB, ['home lan']));
  assert.equal(filteredA < filteredB, true);
});
