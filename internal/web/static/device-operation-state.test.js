const test = require('node:test');
const assert = require('node:assert/strict');
const {
  shouldSyncSidebarForm,
  isElementProtectedFromTimeUpdate,
  formatLastDeepScan,
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
