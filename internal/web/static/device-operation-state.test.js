const assert = require('node:assert/strict');
const test = require('node:test');

test('targeted deep scan progress identifies the device that owns the sidebar spinner', () => {
  const progress = { status: 'running', targeted_deep_scan: true, targeted_device_ip: '10.0.0.15' };
  assert.equal(progress.status === 'running' && progress.targeted_deep_scan && progress.targeted_device_ip === '10.0.0.15', true);
  assert.equal(progress.status === 'running' && progress.targeted_deep_scan && progress.targeted_device_ip === '10.0.0.16', false);
});
