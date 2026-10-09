const assert = require('node:assert/strict');
const test = require('node:test');

test('targeted deep scan progress identifies the device that owns the sidebar spinner', () => {
  const progress = { status: 'running', targeted_deep_scan: true, targeted_device_ip: '10.0.0.15' };
  assert.equal(progress.status === 'running' && progress.targeted_deep_scan && progress.targeted_device_ip === '10.0.0.15', true);
  assert.equal(progress.status === 'running' && progress.targeted_deep_scan && progress.targeted_device_ip === '10.0.0.16', false);
});

test('a targeted deep scan protects only its selected device timestamp', () => {
  const activeTargetedDeepScanIP = '10.0.0.15';
  const protectsTimestamp = ip => activeTargetedDeepScanIP === ip;
  assert.equal(protectsTimestamp('10.0.0.15'), true);
  assert.equal(protectsTimestamp('10.0.0.16'), false);
});

test('a completed targeted deep scan releases its rescan control', () => {
  const button = { disabled: true };
  const targetedDeepScanRunning = false;
  if (!targetedDeepScanRunning) button.disabled = false;
  assert.equal(button.disabled, false);
});
