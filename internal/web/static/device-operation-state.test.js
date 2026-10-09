const assert = require('node:assert/strict');
const test = require('node:test');

test('deep scan operation remains active across sidebar rerenders', () => {
  const operations = new Map();
  operations.set('10.0.0.15', { kind: 'deep-scan', status: 'running' });
  assert.equal(operations.get('10.0.0.15').status, 'running');
  assert.equal(operations.get('10.0.0.15').kind, 'deep-scan');
});
