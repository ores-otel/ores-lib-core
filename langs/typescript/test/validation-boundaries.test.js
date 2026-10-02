import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeEmailForRevocation, validCorrelationId, classifyIdempotency } from '../src/index.js';

test('ASCII normalization preserves the agreed output', () => {
  assert.equal(normalizeEmailForRevocation(' \tAlice+Ops@EXAMPLE.COM\r\n'), 'alice+ops@example.com');
  assert.equal(normalizeEmailForRevocation('k@example.com'), 'k@example.com');
});
test('rejects a non-ASCII local part before Unicode case folding', () => {
  assert.throws(() => normalizeEmailForRevocation('\u212A@example.com'), /ASCII/);
});
test('rejects a non-ASCII domain before Unicode case folding', () => {
  assert.throws(() => normalizeEmailForRevocation('a@\u212A.example'), /ASCII/);
});
test('non-ASCII whitespace, combining marks and unpaired surrogates are not normalized away', () => {
  for (const value of ['\u00a0a@example.com', 'a@example.com\u200b', '\u0130@example.com', 'e\u0301@example.com', '\ud800@example.com']) {
    assert.throws(() => normalizeEmailForRevocation(value));
  }
});
test('email boundary does not coerce runtime values', () => {
  for (const value of [null, undefined, 18, true, {}, [], new String('a@example.com')]) {
    assert.throws(() => normalizeEmailForRevocation(value), TypeError);
  }
});
test('email structural and interior-control rejection is retained', () => {
  for (const value of ['a\n@example.com', 'a@example\n.com', 'a\0@example.com', 'a..b@example.com', '.a@example.com', 'a@localhost', 'a@-example.com', 'a@example-.com', 'a@@example.com']) {
    assert.throws(() => normalizeEmailForRevocation(value));
  }
});
test('correlation IDs retain strict complete-string and ASCII bounds', () => {
  assert.equal(validCorrelationId('a'.repeat(8)), true);
  assert.equal(validCorrelationId('a'.repeat(128)), true);
  for (const value of ['a'.repeat(7), 'a'.repeat(129), 'request-1\n', 'request-1\r', 'request-1\u2028', 'request-1\u2029', 'request-\u212A', 'request-😀', null, 12345678]) {
    assert.equal(validCorrelationId(value), false);
  }
});
test('idempotency accepts only 32-byte typed arrays', () => {
  for (const value of [[], Array(32).fill(0), new Uint8Array(31), new Uint8Array(33), null, undefined]) {
    assert.throws(() => classifyIdempotency(undefined, value), TypeError);
  }
});
test('a stored malformed digest cannot be treated as absent or a replay', () => {
  for (const value of [null, [], Array(32).fill(0), new Uint8Array(31), new Uint8Array(33)]) {
    assert.throws(() => classifyIdempotency(value, new Uint8Array(32)), TypeError);
  }
});
test('idempotency does not mutate inputs and handles every byte position', () => {
  const stored = new Uint8Array(32);
  assert.equal(classifyIdempotency(undefined, stored), 'new');
  assert.equal(classifyIdempotency(stored, stored.slice()), 'replay');
  for (let index = 0; index < 32; index += 1) {
    const incoming = stored.slice();
    incoming[index] = 255;
    assert.equal(classifyIdempotency(stored, incoming), 'conflict');
    assert.equal(incoming[index], 255);
    assert.deepEqual(stored, new Uint8Array(32));
  }
});
test('errors omit the rejected email and digest contents', () => {
  const value = 'private-\u212A@example.com';
  assert.throws(() => normalizeEmailForRevocation(value), error => !error.message.includes(value));
  assert.throws(() => classifyIdempotency(undefined, [99]), error => !error.message.includes('99'));
});
