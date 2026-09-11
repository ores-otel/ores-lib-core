import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { planRpcRetry, RETRY_REASON } from '../src/rpc-retry.js';

const policy = Object.freeze({ max_attempts: 4, timeout_ms: 1000, initial_backoff_ms: 100, max_backoff_ms: 400 });
const attempt = Object.freeze({ attempts_completed: 1, elapsed_ms: 0, code: 14,
  cancelled: false, replay_safe: true, jitter_permille: 1000 });
const csv = readFileSync(new URL('../../../contracts/rpc-retry-v1.csv', import.meta.url), 'utf8').trim().split('\n');
const header = csv.shift().split(',');
assert.deepEqual(header, ['name', ...Object.keys(policy), ...Object.keys(attempt),
  'retry_after_ms', 'retry', 'delay_ms', 'reason']);
assert.equal(csv.length, 58, 'shared corpus must not be silently truncated');
assert.equal(new Set(csv.map((line) => line.split(',')[0])).size, csv.length);
for (const line of csv) {
  const row = Object.fromEntries(line.split(',').map((value, index) => [header[index], value]));
  test(`cross-runtime fixture: ${row.name}`, () => {
    assert.equal(line.split(',').length, header.length);
    for (const key of ['cancelled', 'replay_safe', 'retry']) assert(['true', 'false'].includes(row[key]));
    const p = Object.fromEntries(Object.keys(policy).map((key) => [key, Number(row[key])]));
    const a = Object.fromEntries(Object.keys(attempt).map((key) => [key,
      ['cancelled', 'replay_safe'].includes(key) ? row[key] === 'true' : Number(row[key])]));
    if (row.retry_after_ms !== '') a.retry_after_ms = Number(row.retry_after_ms);
    assert.deepEqual(planRpcRetry(p, a), { retry: row.retry === 'true', delay_ms: Number(row.delay_ms), reason: Number(row.reason) });
  });
}

for (const bad of [null, undefined, [], 'policy', 42, new Date(), Object.create(policy)]) {
  test(`reject non-record policy ${String(bad)}`, () => {
    assert.equal(planRpcRetry(bad, attempt).reason, RETRY_REASON.invalid_input);
  });
}
for (const value of [NaN, Infinity, -Infinity, 1.5, '4', true, null, undefined, 2 ** 53]) {
  test(`reject non-portable numeric ${String(value)}`, () => {
    assert.equal(planRpcRetry({ ...policy, max_attempts: value }, attempt).reason, RETRY_REASON.invalid_input);
  });
}
test('does not read accessor properties', () => {
  const bad = { ...attempt, get replay_safe() { throw new Error('must not run'); } };
  assert.equal(planRpcRetry(policy, bad).reason, RETRY_REASON.invalid_input);
});
test('rejects unknown, symbol, missing and undefined optional fields', () => {
  const { code, ...missing } = attempt;
  for (const bad of [{ ...attempt, extra: 1 }, { ...attempt, [Symbol('hidden')]: 1 },
    missing, { ...attempt, retry_after_ms: undefined }, { ...attempt, cancelled: 0 },
    { ...attempt, replay_safe: 1 }, { ...attempt, retry_after_ms: null }]) {
    assert.equal(planRpcRetry(policy, bad).reason, RETRY_REASON.invalid_input);
  }
});
test('input records stay immutable and output is frozen', () => {
  const before = JSON.stringify({ policy, attempt });
  const decision = planRpcRetry(policy, attempt);
  assert(Object.isFrozen(decision));
  assert.equal(JSON.stringify({ policy, attempt }), before);
  assert.deepEqual(planRpcRetry(policy, attempt), decision);
});
test('bounded exhaustive safety properties', () => {
  for (let completed = 1; completed <= 8; completed++) {
    for (const elapsed of [0, 1, 500, 999, 1000, 1001]) {
      for (const jitter of [0, 1, 499, 500, 999, 1000]) {
        for (const code of Array.from({ length: 17 }, (_, i) => i)) {
          const a = { ...attempt, attempts_completed: completed, elapsed_ms: elapsed, jitter_permille: jitter, code };
          const d = planRpcRetry(policy, a);
          if (d.retry) {
            assert([8, 14].includes(code));
            assert(completed < policy.max_attempts);
            assert(d.delay_ms >= 0 && d.delay_ms < policy.timeout_ms - elapsed);
            assert(Number.isInteger(d.delay_ms));
            assert.equal(d.reason, RETRY_REASON.retry);
          } else assert.equal(d.delay_ms, 0);
          assert(!planRpcRetry(policy, { ...a, replay_safe: false }).retry);
          assert(!planRpcRetry(policy, { ...a, cancelled: true }).retry);
        }
      }
    }
  }
});
