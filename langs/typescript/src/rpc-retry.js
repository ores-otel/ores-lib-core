/** Deterministic RPC retry planning; transport, clocks, randomness and credentials stay outside. */
export const RETRY_REASON = Object.freeze({
  retry: 1, invalid_input: 2, cancelled: 3, unsafe_replay: 4,
  attempts_exhausted: 5, deadline_exhausted: 6, non_retryable: 7,
});

const POLICY_KEYS = Object.freeze([
  'max_attempts', 'timeout_ms', 'initial_backoff_ms', 'max_backoff_ms',
]);
const ATTEMPT_KEYS = Object.freeze([
  'attempts_completed', 'elapsed_ms', 'code', 'cancelled', 'replay_safe', 'jitter_permille',
]);
const bounded = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;

// Accept inert JSON-shaped records only. Inherited values and accessor properties are not inputs.
function record(value, required, optional = []) {
  if (value === null || typeof value !== 'object') return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  return required.every((key) => Object.hasOwn(descriptors, key))
    && Reflect.ownKeys(descriptors).every((key) => typeof key === 'string'
      && (required.includes(key) || optional.includes(key))
      && Object.hasOwn(descriptors[key], 'value') && descriptors[key].enumerable);
}

const stop = (reason) => Object.freeze({ retry: false, delay_ms: 0, reason });

/**
 * Plan AFTER a failed completed attempt. max_attempts includes the original call.
 * replay_safe is trusted method metadata, not a request parameter or proof supplied by a client.
 * An idempotency key alone does not make a write safe to replay.
 * elapsed_ms is monotonic elapsed time; the host rechecks cancellation/deadline before sending.
 * jitter_permille is an injected integer sample in [0, 1000]; this function draws no randomness.
 * retry_after_ms is an optional SERVER MINIMUM, never shortened to the local backoff cap.
 * No request payload, token, idempotency key, SQL or driver error is accepted or returned.
 */
export function planRpcRetry(policy, attempt) {
  if (!record(policy, POLICY_KEYS) || !record(attempt, ATTEMPT_KEYS, ['retry_after_ms'])) {
    return stop(RETRY_REASON.invalid_input);
  }
  if (!bounded(policy.max_attempts, 1, 8)
      || !bounded(policy.timeout_ms, 1, 3_600_000)
      || !bounded(policy.initial_backoff_ms, 1, 60_000)
      || !bounded(policy.max_backoff_ms, policy.initial_backoff_ms, 60_000)
      || !bounded(attempt.attempts_completed, 1, 8)
      || !bounded(attempt.elapsed_ms, 0, 3_600_000)
      || !bounded(attempt.code, 0, 16)
      || typeof attempt.cancelled !== 'boolean' || typeof attempt.replay_safe !== 'boolean'
      || !bounded(attempt.jitter_permille, 0, 1000)
      || (Object.hasOwn(attempt, 'retry_after_ms') && !bounded(attempt.retry_after_ms, 0, 3_600_000))) {
    return stop(RETRY_REASON.invalid_input);
  }
  if (attempt.cancelled) return stop(RETRY_REASON.cancelled);
  if (!attempt.replay_safe) return stop(RETRY_REASON.unsafe_replay);
  if (attempt.attempts_completed >= policy.max_attempts) return stop(RETRY_REASON.attempts_exhausted);
  if (attempt.elapsed_ms >= policy.timeout_ms) return stop(RETRY_REASON.deadline_exhausted);
  // gRPC/Connect RESOURCE_EXHAUSTED (8) and UNAVAILABLE (14), explicitly allowlisted.
  if (attempt.code !== 8 && attempt.code !== 14) return stop(RETRY_REASON.non_retryable);
  const cap = Math.min(policy.max_backoff_ms,
    policy.initial_backoff_ms * (2 ** (attempt.attempts_completed - 1)));
  const jittered = Math.floor(cap * attempt.jitter_permille / 1000);
  const delay = Math.max(jittered, attempt.retry_after_ms ?? 0);
  // Equality leaves no time for the call; never shorten a server minimum to fit a deadline.
  if (delay >= policy.timeout_ms - attempt.elapsed_ms) return stop(RETRY_REASON.deadline_exhausted);
  return Object.freeze({ retry: true, delay_ms: delay, reason: RETRY_REASON.retry });
}
