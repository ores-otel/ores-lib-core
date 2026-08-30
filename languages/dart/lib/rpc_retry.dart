/// Pure RPC retry planning. The host owns transport, time, randomness and cancellation.
class RpcRetryPolicy {
  final int maxAttempts;
  final int timeoutMs;
  final int initialBackoffMs;
  final int maxBackoffMs;
  const RpcRetryPolicy({required this.maxAttempts, required this.timeoutMs,
    required this.initialBackoffMs, required this.maxBackoffMs});
}

class RpcRetryAttempt {
  final int attemptsCompleted;
  final int elapsedMs;
  final int code;
  final bool cancelled;
  /// Trusted method metadata; a client-supplied idempotency key alone is not sufficient.
  final bool replaySafe;
  final int jitterPermille;
  /// Server minimum, never shortened to fit a deadline or the local backoff cap.
  final int? retryAfterMs;
  const RpcRetryAttempt({required this.attemptsCompleted, required this.elapsedMs,
    required this.code, required this.cancelled, required this.replaySafe,
    required this.jitterPermille, this.retryAfterMs});
}

enum RpcRetryReason {
  retry(1), invalidInput(2), cancelled(3), unsafeReplay(4),
  attemptsExhausted(5), deadlineExhausted(6), nonRetryable(7);
  final int wireCode;
  const RpcRetryReason(this.wireCode);
}

class RpcRetryDecision {
  final bool retry;
  final int delayMs;
  final RpcRetryReason reason;
  const RpcRetryDecision._(this.retry, this.delayMs, this.reason);
}

bool _bounded(int value, int min, int max) => value >= min && value <= max;
RpcRetryDecision _stop(RpcRetryReason reason) => RpcRetryDecision._(false, 0, reason);

/// Call after a failed completed attempt. maxAttempts includes the original call.
/// elapsedMs is monotonic elapsed time. Recheck cancellation/deadline before each send.
/// No request, key, token, ORM entity, driver error, environment or global state is used.
RpcRetryDecision planRpcRetry(RpcRetryPolicy policy, RpcRetryAttempt attempt) {
  final minimum = attempt.retryAfterMs;
  final valid = _bounded(policy.maxAttempts, 1, 8)
    && _bounded(policy.timeoutMs, 1, 3600000)
    && _bounded(policy.initialBackoffMs, 1, 60000)
    && _bounded(policy.maxBackoffMs, policy.initialBackoffMs, 60000)
    && _bounded(attempt.attemptsCompleted, 1, 8)
    && _bounded(attempt.elapsedMs, 0, 3600000)
    && _bounded(attempt.code, 0, 16)
    && _bounded(attempt.jitterPermille, 0, 1000)
    && (minimum == null || _bounded(minimum, 0, 3600000));
  if (!valid) return _stop(RpcRetryReason.invalidInput);
  if (attempt.cancelled) return _stop(RpcRetryReason.cancelled);
  if (!attempt.replaySafe) return _stop(RpcRetryReason.unsafeReplay);
  if (attempt.attemptsCompleted >= policy.maxAttempts) return _stop(RpcRetryReason.attemptsExhausted);
  if (attempt.elapsedMs >= policy.timeoutMs) return _stop(RpcRetryReason.deadlineExhausted);
  if (attempt.code != 8 && attempt.code != 14) return _stop(RpcRetryReason.nonRetryable);
  final exponential = policy.initialBackoffMs * (1 << (attempt.attemptsCompleted - 1));
  final cap = exponential < policy.maxBackoffMs ? exponential : policy.maxBackoffMs;
  final jittered = cap * attempt.jitterPermille ~/ 1000;
  final serverMinimum = minimum ?? 0;
  final delay = jittered > serverMinimum ? jittered : serverMinimum;
  if (delay >= policy.timeoutMs - attempt.elapsedMs) return _stop(RpcRetryReason.deadlineExhausted);
  return RpcRetryDecision._(true, delay, RpcRetryReason.retry);
}
