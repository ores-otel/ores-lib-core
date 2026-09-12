import 'dart:io';
import '../lib/rpc_retry.dart';

/// Checks one fixture row of the shared corpus against the Dart planner.
void checkFixtureRow(String line) {
  final row = line.split(',');
  if (row.length != 15) throw StateError('Malformed shared RPC fixture');
  int number(int index) => int.parse(row[index]);
  bool boolean(int index) {
    if (row[index] != 'true' && row[index] != 'false') throw StateError('Invalid fixture boolean');
    return row[index] == 'true';
  }
  final policy = RpcRetryPolicy(maxAttempts: number(1), timeoutMs: number(2),
    initialBackoffMs: number(3), maxBackoffMs: number(4));
  final attempt = RpcRetryAttempt(attemptsCompleted: number(5), elapsedMs: number(6),
    code: number(7), cancelled: boolean(8), replaySafe: boolean(9),
    jitterPermille: number(10), retryAfterMs: row[11].isEmpty ? null : number(11));
  final decision = planRpcRetry(policy, attempt);
  if (decision.retry != boolean(12) || decision.delayMs != number(13)
      || decision.reason.wireCode != number(14)) {
    throw StateError('RPC conformance failure: ${row[0]}');
  }
}

/// Checks one bounded (attempts, elapsed, jitter, code) combination for safety.
void checkSafetyCombination(RpcRetryPolicy policy, (int, int, int, int) combination) {
  final (completed, elapsed, jitter, code) = combination;
  final attempt = RpcRetryAttempt(attemptsCompleted: completed, elapsedMs: elapsed,
    code: code, cancelled: false, replaySafe: true, jitterPermille: jitter);
  final result = planRpcRetry(policy, attempt);
  if (result.retry && ((code != 8 && code != 14) || completed >= policy.maxAttempts
      || result.delayMs < 0 || result.delayMs >= policy.timeoutMs - elapsed)) {
    throw StateError('Unsafe RPC retry');
  }
  if (!result.retry && result.delayMs != 0) throw StateError('Nonzero stopped retry delay');
  for (final cancelled in [false, true]) {
    final unsafe = RpcRetryAttempt(attemptsCompleted: completed, elapsedMs: elapsed,
      code: code, cancelled: cancelled, replaySafe: false, jitterPermille: jitter);
    if (planRpcRetry(policy, unsafe).retry) throw StateError('Unsafe write replay');
  }
  final cancelled = RpcRetryAttempt(attemptsCompleted: completed, elapsedMs: elapsed,
    code: code, cancelled: true, replaySafe: true, jitterPermille: jitter);
  if (planRpcRetry(policy, cancelled).retry) throw StateError('Cancelled call retried');
}

// Run from langs/dart, like the existing native CI checks. No network/dependencies.
void main() {
  final rows = File('../../contracts/rpc-retry-v1.csv').readAsLinesSync().skip(1).toList();
  for (final line in rows) {
    checkFixtureRow(line);
  }
  if (rows.length < 50) throw StateError('RPC fixture corpus unexpectedly empty or truncated');
  const policy = RpcRetryPolicy(maxAttempts: 4, timeoutMs: 1000, initialBackoffMs: 100, maxBackoffMs: 400);
  // The bounded search space is a value built with collection-for; its length is
  // the number of combinations checked, so no running counter is needed.
  final combinations = [
    for (final completed in List<int>.generate(8, (index) => index + 1))
      for (final elapsed in [0, 1, 500, 999, 1000, 1001])
        for (final jitter in [0, 1, 499, 500, 999, 1000])
          for (final code in List<int>.generate(17, (index) => index))
            (completed, elapsed, jitter, code),
  ];
  for (final combination in combinations) {
    checkSafetyCombination(policy, combination);
  }
  stdout.writeln('RPC retry: ${rows.length} shared fixtures and ${combinations.length} safety combinations passed');
}
