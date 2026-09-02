import 'dart:io';
import '../lib/rpc_retry.dart';

// Run from languages/dart, like the existing native CI checks. No network/dependencies.
void main() {
  final rows = File('../../contracts/rpc-retry-v1.csv').readAsLinesSync().skip(1);
  var count = 0;
  for (final line in rows) {
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
    count++;
  }
  if (count < 50) throw StateError('RPC fixture corpus unexpectedly empty or truncated');
  const policy = RpcRetryPolicy(maxAttempts: 4, timeoutMs: 1000, initialBackoffMs: 100, maxBackoffMs: 400);
  var combinations = 0;
  for (var completed = 1; completed <= 8; completed++) {
    for (final elapsed in [0, 1, 500, 999, 1000, 1001]) {
      for (final jitter in [0, 1, 499, 500, 999, 1000]) {
        for (var code = 0; code <= 16; code++) {
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
          combinations++;
        }
      }
    }
  }
  stdout.writeln('RPC retry: $count shared fixtures and $combinations safety combinations passed');
}
