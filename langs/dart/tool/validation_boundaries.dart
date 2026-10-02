import '../lib/ores_lib_core.dart';

void require(bool condition, String label) {
  if (!condition) throw StateError(label);
}

void rejects(void Function() action) {
  try {
    action();
  } on FormatException {
    return;
  }
  throw StateError('invalid input was accepted');
}

// No dart:io and no assertions: the same checks execute in the VM and dart2js.
void main() {
  require(
      normalizeEmailForRevocation(' \tAlice+Ops@EXAMPLE.COM\r\n') ==
          'alice+ops@example.com',
      'ASCII normalization output');
  for (final value in [
    '\u212A@example.com',
    'a@\u212A.example',
    '\u00a0a@example.com',
    'a@example.com\u200b',
    '\u0130@example.com',
    'e\u0301@example.com',
    '\ud800@example.com',
    'a\n@example.com',
    'a@example\n.com',
    'a\x00@example.com',
    'a..b@example.com',
    '.a@example.com',
    'a@localhost',
    'a@-example.com',
    'a@example-.com',
    'a@@example.com',
  ]) {
    rejects(() => normalizeEmailForRevocation(value));
  }
  require(validCorrelationId('a' * 8), 'minimum correlation ID');
  require(validCorrelationId('a' * 128), 'maximum correlation ID');
  for (final value in [
    'a' * 7,
    'a' * 129,
    'request-1\n',
    'request-1\r',
    'request-1\u2028',
    'request-1\u2029',
    'request-\u212A',
    'request-😀',
  ]) {
    require(!validCorrelationId(value), 'invalid correlation ID');
  }
  final zero = List<int>.filled(32, 0);
  require(classifyIdempotency(null, zero) == IdempotencyDisposition.newRequest,
      'new request');
  require(classifyIdempotency(zero, List<int>.of(zero)) ==
      IdempotencyDisposition.replay, 'identical digest');
  for (final length in [0, 31, 33]) {
    final bad = List<int>.filled(length, 0);
    rejects(() => classifyIdempotency(null, bad));
    rejects(() => classifyIdempotency(bad, zero));
  }
  for (final index in List<int>.generate(32, (position) => position)) {
    final changed = List<int>.of(zero)..[index] = 255;
    require(classifyIdempotency(zero, changed) ==
        IdempotencyDisposition.conflict, 'different digest');
    require(changed[index] == 255 && zero.every((value) => value == 0),
        'inputs must not be mutated');
    for (final invalid in [-1, 256, 4294967296]) {
      final bad = List<int>.of(zero)..[index] = invalid;
      rejects(() => classifyIdempotency(null, bad));
      rejects(() => classifyIdempotency(zero, bad));
      rejects(() => classifyIdempotency(bad, zero));
    }
  }
  print('validation boundary regressions passed');
}
