import 'package:ores_lib_core/ores_lib_core.dart';

void main() {
  final redactedRecord = redactRecord({
    'requestId': 'req-12345678',
    'accessToken': 'must-not-escape',
  });
  if (redactedRecord['accessToken'] != redacted) {
    throw StateError('credential field was not redacted');
  }
  if (!validCorrelationId('req-12345678') || validCorrelationId('bad space')) {
    throw StateError('correlation validation drifted');
  }
  if (Secret('must-not-escape').toString() != redacted) {
    throw StateError('secret serialization was not redacted');
  }
  if (normalizeEmailForRevocation('  Alex+Ops@Example.COM\n') != 'alex+ops@example.com') {
    throw StateError('email normalization drifted');
  }
  try { normalizeEmailForRevocation('a..b@example.com'); throw StateError('ambiguous email accepted'); } on FormatException { /* expected */ }
  if (redactRecord({'normalizedEmail':'alex@example.com'})['normalizedEmail'] != redacted) {
    throw StateError('normalized email was not redacted');
  }
  final authorized = authorizedOrganizations(
    ['org-a','org-b','org-unknown'],
    const [RevocationGrant('org-b',true),RevocationGrant('org-a',false),RevocationGrant('org-c',true)],
  );
  if (authorized.length != 1 || authorized.single != 'org-b') {
    throw StateError('authorization intersection drifted');
  }
  final one = List<int>.filled(32, 1); final two = List<int>.filled(32, 2);
  if (classifyIdempotency(null, one) != IdempotencyDisposition.newRequest || classifyIdempotency(one, one) != IdempotencyDisposition.replay || classifyIdempotency(one, two) != IdempotencyDisposition.conflict) {
    throw StateError('idempotency classification drifted');
  }
}
