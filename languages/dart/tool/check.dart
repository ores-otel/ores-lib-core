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
  if (normalizeEmailForRevocation('  Alex+Ops@Example.COM\n') !=
      'alex+ops@example.com') {
    throw StateError('email normalization drifted');
  }
  try {
    normalizeEmailForRevocation('a..b@example.com');
    throw StateError('ambiguous email accepted');
  } on FormatException {/* expected */}
  if (redactRecord(
          {'normalizedEmail': 'alex@example.com'})['normalizedEmail'] !=
      redacted) {
    throw StateError('normalized email was not redacted');
  }
  final authorized = authorizedOrganizations(
    ['org-a', 'org-b', 'org-unknown'],
    const [
      RevocationGrant('org-b', true),
      RevocationGrant('org-a', false),
      RevocationGrant('org-c', true)
    ],
  );
  if (authorized.length != 1 || authorized.single != 'org-b') {
    throw StateError('authorization intersection drifted');
  }
  final one = List<int>.filled(32, 1);
  final two = List<int>.filled(32, 2);
  if (classifyIdempotency(null, one) != IdempotencyDisposition.newRequest ||
      classifyIdempotency(one, one) != IdempotencyDisposition.replay ||
      classifyIdempotency(one, two) != IdempotencyDisposition.conflict) {
    throw StateError('idempotency classification drifted');
  }
  const directoryGrants = [
    DirectoryGrant(
      grantId: '20000000-0000-4000-8000-000000000001',
      organizationId: '10000000-0000-4000-8000-000000000001',
      scopes: [directoryRevocationsExecuteScope],
      roles: [directoryAdminRole],
      grantedAt: '2026-08-11T21:00:00Z',
    )
  ];
  if (authorizedDirectoryOrganizations(
                  null, directoryRevocationsExecuteScope, directoryGrants)
              .length !=
          1 ||
      authorizedDirectoryOrganizations(null, 'directory.*', directoryGrants)
          .isNotEmpty) {
    throw StateError('directory grants must require exact role and scope');
  }
  const projectBoundedGrant = DirectoryGrant(
    grantId: '20000000-0000-4000-8000-000000000002',
    organizationId: '10000000-0000-4000-8000-000000000001',
    projectIds: ['30000000-0000-4000-8000-000000000001'],
    scopes: [directoryRevocationsExecuteScope],
    roles: [directoryAdminRole],
    grantedAt: '2026-08-11T21:00:00Z',
  );
  if (authorizedDirectoryOrganizations(
          null, directoryRevocationsExecuteScope, [projectBoundedGrant])
      .isNotEmpty) {
    throw StateError('project grant was elevated to organization authority');
  }
}
