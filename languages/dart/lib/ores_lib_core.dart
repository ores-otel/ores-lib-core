const redacted = '[REDACTED]';
const _sensitive = {
  'authorization',
  'cookie',
  'password',
  'secret',
  'token',
  'email',
  'normalized_email',
  'email_lookup_hmac',
  'access_token',
  'refresh_token',
  'id_token',
  'client_secret',
  'private_key',
  'totp_seed',
  'webauthn_challenge',
  'face_image',
  'face_template',
  'fingerprint_image',
  'fingerprint_template',
  'biometric_template',
  'voiceprint'
};
String _compact(String value) =>
    value.trim().toLowerCase().replaceAll(RegExp(r'[^a-z0-9]'), '');
bool isSensitiveField(String key) {
  final normalized = _compact(key);
  return _sensitive.any((field) =>
      normalized == _compact(field) || normalized.endsWith(_compact(field)));
}

Map<String, Object?> redactRecord(Map<String, Object?> value) => value
    .map((key, item) => MapEntry(key, isSensitiveField(key) ? redacted : item));
bool validCorrelationId(String value) =>
    value.length >= 8 &&
    value.length <= 128 &&
    RegExp(r'^[A-Za-z0-9._:-]+$').hasMatch(value);

final class Secret<T> {
  const Secret(this._value);
  final T _value;
  R expose<R>(R Function(T) action) => action(_value);
  @override
  String toString() => redacted;
}

String normalizeEmailForRevocation(String value) {
  final normalized = value
      .replaceFirst(RegExp(r'^[ \t\r\n]+'), '')
      .replaceFirst(RegExp(r'[ \t\r\n]+$'), '')
      .toLowerCase();
  if (normalized.isEmpty) {
    throw const FormatException('email is empty');
  }
  if (normalized.length > 320) {
    throw const FormatException('email is too long');
  }
  if (normalized.codeUnits.any((value) => value > 127)) {
    throw const FormatException('email must be ASCII');
  }
  final parts = normalized.split('@');
  if (parts.length != 2 || parts[0].isEmpty || parts[1].isEmpty) {
    throw const FormatException('email structure is invalid');
  }
  final local = parts[0];
  final domain = parts[1];
  if (local.length > 64 ||
      local.startsWith('.') ||
      local.endsWith('.') ||
      local.contains('..') ||
      local.codeUnits.any((value) => !_validEmailLocalCodeUnit(value))) {
    throw const FormatException('email local part is invalid');
  }
  final labels = domain.split('.');
  if (domain.length > 255 ||
      labels.length < 2 ||
      labels.any((label) => !_validDomainLabel(label))) {
    throw const FormatException('email domain is invalid');
  }
  return normalized;
}

bool _validEmailLocalCodeUnit(int value) =>
    (value >= 97 && value <= 122) ||
    (value >= 48 && value <= 57) ||
    ".!#\$%&'*+-/=?^_`{|}~".codeUnits.contains(value);
bool _validDomainLabel(String label) =>
    label.isNotEmpty &&
    label.length <= 63 &&
    !label.startsWith('-') &&
    !label.endsWith('-') &&
    label.codeUnits.every((value) =>
        (value >= 97 && value <= 122) ||
        (value >= 48 && value <= 57) ||
        value == 45);

abstract interface class EmailLookupHmac {
  String get keyId;
  List<int> derive(String normalizedEmail);
}

final class RevocationGrant {
  const RevocationGrant(this.organizationId, this.sessionsRevoke);
  final String organizationId;
  final bool sessionsRevoke;
}

const directoryAdminRole = 'directory_admin';
const directoryRevocationsExecuteScope = 'directory.revocations.execute';

final class DirectoryGrant {
  const DirectoryGrant(
      {required this.grantId,
      required this.organizationId,
      this.projectIds,
      required this.scopes,
      required this.roles,
      required this.grantedAt,
      this.expiresAt});
  final String grantId;
  final String organizationId;
  final List<String>? projectIds;
  final List<String> scopes;
  final List<String> roles;
  final String grantedAt;
  final String? expiresAt;
  bool allows(String requiredScope) =>
      !requiredScope.contains('*') &&
      roles.contains(directoryAdminRole) &&
      scopes.contains(requiredScope);
}

List<String> authorizedDirectoryOrganizations(List<String>? requested,
    String requiredScope, List<DirectoryGrant> grants) {
  final requestedSet = requested?.toSet();
  final authorized = grants
      .where((grant) =>
          grant.allows(requiredScope) &&
          grant.projectIds == null &&
          (requestedSet == null || requestedSet.contains(grant.organizationId)))
      .map((grant) => grant.organizationId)
      .toSet()
      .toList()
    ..sort();
  return authorized;
}

List<String> authorizedOrganizations(
    List<String>? requested, List<RevocationGrant> grants) {
  final requestedSet = requested?.toSet();
  final authorized = grants
      .where((grant) =>
          grant.sessionsRevoke &&
          (requestedSet == null || requestedSet.contains(grant.organizationId)))
      .map((grant) => grant.organizationId)
      .toSet()
      .toList()
    ..sort();
  return authorized;
}

enum IdempotencyDisposition { newRequest, replay, conflict }

IdempotencyDisposition classifyIdempotency(
    List<int>? existingRequestDigest, List<int> incomingRequestDigest) {
  if (incomingRequestDigest.length != 32) {
    throw const FormatException('incoming digest must contain 32 bytes');
  }
  if (existingRequestDigest == null) {
    return IdempotencyDisposition.newRequest;
  }
  if (existingRequestDigest.length != 32) {
    throw const FormatException('existing digest must contain 32 bytes');
  }
  var difference = 0;
  for (var index = 0; index < existingRequestDigest.length; index += 1) {
    difference |= existingRequestDigest[index] ^ incomingRequestDigest[index];
  }
  return difference == 0
      ? IdempotencyDisposition.replay
      : IdempotencyDisposition.conflict;
}
