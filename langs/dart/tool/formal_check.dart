import 'dart:convert';
import 'dart:io';

import 'package:ores_lib_core/ores_lib_core.dart';

Never fail(String message) => throw StateError(message);

List<String> variants(String root, String prefix) => <String>[
      '$prefix$root',
      '$prefix${root.toUpperCase()}',
      '$prefix${root.replaceAll('_', '-')}',
      '  $prefix${root.replaceAll('_', '.')}  ',
    ];

void main() {
  final assurance = jsonDecode(
    File('../../formal/redaction-assurance.v1.json').readAsStringSync(),
  ) as Map<String, Object?>;
  final domain = assurance['domain']! as Map<String, Object?>;
  final roots = (domain['sensitiveRoots']! as List<Object?>).cast<String>();
  final safeFields = (domain['safeFields']! as List<Object?>).cast<String>();
  final prefixes = (domain['prefixes']! as List<Object?>).cast<String>();

  for (final root in roots) {
    for (final prefix in prefixes) {
      for (final key in variants(root, prefix)) {
        if (!isSensitiveField(key)) fail('normalization closure failed: $key');
        final left = redactRecord(<String, Object?>{
          key: 'secret-alpha',
          'message': 'safe',
        });
        final right = redactRecord(<String, Object?>{
          key: 'secret-bravo',
          'message': 'safe',
        });
        if (left[key] != redacted || right[key] != redacted) {
          fail('sensitive value escaped: $key');
        }
        if (jsonEncode(left) != jsonEncode(right)) {
          fail('sensitive-value noninterference failed: $key');
        }
        if (jsonEncode(redactRecord(left)) != jsonEncode(left)) {
          fail('redaction idempotence failed: $key');
        }
      }
    }
  }

  for (final key in safeFields) {
    if (isSensitiveField(key)) fail('safe field classified as sensitive: $key');
    final record = redactRecord(<String, Object?>{key: 'safe-value'});
    if (record[key] != 'safe-value') fail('safe field changed: $key');
  }

  final secret = Secret<String>('must-not-escape');
  if (secret.toString() != redacted) fail('secret representation escaped');
  if (secret.expose((value) => value.length) != 'must-not-escape'.length) {
    fail('explicit secret reveal drifted');
  }

  stdout.writeln(
    'Dart formal properties passed: roots=${roots.length} prefixes=${prefixes.length}',
  );
}
