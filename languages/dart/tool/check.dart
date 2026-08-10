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
}
