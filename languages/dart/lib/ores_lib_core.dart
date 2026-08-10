const redacted = '[REDACTED]';
const _sensitive = {'authorization','cookie','password','secret','token','access_token','refresh_token','id_token','client_secret','private_key','totp_seed','webauthn_challenge','face_image','face_template','fingerprint_image','fingerprint_template','biometric_template','voiceprint'};
String _compact(String value)=>value.trim().toLowerCase().replaceAll(RegExp(r'[^a-z0-9]'), '');
bool isSensitiveField(String key) { final normalized=_compact(key); return _sensitive.any((field)=>normalized==_compact(field)||normalized.endsWith(_compact(field))); }
Map<String,Object?> redactRecord(Map<String,Object?> value)=>value.map((key,item)=>MapEntry(key,isSensitiveField(key)?redacted:item));
bool validCorrelationId(String value)=>value.length>=8&&value.length<=128&&RegExp(r'^[A-Za-z0-9._:-]+$').hasMatch(value);
final class Secret<T> { const Secret(this._value); final T _value; R expose<R>(R Function(T) action)=>action(_value); @override String toString()=>redacted; }
