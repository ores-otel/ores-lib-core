package orescore

import "strings"
const Redacted = "[REDACTED]"
var sensitive = []string{"authorization","cookie","password","secret","token","access_token","refresh_token","id_token","client_secret","private_key","totp_seed","webauthn_challenge","face_image","face_template","fingerprint_image","fingerprint_template","biometric_template","voiceprint"}
func compactKey(value string) string { var builder strings.Builder; for _, r := range strings.ToLower(strings.TrimSpace(value)) { if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') { builder.WriteRune(r) } }; return builder.String() }
func IsSensitiveField(key string) bool { normalized := compactKey(key); for _, field := range sensitive { expected := compactKey(field); if normalized == expected || strings.HasSuffix(normalized, expected) { return true } }; return false }
func RedactRecord(input map[string]any) map[string]any { out := make(map[string]any, len(input)); for key, value := range input { if IsSensitiveField(key) { out[key] = Redacted } else { out[key] = value } }; return out }
func ValidCorrelationID(value string) bool { if len(value)<8 || len(value)>128 { return false }; for _, r := range value { if !((r>='a'&&r<='z')||(r>='A'&&r<='Z')||(r>='0'&&r<='9')||strings.ContainsRune("._:-", r)) { return false } }; return true }
type SecurityLogSink interface { Emit(action, outcome, reasonCode string, fields map[string]string) }
