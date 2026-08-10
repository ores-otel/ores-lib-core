export const REDACTED = "[REDACTED]";
const SENSITIVE = new Set(["authorization","cookie","password","secret","token","access_token","refresh_token","id_token","client_secret","private_key","totp_seed","webauthn_challenge","face_image","face_template","fingerprint_image","fingerprint_template","biometric_template","voiceprint"]);
export function isSensitiveField(key) { const compact = String(key).trim().toLowerCase().replace(/[^a-z0-9]/g, ""); return [...SENSITIVE].some((field) => { const expected = field.replace(/[^a-z0-9]/g, ""); return compact === expected || compact.endsWith(expected); }); }
export function redactRecord(record) { return Object.fromEntries(Object.entries(record).map(([key, value]) => [key, isSensitiveField(key) ? REDACTED : value])); }
export function validCorrelationId(value) { return typeof value === "string" && value.length >= 8 && value.length <= 128 && /^[A-Za-z0-9._:-]+$/.test(value); }
export class Secret { #value; constructor(value) { this.#value = value; } expose(action) { return action(this.#value); } toString() { return REDACTED; } toJSON() { return REDACTED; } }
