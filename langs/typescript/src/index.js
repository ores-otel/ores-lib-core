export const REDACTED = "[REDACTED]";
const SENSITIVE = new Set(["authorization","cookie","password","secret","token","email","normalized_email","email_lookup_hmac","access_token","refresh_token","id_token","client_secret","private_key","totp_seed","webauthn_challenge","face_image","face_template","fingerprint_image","fingerprint_template","biometric_template","voiceprint"]);
export function isSensitiveField(key) { const compact = String(key).trim().toLowerCase().replace(/[^a-z0-9]/g, ""); return [...SENSITIVE].some((field) => { const expected = field.replace(/[^a-z0-9]/g, ""); return compact === expected || compact.endsWith(expected); }); }
export function redactRecord(record) { return Object.fromEntries(Object.entries(record).map(([key, value]) => [key, isSensitiveField(key) ? REDACTED : value])); }
export function validCorrelationId(value) { return typeof value === "string" && value.length >= 8 && value.length <= 128 && /^[A-Za-z0-9._:-]+$/.test(value); }
export class Secret { #value; constructor(value) { this.#value = value; } expose(action) { return action(this.#value); } toString() { return REDACTED; } toJSON() { return REDACTED; } }

export function normalizeEmailForRevocation(value) {
  if (typeof value !== "string") throw new TypeError("email must be a string");
  const normalized = value.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, "").toLowerCase();
  if (normalized.length === 0) throw new TypeError("email is empty");
  if (normalized.length > 320) throw new TypeError("email is too long");
  if (!/^[\x00-\x7F]+$/.test(normalized)) throw new TypeError("email must be ASCII");
  const parts = normalized.split("@");
  if (parts.length !== 2 || parts[0].length === 0 || parts[1].length === 0) throw new TypeError("email structure is invalid");
  const [local, domain] = parts;
  if (local.length > 64 || local.startsWith(".") || local.endsWith(".") || local.includes("..") || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)) throw new TypeError("email local part is invalid");
  const labels = domain.split(".");
  if (domain.length > 255 || labels.length < 2 || labels.some((label) => label.length === 0 || label.length > 63 || label.startsWith("-") || label.endsWith("-") || !/^[a-z0-9-]+$/.test(label))) throw new TypeError("email domain is invalid");
  return normalized;
}

export function authorizedOrganizations(requested, grants) {
  const requestedSet = requested === undefined ? undefined : new Set(requested);
  return [...new Set(grants.filter((grant) => grant.sessionsRevoke && (requestedSet === undefined || requestedSet.has(grant.organizationId))).map((grant) => grant.organizationId))].sort();
}

export const DIRECTORY_ADMIN_ROLE = "directory_admin";
export const DIRECTORY_REVOCATIONS_EXECUTE_SCOPE = "directory.revocations.execute";

export function authorizedDirectoryOrganizations(requested, requiredScope, grants) {
  if (typeof requiredScope !== "string" || requiredScope.includes("*")) return [];
  const requestedSet = requested === undefined ? undefined : new Set(requested);
  return [...new Set(grants
    .filter((grant) => Array.isArray(grant.roles) && grant.roles.includes(DIRECTORY_ADMIN_ROLE))
    .filter((grant) => Array.isArray(grant.scopes) && grant.scopes.includes(requiredScope))
    .filter((grant) => grant.projectIds === undefined)
    .filter((grant) => requestedSet === undefined || requestedSet.has(grant.organizationId))
    .map((grant) => grant.organizationId))].sort();
}

export function classifyIdempotency(existingRequestDigest, incomingRequestDigest) {
  if (!(incomingRequestDigest instanceof Uint8Array) || incomingRequestDigest.length !== 32) throw new TypeError("incoming digest must be a 32-byte Uint8Array");
  if (existingRequestDigest === undefined) return "new";
  if (!(existingRequestDigest instanceof Uint8Array) || existingRequestDigest.length !== 32) throw new TypeError("existing digest must be a 32-byte Uint8Array");
  if (existingRequestDigest.length !== incomingRequestDigest.length) return "conflict";
  let difference = 0;
  for (let index = 0; index < existingRequestDigest.length; index += 1) difference |= existingRequestDigest[index] ^ incomingRequestDigest[index];
  return difference === 0 ? "replay" : "conflict";
}
