# Shared Auth data model and revocation protocol

The canonical wire schema lives in `ores-interfaces/contracts/shared-auth/v1/schema.json`;
`database/postgres/shared_auth_v1.sql` is its PostgreSQL 15+/Supabase persistence profile.
The schema is organization-first: projects belong to one organization, memberships join a
global identity to one organization, and composite foreign keys prevent role bindings,
sessions, or project references from crossing an organization boundary.

## Sensitive-material boundary

The database does not store an address. The server normalizes an ASCII address in memory and
uses a KMS-managed pepper to compute HMAC-SHA-256. Only that digest, its key identifier, and a
display-safe redaction are persisted. A plain SHA-256 address digest is not acceptable because
the email search space is enumerable.

The migration requires PostgreSQL 15+ but does not install extensions. UUID generation uses
the core `gen_random_uuid()` function; HMAC derivation remains in the KMS-backed application
adapter so the database never receives the email or pepper.

Factors store an external-credential-reference HMAC and/or a public fingerprint. There are no
columns for private keys, TOTP/recovery secrets, WebAuthn verifier material, face/fingerprint
images, or biometric templates. `platform_biometric` records only that the external platform
authenticator performed user verification. Sessions similarly store a keyed audit digest, not
a bearer token, refresh token, cookie, or raw provider session ID.

## Revoke sessions by normalized email

1. Online-introspect the administrator credential for the exact Shared Auth audience. Actor
   identity is taken from that verified context, never from the command body.
2. Parse and normalize the email with `normalize_email_for_revocation`. Reject non-ASCII input,
   ambiguous dots, invalid domain labels, or an already-noncanonical wire value.
3. Build a canonical request digest, including the email lookup HMAC—not the email—the sorted
   scope, reason, and `dryRun` flag.
4. Insert `revocation_operation` under `(actor_subject, idempotency_key)`. On uniqueness conflict,
   constant-time compare `request_digest`: replay the sanitized result if equal; return
   `IDEMPOTENCY_KEY_REUSED` if different.
5. Compute the intersection between requested organizations and current `sessions.revoke`
   grants. Never use a product JWT role claim as the authority. Do not return inaccessible
   organization IDs; only return the aggregate `unprocessedOrganizationCount`.
6. In a separate transaction for each authorized organization, lock matching active sessions,
   revoke them at the upstream identity provider, update local state, append `audit_event`, and
   insert one `revocation_organization_result` with `authorization_verified = true`.
7. Mark the operation `completed`, `partial`, `denied`, or `no_match`, then emit the same
   sanitized event through an injected `ores.otel.log` sink. Never use email, session IDs, or
   user IDs as OpenTelemetry attribute keys or metric labels.

Authorization is re-evaluated on a retry before any new organization transaction. A completed
same-digest operation replays its stored counts and authorized organization results without
performing revocation again.

## Database access

The migration forces row-level security but intentionally creates no browser policy and grants
nothing to `PUBLIC`. The Shared Auth server uses a dedicated `BYPASSRLS` role created by private
deployment SQL with the minimum table/function grants it needs. Possession of that role is not
authorization: the server still performs online introspection and the per-organization check
above. Supabase `anon` and `authenticated` roles must never receive direct grants.
