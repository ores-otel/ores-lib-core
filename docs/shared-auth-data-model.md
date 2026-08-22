# Shared Auth data model and revocation protocol

The canonical wire schema lives in `ores-interfaces/contracts/shared-auth-admin/v1/schema.json`;
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

## Canonical global-revocation boundary

1. Online-introspect the administrator credential for the exact audience, AAL2+, current
   session/epoch, and an active `DirectoryAdminGrantSet`. Product JWT role claims are not
   authority.
2. Require an organization-wide `directory_admin` grant with exact
   `directory.revocations.execute` scope. A grant carrying `projectIds` can authorize only those
   projects and must never be promoted to organization authority.
3. Exchange the administrator token through the service-authenticated, exact-audience
   `AdminRevocationTokenExchangeRequest/Result` boundary. Subject/access tokens are write-only,
   short-lived, and never logged or persisted.
4. Convert the transient email to the KMS-HMAC lookup key, resolve ambiguity through the opaque
   selection handoff, and preview exact scopes plus honest complete/partial/unavailable inventory.
5. Issue an opaque, single-use commit authorization only after fresh phishing-resistant WebAuthn.
   Bind it to preview, principal, exact scopes, actor, and freshness/dual-control state.
6. Atomically consume that handle, store only a keyed idempotency digest, and commit the principal
   auth-epoch/not-before fence before any provider fan-out. Persist per-provider target state and
   an honest partial outcome.
7. Append redacted audit correlation and emit the same sanitized event through an injected
   `ores.otel.log` sink. Never use email, raw session IDs, bearer material, or user IDs as
   OpenTelemetry attribute keys or metric labels.

Authorization is re-evaluated on a retry before any new transaction. A completed same-digest
operation replays its stored result without performing revocation again.

### Persistence readiness

`database/postgres/shared_auth_v1.sql` still contains the earlier per-organization draft: it
stores a raw idempotency key, uses `per_organization_sessions.revoke`, and has no principal
auth-epoch fence or per-provider target table. It is retained for review/migration development,
but `contracts/shared-auth-data-model.json` explicitly disables the production capability until
those gaps are replaced and a disposable PostgreSQL/Supabase migration test passes.

## Database access

The migration forces row-level security but intentionally creates no browser policy and grants
nothing to `PUBLIC`. The Shared Auth server uses a dedicated `BYPASSRLS` role created by private
deployment SQL with the minimum table/function grants it needs. Possession of that role is not
authorization: the server still performs online introspection and the per-organization check
above. Supabase `anon` and `authenticated` roles must never receive direct grants.
