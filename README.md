# ores-lib-core

Small, security-oriented building blocks shared across OreSoftware services and clients.

This repository intentionally avoids product policy and global runtime mutation. It supplies
redaction, correlation-ID validation, secret wrappers, bounded pagination primitives, and
injectable security-log sinks. It also supplies the canonical PostgreSQL/Supabase persistence
profile and portable helpers for Shared Auth's authorized, idempotent email-based session
revocation. Canonical wire types live in
[`ores-otel/ores-interfaces`](https://github.com/ores-otel/ores-interfaces), and structured
logging is provided by
[`ores-otel/ores.otel.log`](https://github.com/ores-otel/ores.otel.log). Both are declared in
`.zpkg.toml`; applications choose the native language target they use.

## Invariants

- Secret wrappers redact `Debug`/string output and require an explicit reveal operation.
- Sensitive field names are matched case-insensitively and include tokens, cookies, key
  material, TOTP seeds, biometric material, and provider credentials.
- Correlation identifiers are bounded and contain only portable characters.
- Shared page limits are bounded; administrative cursor values remain opaque.
- The core library never installs a global logger or OpenTelemetry provider.
- Face/fingerprint verification is represented only as a platform-authenticator verdict;
  raw biometric data is not accepted, retained, or logged.
- Normalized email exists in memory only; persistence uses HMAC-SHA-256 with a KMS pepper.
- A repeated `(actor principal, idempotency-key HMAC)` replays only an identical canonical
  request digest; raw idempotency keys are not persistence or audit material.
- Organization-wide revocation requires an active `directory_admin` grant with the exact
  `directory.revocations.execute` scope. Project-bounded grants are never elevated to whole-
  organization authority, and inaccessible organizations are never identified.

The security-critical redaction behavior has an executable formal-assurance
layer under [`formal/`](formal/README.md). A closed JSON Schema declares the
finite domain, and Rust, Dart, and TypeScript independently check idempotence,
sensitive-value noninterference, safe-field preservation, normalization
closure, and secret-representation opacity in CI.

## Shared Auth dashboard profile

`contracts/shared-auth-dashboard-runtime.json` and
`docs/shared-auth-dashboard-runtime.md` define the runtime boundary for the Rust Shared Auth
administrative server: online introspection, exact audience and organization membership,
no cross-organization fallback, bounded cursor pagination, redacted telemetry, and truthful
capability advertising. The dashboard is a read-only projection and never becomes a second
authentication or product-authorization authority.

`database/postgres/shared_auth_v1.sql`, `contracts/shared-auth-data-model.json`, and
`docs/shared-auth-data-model.md` define the organizations/projects/users/memberships/roles,
safe sessions/factors, append-only audit events, and per-organization revocation operation.
The migration forces RLS with no browser policies; deployment SQL grants a dedicated server
role access only after the application has performed online authorization.

The current revocation tables are a non-production persistence draft. They do not yet implement
the canonical principal auth-epoch/not-before fence, opaque single-use commit authorization,
keyed idempotency storage, or per-provider target state. The contract therefore sets
`productionCapabilityEnabled: false`; deploying this migration must not enable the revocation
route.

## Language layout

Reviewed native implementations live under Rust, TypeScript, Go, Python, Dart, Java, and Swift.
The directory-per-language layout keeps package metadata and tests isolated while sharing the
canonical contracts and Zed dependency graph.

## Zed package

```sh
zed add ores-otel/ores-lib-core@^0.1
zed install
```

After `ores-interfaces`, `next-loggers`, and this package have registry-backed releases and
the generated `.zpkg.lock` is committed, CI and deployments should use:

```sh
zed install --frozen
```

The dependency graph is acyclic: `ores-interfaces` is foundational and therefore does not
depend on logging; `next-loggers` (the Zed package published by the `ores.otel.log` repo)
imports those contracts; `ores-lib-core` imports both contracts and the injectable logger
package.
