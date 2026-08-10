# ores-lib-core

Small, security-oriented building blocks shared across OreSoftware services and clients.

This repository intentionally avoids product policy and global runtime mutation. It supplies
redaction, correlation-ID validation, secret wrappers, bounded pagination primitives, and
injectable security-log sinks. Canonical wire types live in
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

## Shared Auth dashboard profile

`contracts/shared-auth-dashboard-runtime.json` and
`docs/shared-auth-dashboard-runtime.md` define the runtime boundary for the Rust Shared Auth
administrative server: online introspection, exact audience and organization membership,
no cross-organization fallback, bounded cursor pagination, redacted telemetry, and truthful
capability advertising. The dashboard is a read-only projection and never becomes a second
authentication or product-authorization authority.

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

The dependency graph is acyclic: `ores-interfaces` is foundational; `next-loggers` imports
those contracts; `ores-lib-core` imports both contracts and the injectable logger package.
