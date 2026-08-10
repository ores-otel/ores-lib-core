# ores-lib-core

Small, security-oriented building blocks shared across OreSoftware services and clients.

This repository intentionally avoids product policy and global runtime mutation. It supplies
redaction, correlation-ID validation, secret wrappers, and injectable security-log sinks.
Canonical wire types live in [`ores-otel/ores-interfaces`](https://github.com/ores-otel/ores-interfaces),
and structured logging is provided by [`ores-otel/ores.otel.log`](https://github.com/ores-otel/ores.otel.log).
Both are declared in `.zpkg.toml`; applications choose the native language target they use.

## Invariants

- Secret wrappers redact `Debug`/string output and require an explicit reveal operation.
- Sensitive field names are matched case-insensitively and include tokens, cookies, key
  material, TOTP seeds, biometric material, and provider credentials.
- Correlation identifiers are bounded and contain only portable characters.
- The core library never installs a global logger or OpenTelemetry provider.
- Face/fingerprint verification is represented only as a platform-authenticator verdict;
  raw biometric data is not accepted, retained, or logged.

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
