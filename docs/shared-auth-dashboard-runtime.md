# Shared Auth dashboard runtime boundary

`shared-auth-web-server.js` is a Rust administrative projection, not another authentication
authority. It consumes `ores-otel/ores-interfaces`, this core package, and the structured
logger published from `ores-otel/ores.otel.log` under the Zed coordinate
`oresoftware/next-loggers`.

The machine-readable policy is `contracts/shared-auth-dashboard-runtime.json`.

## Required behavior

- Authenticate every request through Shared Auth online introspection with an exact audience.
- Re-check exact organization membership after introspection and before each projection query.
- Never fall back to another organization when the selected organization is missing or denied.
- Keep product role/resource authorization in the product authority; dashboard role rows are
  explicit scoped projections, not global token claims.
- Use bounded opaque-cursor pagination with a maximum page size of 200.
- Emit request/trace correlation through an injected logger. Do not install a global logger or
  OpenTelemetry provider from a shared library.
- Hash or omit session and network identifiers. Redact or omit email addresses. Never log
  bearer tokens, cookies, private keys, TOTP seeds, WebAuthn challenges, or biometric material.
- Advertise only capabilities supported by same-commit evidence. SSH and Kerberos remain
  online-introspection dependent; OpenPGP remains provenance-only; face/fingerprint wording
  means local platform-authenticator verification without server-side biometric retention.
