# Governance

This directory binds the canonical `ores-lib-core` repository structure to its contract, conformance, package, and admission authorities.

The governed surfaces are intentionally distinct:

- `langs/*` — publishable/runtime language implementations.
- `languages/typescript` — schema-IR/compiler tooling; it is not a second TypeScript runtime package.
- `admin-orm` — private/server-only ORM implementation and not a public package target.
- `database/postgres` — database/schema target.
- `contracts/dependencies.json` — dependency/security policy mirrored by `.zpkg.toml`.
- `contract-admission/contract-ir-consumer.json` — fail-closed TypeSpec/JSON Schema consumer policy.
- `conformance/` — shared behavioral corpus/evidence boundary.

Run `node governance/check.mjs` before promotion. New runtime languages, package targets, dependency entries, or authority-policy changes must be reconciled explicitly instead of landing in only one lane.
