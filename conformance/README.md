# Conformance

`contracts/` is the authority boundary for API/data-shape inputs in `ores-otel/ores-lib-core`. `conformance/` owns shared implementation-neutral behavioral expectations.

## Rules

1. Feed the same `conformance/cases/` bytes to every implementation under test.
2. Do not maintain runtime-specific golden vectors as conformance authority.
3. Bind promotion evidence to the exact contract, corpus, and conformance-spec digests.
4. Missing, failed, or stale evidence from a required participant fails closed.
5. Generated reports and normalized runtime receipts are evidence only, never authority.
6. `contracts/` and `conformance/` remain separate first-class inputs; neither silently rewrites the other.

`cases/bootstrap.v1.json` establishes only this repository-level boundary. It does **not** claim behavioral parity. Add domain-specific behavior cases and required participants before changing coverage to `behavioral`.
