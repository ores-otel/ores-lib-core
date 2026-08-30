# Portable RPC retry foundation

This is a deterministic policy library, not a new network protocol or a deployed
RPC endpoint. The implementations use no additional runtime dependencies:

- Rust: `ores_lib_core::rpc_retry::plan_rpc_retry`.
- Browser/Node: `@oresoftware/ores-lib-core/src/rpc-retry.js`, with adjacent types.
- Flutter/Dart: `package:ores_lib_core/rpc_retry.dart`.

The proposed wire/client-policy contract is in
[ores-interfaces PR #10](https://github.com/ores-otel/ores-interfaces/pull/10),
source commit `006852a65b191f6348bf7fcb73642777a220dcd6`, under
`contracts/rpc-retry/v1`. This is a source witness, not a released Zed package pin. Its TypeSpec, reviewed JSON
Schema and Proto3 fixtures are distinct from persistence schemas. Publishing an
SDK still requires an exact released interface/Zed pin and generated provenance;
this change neither fabricates a lock nor advertises generated SDK completion.

## Functional boundary

The planner receives immutable policy plus attempt observations and returns a
retry decision. It never reads the environment, clocks or randomness, sleeps,
performs networking/SQL, logs, or accepts tokens, payloads or raw database errors.
Rust can later expose selected functions through WASM/wasm-bindgen for browsers
or a native Flutter bridge. No WASM/FFI artifact is claimed in this change; Dart
and JS implementations already share the same reviewed behavioral fixture corpus.

Use generated Rust/Dart/TypeScript clients for transport and codecs. Do not create
custom framing, translate every call through WASM, or place Diesel/SeaORM models
in client bundles. The service adapter may be Tonic/gRPC(-Web) or a separately
verified Connect runtime; this pure module commits to neither runtime.

## Safety contract

`max_attempts` includes the initial call. Only reviewed replay-safe methods may
retry resource-exhausted (8) or unavailable (14) failures. A write is not replay
safe merely because a client supplied an idempotency key: the resource API must
atomically deduplicate identical authorized requests and reject key/digest
conflicts. Authentication and authorization are rechecked server-side on every
attempt. Streaming/resumable operations need a separate policy.

Attempt elapsed time is monotonic, not wall-clock time. The injected jitter sample
is an integer in 0..1000. Backoff uses `floor(capped_exponential * jitter / 1000)`.
A valid server retry-after minimum is never shortened to the local backoff cap.
If the delay equals/exceeds the remaining deadline, the planner stops. Inputs are
bounded so intermediate arithmetic is exact in Rust, JS and Dart web. Malformed
or unsupported values fail closed with reason 2; JS input records must be inert
JSON-shaped objects, not getters/prototypes/proxies supplied as executable input.

Decision priority is invalid input, cancelled, unsafe replay, attempts exhausted,
deadline exhausted, non-retryable status, then backoff/deadline evaluation. Stop
decisions always contain zero delay. The host must check deadline/cancellation
before the initial send, after sleeping, and during in-flight work, use a bounded
transport timeout, sample fresh jitter, and prevent stacked transport/SDK retries
from exceeding the logical request's budget. The planner is not that host loop.

## Diesel and SeaORM

`DatabaseFailure` is a typed, ORM-neutral server-side classification seam. Both
adapters must map typed errors into this seam, never parse or expose driver text.
Unavailable/overloaded/not-found/already-exists/transaction-conflict/permission/
internal map to statuses 14/8/5/6/10/7/13. Transaction conflicts require a separate
transaction-level decision, not automatic whole-RPC replay. Public visibility of
not-found/conflict/permission outcomes still requires resource authorization.

This is **not** a Diesel/SeaORM adapter implementation or database parity proof.
Persistence TypeSpec P0 and independently authored JSON Schema P1 remain separate
sources; P1 mismatch vetoes release. Diesel/diesel-async remains primary and SeaORM
secondary, with both derived from certified persistence candidates. API writers,
read-only web roles, and migrator-only DDL boundaries are unchanged.

## Checks

`contracts/rpc-retry-v1.csv` contains 58 hand-specified reference cases, including
boundaries, every status code, minimum retry-after, cancellation and replay safety.
Each runtime consumes the same CSV. Tests also exhaust 4,896 bounded combinations
and check that unsafe/cancelled calls never retry and retries fit the deadline.

Run from the repository root using existing toolchain installations:

```sh
(cd languages/typescript && npm test)
(cd languages/rust && cargo test)
(cd languages/dart && dart run tool/rpc_retry_check.dart)
```

The existing native workflow discovers the Rust/JS tests and runs the Dart checker.
`languages/typescript/test/rpc-retry.types.ts` is an additional strict declaration
check (`tsc --noEmit --strict --module nodenext --target es2022 ...`); TypeScript is
not silently downloaded or added as an unpinned dependency. Full-repository,
Dart-web, browser/WASM and database integration gates must be reported separately.

## Next implementation gates

1. Lock and certify TypeSpec/JSON Schema/Proto generation, descriptors, optional
   presence, Buf compatibility and generated Rust/Dart/TS SDKs in `*-interfaces`.
2. Add one authenticated unary RPC pilot with generated clients, host deadline /
   cancellation adapters, payload bounds and atomic server deduplication. Verify
   browser and Flutter transport support rather than assuming all streaming modes.
3. Implement Diesel and SeaORM adapters and compare authorized operations against
   disposable PostgreSQL candidates from independently authored P0/P1 sources.
4. Add browser WASM and native Flutter bridge wrappers only where shared Rust
   behavior is worth their packaging cost, then pin certified test-org artifacts.

No production DDL, deployment, registry publication, or automatic merge is part of
this foundation.
