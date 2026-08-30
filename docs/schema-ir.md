# Schema IR compiler pilot

The contract belongs to `ores-otel/ores-interfaces/contracts/schema-ir/v1`.
Product `*-lib-core` repositories remain the authorities for product persistence.
This additive build-time compiler does not modify existing Shared Auth schemas,
runtime security helpers, migrations, or the browser-safe package root.

## Use the dedicated Node entrypoint

```js
import { compileSchemaIr } from "./languages/typescript/src/schema-ir/index.js";

const result = compileSchemaIr(input); // input is parsed JSON or another JSON value
if (!result.ok) {
  // Structured diagnostics have code, JSON Pointer path, and a value-free message.
  reportDiagnostics(result.errors);
} else {
  // result.files maps relative artifact paths to UTF-8 contents.
  // The caller explicitly owns reviewed writes. This module performs no I/O.
  reviewArtifacts(result.files, result.irSha256);
}
```

`validateSchemaIr(input)` returns an immutable diagnostic array. Empty means the
structural and relational validation passed. Compilation additionally checks
emitted relation-name collisions and returns **no files** on validation failure.
The entrypoint is deliberately not re-exported from `src/index.js`: importing
Node's build-time crypto module must not break existing browser consumers.

Outputs: normalized `schema-ir.json`, one closed JSON Schema per entity,
`postgres/desired.sql`, `typescript/models.ts`, `rust/models.rs`,
`dart/models.dart`, `cue/models.cue`, and `manifest.json`. Entity and field
ordering is normalized; composite-key order is not. Manifest hashes cover every
non-manifest artifact and omit clocks, absolute paths, environment, and secrets.
The named canonicalization algorithm is not RFC 8785/JCS.

Rust uses `SchemaOptional<Option<T>>` to distinguish missing from present-null;
Dart uses immutable missing/present wrappers; TypeScript uses `?` independently
from `| null`. Enable `strictNullChecks` and `exactOptionalPropertyTypes` in TS.
No serializer or runtime validator is implied by a generated language type.

## Test without installing dependencies

The implementation uses only Node built-ins and follows this repository's
JavaScript-plus-TypeScript-declarations package layout. Existing Zed dependency
resolution remains unchanged; no npm dependency or placeholder lock is added.

```sh
node --test languages/typescript/test/schema-ir.test.js
```

The independent source-pinned fixture suite lives in `ores-otel-e2e/schema-ir`.
It verifies the exact input/compiler file hashes before comparing outputs. That
source-conformance proof does not substitute for a real Zed artifact install.

## Boundaries and remaining gates

Only `string`, `uuid`, `int32`, and `boolean` are supported. Explicit string/range
bounds, PKs, unique keys, indexes, and typed FKs are supported. Unknown metadata,
reserved/system names, unsafe identifiers, malformed JSON objects, duplicate
names, invalid keys and incompatible relations fail closed.

SQL is desired state only. The compiler neither connects to a database nor
executes SQL. Schema provisioning, RLS, grants, defaults, triggers, data backfills,
locking, destructive-change approval, and production rollout remain outside it.
Foreign keys follow all CREATE TABLE statements, so cycles and self-references do
not depend on input declaration order. No cascade semantics are inferred.

TypeSpec input, CUE input, arbitrary JSON Schema import, Atlas planning, SeaORM or
Drizzle adapters, serializer generation, and complete multi-language constraint
parity are **not implemented**. The CUE/Rust/Dart outputs and disposable-PostgreSQL
acceptance require their native toolchains before promotion; tests of output text
are not evidence that those compilers or PostgreSQL executed successfully.

References:
- https://typespec.io/docs/extending-typespec/emitters-basics/
- https://cuelang.org/docs/concept/how-cue-works-with-json-schema/
- https://www.postgresql.org/docs/current/ddl-constraints.html
