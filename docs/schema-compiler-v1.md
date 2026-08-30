# Schema compiler v1: one checked model, three reviewable outputs

This additive library consumes `ores.schema-ir.v1` JSON data and returns a
JSON Schema Draft 2020-12 bundle, TypeScript shape declarations, and PostgreSQL
desired-state SQL. The canonical meta-contract and authoring types live in
[ores-interfaces PR 8](https://github.com/ores-otel/ores-interfaces/pull/8),
commit `e9fafe156cf197a914bd041fb7d90ebf9698f8f7`.

It is a bounded compiler foundation, **not** a general JSON Schema-to-SQL
converter, a TypeSpec/CUE frontend, a migration engine, or a production schema.
Existing Shared Auth contracts, migrations, authorization, and capability flags
are untouched. Human-authored product persistence inputs and their histories
remain in each product's `*-lib-core`.

## API

```js
import { compileSchema } from "@oresoftware/ores-lib-core/src/schema-compiler/index.js";

const result = compileSchema({
  version: "ores.schema-ir.v1",
  models: [{
    name: "Organization",
    fields: [
      { name: "id", type: "uuid", required: true, nullable: false },
      { name: "name", type: "string", required: true, nullable: false, maxLength: 100 },
    ],
    storage: {
      schema: "schema_demo",
      table: "organizations",
      columns: [{ field: "id", name: "id" }, { field: "name", name: "name" }],
      primaryKey: ["id"],
      uniqueKeys: [["name"]],
      foreignKeys: [],
    },
  }],
});

// The caller owns output storage, review, and any later deployment effects.
if (result.ok) {
  const { jsonSchema, typescript, postgres } = result.artifacts;
  // Pass these strings to the caller's artifact/review layer.
} else {
  // Diagnostics contain stable codes and structural paths, not input values.
  const diagnostics = result.diagnostics;
}
```

The API deliberately accepts `unknown`, even when a caller uses the immutable
`SchemaIR` authoring type from `ores-interfaces/src/schema-ir.d.ts`. Untrusted
input must still pass runtime validation. No success branch exists with partial
artifacts. Results and their diagnostics are frozen; the input is never mutated.

The implementation uses the repository's existing dependency-free JS/TypeScript
package. It installs no dependencies and changes no Zed configuration or lock.
No CLI is added: there is no argv boundary, environment parsing, database driver,
filesystem access, network fetch, logger installation, or SQL execution.

## Supported profile and deliberate rejection

V1 supports string, boolean, signed int32, canonical lowercase hyphenated UUID,
explicit presence/nullability, and bounded string lengths. Storage is explicit:
complete field-to-column mappings, schema/table names, primary keys, unique keys,
composite foreign keys, and restrict/cascade/set-null delete policies.

Unknown versions, properties, and scalar types fail closed. No fallback to text,
JSONB, an inferred column name, or arbitrary SQL is allowed. Defaults, expression
checks, general/partial indexes, decimals/int64, unions, nested models, generated
columns, RLS, and ORM adapters require a later explicit capability extension.

The compiler rejects duplicate model/field/table/column names, incomplete
mappings, unknown key fields, nullable primary keys, invalid candidate references,
type-mismatched foreign keys, contradictory delete policies, and invalid SET NULL.
System schemas and PostgreSQL system columns are prohibited. Every persisted row
field must be required: SQL NULL is not a substitute for an absent JSON property.
Model optional PATCH/input payloads separately without storage mappings.

The entrypoint snapshots bounded JSON data, rejects cycles, accessor properties,
symbols, sparse arrays, custom prototypes and non-JSON values, and never invokes
ordinary property getters. Limits are 16 nesting levels, 200,000 visited values,
16,384 entries per input array, and 100 diagnostics. It is **not a sandbox for
hostile executable JavaScript**: callers should parse untrusted JSON, not pass
Proxy objects or executable objects. No general JSON Schema evaluator or remote
reference resolver runs inside the compiler.

## Determinism and SQL safety boundary

Models, fields, columns, keys, and foreign-key statements have deterministic
ordering. Reordering declarations or JSON object keys produces byte-identical
artifacts. Composite key order is meaningful and is preserved, not sorted away.

Identifiers are at most 63 portable ASCII characters, validated before quoting.
PostgreSQL builtin types/functions are schema-qualified. All tables are emitted
before foreign keys, so cycles and self-references do not depend on declaration
order. Primary/unique/foreign constraints have stable bounded names. The internal
FNV-1a name function is **not** an integrity hash; generated constraint/index/table
name collisions are separately rejected before emission.

SQL is desired state for a disposable database, **not an idempotent migration**.
The compiler does not add `IF NOT EXISTS` to conceal drift and never executes
`DROP`, `ALTER`, or any other statement. DDL strings include second-pass
`ALTER TABLE ... ADD CONSTRAINT` statements, but execution belongs elsewhere.
Use the existing `declarative-migrations/declarative-postgres-migrate.rs` DPM
`diff`/`verify` flow, then reviewed, separately authorized migrator jobs. SQL has
not yet been executed against a PostgreSQL shadow database for this slice.

JSON Schema validates individual instances, not cross-row uniqueness or foreign
keys. The bundle root accepts any declared model; select the relevant `$defs`
entry for a particular request. UUID uses a canonical pattern as well as `format`
so it does not depend only on optional format assertion behavior. TypeScript
output is static shape information, not UUID/length/int32 runtime validation or a
codec. Enable `strictNullChecks` and `exactOptionalPropertyTypes` in consumers.

String length is measured in Unicode code points. Full JSON/PostgreSQL value
domain equivalence is not claimed (for example, PostgreSQL text excludes NUL).
Normalization, Unicode policy, database encoding, collation, permissions and RLS
are future conformance gates, not inferred from successful code generation.

## Tests and provenance

From `languages/typescript`:

```sh
node --test test/schema-compiler.test.js
tsc --noEmit --strict --exactOptionalPropertyTypes --target es2022 \
  --module nodenext --moduleResolution nodenext test/schema-compiler.types.ts
```

The existing `npm test` glob also runs the new Node suite in the current native
CI matrix. Type checking is an explicit local command; the existing workflow
does not run this new TypeScript type fixture automatically.

Tests cover all three golden outputs, 40 declaration-order permutations,
immutable input/results, invalid references and injection attempts, composite and
cyclic foreign keys, SQL-name collisions, bounded diagnostics, and non-JSON input.
Golden SQL comparisons are not a substitute for an actual PostgreSQL test.

The synthetic fixture is a byte-for-byte vendored test asset from the exact
`ores-interfaces` commit in `test/fixtures/schema-compiler/provenance.json`.
Its SHA-256 is checked by tests. The recorded meta-schema digest is provenance,
not proof of full independent meta-schema validation in the Node suite. This
fixture pin does not imply a published Zed artifact or a runtime dependency pin.

## Ordered next steps

1. Add pinned TypeSpec compiler-API and CUE lowering adapters to this IR; reject
   every unrepresentable constraint rather than silently dropping it. Do not
   parse TypeSpec source with regexes or treat its compiler AST as our stable IR.
2. Add Rust/Dart/Go output, validators/codecs, and compilation/execution of the
   same fixtures in each language. Add a real independent Draft 2020-12 gate and
   automatic TypeScript type checks to the appropriate test-org pipeline.
3. Execute generated SQL in a disposable PostgreSQL database, test actual
   constraints and catalog readback, then prove DPM convergence and reviewable
   migration diffs. Generate ORM adapters only from that verified model.
4. Publish and digest-pin the reviewed compiler/contracts through Zed before
   piloting a product. Keep production migrations and permissions separate.

References:
- https://typespec.io/docs/extending-typespec/emitters-basics/
- https://json-schema.org/understanding-json-schema/reference/object
- https://json-schema.org/understanding-json-schema/reference/null
- https://www.postgresql.org/docs/current/ddl-constraints.html
