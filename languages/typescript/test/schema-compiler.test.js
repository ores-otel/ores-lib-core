import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { compileSchema } from "../src/schema-compiler/index.js";
import { constraintName } from "../src/schema-compiler/naming.js";

const folder = new URL("./fixtures/schema-compiler/", import.meta.url);
const raw = readFileSync(new URL("team-directory.json", folder), "utf8");
const fixture = JSON.parse(raw);
const fresh = () => structuredClone(fixture);
function success(input) {
  const result = compileSchema(input);
  assert.equal(result.ok, true, JSON.stringify(result));
  return result.artifacts;
}
function failure(input, code) {
  const result = compileSchema(input);
  assert.equal(result.ok, false);
  assert.equal(Object.hasOwn(result, "artifacts"), false);
  assert.ok(result.diagnostics.some((diagnostic) => diagnostic.code === code), JSON.stringify(result));
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.diagnostics));
}

// These snapshots are reviewed artifacts, not proof that a database has accepted DDL.
for (const [target, file] of [["jsonSchema", "expected.schema.json"], ["typescript", "expected.d.ts"], ["postgres", "expected.sql"]]) {
  test(`golden ${target} output`, () => {
    assert.equal(success(fresh())[target], readFileSync(new URL(file, folder), "utf8"));
  });
}

test("fixture bytes match an immutable interfaces source pin", () => {
  const provenance = JSON.parse(readFileSync(new URL("provenance.json", folder), "utf8"));
  assert.equal(provenance.repository, "ores-otel/ores-interfaces");
  assert.match(provenance.commit, /^[a-f0-9]{40}$/);
  assert.equal(createHash("sha256").update(raw).digest("hex"), provenance.sha256);
});

test("presence, nullability, integer bounds, and string constraints stay explicit", () => {
  const artifacts = success(fresh());
  const schema = JSON.parse(artifacts.jsonSchema);
  assert.deepEqual(schema.$defs.MemberPatch.required, []);
  assert.deepEqual(schema.$defs.MemberPatch.properties.displayName.type, ["string", "null"]);
  assert.equal(schema.$defs.MemberPatch.properties.enabled.type, "boolean");
  assert.ok(schema.$defs.Member.required.includes("displayName"));
  assert.equal(schema.$defs.Member.properties.rank.minimum, -2147483648);
  assert.equal(schema.$defs.Member.properties.rank.maximum, 2147483647);
  assert.equal(schema.$defs.Organization.properties.name.minLength, 1);
  assert.equal(schema.$defs.Organization.properties.name.maxLength, 100);
  assert.match(artifacts.typescript, /readonly "displayName"\?: string \| null;/);
  assert.match(artifacts.typescript, /readonly "enabled"\?: boolean;/);
  assert.ok(!artifacts.postgres.includes("member_patch"));
});

test("UUID pattern is canonical and cannot accept a trailing newline", () => {
  const pattern = new RegExp(JSON.parse(success(fresh()).jsonSchema).$defs.Member.properties.id.pattern);
  assert.ok(pattern.test("12345678-1234-1234-1234-123456789abc"));
  for (const invalid of ["bad", "12345678-1234-1234-1234-123456789ABC", "12345678-1234-1234-1234-123456789abc\n"]) {
    assert.equal(pattern.test(invalid), false);
  }
});

test("SQL is qualified and all foreign keys follow all CREATE TABLE statements", () => {
  const sql = success(fresh()).postgres;
  assert.match(sql, /"organization_id" pg_catalog\.uuid NOT NULL/);
  assert.match(sql, /pg_catalog\.char_length\("display_name"\) <= 120/);
  assert.ok(sql.lastIndexOf("CREATE TABLE") < sql.indexOf("ALTER TABLE"));
  assert.match(sql, /MATCH SIMPLE ON DELETE RESTRICT ON UPDATE NO ACTION/);
  assert.ok(!sql.includes("IF NOT EXISTS"));
  assert.ok(!sql.includes("DROP "));
  for (const [, name] of sql.matchAll(/CONSTRAINT "([^"]+)"/g)) {
    assert.ok(name.length <= 63);
  }
});

test("compilation is input-immutable and returns frozen results", () => {
  const input = fresh();
  const before = JSON.stringify(input);
  function freeze(value) {
    if (value !== null && typeof value === "object") {
      Object.values(value).forEach(freeze);
      Object.freeze(value);
    }
  }
  freeze(input);
  const result = compileSchema(input);
  assert.equal(result.ok, true);
  assert.equal(JSON.stringify(input), before);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.artifacts));
});

test("40 deterministic permutations produce byte-identical artifacts", () => {
  const expected = success(fresh());
  let state = 1729;
  function shuffle(items) {
    for (let index = items.length - 1; index > 0; index -= 1) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      const other = state % (index + 1);
      [items[index], items[other]] = [items[other], items[index]];
    }
  }
  for (let round = 0; round < 40; round += 1) {
    const input = fresh();
    shuffle(input.models);
    for (const model of input.models) {
      shuffle(model.fields);
      if (model.storage) {
        shuffle(model.storage.columns);
        shuffle(model.storage.uniqueKeys);
        shuffle(model.storage.foreignKeys);
      }
    }
    const reordered = JSON.parse(JSON.stringify(input, (key, value) => value && typeof value === "object" && !Array.isArray(value)
      ? Object.fromEntries(Object.entries(value).reverse()) : value));
    assert.deepEqual(success(reordered), expected);
  }
});

test("constraint names remain stable when unrelated tables are added", () => {
  const input = fresh();
  const extra = structuredClone(input.models[0]);
  extra.name = "Another";
  extra.storage.table = "another";
  input.models.unshift(extra);
  const names = [...success(fresh()).postgres.matchAll(/CONSTRAINT "([^"]+)"/g)].map((match) => match[1]);
  const next = success(input).postgres;
  assert.ok(names.every((name) => next.includes(`CONSTRAINT "${name}"`)));
});

test("cycles and composite candidate keys are emitted in a second pass", () => {
  const input = fresh();
  const organization = input.models[0];
  const member = input.models[1];
  organization.fields.push({ name: "ownerId", type: "uuid", required: true, nullable: true });
  organization.storage.columns.push({ field: "ownerId", name: "owner_id" });
  organization.storage.foreignKeys.push({ fields: ["ownerId"], references: { model: "Member", fields: ["id"] }, onDelete: "setNull" });
  member.storage.uniqueKeys.push(["id", "organizationId"]);
  const sql = success(input).postgres;
  assert.equal((sql.match(/ALTER TABLE/g) ?? []).length, 2);
  assert.match(sql, /ON DELETE SET NULL/);
  assert.match(sql, /UNIQUE \("id", "organization_id"\)/);
  assert.ok(sql.lastIndexOf("CREATE TABLE") < sql.indexOf("ALTER TABLE"));
});

test("wire-only models produce no DDL and public is not recreated", () => {
  const wire = fresh();
  wire.models.forEach((model) => { delete model.storage; });
  assert.match(success(wire).postgres, /No persisted models/);
  const input = fresh();
  input.models.filter((model) => model.storage).forEach((model) => { model.storage.schema = "public"; });
  assert.ok(!success(input).postgres.includes("CREATE SCHEMA"));
});

test("63-character SQL names retain bounded explicit index names", () => {
  const input = fresh();
  input.models[0].storage.table = "t".repeat(63);
  assert.ok(success(input).postgres.includes(`"${"t".repeat(63)}"`));
});

const invalidCases = [
  ["unknown version", (x) => { x.version = "ores.schema-ir.v2"; }, "UNSUPPORTED_VERSION"],
  ["unknown top-level property", (x) => { x.defaultSql = "not-supported"; }, "UNKNOWN_PROPERTY"],
  ["empty model list", (x) => { x.models = []; }, "INVALID_ARRAY"],
  ["missing fields", (x) => { delete x.models[0].fields; }, "MISSING_PROPERTY"],
  ["implicit required", (x) => { delete x.models[0].fields[0].required; }, "MISSING_PROPERTY"],
  ["nullable is not boolean", (x) => { x.models[0].fields[0].nullable = "false"; }, "INVALID_BOOLEAN"],
  ["unsupported scalar", (x) => { x.models[0].fields[0].type = "int64"; }, "UNSUPPORTED_TYPE"],
  ["SQL punctuation", (x) => { x.models[0].storage.table = "x;DROP TABLE y"; }, "INVALID_IDENTIFIER"],
  ["trailing newline", (x) => { x.models[0].name += "\n"; }, "INVALID_IDENTIFIER"],
  ["Unicode identifier", (x) => { x.models[0].storage.schema = "schéma"; }, "INVALID_IDENTIFIER"],
  ["overlong identifier", (x) => { x.models[0].storage.table = "a".repeat(64); }, "INVALID_IDENTIFIER"],
  ["duplicate model", (x) => { x.models.push(structuredClone(x.models[0])); }, "DUPLICATE_MODEL"],
  ["duplicate field", (x) => { x.models[0].fields.push(structuredClone(x.models[0].fields[0])); }, "DUPLICATE_FIELD"],
  ["duplicate columns", (x) => { x.models[0].storage.columns[1].name = "id"; }, "DUPLICATE_COLUMN"],
  ["duplicate mappings", (x) => { x.models[0].storage.columns[1].field = "id"; }, "DUPLICATE_COLUMN"],
  ["missing mapping", (x) => { x.models[0].storage.columns.pop(); }, "INCOMPLETE_MAPPING"],
  ["extra mapping", (x) => { x.models[0].storage.columns.push({ field: "extra", name: "extra" }); }, "INCOMPLETE_MAPPING"],
  ["lossy optional persistence", (x) => { x.models[1].fields[2].required = false; }, "LOSSY_PRESENCE"],
  ["duplicate qualified table", (x) => { x.models[1].storage.table = x.models[0].storage.table; }, "DUPLICATE_TABLE"],
  ["unknown primary field", (x) => { x.models[0].storage.primaryKey = ["absent"]; }, "UNKNOWN_KEY_FIELD"],
  ["nullable primary key", (x) => { x.models[0].fields[0].nullable = true; }, "NULLABLE_PRIMARY_KEY"],
  ["repeated key field", (x) => { x.models[0].storage.primaryKey = ["id", "id"]; }, "DUPLICATE_KEY_FIELD"],
  ["redundant unique key", (x) => { x.models[0].storage.uniqueKeys.push(["id"]); }, "DUPLICATE_KEY"],
  ["absent referenced model", (x) => { x.models[1].storage.foreignKeys[0].references.model = "Absent"; }, "UNKNOWN_REFERENCE"],
  ["wire-only reference", (x) => { x.models[1].storage.foreignKeys[0].references.model = "MemberPatch"; }, "UNKNOWN_REFERENCE"],
  ["unknown foreign-key field", (x) => { x.models[1].storage.foreignKeys[0].fields = ["absent"]; }, "INVALID_FOREIGN_KEY"],
  ["unknown target field", (x) => { x.models[1].storage.foreignKeys[0].references.fields = ["absent"]; }, "INVALID_FOREIGN_KEY"],
  ["foreign-key arity", (x) => { x.models[1].storage.foreignKeys[0].fields = ["id", "organizationId"]; }, "INVALID_FOREIGN_KEY"],
  ["nonunique reference", (x) => { x.models[0].storage.uniqueKeys = []; x.models[1].storage.foreignKeys[0].references.fields = ["name"]; }, "NON_UNIQUE_REFERENCE"],
  ["foreign-key type mismatch", (x) => { x.models[1].fields[1].type = "string"; }, "FOREIGN_KEY_TYPE_MISMATCH"],
  ["invalid SET NULL", (x) => { x.models[1].storage.foreignKeys[0].onDelete = "setNull"; }, "INVALID_SET_NULL"],
  ["unknown delete action", (x) => { x.models[1].storage.foreignKeys[0].onDelete = "setDefault"; }, "UNSUPPORTED_DELETE_ACTION"],
  ["contradictory foreign-key policies", (x) => { x.models[1].storage.foreignKeys.push({ ...structuredClone(x.models[1].storage.foreignKeys[0]), onDelete: "cascade" }); }, "DUPLICATE_FOREIGN_KEY"],
  ["length on uuid", (x) => { x.models[0].fields[0].maxLength = 5; }, "INVALID_LENGTH"],
  ["fractional length", (x) => { x.models[0].fields[1].maxLength = 2.5; }, "INVALID_LENGTH"],
  ["contradictory length", (x) => { x.models[0].fields[1].minLength = 101; }, "CONTRADICTORY_LENGTH"],
  ["arbitrary SQL default", (x) => { x.models[0].storage.default = "now()"; }, "UNKNOWN_PROPERTY"],
  ["system schema", (x) => { x.models[0].storage.schema = "pg_catalog"; }, "RESERVED_SCHEMA"],
  ["information schema", (x) => { x.models[0].storage.schema = "information_schema"; }, "RESERVED_SCHEMA"],
  ["system column", (x) => { x.models[0].storage.columns[0].name = "ctid"; }, "RESERVED_COLUMN"],
];
for (const [title, change, code] of invalidCases) {
  test(`rejects ${title} without partial artifacts`, () => {
    const input = fresh();
    change(input);
    failure(input, code);
  });
}

test("generated index / table collisions fail before emission", () => {
  const input = fresh();
  input.models[1].storage.table = constraintName(input.models[0].storage, "pk", ["id"]);
  failure(input, "SQL_NAME_COLLISION");
});

test("diagnostics never echo invalid input values", () => {
  const input = fresh();
  input.models[0].storage.table = "input-must-not-appear";
  const result = compileSchema(input);
  assert.equal(result.ok, false);
  assert.ok(!JSON.stringify(result).includes("input-must-not-appear"));
});

test("getter properties are rejected without invoking the getter", () => {
  let called = false;
  const input = fresh();
  Object.defineProperty(input, "extra", { enumerable: true, get() { called = true; return 1; } });
  failure(input, "INPUT_NOT_JSON");
  assert.equal(called, false);
});

for (const [title, input] of [["undefined", undefined], ["NaN", NaN], ["Infinity", Infinity], ["bigint", 1n], ["Date", new Date(0)], ["function", () => 1], ["sparse array", [,]]]) {
  test(`rejects non-JSON ${title}`, () => failure(input, "INPUT_NOT_JSON"));
}

test("cycles, symbols, and custom prototypes are rejected", () => {
  const cycle = fresh();
  cycle.extra = cycle;
  failure(cycle, "INPUT_NOT_JSON");
  const symbol = fresh();
  symbol[Symbol("hidden")] = 1;
  failure(symbol, "INPUT_NOT_JSON");
  failure(Object.create({ version: "ores.schema-ir.v1" }), "INPUT_NOT_JSON");
});

test("input resource limits and diagnostic counts are bounded", () => {
  failure(new Array(16385).fill(null), "INPUT_LIMIT");
  let deep = null;
  for (let index = 0; index < 20; index += 1) {
    deep = { nested: deep };
  }
  failure(deep, "INPUT_LIMIT");
  const input = { version: "ores.schema-ir.v1", models: Array.from({ length: 64 }, () => ({ name: "Model", fields: Array.from({ length: 128 }, () => ({ unexpected: true })) })) };
  const result = compileSchema(input);
  assert.equal(result.ok, false);
  assert.equal(result.diagnostics.length, 100);
});

test("composite foreign keys preserve column order and support self references", () => {
  const input = fresh();
  const member = input.models[1];
  member.storage.uniqueKeys.push(["organizationId", "id"]);
  member.fields.push({ name: "managerId", type: "uuid", required: true, nullable: true });
  member.storage.columns.push({ field: "managerId", name: "manager_id" });
  member.storage.foreignKeys.push({
    fields: ["organizationId", "managerId"],
    references: { model: "Member", fields: ["organizationId", "id"] },
    onDelete: "restrict",
  });
  const sql = success(input).postgres;
  assert.match(sql, /FOREIGN KEY \("organization_id", "manager_id"\) REFERENCES "schema_demo"\."members" \("organization_id", "id"\)/);
  assert.match(sql, /UNIQUE \("organization_id", "id"\)/);
  assert.ok(sql.lastIndexOf("CREATE TABLE") < sql.indexOf("ALTER TABLE"));
  member.storage.foreignKeys.at(-1).references.fields.reverse();
  failure(input, "NON_UNIQUE_REFERENCE");
});

test("zero length bounds and nullable unique fields are preserved", () => {
  const input = fresh();
  input.models[0].fields[1].minLength = 0;
  input.models[0].fields[1].maxLength = 0;
  input.models[0].fields[1].nullable = true;
  const artifacts = success(input);
  const field = JSON.parse(artifacts.jsonSchema).$defs.Organization.properties.name;
  assert.deepEqual(field, { type: ["string", "null"], minLength: 0, maxLength: 0 });
  assert.match(artifacts.postgres, /"name" pg_catalog\.text CHECK \(pg_catalog\.char_length\("name"\) >= 0\) CHECK \(pg_catalog\.char_length\("name"\) <= 0\)/);
  assert.match(artifacts.postgres, /UNIQUE \("name"\)/);
});

// Invalid JSON-shaped bounds must never reach a coercing relational comparison.
for (const [label, value] of [["null", null], ["boolean", false], ["array", []], ["object", {}], ["non-coercible object", { toString: null, valueOf: null }], ["numeric string", "12"], ["fractional number", 2.5]]) {
  for (const bound of ["minLength", "maxLength"]) {
    test(`rejects ${label} ${bound} with diagnostics rather than throwing`, () => {
      const input = fresh();
      input.models[0].fields[1][bound] = value;
      assert.doesNotThrow(() => failure(input, "INVALID_LENGTH"));
    });
  }
}
