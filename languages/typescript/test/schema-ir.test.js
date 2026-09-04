import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { compileSchemaIr, validateSchemaIr } from "../src/schema-ir/index.js";

const field = (name, type, overrides = {}) => ({ name, column: name.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`), type, required: true, nullable: false, ...overrides });
const fixture = () => ({ schemaVersion: "ores.schema-ir.v1", databaseSchema: "example", entities: [
  { name: "Organization", table: "organizations", fields: [field("id", "uuid"), field("slug", "string", { minLength: 1, maxLength: 64 })], primaryKey: ["id"], uniqueKeys: [["slug"]] },
  { name: "Member", table: "members", fields: [field("id", "uuid"), field("organizationId", "uuid"), field("nickname", "string", { required: false, nullable: true, maxLength: 80 }), field("score", "int32", { minimum: 0, maximum: 150 }), field("enabled", "boolean")], primaryKey: ["id"], indexes: [["organizationId"]], foreignKeys: [{ fields: ["organizationId"], references: { entity: "Organization", fields: ["id"] } }] },
] });
const member = (ir) => ir.entities[1];
const success = (ir = fixture()) => { const result = compileSchemaIr(ir); assert.equal(result.ok, true, JSON.stringify(result)); return result; };
const rejection = (mutate, expected) => {
  const input = fixture(); mutate(input);
  const result = compileSchemaIr(input);
  assert.equal(result.ok, false);
  assert.equal(result.errors[0].code, expected);
  assert.equal(Object.hasOwn(result, "files"), false);
  assert.equal(validateSchemaIr(input)[0].code, expected);
};

const invalid = [
  ["unknown version", (x) => { x.schemaVersion = "ores.schema-ir.v2"; }, "UNSUPPORTED_VERSION"],
  ["raw SQL metadata", (x) => { x.sql = "DROP TABLE victims"; }, "UNKNOWN_PROPERTY"],
  ["unknown field metadata", (x) => { member(x).fields[0].defaultSql = "random()"; }, "UNKNOWN_PROPERTY"],
  ["unknown entity metadata", (x) => { member(x).rls = true; }, "UNKNOWN_PROPERTY"],
  ["unknown reference metadata", (x) => { member(x).foreignKeys[0].onDelete = "CASCADE"; }, "UNKNOWN_PROPERTY"],
  ["missing version", (x) => { delete x.schemaVersion; }, "MISSING_PROPERTY"],
  ["missing nullability", (x) => { delete member(x).fields[0].nullable; }, "MISSING_PROPERTY"],
  ["nonboolean presence", (x) => { member(x).fields[0].required = "true"; }, "INVALID_TYPE"],
  ["table injection", (x) => { member(x).table = 'members"; DROP TABLE t; --'; }, "INVALID_IDENTIFIER"],
  ["schema injection", (x) => { x.databaseSchema = "public; DROP SCHEMA public"; }, "INVALID_IDENTIFIER"],
  ["path traversal", (x) => { member(x).name = "../Member"; }, "INVALID_IDENTIFIER"],
  ["identifier truncation", (x) => { member(x).table = "a".repeat(64); }, "INVALID_IDENTIFIER"],
  ["system schema", (x) => { x.databaseSchema = "pg_catalog"; }, "INVALID_IDENTIFIER"],
  ["information schema", (x) => { x.databaseSchema = "information_schema"; }, "INVALID_IDENTIFIER"],
  ["reserved field", (x) => { member(x).fields[2].name = "self"; }, "INVALID_IDENTIFIER"],
  ["Dart object member", (x) => { member(x).fields[2].name = "hashCode"; }, "INVALID_IDENTIFIER"],
  ["generated helper name", (x) => { member(x).name = "SchemaOptional"; }, "INVALID_IDENTIFIER"],
  ["unsupported int64", (x) => { member(x).fields[3].type = "int64"; }, "UNSUPPORTED_TYPE"],
  ["unsupported arbitrary JSON", (x) => { member(x).fields[3].type = "json"; }, "UNSUPPORTED_TYPE"],
  ["duplicate entities", (x) => { x.entities.push(structuredClone(x.entities[0])); }, "DUPLICATE"],
  ["case-insensitive filenames", (x) => { x.entities.push({ ...structuredClone(x.entities[0]), name: "ORGANIZATION", table: "other" }); }, "DUPLICATE"],
  ["duplicate tables", (x) => { member(x).table = "organizations"; }, "DUPLICATE"],
  ["duplicate field names", (x) => { member(x).fields.push(field("score", "int32", { column: "other" })); }, "DUPLICATE"],
  ["duplicate columns", (x) => { member(x).fields.push(field("other", "int32", { column: "score" })); }, "DUPLICATE"],
  ["unknown primary field", (x) => { member(x).primaryKey = ["missing"]; }, "INVALID_REFERENCE"],
  ["empty primary key", (x) => { member(x).primaryKey = []; }, "INVALID_ARRAY"],
  ["nullable primary key", (x) => { member(x).fields[0].nullable = true; }, "INVALID_PRIMARY_KEY"],
  ["optional primary key", (x) => { member(x).fields[0].required = false; }, "INVALID_PRIMARY_KEY"],
  ["duplicate unique key", (x) => { x.entities[0].uniqueKeys.push(["id"]); }, "DUPLICATE"],
  ["duplicate indexes", (x) => { member(x).indexes.push(["organizationId"]); }, "DUPLICATE"],
  ["unknown index field", (x) => { member(x).indexes = [["missing"]]; }, "INVALID_REFERENCE"],
  ["unknown target entity", (x) => { member(x).foreignKeys[0].references.entity = "Missing"; }, "INVALID_REFERENCE"],
  ["unknown target field", (x) => { member(x).foreignKeys[0].references.fields = ["missing"]; }, "INVALID_REFERENCE"],
  ["foreign-key type mismatch", (x) => { member(x).fields[1].type = "string"; }, "INVALID_REFERENCE"],
  ["nonunique target", (x) => { delete x.entities[0].uniqueKeys; member(x).fields[1].type = "string"; member(x).foreignKeys[0].references.fields = ["slug"]; }, "INVALID_REFERENCE"],
  ["mismatched arity", (x) => { member(x).foreignKeys[0].fields.push("id"); }, "INVALID_REFERENCE"],
  ["duplicate foreign keys", (x) => { member(x).foreignKeys.push(structuredClone(member(x).foreignKeys[0])); }, "DUPLICATE"],
  ["length on integer", (x) => { member(x).fields[3].maxLength = 1; }, "INVALID_CONSTRAINT"],
  ["range on string", (x) => { member(x).fields[2].minimum = 1; }, "INVALID_CONSTRAINT"],
  ["inverted range", (x) => { member(x).fields[3].minimum = 151; }, "INVALID_RANGE"],
  ["inverted string bounds", (x) => { member(x).fields[2].minLength = 81; }, "INVALID_RANGE"],
  ["int32 overflow", (x) => { member(x).fields[3].maximum = 2147483648; }, "INVALID_RANGE"],
  ["fractional bound", (x) => { member(x).fields[3].maximum = 0.5; }, "INVALID_RANGE"],
  ["negative length", (x) => { member(x).fields[2].maxLength = -1; }, "INVALID_RANGE"],
  ["NaN input", (x) => { member(x).fields[3].maximum = NaN; }, "INVALID_JSON"],
  ["Infinity input", (x) => { member(x).fields[3].maximum = Infinity; }, "INVALID_JSON"],
  ["undefined input", (x) => { member(x).fields[2].maxLength = undefined; }, "INVALID_JSON"],
  ["non-JSON Date", (x) => { x.entities = new Date(); }, "INVALID_JSON"],
  ["cyclic input", (x) => { x.entities.push(x); }, "INVALID_JSON"],
  ["sparse array", (x) => { delete member(x).fields[2]; }, "INVALID_JSON"],
  ["symbol metadata", (x) => { x[Symbol("hidden")] = true; }, "INVALID_JSON"],
  ["oversized entity set", (x) => { x.entities = Array.from({ length: 65 }, () => x.entities[0]); }, "INVALID_ARRAY"],
  ["oversized field set", (x) => { member(x).fields = Array.from({ length: 257 }, () => field("id", "uuid")); }, "INVALID_ARRAY"],
];
for (const [title, mutate, expected] of invalid) test(`rejects ${title}`, () => rejection(mutate, expected));
for (const input of [null, false, 7, "schema", [], undefined]) test(`rejects nonobject root ${String(input)}`, () => { assert.equal(compileSchemaIr(input).ok, false); });

test("does not invoke input getters", () => {
  const input = fixture(); let called = false;
  Object.defineProperty(input, "unexpected", { enumerable: true, get() { called = true; throw new Error("getter executed"); } });
  assert.equal(compileSchemaIr(input).errors[0].code, "INVALID_JSON"); assert.equal(called, false);
});
test("valid schema passes semantic validation", () => { assert.deepEqual(validateSchemaIr(fixture()), []); });
test("output includes all six target families and provenance", () => {
  assert.deepEqual(Object.keys(success().files).sort(), ["cue/models.cue", "dart/models.dart", "json-schema/Member.schema.json", "json-schema/Organization.schema.json", "manifest.json", "postgres/desired.sql", "rust/models.rs", "schema-ir.json", "typescript/models.ts"]);
});
test("input is unchanged and deeply frozen inputs are supported", () => {
  const input = fixture(); const before = JSON.stringify(input);
  const freeze = (x) => { if (x !== null && typeof x === "object") { Object.values(x).forEach(freeze); Object.freeze(x); } return x; };
  success(freeze(input)); assert.equal(JSON.stringify(input), before);
});
test("outputs are immutable", () => { const result = success(); assert.throws(() => { result.files["postgres/desired.sql"] = "changed"; }, TypeError); });
test("100 deterministic declaration/key permutations produce identical bytes", () => {
  const expected = success().files;
  for (let seed = 0; seed < 100; seed += 1) {
    const input = fixture();
    if (seed % 2) input.entities.reverse();
    for (const entity of input.entities) if (seed % 3) entity.fields.reverse();
    const reorder = (value) => value && typeof value === "object" ? Array.isArray(value) ? value.map(reorder) : Object.fromEntries(Object.keys(value).sort().reverse().map((key) => [key, reorder(value[key])])) : value;
    assert.deepEqual(success(reorder(input)).files, expected);
  }
});
test("manifest independently verifies every artifact hash", () => {
  const result = success(); const manifest = JSON.parse(result.files["manifest.json"]);
  assert.equal(manifest.artifacts.length, Object.keys(result.files).length - 1);
  for (const { path, sha256 } of manifest.artifacts) assert.equal(createHash("sha256").update(result.files[path], "utf8").digest("hex"), sha256);
  assert.equal(manifest.irSha256, createHash("sha256").update(result.files["schema-ir.json"]).digest("hex"));
  assert.match(manifest.canonicalization, /not-rfc8785/);
});
test("generation is independent of process environment", () => {
  const before = success().files;
  const previous = process.env.ORES_SCHEMA_TEST_UNRELATED;
  process.env.ORES_SCHEMA_TEST_UNRELATED = "synthetic-test-value";
  try { assert.deepEqual(success().files, before); } finally { if (previous === undefined) delete process.env.ORES_SCHEMA_TEST_UNRELATED; else process.env.ORES_SCHEMA_TEST_UNRELATED = previous; }
});
test("changed model changes provenance", () => { const input = fixture(); member(input).fields[3].maximum = 149; assert.notEqual(success(input).irSha256, success().irSha256); });
test("SQL quotes identifiers and preserves checks, PK, FK and indexes", () => {
  const sql = success().files["postgres/desired.sql"];
  assert.match(sql, /"score" INTEGER NOT NULL CHECK \("score" >= 0 AND "score" <= 150\)/);
  assert.match(sql, /"nickname" TEXT CHECK \(char_length\("nickname"\) <= 80\)/);
  assert.match(sql, /PRIMARY KEY \("id"\)/);
  assert.match(sql, /REFERENCES "example"\."organizations" \("id"\) MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION/);
  assert.match(sql, /CREATE INDEX "ores_idx_[a-f0-9]{24}" ON "example"\."members" \("organization_id"\)/);
  assert.ok(sql.lastIndexOf("CREATE TABLE") < sql.indexOf("ALTER TABLE"));
  assert.doesNotMatch(sql.split("\n").filter((line) => !line.startsWith("--")).join("\n"), /DROP |CASCADE|CREATE EXTENSION|CREATE SCHEMA/);
});
test("self-referential and cyclic foreign keys emit after every table", () => {
  const input = fixture();
  input.entities[0].fields.push(field("memberId", "uuid", { nullable: true }));
  input.entities[0].foreignKeys = [{ fields: ["memberId"], references: { entity: "Member", fields: ["id"] } }, { fields: ["id"], references: { entity: "Organization", fields: ["id"] } }];
  const sql = success(input).files["postgres/desired.sql"];
  assert.equal((sql.match(/FOREIGN KEY/g) ?? []).length, 3);
  assert.ok(sql.lastIndexOf("CREATE TABLE") < sql.indexOf("ALTER TABLE"));
});
test("composite keys preserve declared column order", () => {
  const input = fixture(); member(input).primaryKey = ["organizationId", "id"];
  assert.match(success(input).files["postgres/desired.sql"], /PRIMARY KEY \("organization_id", "id"\)/);
});
test("all four presence/nullability combinations stay distinct", () => {
  const input = fixture();
  member(input).fields.push(...[field("requiredValue", "string"), field("requiredNull", "string", { nullable: true }), field("optionalValue", "string", { required: false }), field("optionalNull", "string", { required: false, nullable: true })]);
  const { files } = success(input); const schema = JSON.parse(files["json-schema/Member.schema.json"]);
  assert.equal(schema.additionalProperties, false);
  assert.ok(schema.required.includes("requiredValue")); assert.ok(schema.required.includes("requiredNull"));
  assert.ok(!schema.required.includes("optionalValue")); assert.ok(!schema.required.includes("optionalNull"));
  assert.equal(schema.properties.optionalValue.type, "string"); assert.deepEqual(schema.properties.optionalNull.type, ["string", "null"]);
  assert.match(files["typescript/models.ts"], /readonly optionalNull\?: string \| null;/);
  assert.match(files["rust/models.rs"], /pub r#optionalNull: SchemaOptional<std::option::Option<std::string::String>>/);
  assert.match(files["dart/models.dart"], /final SchemaOptional<String\?> optionalNull;/);
  assert.match(files["cue/models.cue"], /"optionalNull"\?: null \| \(string/);
  assert.match(files["postgres/desired.sql"], /"optional_value" TEXT NOT NULL/);
});
test("uuid constraints do not depend on format assertion being enabled", () => {
  const schema = JSON.parse(success().files["json-schema/Member.schema.json"]);
  assert.equal(schema.properties.id.format, "uuid");
  assert.equal(new RegExp(schema.properties.id.pattern).test("00000000-0000-0000-0000-000000000001"), true);
  assert.equal(new RegExp(schema.properties.id.pattern).test("not-a-uuid"), false);
});
test("PostgreSQL text NUL is excluded by generated schema", () => {
  const schema = JSON.parse(success().files["json-schema/Member.schema.json"]);
  const pattern = new RegExp(schema.properties.nickname.pattern, "u");
  assert.equal(pattern.test("A\u0000B"), false); assert.equal(pattern.test("café 😀"), true);
});
test("int32 bounds are emitted even when no custom range is supplied", () => {
  const input = fixture(); delete member(input).fields[3].minimum; delete member(input).fields[3].maximum;
  const schema = JSON.parse(success(input).files["json-schema/Member.schema.json"]);
  assert.equal(schema.properties.score.minimum, -2147483648); assert.equal(schema.properties.score.maximum, 2147483647);
});
test("zero string length remains an actual constraint", () => { const input = fixture(); member(input).fields[2].maxLength = 0; assert.match(success(input).files["postgres/desired.sql"], /char_length\("nickname"\) <= 0/); });
test("optional helpers are not emitted when unused", () => {
  const input = fixture(); member(input).fields.forEach((f) => { f.required = true; });
  assert.doesNotMatch(success(input).files["rust/models.rs"], /enum SchemaOptional/);
  assert.doesNotMatch(success(input).files["dart/models.dart"], /class SchemaOptional/);
});
test("schema equality does not mutate raw declaration ordering", () => { const input = fixture(); const names = input.entities.map((e) => e.name); success(input); assert.deepEqual(input.entities.map((e) => e.name), names); });

test("rejects array subclasses without calling overridden methods", () => {
  class Custom extends Array { map() { throw new Error("must not run"); } }
  const input = fixture(); input.entities = new Custom(...input.entities);
  assert.equal(compileSchemaIr(input).errors[0].code, "INVALID_JSON");
});
test("rejects objects with inherited metadata", () => { const input = Object.assign(Object.create({ unexpected: true }), fixture()); assert.equal(compileSchemaIr(input).errors[0].code, "INVALID_JSON"); });
test("rejects hidden non-enumerable metadata", () => { const input = fixture(); Object.defineProperty(input, "hidden", { value: true }); assert.equal(compileSchemaIr(input).errors[0].code, "INVALID_JSON"); });
test("rejects excessive nesting before schema traversal", () => { const input = fixture(); let value = {}; for (let i = 0; i < 30; i += 1) value = { nested: value }; input.nested = value; assert.equal(compileSchemaIr(input).errors[0].code, "RESOURCE_LIMIT"); });
test("fails closed when a declared table collides with a generated index name", () => {
  const input = fixture();
  const name = /CREATE INDEX "([^"]+)"/.exec(success(input).files["postgres/desired.sql"])[1];
  input.entities.push({ name: "Collision", table: name, fields: [field("id", "uuid")], primaryKey: ["id"] });
  const result = compileSchemaIr(input);
  assert.equal(result.ok, false); assert.equal(result.errors[0].code, "NAME_COLLISION"); assert.equal(Object.hasOwn(result, "files"), false);
});
test("accepts 63-character SQL identifiers without truncation", () => { const input = fixture(); member(input).table = "a".repeat(63); assert.ok(success(input).files["postgres/desired.sql"].includes('"' + "a".repeat(63) + '"')); });

for (const property of ["uniqueKeys", "indexes", "foreignKeys"]) test(`rejects explicitly null ${property}`, () => {
  rejection((input) => { member(input)[property] = null; }, "INVALID_ARRAY");
});
for (const column of ["tableoid", "xmin", "cmin", "xmax", "cmax", "ctid"]) test(`rejects PostgreSQL system column ${column}`, () => {
  rejection((input) => { member(input).fields[2].column = column; }, "INVALID_IDENTIFIER");
});
for (const suffix of ["\n", "\r", "\u2028", "\u2029"]) test(`rejects identifier line suffix ${JSON.stringify(suffix)}`, () => {
  rejection((input) => { member(input).table += suffix; }, "INVALID_IDENTIFIER");
});
test("UUID length rejects suffixes even in validators with permissive end anchors", () => {
  const uuid = JSON.parse(success().files["json-schema/Member.schema.json"]).properties.id;
  assert.equal(uuid.minLength, 36); assert.equal(uuid.maxLength, 36);
});
