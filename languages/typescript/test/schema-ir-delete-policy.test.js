import test from "node:test";
import assert from "node:assert/strict";

import { compileSchemaIr } from "../src/schema-ir/index.js";

const field = (name, type, overrides = {}) => ({
  name,
  column: name.replace(/[A-Z]/g, (character) => `_${character.toLowerCase()}`),
  type,
  required: true,
  nullable: false,
  ...overrides,
});

function fixture(onDelete) {
  const foreignKey = {
    fields: ["organizationId"],
    references: { entity: "Organization", fields: ["id"] },
  };
  if (onDelete !== undefined) foreignKey.onDelete = onDelete;
  return {
    schemaVersion: "ores.schema-ir.v1",
    databaseSchema: "example",
    entities: [
      {
        name: "Organization",
        table: "organizations",
        fields: [field("id", "uuid")],
        primaryKey: ["id"],
      },
      {
        name: "Member",
        table: "members",
        fields: [field("id", "uuid"), field("organizationId", "uuid")],
        primaryKey: ["id"],
        foreignKeys: [foreignKey],
      },
    ],
  };
}

function sqlFor(onDelete) {
  const result = compileSchemaIr(fixture(onDelete));
  assert.equal(result.ok, true, JSON.stringify(result));
  return result.files["postgres/desired.sql"];
}

test("omitted delete policy preserves the v1 NO ACTION default", () => {
  assert.match(sqlFor(undefined), /ON DELETE NO ACTION/);
});

test("explicit safe delete policies are emitted exactly", () => {
  assert.match(sqlFor("noAction"), /ON DELETE NO ACTION/);
  assert.match(sqlFor("restrict"), /ON DELETE RESTRICT/);
  assert.match(sqlFor("cascade"), /ON DELETE CASCADE/);
});

test("SET NULL requires nullable local fields", () => {
  const invalid = compileSchemaIr(fixture("setNull"));
  assert.equal(invalid.ok, false);
  assert.equal(invalid.errors[0].code, "INVALID_REFERENCE");

  const valid = fixture("setNull");
  valid.entities[1].fields[1].nullable = true;
  const result = compileSchemaIr(valid);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.match(result.files["postgres/desired.sql"], /ON DELETE SET NULL/);
});

test("one relationship cannot declare conflicting delete policies", () => {
  const input = fixture("restrict");
  input.entities[1].foreignKeys.push({
    ...structuredClone(input.entities[1].foreignKeys[0]),
    onDelete: "cascade",
  });
  const result = compileSchemaIr(input);
  assert.equal(result.ok, false);
  assert.equal(result.errors[0].code, "DUPLICATE");
});

test("unsupported delete policy is rejected without interpolation", () => {
  const result = compileSchemaIr(fixture("CASCADE"));
  assert.equal(result.ok, false);
  assert.equal(result.errors[0].code, "UNKNOWN_PROPERTY");
  assert.doesNotMatch(result.errors[0].message, /CASCADE/);
});
