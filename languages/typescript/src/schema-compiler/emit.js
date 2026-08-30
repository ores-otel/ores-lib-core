import { constraintName, foreignIdentity } from "./naming.js";

// Internal emitters accept only the validated, immutable IR snapshot.
const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const sortBy = (items, key) => [...items].sort((left, right) => compare(key(left), key(right)));
const quote = (identifier) => `"${identifier}"`; // The validator rejects quotes and non-ASCII identifiers.
const qualified = (storage) => `${quote(storage.schema)}.${quote(storage.table)}`;
const SQL_TYPES = Object.freeze({ string: "pg_catalog.text", boolean: "pg_catalog.bool", int32: "pg_catalog.int4", uuid: "pg_catalog.uuid" });
const TS_TYPES = Object.freeze({ string: "string", boolean: "boolean", int32: "number", uuid: "string" });
const UUID_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![\\s\\S])";

function propertySchema(field) {
  const scalar = field.type === "int32" ? "integer" : field.type === "boolean" ? "boolean" : "string";
  const result = { type: field.nullable ? [scalar, "null"] : scalar };
  if (field.type === "int32") {
    result.minimum = -2147483648;
    result.maximum = 2147483647;
  }
  if (field.type === "uuid") {
    result.format = "uuid";
    result.pattern = UUID_PATTERN;
  }
  for (const key of ["minLength", "maxLength"]) {
    if (field[key] !== undefined) {
      result[key] = field[key];
    }
  }
  return result;
}

export function emitJsonSchema(ir) {
  const models = sortBy(ir.models, (model) => model.name);
  const definitions = models.map((model) => {
    const fields = sortBy(model.fields, (field) => field.name);
    return [model.name, {
      type: "object",
      additionalProperties: false,
      properties: Object.fromEntries(fields.map((field) => [field.name, propertySchema(field)])),
      required: fields.filter((field) => field.required).map((field) => field.name),
    }];
  });
  return `${JSON.stringify({
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $comment: "Generated from ores.schema-ir.v1. Root accepts any declared model; select a $defs entry to require a particular model. Cross-row SQL constraints are not JSON instance validation.",
    anyOf: models.map((model) => ({ $ref: `#/$defs/${model.name}` })),
    $defs: Object.fromEntries(definitions),
  }, null, 2)}\n`;
}

export function emitTypescript(ir) {
  const models = sortBy(ir.models, (model) => model.name).map((model) => {
    const fields = sortBy(model.fields, (field) => field.name).map((field) =>
      `  readonly ${JSON.stringify(field.name)}${field.required ? "" : "?"}: ${TS_TYPES[field.type]}${field.nullable ? " | null" : ""};`);
    return `export interface ${model.name} {\n${fields.join("\n")}\n}`;
  });
  return [
    "// Generated from ores.schema-ir.v1; do not edit.",
    "// These are shape declarations, not runtime validators (UUID/length/int32 constraints remain in JSON Schema).",
    "// Enable strictNullChecks and exactOptionalPropertyTypes in consumers.",
    "",
    models.join("\n\n"),
    "",
  ].join("\n");
}

export function emitPostgres(ir) {
  const models = new Map(ir.models.map((model) => [model.name, model]));
  const stored = sortBy(ir.models.filter((model) => model.storage), (model) => qualified(model.storage));
  const statements = ["-- Generated desired-state SQL from ores.schema-ir.v1; NOT a migration plan.",
    "-- Apply only to a disposable desired-state database; use DPM diff/verify and reviewed migrator jobs for real targets."];
  if (stored.length === 0) {
    return `${statements.join("\n")}\n-- No persisted models.\n`;
  }
  // public already exists in standard PostgreSQL databases. Other namespaces are explicit.
  const schemas = [...new Set(stored.map((model) => model.storage.schema))].sort(compare);
  schemas.filter((schema) => schema !== "public").forEach((schema) => statements.push(`CREATE SCHEMA ${quote(schema)};`));
  function columns(storage, fields) {
    const mapping = new Map(storage.columns.map((column) => [column.field, column.name]));
    return fields.map((field) => quote(mapping.get(field))).join(", ");
  }
  stored.forEach((model) => {
    const storage = model.storage;
    const fields = new Map(model.fields.map((field) => [field.name, field]));
    const rows = sortBy(storage.columns, (column) => column.name).map((column) => {
      const field = fields.get(column.field);
      const checks = [];
      if (field.minLength !== undefined) {
        checks.push(`CHECK (pg_catalog.char_length(${quote(column.name)}) >= ${field.minLength})`);
      }
      if (field.maxLength !== undefined) {
        checks.push(`CHECK (pg_catalog.char_length(${quote(column.name)}) <= ${field.maxLength})`);
      }
      return `  ${quote(column.name)} ${SQL_TYPES[field.type]}${field.nullable ? "" : " NOT NULL"}${checks.length ? ` ${checks.join(" ")}` : ""}`;
    });
    rows.push(`  CONSTRAINT ${quote(constraintName(storage, "pk", storage.primaryKey))} PRIMARY KEY (${columns(storage, storage.primaryKey)})`);
    sortBy(storage.uniqueKeys, (key) => key.join("\u0000")).forEach((key) => rows.push(`  CONSTRAINT ${quote(constraintName(storage, "uk", key))} UNIQUE (${columns(storage, key)})`));
    statements.push(`CREATE TABLE ${qualified(storage)} (\n${rows.join(",\n")}\n);`);
  });
  // A second pass permits self-references and cycles without ordering-dependent failures.
  stored.forEach((model) => {
    const storage = model.storage;
    sortBy(storage.foreignKeys, (key) => JSON.stringify([key.fields, key.references.model, key.references.fields, key.onDelete])).forEach((key) => {
      const target = models.get(key.references.model).storage;
      const action = { restrict: "RESTRICT", cascade: "CASCADE", setNull: "SET NULL" }[key.onDelete];
      statements.push(`ALTER TABLE ${qualified(storage)} ADD CONSTRAINT ${quote(constraintName(storage, "fk", foreignIdentity(key, target)))} FOREIGN KEY (${columns(storage, key.fields)}) REFERENCES ${qualified(target)} (${columns(target, key.references.fields)}) MATCH SIMPLE ON DELETE ${action} ON UPDATE NO ACTION;`);
    });
  });
  return `${statements.join("\n\n")}\n`;
}
