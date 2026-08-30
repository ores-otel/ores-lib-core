/** Node-only build-time compiler. No filesystem, process environment, network, or DB access. */
import { createHash } from "node:crypto";
import { IR_VERSION, IrValidationError, normalizeSchemaIr, validateSchemaIr } from "./validate.js";
export { IR_VERSION, validateSchemaIr };
const GENERATOR = "ores.schema-compiler.v1";
const UUID_PATTERN = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
const sha256 = (text) => createHash("sha256").update(text, "utf8").digest("hex");
const canonical = (value) => value !== null && typeof value === "object"
  ? Array.isArray(value) ? value.map(canonical) : Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]))
  : value;
const json = (value) => `${JSON.stringify(canonical(value), null, 2)}\n`;
const quote = (value) => `"${value}"`; // Identifiers are validated before any emitter runs.
const sqlName = (ir, entity) => `${quote(ir.databaseSchema)}.${quote(entity.table)}`;
const columns = (entity, names) => names.map((name) => quote(entity.fields.find((field) => field.name === name).column)).join(", ");
const generatedName = (kind, table, detail) => `ores_${kind}_${sha256(JSON.stringify([table, detail])).slice(0, 24)}`;
const sqlScalar = Object.freeze({ string: "TEXT", uuid: "UUID", int32: "INTEGER", boolean: "BOOLEAN" });

function emitSql(ir) {
  const relations = new Set(ir.entities.map((entity) => entity.table));
  const relationName = (kind, table, detail) => {
    const name = generatedName(kind, table, detail);
    if (relations.has(name)) throw new IrValidationError("NAME_COLLISION", "/entities", "Generated relation name collides with a declared relation.");
    relations.add(name);
    return quote(name);
  };
  const tables = ir.entities.map((entity) => {
    const declarations = entity.fields.map((field) => {
      const name = quote(field.column);
      const checks = [
        field.minLength === undefined ? null : `char_length(${name}) >= ${field.minLength}`,
        field.maxLength === undefined ? null : `char_length(${name}) <= ${field.maxLength}`,
        field.minimum === undefined ? null : `${name} >= ${field.minimum}`,
        field.maximum === undefined ? null : `${name} <= ${field.maximum}`,
      ].filter((check) => check !== null);
      return `  ${name} ${sqlScalar[field.type]}${field.nullable ? "" : " NOT NULL"}${checks.length ? ` CHECK (${checks.join(" AND ")})` : ""}`;
    });
    declarations.push(`  CONSTRAINT ${relationName("pk", entity.table, entity.primaryKey)} PRIMARY KEY (${columns(entity, entity.primaryKey)})`);
    for (const key of entity.uniqueKeys) declarations.push(`  CONSTRAINT ${relationName("uq", entity.table, key)} UNIQUE (${columns(entity, key)})`);
    return `CREATE TABLE ${sqlName(ir, entity)} (\n${declarations.join(",\n")}\n);`;
  });
  // Foreign keys follow ALL table declarations: self-references and cycles are valid.
  const references = ir.entities.flatMap((entity) => entity.foreignKeys.map((fk) => {
    const target = ir.entities.find((candidate) => candidate.name === fk.references.entity);
    return `ALTER TABLE ${sqlName(ir, entity)} ADD CONSTRAINT ${quote(generatedName("fk", entity.table, fk))} FOREIGN KEY (${columns(entity, fk.fields)}) REFERENCES ${sqlName(ir, target)} (${columns(target, fk.references.fields)}) MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION;`;
  }));
  const indexes = ir.entities.flatMap((entity) => entity.indexes.map((key) => `CREATE INDEX ${relationName("idx", entity.table, key)} ON ${sqlName(ir, entity)} (${columns(entity, key)});`));
  return ["-- Generated desired state, NOT an executable migration plan.", "-- Schema provisioning, RLS, grants, triggers, defaults and backfills remain external.", "-- No CREATE/ALTER/DROP is executed by this compiler.", "", [...tables, ...references, ...indexes].join("\n\n"), ""].join("\n");
}
function propertySchema(field) {
  const type = field.type === "int32" ? "integer" : field.type === "boolean" ? "boolean" : "string";
  const result = { type: field.nullable ? [type, "null"] : type };
  if (field.type === "uuid") Object.assign(result, { format: "uuid", pattern: UUID_PATTERN, minLength: 36, maxLength: 36 });
  if (field.type === "string") result.pattern = "^[^\\u0000]*$"; // PostgreSQL TEXT cannot store NUL.
  if (field.type === "int32") Object.assign(result, { minimum: field.minimum ?? -2147483648, maximum: field.maximum ?? 2147483647 });
  for (const key of ["minLength", "maxLength"]) if (field[key] !== undefined) result[key] = field[key];
  return result;
}
function emitJsonSchema(ir, entity) {
  return json({ $schema: "https://json-schema.org/draft/2020-12/schema", $id: `urn:ores:schema-ir:v1:${ir.databaseSchema}:${entity.name}`, title: entity.name, type: "object", additionalProperties: false, properties: Object.fromEntries(entity.fields.map((field) => [field.name, propertySchema(field)])), required: entity.fields.filter((field) => field.required).map((field) => field.name) });
}
function emitTypeScript(ir) {
  const types = { string: "string", uuid: "string", int32: "number", boolean: "boolean" };
  return ["// Generated types only. Validate boundary data with the emitted schema.", "// Enable strictNullChecks and exactOptionalPropertyTypes.", "", ...ir.entities.map((entity) => `export interface ${entity.name} {\n${entity.fields.map((field) => `  readonly ${field.name}${field.required ? "" : "?"}: ${types[field.type]}${field.nullable ? " | null" : ""};`).join("\n")}\n}`), ""].join("\n\n");
}
function emitRust(ir) {
  const types = { string: "std::string::String", uuid: "std::string::String", int32: "i32", boolean: "bool" };
  const fieldType = (field) => {
    const scalar = field.nullable ? `std::option::Option<${types[field.type]}>` : types[field.type];
    return field.required ? scalar : `SchemaOptional<${scalar}>`;
  };
  const optional = ir.entities.some((entity) => entity.fields.some((field) => !field.required));
  return ["// Generated owned types only; no serde or runtime validation is implied.", ...(optional ? ["#[derive(Debug, Clone, PartialEq, Eq)]\npub enum SchemaOptional<T> { Missing, Present(T) }"] : []), ...ir.entities.map((entity) => `#[derive(Debug, Clone, PartialEq, Eq)]\n#[allow(non_snake_case)]\npub struct ${entity.name} {\n${entity.fields.map((field) => `    pub r#${field.name}: ${fieldType(field)},`).join("\n")}\n}`), ""].join("\n\n");
}
function emitDart(ir) {
  const types = { string: "String", uuid: "String", int32: "int", boolean: "bool" };
  const fieldType = (field) => {
    const scalar = `${types[field.type]}${field.nullable ? "?" : ""}`;
    return field.required ? scalar : `SchemaOptional<${scalar}>`;
  };
  const optional = ir.entities.some((entity) => entity.fields.some((field) => !field.required));
  const helper = "sealed class SchemaOptional<T> { const SchemaOptional(); }\nfinal class SchemaMissing<T> extends SchemaOptional<T> { const SchemaMissing(); }\nfinal class SchemaPresent<T> extends SchemaOptional<T> {\n  final T value;\n  const SchemaPresent(this.value);\n}";
  return ["// Generated Dart 3 immutable types only; validate JSON before constructing.", ...(optional ? [helper] : []), ...ir.entities.map((entity) => `final class ${entity.name} {\n${entity.fields.map((field) => `  final ${fieldType(field)} ${field.name};`).join("\n")}\n  const ${entity.name}({\n${entity.fields.map((field) => field.required ? `    required this.${field.name},` : `    this.${field.name} = const SchemaMissing(),`).join("\n")}\n  });\n}`), ""].join("\n\n");
}
function emitCue(ir) {
  const usesStrings = ir.entities.some((entity) => entity.fields.some((field) => field.minLength !== undefined || field.maxLength !== undefined));
  const constraint = (field) => {
    const base = field.type === "boolean" ? ["bool"] : field.type === "int32" ? ["int", `>=${field.minimum ?? -2147483648}`, `<=${field.maximum ?? 2147483647}`] : ["string"];
    if (field.type === "uuid") base.push(`=~${JSON.stringify(UUID_PATTERN)}`);
    if (field.type === "string") base.push('!~"\\\\x00"');
    if (field.minLength !== undefined) base.push(`strings.MinRunes(${field.minLength})`);
    if (field.maxLength !== undefined) base.push(`strings.MaxRunes(${field.maxLength})`);
    const value = base.join(" & ");
    return field.nullable ? `null | (${value})` : value;
  };
  return ["// Generated structural constraints. Relational integrity remains in PostgreSQL.", "package models", ...(usesStrings ? ['import "strings"'] : []), ...ir.entities.map((entity) => `#${entity.name}: {\n${entity.fields.map((field) => `  ${JSON.stringify(field.name)}${field.required ? "!" : "?"}: ${constraint(field)}`).join("\n")}\n}`), ""].join("\n\n");
}

/** Returns all outputs or typed diagnostics; never returns partial output on failure. */
export function compileSchemaIr(input) {
  try {
    const ir = normalizeSchemaIr(input);
    const canonicalIr = json(ir);
    const entries = [
      ["schema-ir.json", canonicalIr], ["postgres/desired.sql", emitSql(ir)],
      ["typescript/models.ts", emitTypeScript(ir)], ["rust/models.rs", emitRust(ir)],
      ["dart/models.dart", emitDart(ir)], ["cue/models.cue", emitCue(ir)],
      ...ir.entities.map((entity) => [`json-schema/${entity.name}.schema.json`, emitJsonSchema(ir, entity)]),
    ].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    const irSha256 = sha256(canonicalIr);
    const manifest = json({ generator: GENERATOR, schemaVersion: IR_VERSION, canonicalization: "sorted-object-keys-and-normalized-ir-v1-not-rfc8785", irSha256, artifacts: entries.map(([path, content]) => ({ path, sha256: sha256(content) })) });
    return Object.freeze({ ok: true, irSha256, files: Object.freeze(Object.fromEntries([...entries, ["manifest.json", manifest]])) });
  } catch (error) {
    if (error instanceof IrValidationError) return Object.freeze({ ok: false, errors: Object.freeze([error.diagnostic]) });
    throw error;
  }
}
