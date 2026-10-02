import { constraintName, foreignIdentity } from "./naming.js";

// Closed, bounded JSON input boundary. This module has no I/O or environment access.
const VERSION = "ores.schema-ir.v1";
const MODEL_NAME = /^[A-Z][A-Za-z0-9]{0,62}(?![\s\S])/;
const FIELD_NAME = /^[a-z][A-Za-z0-9_]{0,62}(?![\s\S])/;
const SQL_NAME = /^[a-z][a-z0-9_]{0,62}(?![\s\S])/;
const SCALARS = new Set(["string", "boolean", "int32", "uuid"]);
const SYSTEM_COLUMNS = new Set(["tableoid", "xmin", "cmin", "xmax", "cmax", "ctid"]);

class InputError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function snapshotJson(input) {
  const ancestors = new WeakSet();
  let nodes = 0;
  function visit(value, depth) {
    nodes += 1;
    if (depth > 16 || nodes > 200000) {
      throw new InputError("INPUT_LIMIT");
    }
    if (value === null || typeof value === "string" || typeof value === "boolean") {
      return value;
    }
    if (typeof value === "number" && Number.isFinite(value)) {
      return Object.is(value, -0) ? 0 : value;
    }
    if (typeof value !== "object" || value === null || ancestors.has(value)) {
      throw new InputError("INPUT_NOT_JSON");
    }
    const array = Array.isArray(value);
    const prototype = Object.getPrototypeOf(value);
    if ((array && prototype !== Array.prototype) ||
        (!array && prototype !== Object.prototype && prototype !== null) ||
        Object.getOwnPropertySymbols(value).length !== 0) {
      throw new InputError("INPUT_NOT_JSON");
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (array && value.length > 16384) {
      throw new InputError("INPUT_LIMIT");
    }
    const entries = Object.entries(descriptors).filter(([key]) => !(array && key === "length"));
    if (entries.some(([, descriptor]) => !("value" in descriptor) || !descriptor.enumerable)) {
      throw new InputError("INPUT_NOT_JSON");
    }
    if (array && (entries.length !== value.length || entries.some(([key]) =>
      !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length))) {
      throw new InputError("INPUT_NOT_JSON");
    }
    ancestors.add(value);
    const result = array
      ? Array.from({ length: value.length }, (_, index) => visit(descriptors[index].value, depth + 1))
      : Object.fromEntries(entries.map(([key, descriptor]) => [key, visit(descriptor.value, depth + 1)]));
    ancestors.delete(value);
    return Object.freeze(result);
  }
  return visit(input, 0);
}

/** Internal validator. Never include untrusted input values in diagnostics. */
export function validate(input) {
  let value;
  try {
    value = snapshotJson(input);
  } catch (error) {
    return {
      diagnostics: [{ code: error instanceof InputError ? error.code : "INPUT_NOT_JSON", path: "$", message: "Expected a bounded JSON data document without cycles, accessors, or executable values." }],
    };
  }
  const diagnostics = [];
  function error(code, path, message) {
    if (diagnostics.length < 100) {
      diagnostics.push({ code, path, message });
    }
    return false;
  }
  function record(item, required, optional, path) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      return error("INVALID_SHAPE", path, "Expected an object.");
    }
    const allowed = new Set([...required, ...optional]);
    if (Object.keys(item).some((key) => !allowed.has(key))) {
      return error("UNKNOWN_PROPERTY", path, "Unknown properties are not supported.");
    }
    if (required.some((key) => !Object.hasOwn(item, key))) {
      return error("MISSING_PROPERTY", path, "Missing required properties.");
    }
    return true;
  }
  function array(item, min, max, path) {
    if (!Array.isArray(item) || item.length < min || item.length > max) {
      return error("INVALID_ARRAY", path, `Expected an array with ${min} to ${max} entries.`);
    }
    return true;
  }
  function name(item, pattern, path) {
    if (typeof item !== "string" || !pattern.test(item)) {
      return error("INVALID_IDENTIFIER", path, "Expected a portable ASCII identifier of at most 63 characters.");
    }
    return true;
  }
  function fieldList(item, path) {
    if (!array(item, 1, 128, path)) {
      return;
    }
    item.forEach((field, index) => name(field, FIELD_NAME, `${path}[${index}]`));
    if (new Set(item).size !== item.length) {
      error("DUPLICATE_KEY_FIELD", path, "A key cannot repeat a field.");
    }
  }
  function storage(item, path) {
    if (!record(item, ["schema", "table", "columns", "primaryKey", "uniqueKeys", "foreignKeys"], [], path)) {
      return;
    }
    name(item.schema, SQL_NAME, `${path}.schema`);
    name(item.table, SQL_NAME, `${path}.table`);
    if (array(item.columns, 1, 128, `${path}.columns`)) {
      item.columns.forEach((column, index) => {
        const here = `${path}.columns[${index}]`;
        if (record(column, ["field", "name"], [], here)) {
          name(column.field, FIELD_NAME, `${here}.field`);
          name(column.name, SQL_NAME, `${here}.name`);
        }
      });
    }
    fieldList(item.primaryKey, `${path}.primaryKey`);
    if (array(item.uniqueKeys, 0, 64, `${path}.uniqueKeys`)) {
      item.uniqueKeys.forEach((key, index) => fieldList(key, `${path}.uniqueKeys[${index}]`));
    }
    if (array(item.foreignKeys, 0, 64, `${path}.foreignKeys`)) {
      item.foreignKeys.forEach((key, index) => {
        const here = `${path}.foreignKeys[${index}]`;
        if (!record(key, ["fields", "references", "onDelete"], [], here)) {
          return;
        }
        fieldList(key.fields, `${here}.fields`);
        if (record(key.references, ["model", "fields"], [], `${here}.references`)) {
          name(key.references.model, MODEL_NAME, `${here}.references.model`);
          fieldList(key.references.fields, `${here}.references.fields`);
        }
        if (!["restrict", "cascade", "setNull"].includes(key.onDelete)) {
          error("UNSUPPORTED_DELETE_ACTION", `${here}.onDelete`, "Unsupported foreign-key delete action.");
        }
      });
    }
  }
  if (!record(value, ["version", "models"], [], "$")) {
    return { diagnostics };
  }
  if (value.version !== VERSION) {
    error("UNSUPPORTED_VERSION", "$.version", "Expected ores.schema-ir.v1; version fallback is prohibited.");
  }
  if (!array(value.models, 1, 64, "$.models")) {
    return { diagnostics };
  }
  value.models.forEach((model, index) => {
    const path = `$.models[${index}]`;
    if (!record(model, ["name", "fields"], ["storage"], path)) {
      return;
    }
    name(model.name, MODEL_NAME, `${path}.name`);
    if (array(model.fields, 1, 128, `${path}.fields`)) {
      model.fields.forEach((field, fieldIndex) => {
        const here = `${path}.fields[${fieldIndex}]`;
        if (!record(field, ["name", "type", "required", "nullable"], ["minLength", "maxLength"], here)) {
          return;
        }
        name(field.name, FIELD_NAME, `${here}.name`);
        if (!SCALARS.has(field.type)) {
          error("UNSUPPORTED_TYPE", `${here}.type`, "Unsupported scalar; no implicit coercion or fallback exists.");
        }
        for (const key of ["required", "nullable"]) {
          if (typeof field[key] !== "boolean") {
            error("INVALID_BOOLEAN", `${here}.${key}`, "Presence and nullability must be explicit booleans.");
          }
        }
        for (const key of ["minLength", "maxLength"]) {
          if (Object.hasOwn(field, key) && (field.type !== "string" || !Number.isInteger(field[key]) || field[key] < 0 || field[key] > 1048576)) {
            error("INVALID_LENGTH", `${here}.${key}`, "String lengths must be integers from 0 to 1048576 and apply only to string fields.");
          }
        }
        if (Number.isInteger(field.minLength) && Number.isInteger(field.maxLength) && field.minLength > field.maxLength) {
          error("CONTRADICTORY_LENGTH", here, "Minimum string length exceeds maximum string length.");
        }
      });
    }
    if (Object.hasOwn(model, "storage")) {
      storage(model.storage, `${path}.storage`);
    }
  });
  if (diagnostics.length !== 0) {
    return { diagnostics };
  }

  // All nested shapes are now known. Check graph and relational invariants separately.
  const models = new Map(value.models.map((model) => [model.name, model]));
  if (models.size !== value.models.length) {
    error("DUPLICATE_MODEL", "$.models", "Model names must be unique.");
  }
  const tables = new Set();
  value.models.forEach((model, index) => {
    const path = `$.models[${index}]`;
    const fields = new Map(model.fields.map((field) => [field.name, field]));
    if (fields.size !== model.fields.length) {
      error("DUPLICATE_FIELD", `${path}.fields`, "Field names must be unique within a model.");
    }
    if (!model.storage) {
      return;
    }
    const sql = model.storage;
    if (sql.schema.startsWith("pg_") || sql.schema === "information_schema") {
      error("RESERVED_SCHEMA", `${path}.storage.schema`, "System schema names cannot be compiler targets.");
    }
    const table = `${sql.schema}.${sql.table}`;
    if (tables.has(table)) {
      error("DUPLICATE_TABLE", `${path}.storage`, "Each qualified table must have exactly one owning model.");
    }
    tables.add(table);
    const columns = new Map(sql.columns.map((column) => [column.field, column.name]));
    if (columns.size !== sql.columns.length || new Set(sql.columns.map((column) => column.name)).size !== sql.columns.length) {
      error("DUPLICATE_COLUMN", `${path}.storage.columns`, "Column names and mapped fields must both be unique.");
    }
    if (sql.columns.some((column) => SYSTEM_COLUMNS.has(column.name))) {
      error("RESERVED_COLUMN", `${path}.storage.columns`, "PostgreSQL system column names cannot be user columns.");
    }
    if (columns.size !== fields.size || [...columns.keys()].some((field) => !fields.has(field)) || [...fields.keys()].some((field) => !columns.has(field))) {
      error("INCOMPLETE_MAPPING", `${path}.storage.columns`, "Storage must explicitly map every field exactly once, without extra fields.");
    }
    if (model.fields.some((field) => !field.required)) {
      error("LOSSY_PRESENCE", `${path}.storage`, "Stored row fields must be required. Model optional patch/input fields separately; SQL NULL cannot preserve absence.");
    }
    const keys = [sql.primaryKey, ...sql.uniqueKeys];
    const keySignatures = keys.map((key) => [...key].sort().join("\u0000"));
    if (new Set(keySignatures).size !== keySignatures.length) {
      error("DUPLICATE_KEY", `${path}.storage`, "Primary and unique keys must not duplicate the same field set.");
    }
    keys.forEach((key) => {
      if (key.some((field) => !fields.has(field))) {
        error("UNKNOWN_KEY_FIELD", `${path}.storage`, "All primary and unique key fields must resolve within the owning model.");
      }
    });
    if (sql.primaryKey.some((field) => fields.get(field)?.nullable)) {
      error("NULLABLE_PRIMARY_KEY", `${path}.storage.primaryKey`, "Primary-key fields must be non-nullable.");
    }
    const seenForeignKeys = new Set();
    sql.foreignKeys.forEach((key, keyIndex) => {
      const here = `${path}.storage.foreignKeys[${keyIndex}]`;
      const signature = JSON.stringify([key.fields, key.references.model, key.references.fields]);
      if (seenForeignKeys.has(signature)) {
        error("DUPLICATE_FOREIGN_KEY", here, "A relationship must have exactly one delete policy.");
      }
      seenForeignKeys.add(signature);
      const target = models.get(key.references.model);
      const targetFields = new Map((target?.fields ?? []).map((field) => [field.name, field]));
      if (!target?.storage) {
        error("UNKNOWN_REFERENCE", `${here}.references`, "Foreign keys must target a stored model in the same document.");
        return;
      }
      if (key.fields.length !== key.references.fields.length || key.fields.some((field) => !fields.has(field)) || key.references.fields.some((field) => !targetFields.has(field))) {
        error("INVALID_FOREIGN_KEY", here, "Foreign-key field lists must resolve and have equal arity.");
        return;
      }
      if (!([target.storage.primaryKey, ...target.storage.uniqueKeys].some((candidate) => candidate.length === key.references.fields.length && candidate.every((field, fieldIndex) => field === key.references.fields[fieldIndex])))) {
        error("NON_UNIQUE_REFERENCE", `${here}.references`, "The ordered referenced fields must match a declared primary or unique key.");
      }
      if (key.fields.some((field, fieldIndex) => fields.get(field).type !== targetFields.get(key.references.fields[fieldIndex]).type)) {
        error("FOREIGN_KEY_TYPE_MISMATCH", here, "Foreign-key scalar types must match exactly.");
      }
      if (key.onDelete === "setNull" && key.fields.some((field) => !fields.get(field).nullable)) {
        error("INVALID_SET_NULL", here, "SET NULL requires every referencing field to be nullable.");
      }
    });
  });
  if (diagnostics.length === 0) {
    // PK/UNIQUE constraints create relations in the same namespace as tables.
    // PostgreSQL's automatic names can collide with a later CREATE TABLE.
    const relations = new Set(value.models.filter((model) => model.storage).map((model) =>       model.storage.schema + "." + model.storage.table));
    value.models.forEach((model, index) => {
      if (!model.storage) {
        return;
      }
      const sql = model.storage;
      const indexes = [constraintName(sql, "pk", sql.primaryKey), ...sql.uniqueKeys.map((key) => constraintName(sql, "uk", key))];
      const foreign = sql.foreignKeys.map((key) => constraintName(sql, "fk", foreignIdentity(key, models.get(key.references.model).storage)));
      if (new Set([...indexes, ...foreign]).size !== indexes.length + foreign.length) {
        error("SQL_NAME_COLLISION", "$.models[" + index + "].storage", "Generated constraint names collide; no SQL can be emitted.");
      }
      indexes.forEach((name) => {
        const qualified = sql.schema + "." + name;
        if (relations.has(qualified)) {
          error("SQL_NAME_COLLISION", "$.models[" + index + "].storage", "Generated index names collide with another relation; no SQL can be emitted.");
        }
        relations.add(qualified);
      });
    });
  }
  return diagnostics.length === 0 ? { value, diagnostics } : { diagnostics };
}
