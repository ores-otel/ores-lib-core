/** Strict, side-effect-free validation for the deliberately bounded v1 IR. */
export const IR_VERSION = "ores.schema-ir.v1";
const TYPES = new Set(["string", "uuid", "int32", "boolean"]);
const DELETE_ACTIONS = new Set(["noAction", "restrict", "cascade", "setNull"]);
const IDENTIFIER = /^[a-z][a-z0-9_]{0,62}$/;
const SYSTEM_COLUMNS = new Set(["tableoid", "xmin", "cmin", "xmax", "cmax", "ctid"]);
const FIELD = /^[a-z][A-Za-z0-9]{0,62}$/;
const MODEL = /^[A-Z][A-Za-z0-9]{0,62}$/;
// Conservative cross-language reserved names. No escaping guesses in emitted code.
const RESERVED_FIELDS = new Set(("abstract as assert async await base break case catch class const continue covariant crate debugger default deferred do dynamic else enum export extends extension external factory false final finally fn for function get if implements import in interface is late let library macro match mixin mod move mut native new null of on operator override part priv pub rethrow return self set static struct super switch sync this throw trait true try type typedef typeof union unsafe use var virtual void where while with yield hashCode runtimeType toString noSuchMethod constructor prototype then").split(" "));
const RESERVED_MODELS = new Set(["SchemaOptional", "SchemaMissing", "SchemaPresent", "String", "Object", "Null", "Never", "Type", "Function", "List", "Map", "Set", "Symbol", "Future", "Stream", "DateTime", "Self"]);
const order = (a, b) => a < b ? -1 : a > b ? 1 : 0;

export class IrValidationError extends Error {
  constructor(code, path, message) {
    super(message);
    this.name = "IrValidationError";
    this.diagnostic = Object.freeze({ code, path, message });
  }
}
const fail = (code, path, message) => { throw new IrValidationError(code, path, message); };

function jsonValue(value, path, ancestors = new Set(), depth = 0, budget = { remaining: 100000 }) {
  budget.remaining -= 1;
  if (depth > 20 || budget.remaining < 0) fail("RESOURCE_LIMIT", path, "IR exceeds the depth or node limit.");
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number" && Number.isFinite(value)) return;
  if (typeof value !== "object") fail("INVALID_JSON", path, "Expected a finite JSON value.");
  const prototype = Object.getPrototypeOf(value);
  if ((Array.isArray(value) && prototype !== Array.prototype) || (!Array.isArray(value) && prototype !== Object.prototype && prototype !== null)) fail("INVALID_JSON", path, "Expected a plain JSON object.");
  if (ancestors.has(value)) fail("INVALID_JSON", path, "Cyclic input is not JSON.");
  const next = new Set([...ancestors, value]);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Array.isArray(value) && value.length > 10000) fail("RESOURCE_LIMIT", path, "Array exceeds the input limit.");
  for (const key of Reflect.ownKeys(descriptors)) {
    if (Array.isArray(value) && key === "length") continue;
    if (typeof key !== "string" || !Object.hasOwn(descriptors[key], "value") || !descriptors[key].enumerable) fail("INVALID_JSON", path, "Only enumerable data properties are accepted.");
    if (Array.isArray(value) && !/^(0|[1-9][0-9]*)$/.test(key)) fail("INVALID_JSON", path, "Arrays cannot carry named properties.");
    jsonValue(descriptors[key].value, `${path}/${key.replace(/~/g, "~0").replace(/\//g, "~1")}`, next, depth + 1, budget);
  }
  if (Array.isArray(value) && Object.keys(value).length !== value.length) fail("INVALID_JSON", path, "Sparse arrays are not JSON.");
}

function record(value, required, optional, path) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("INVALID_TYPE", path, "Expected an object.");
  if (required.some((key) => !Object.hasOwn(value, key))) fail("MISSING_PROPERTY", path, "A required IR property is absent.");
  const allowed = new Set([...required, ...optional]);
  if (Object.keys(value).some((key) => !allowed.has(key))) fail("UNKNOWN_PROPERTY", path, "Unsupported metadata is not silently ignored.");
}
function list(value, path, minimum = 0, maximum = 64) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) fail("INVALID_ARRAY", path, `Expected ${minimum}..${maximum} entries.`);
  return value;
}
function name(value, pattern, path, reserved = new Set()) {
  if (typeof value !== "string" || !pattern.test(value) || reserved.has(value)) fail("INVALID_IDENTIFIER", path, "Expected a bounded, portable, non-reserved identifier.");
  return value;
}
function integer(value, minimum, maximum, path) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) fail("INVALID_RANGE", path, "Integer constraint is outside the supported bounds.");
}
function unique(values, path) {
  if (new Set(values).size !== values.length) fail("DUPLICATE", path, "Duplicate names or declarations are not allowed.");
}
function field(value, path) {
  record(value, ["name", "column", "type", "required", "nullable"], ["minLength", "maxLength", "minimum", "maximum"], path);
  name(value.name, FIELD, `${path}/name`, RESERVED_FIELDS);
  name(value.column, IDENTIFIER, `${path}/column`, SYSTEM_COLUMNS);
  if (!TYPES.has(value.type)) fail("UNSUPPORTED_TYPE", `${path}/type`, "Supported scalars are string, uuid, int32, and boolean.");
  if (typeof value.required !== "boolean" || typeof value.nullable !== "boolean") fail("INVALID_TYPE", path, "Presence and nullability must be explicit booleans.");
  for (const key of ["minLength", "maxLength"]) {
    if (Object.hasOwn(value, key)) {
      if (value.type !== "string") fail("INVALID_CONSTRAINT", `${path}/${key}`, "Length constraints apply only to strings.");
      integer(value[key], 0, 1000000, `${path}/${key}`);
    }
  }
  for (const key of ["minimum", "maximum"]) {
    if (Object.hasOwn(value, key)) {
      if (value.type !== "int32") fail("INVALID_CONSTRAINT", `${path}/${key}`, "Range constraints apply only to int32.");
      integer(value[key], -2147483648, 2147483647, `${path}/${key}`);
    }
  }
  if ((value.minLength ?? 0) > (value.maxLength ?? 1000000) || (value.minimum ?? -2147483648) > (value.maximum ?? 2147483647)) fail("INVALID_RANGE", path, "Minimum cannot exceed maximum.");
  return { ...value };
}
function tuple(value, fields, path) {
  list(value, path, 1, 16);
  if (value.some((key) => typeof key !== "string" || !fields.has(key))) fail("INVALID_REFERENCE", path, "Key references an unknown field.");
  unique(value, path);
  return [...value];
}
function entity(value, path) {
  record(value, ["name", "table", "fields", "primaryKey"], ["uniqueKeys", "indexes", "foreignKeys"], path);
  name(value.name, MODEL, `${path}/name`, RESERVED_MODELS);
  name(value.table, IDENTIFIER, `${path}/table`);
  const fields = list(value.fields, `${path}/fields`, 1, 256).map((item, i) => field(item, `${path}/fields/${i}`));
  unique(fields.map((item) => item.name), `${path}/fields`);
  unique(fields.map((item) => item.column), `${path}/fields`);
  const byName = new Map(fields.map((item) => [item.name, item]));
  const primaryKey = tuple(value.primaryKey, byName, `${path}/primaryKey`);
  if (primaryKey.some((key) => byName.get(key).nullable || !byName.get(key).required)) fail("INVALID_PRIMARY_KEY", `${path}/primaryKey`, "Primary-key fields must be required and non-nullable.");
  const uniqueKeys = list(Object.hasOwn(value, "uniqueKeys") ? value.uniqueKeys : [], `${path}/uniqueKeys`).map((key, i) => tuple(key, byName, `${path}/uniqueKeys/${i}`));
  const indexes = list(Object.hasOwn(value, "indexes") ? value.indexes : [], `${path}/indexes`).map((key, i) => tuple(key, byName, `${path}/indexes/${i}`));
  unique([primaryKey, ...uniqueKeys].map((key) => JSON.stringify([...key].sort(order))), `${path}/uniqueKeys`);
  unique(indexes.map((key) => JSON.stringify(key)), `${path}/indexes`);
  const foreignKeys = list(Object.hasOwn(value, "foreignKeys") ? value.foreignKeys : [], `${path}/foreignKeys`).map((fk, i) => {
    const at = `${path}/foreignKeys/${i}`;
    record(fk, ["fields", "references"], ["onDelete"], at);
    record(fk.references, ["entity", "fields"], [], `${at}/references`);
    name(fk.references.entity, MODEL, `${at}/references/entity`, RESERVED_MODELS);
    list(fk.references.fields, `${at}/references/fields`, 1, 16);
    for (const item of fk.references.fields) name(item, FIELD, `${at}/references/fields`, RESERVED_FIELDS);
    unique(fk.references.fields, `${at}/references/fields`);
    if (Object.hasOwn(fk, "onDelete") && !DELETE_ACTIONS.has(fk.onDelete)) fail("UNKNOWN_PROPERTY", `${at}/onDelete`, "Unsupported delete policy is not silently ignored.");
    const local = tuple(fk.fields, byName, `${at}/fields`);
    if (local.length !== fk.references.fields.length) fail("INVALID_REFERENCE", at, "Foreign-key arities must match.");
    return {
      fields: local,
      references: { entity: fk.references.entity, fields: [...fk.references.fields] },
      onDelete: fk.onDelete ?? "noAction",
    };
  });
  unique(foreignKeys.map((fk) => JSON.stringify([fk.fields, fk.references])), `${path}/foreignKeys`);
  return { name: value.name, table: value.table, fields: fields.sort((a, b) => order(a.name, b.name)), primaryKey, uniqueKeys: uniqueKeys.sort((a, b) => order(JSON.stringify(a), JSON.stringify(b))), indexes: indexes.sort((a, b) => order(JSON.stringify(a), JSON.stringify(b))), foreignKeys: foreignKeys.sort((a, b) => order(JSON.stringify(a), JSON.stringify(b))) };
}

/** Internal normalization allocates new objects and never freezes/mutates input. */
export function normalizeSchemaIr(input) {
  jsonValue(input, "");
  record(input, ["schemaVersion", "databaseSchema", "entities"], [], "");
  if (input.schemaVersion !== IR_VERSION) fail("UNSUPPORTED_VERSION", "/schemaVersion", "Only ores.schema-ir.v1 is supported.");
  name(input.databaseSchema, IDENTIFIER, "/databaseSchema");
  if (input.databaseSchema.startsWith("pg_") || input.databaseSchema === "information_schema") fail("INVALID_IDENTIFIER", "/databaseSchema", "System schemas are not supported.");
  const entities = list(input.entities, "/entities", 1).map((item, i) => entity(item, `/entities/${i}`));
  unique(entities.map((item) => item.name.toLowerCase()), "/entities");
  unique(entities.map((item) => item.table), "/entities");
  const byName = new Map(entities.map((item) => [item.name, item]));
  entities.forEach((item, i) => item.foreignKeys.forEach((fk, j) => {
    const path = `/entities/${i}/foreignKeys/${j}`;
    const target = byName.get(fk.references.entity);
    if (!target) fail("INVALID_REFERENCE", path, "Foreign-key target entity does not exist.");
    const targetFields = new Map(target.fields.map((f) => [f.name, f]));
    tuple(fk.references.fields, targetFields, `${path}/references/fields`);
    if (![target.primaryKey, ...target.uniqueKeys].some((key) => JSON.stringify(key) === JSON.stringify(fk.references.fields))) fail("INVALID_REFERENCE", path, "Foreign-key target must be an explicitly declared, ordered unique key.");
    const localFields = new Map(item.fields.map((f) => [f.name, f]));
    if (fk.fields.some((key, k) => localFields.get(key).type !== targetFields.get(fk.references.fields[k]).type)) fail("INVALID_REFERENCE", path, "Foreign-key scalar types must match.");
    if (fk.onDelete === "setNull" && fk.fields.some((key) => !localFields.get(key).nullable)) fail("INVALID_REFERENCE", path, "SET NULL requires every local foreign-key field to be nullable.");
  }));
  return { schemaVersion: IR_VERSION, databaseSchema: input.databaseSchema, entities: entities.sort((a, b) => order(a.name, b.name)) };
}

/** An empty diagnostic array means that structural AND relational checks passed. */
export function validateSchemaIr(input) {
  try {
    normalizeSchemaIr(input);
    return Object.freeze([]);
  } catch (error) {
    if (error instanceof IrValidationError) return Object.freeze([error.diagnostic]);
    throw error;
  }
}
