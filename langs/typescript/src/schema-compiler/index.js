import { validate } from "./validate.js";
import { emitJsonSchema, emitPostgres, emitTypescript } from "./emit.js";

/** Compile a JSON data document without I/O, global mutation, or partial output. */
export function compileSchema(input) {
  const result = validate(input);
  if (result.diagnostics.length !== 0) {
    return Object.freeze({
      ok: false,
      diagnostics: Object.freeze(result.diagnostics.map((diagnostic) => Object.freeze(diagnostic))),
    });
  }
  return Object.freeze({
    ok: true,
    artifacts: Object.freeze({
      jsonSchema: emitJsonSchema(result.value),
      typescript: emitTypescript(result.value),
      postgres: emitPostgres(result.value),
    }),
  });
}
