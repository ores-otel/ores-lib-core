export interface SchemaDiagnostic {
  readonly code: string;
  /** Structural JSON path. Input values are never reproduced in diagnostics. */
  readonly path: string;
  readonly message: string;
}
export interface SchemaArtifacts {
  /** Draft 2020-12 bundle with local references and one definition per model. */
  readonly jsonSchema: string;
  /** Shape declarations only; consumers still need runtime validation. */
  readonly typescript: string;
  /** Desired-state SQL only; this library never executes it. */
  readonly postgres: string;
}
export type SchemaCompileResult =
  | Readonly<{ ok: true; artifacts: Readonly<SchemaArtifacts> }>
  | Readonly<{ ok: false; diagnostics: readonly SchemaDiagnostic[] }>;
/**
 * Validate ores.schema-ir.v1 JSON data and emit all three targets or diagnostics.
 * For authoring types use ores-interfaces/src/schema-ir.d.ts. `unknown` here is
 * intentional: the runtime boundary must validate even statically typed input.
 */
export function compileSchema(input: unknown): SchemaCompileResult;
