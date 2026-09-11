/** Node-only build-time entrypoint; intentionally not re-exported by the browser-safe root. */
export declare const IR_VERSION: "ores.schema-ir.v1";
export interface SchemaDiagnostic {
  readonly code: string;
  /** JSON Pointer into the input; no input values are included in diagnostic messages. */
  readonly path: string;
  readonly message: string;
}
export interface CompilationSuccess {
  readonly ok: true;
  readonly irSha256: string;
  /** UTF-8 artifacts. The caller owns any filesystem/database side effects. */
  readonly files: Readonly<Record<string, string>>;
}
export interface CompilationFailure {
  readonly ok: false;
  readonly errors: readonly SchemaDiagnostic[];
}
export declare function validateSchemaIr(input: unknown): readonly SchemaDiagnostic[];
export declare function compileSchemaIr(input: unknown): CompilationSuccess | CompilationFailure;
