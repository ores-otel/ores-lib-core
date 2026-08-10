export declare const REDACTED = "[REDACTED]";
export declare function isSensitiveField(key: string): boolean;
export declare function redactRecord<T extends Record<string, unknown>>(record: T): Record<string, unknown>;
export declare function validCorrelationId(value: unknown): value is string;
export declare class Secret<T> { constructor(value: T); expose<R>(action: (value: T) => R): R; toString(): string; toJSON(): string; }
export interface SecurityLogSink { emit(action: string, outcome: string, reasonCode: string | undefined, fields: Readonly<Record<string, string>>): void; }
