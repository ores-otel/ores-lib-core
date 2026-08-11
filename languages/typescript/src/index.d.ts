export declare const REDACTED = "[REDACTED]";
export declare function isSensitiveField(key: string): boolean;
export declare function redactRecord<T extends Record<string, unknown>>(record: T): Record<string, unknown>;
export declare function validCorrelationId(value: unknown): value is string;
export declare class Secret<T> { constructor(value: T); expose<R>(action: (value: T) => R): R; toString(): string; toJSON(): string; }
export interface SecurityLogSink { emit(action: string, outcome: string, reasonCode: string | undefined, fields: Readonly<Record<string, string>>): void; }
export declare function normalizeEmailForRevocation(value: string): string;
export interface RevocationGrant { organizationId: string; sessionsRevoke: boolean; }
/** Sorted, de-duplicated authorized intersection. Rejected IDs must never be disclosed. */
export declare function authorizedOrganizations(requested: readonly string[] | undefined, grants: readonly RevocationGrant[]): string[];
export type IdempotencyDisposition = "new" | "replay" | "conflict";
/** Both digest arrays must contain exactly 32 bytes. */
export declare function classifyIdempotency(existingRequestDigest: Uint8Array | undefined, incomingRequestDigest: Uint8Array): IdempotencyDisposition;
export interface EmailLookupHmac { readonly keyId: string; derive(normalizedEmail: string): Promise<Uint8Array> | Uint8Array; }
