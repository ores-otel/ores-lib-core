// Generated from ores.schema-ir.v1; do not edit.
// These are shape declarations, not runtime validators (UUID/length/int32 constraints remain in JSON Schema).
// Enable strictNullChecks and exactOptionalPropertyTypes in consumers.

export interface Member {
  readonly "displayName": string | null;
  readonly "enabled": boolean;
  readonly "id": string;
  readonly "organizationId": string;
  readonly "rank": number;
}

export interface MemberPatch {
  readonly "displayName"?: string | null;
  readonly "enabled"?: boolean;
}

export interface Organization {
  readonly "id": string;
  readonly "name": string;
}
