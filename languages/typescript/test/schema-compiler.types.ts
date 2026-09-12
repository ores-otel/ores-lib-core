import { compileSchema } from "../src/schema-compiler/index.js";
import type { Member, MemberPatch, Organization } from "./fixtures/schema-compiler/expected.js";

const result = compileSchema({ version: "ores.schema-ir.v1", models: [] });
if (result.ok) {
  const sql: string = result.artifacts.postgres;
  void sql;
  // @ts-expect-error Successful compilation has no diagnostic branch.
  result.diagnostics;
  // @ts-expect-error Published artifacts are immutable.
  result.artifacts.postgres = "mutated";
} else {
  const code: string | undefined = result.diagnostics[0]?.code;
  void code;
  // @ts-expect-error Failed compilation has no partial artifacts.
  result.artifacts;
  // @ts-expect-error Diagnostics are immutable.
  result.diagnostics.push({ code: "x", path: "$", message: "x" });
}

const organization: Organization = { id: "00000000-0000-0000-0000-000000000001", name: "Example" };
const member: Member = { id: organization.id, organizationId: organization.id, displayName: null, enabled: true, rank: 0 };
const emptyPatch: MemberPatch = {};
const nullablePatch: MemberPatch = { displayName: null };
// @ts-expect-error Presence and nullability are independent: row displayName is required.
const missing: Member = { id: organization.id, organizationId: organization.id, enabled: true, rank: 0 };
// @ts-expect-error An absent property is not a present undefined value under exactOptionalPropertyTypes.
const undefinedPatch: MemberPatch = { displayName: undefined };
// @ts-expect-error The optional boolean is not nullable.
const nullBoolean: MemberPatch = { enabled: null };
// @ts-expect-error Generated properties are readonly.
member.rank = 1;
void [member, emptyPatch, nullablePatch, missing, undefinedPatch, nullBoolean];
