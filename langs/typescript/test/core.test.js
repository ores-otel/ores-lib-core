import test from "node:test"; import assert from "node:assert/strict";
import {DIRECTORY_ADMIN_ROLE, DIRECTORY_REVOCATIONS_EXECUTE_SCOPE, REDACTED, Secret, authorizedDirectoryOrganizations, authorizedOrganizations, classifyIdempotency, normalizeEmailForRevocation, redactRecord, validCorrelationId} from "../src/index.js";
test("redacts credentials", () => assert.deepEqual(redactRecord({accessToken:"x", ok:"y"}), {accessToken:REDACTED, ok:"y"}));
test("secret serialization is redacted", () => assert.equal(JSON.stringify({secret:new Secret("x")}), `{"secret":"${REDACTED}"}`));
test("validates portable ids", () => { assert.equal(validCorrelationId("req-12345678"), true); assert.equal(validCorrelationId("bad space"), false); });
test("normalizes a strict portable email and redacts it", () => {
  assert.equal(normalizeEmailForRevocation("  Alex+Ops@Example.COM\n"), "alex+ops@example.com");
  assert.throws(() => normalizeEmailForRevocation("a..b@example.com"));
  assert.deepEqual(redactRecord({normalizedEmail: "alex@example.com"}), {normalizedEmail: REDACTED});
});
test("authorizes only the requested grant intersection", () => {
  const grants = [{organizationId:"org-b",sessionsRevoke:true},{organizationId:"org-a",sessionsRevoke:false},{organizationId:"org-c",sessionsRevoke:true}];
  assert.deepEqual(authorizedOrganizations(["org-a","org-b","org-unknown"], grants), ["org-b"]);
});
test("replays only identical request digests", () => {
  assert.equal(classifyIdempotency(undefined, new Uint8Array(32).fill(1)), "new");
  assert.equal(classifyIdempotency(new Uint8Array(32).fill(1), new Uint8Array(32).fill(1)), "replay");
  assert.equal(classifyIdempotency(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)), "conflict");
  assert.throws(() => classifyIdempotency(undefined, new Uint8Array(16)));
});
test("directory grants require exact role and scope", () => {
  const grants = [{
    grantId:"20000000-0000-4000-8000-000000000001",
    organizationId:"10000000-0000-4000-8000-000000000001",
    scopes:[DIRECTORY_REVOCATIONS_EXECUTE_SCOPE],
    roles:[DIRECTORY_ADMIN_ROLE],
    grantedAt:"2026-08-11T21:00:00Z",
  }];
  assert.deepEqual(authorizedDirectoryOrganizations(undefined, DIRECTORY_REVOCATIONS_EXECUTE_SCOPE, grants), ["10000000-0000-4000-8000-000000000001"]);
  assert.deepEqual(authorizedDirectoryOrganizations(undefined, "directory.*", grants), []);
  assert.deepEqual(authorizedDirectoryOrganizations(undefined, DIRECTORY_REVOCATIONS_EXECUTE_SCOPE, [{...grants[0], projectIds: ["30000000-0000-4000-8000-000000000001"]}]), []);
});
