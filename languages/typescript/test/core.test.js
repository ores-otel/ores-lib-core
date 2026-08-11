import test from "node:test"; import assert from "node:assert/strict";
import {REDACTED, Secret, authorizedOrganizations, classifyIdempotency, normalizeEmailForRevocation, redactRecord, validCorrelationId} from "../src/index.js";
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
