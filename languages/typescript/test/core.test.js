import test from "node:test"; import assert from "node:assert/strict";
import {REDACTED, Secret, redactRecord, validCorrelationId} from "../src/index.js";
test("redacts credentials", () => assert.deepEqual(redactRecord({accessToken:"x", ok:"y"}), {accessToken:REDACTED, ok:"y"}));
test("secret serialization is redacted", () => assert.equal(JSON.stringify({secret:new Secret("x")}), `{"secret":"${REDACTED}"}`));
test("validates portable ids", () => { assert.equal(validCorrelationId("req-12345678"), true); assert.equal(validCorrelationId("bad space"), false); });
