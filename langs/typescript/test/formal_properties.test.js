import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  REDACTED,
  Secret,
  isSensitiveField,
  redactRecord,
} from "../src/index.js";

const assurance = JSON.parse(
  await readFile(new URL("../../../formal/redaction-assurance.v1.json", import.meta.url), "utf8"),
);

function variants(root, prefix) {
  return [
    `${prefix}${root}`,
    `${prefix}${root.toUpperCase()}`,
    `${prefix}${root.replaceAll("_", "-")}`,
    `  ${prefix}${root.replaceAll("_", ".")}  `,
  ];
}

test("normalization-closure and sensitive-value-noninterference", () => {
  for (const root of assurance.domain.sensitiveRoots) {
    for (const prefix of assurance.domain.prefixes) {
      for (const key of variants(root, prefix)) {
        assert.equal(isSensitiveField(key), true, key);
        const left = redactRecord({ [key]: "secret-alpha", message: "safe" });
        const right = redactRecord({ [key]: "secret-bravo", message: "safe" });
        assert.deepEqual(left, right, key);
        assert.equal(left[key], REDACTED, key);
      }
    }
  }
});

test("idempotence and safe-field-preservation", () => {
  const input = Object.fromEntries([
    ...assurance.domain.sensitiveRoots.map((key) => [key, `value:${key}`]),
    ...assurance.domain.safeFields.map((key) => [key, `value:${key}`]),
  ]);
  const once = redactRecord(input);
  const twice = redactRecord(once);
  assert.deepEqual(twice, once);
  for (const key of assurance.domain.safeFields) {
    assert.equal(isSensitiveField(key), false, key);
    assert.equal(once[key], input[key], key);
  }
});

test("secret-representation-opacity", () => {
  const secret = new Secret("must-not-escape");
  assert.equal(String(secret), REDACTED);
  assert.equal(JSON.stringify({ secret }), `{"secret":"${REDACTED}"}`);
  assert.equal(secret.expose((value) => value.length), "must-not-escape".length);
});
