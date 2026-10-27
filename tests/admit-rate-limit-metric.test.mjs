import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { admitRateLimitMetricAttributes as admit } from "../scripts/admit-rate-limit-metric.mjs";

const authority = JSON.parse(readFileSync(new URL("../contracts/rate-limit-telemetry-v1.json", import.meta.url)));
const policyIds = ["login-free", "api-paid"];
const decision = Object.freeze({
  "ores.rate_limit.policy_id": "login-free",
  "ores.rate_limit.layer": "authentication",
  "ores.rate_limit.algorithm": "token_bucket",
  "ores.rate_limit.outcome": "deny",
  "ores.rate_limit.source": "redis_authoritative",
  "ores.rate_limit.principal_kind": "authenticated_subject",
});
const reject = (labels, policies = policyIds, metric = "decisions") =>
  assert.throws(() => admit(authority, metric, labels, policies), TypeError);

test("accepts bounded labels and freezes defensive output copy", () => {
  const labels = { ...decision };
  const result = admit(authority, "decisions", labels, policyIds);
  assert.deepEqual(result, labels);
  assert.ok(Object.isFrozen(result));
  labels["ores.rate_limit.outcome"] = "allow";
  assert.equal(result["ores.rate_limit.outcome"], "deny");
});
test("forbids raw PII and trace identifiers in every metric", () => {
  for (const key of [
    "email", "tenant_id", "redis_key", "principal_digest",
    "ores.rate_limit.principal_fingerprint", "trace_id", "http.request_id",
  ]) reject({ ...decision, [key]: "PII" });
});
test("refuses unbounded policy IDs and malicious metric labels", () => {
  reject({ ...decision, "ores.rate_limit.policy_id": "account-actual-user-id" });
  reject(decision, []);
  reject(decision, [...policyIds, policyIds[0]]);
  reject({ ...decision, "ores.rate_limit.outcome": "tenant-123" });
  reject({ ...decision, "ores.rate_limit.retry_bucket": "453123milliseconds" });
  reject({ ...decision, "ores.rate_limit.observed_only": "false" });
});
test("requires core decision labels and rejects metric-specific label drift", () => {
  const missing = { ...decision };
  delete missing["ores.rate_limit.layer"];
  reject(missing);
  reject(decision, policyIds, "backendErrors");
  reject(decision, policyIds, "unknownMetric");
  const backendLabels = {
    "ores.rate_limit.layer": "service",
    "ores.rate_limit.source": "redis_authoritative",
    "ores.rate_limit.failure_mode": "fail_closed",
  };
  assert.deepEqual(admit(authority, "backendErrors", backendLabels, policyIds), backendLabels);
});
test("metric runtime fails closed on corrupted contract authority", () => {
  reject(decision, policyIds, "constructor");
  assert.throws(() => admit({}, "decisions", decision, policyIds), TypeError);
});

test("malformed v1 contract cannot widen metric privacy or policy cardinality", () => {
  const modify = (key, value) => {
    const c = structuredClone(authority);
    Object.assign(c.cardinality, { [key]: value });
    assert.throws(() => admit(c, "decisions", decision, policyIds), TypeError);
  };
  modify("policyIdMaxUtf8Bytes", 9000);
  modify("policyIdIsStaticConfiguration", false);
  modify("dynamicRouteLabelsAllowed", true);
  modify("principalFingerprintAllowedInMetrics", true);

  const relaxed = structuredClone(authority);
  relaxed.attributes.requiredDecision = [];
  assert.throws(() => admit(relaxed, "decisions", decision, policyIds), TypeError);

  const injected = structuredClone(authority);
  injected.metrics.decisions.allowedAttributes.push("ores.rate_limit.user_id");
  assert.throws(() => admit(injected, "decisions", decision, policyIds), TypeError);

  const removedForbidden = structuredClone(authority);
  removedForbidden.forbiddenAttributes = ["token"];
  assert.throws(() => admit(removedForbidden, "decisions", decision, policyIds), TypeError);

  const widenedEnum = structuredClone(authority);
  widenedEnum.enums.outcome.push("tenant-specific-outcome");
  const widenedDecision = {...decision, "ores.rate_limit.outcome": "tenant-specific-outcome"};
  assert.throws(() => admit(widenedEnum, "decisions", widenedDecision, policyIds), TypeError);
});
test("rejects inherited prototype-carrying labels rather than trusting their appearance", () => {
  const inherited = Object.create({ "ores.rate_limit.outcome": "deny" });
  Object.assign(inherited, decision);
  assert.throws(() => admit(authority, "decisions", inherited, policyIds), TypeError);
});
