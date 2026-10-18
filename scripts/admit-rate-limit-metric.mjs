/**
 * Schema-bound, pure low-cardinality metric admission. No runtime clock,
 * transport, PII logging or implicit high-cardinality fallback.
 * All metric labels must match the current independently-authored contract.
 */
const record = (value) => value !== null && typeof value === "object"
  && !Array.isArray(value) && Object.getPrototypeOf(value) !== null
  ? Object.getPrototypeOf(value) === Object.prototype
  : value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === null;
const canonical = (value) => typeof value === "string" &&
  /^[a-z0-9][a-z0-9._-]*$/.test(value);

const ENUM_BY_SUFFIX = Object.freeze({
  layer: "layer",
  algorithm: "algorithm",
  outcome: "outcome",
  source: "source",
  principal_kind: "principalKind",
  failure_mode: "failureMode",
  retry_bucket: "retryBucket",
});

export function admitRateLimitMetricAttributes(contract, metricKey, attributes, policyIds) {
  if (!record(contract) || contract.schema !== "ores-otel/rate-limit-telemetry/v1"
      || !record(contract.metrics) || !record(contract.attributes)
      || !record(contract.enums) || !record(contract.cardinality)) {
    throw new TypeError("rate-limit telemetry authority is missing or invalid");
  }
  if (!Array.isArray(policyIds) || policyIds.length === 0 || policyIds.length > 64
      || policyIds.some((id) => !canonical(id)
        || new TextEncoder().encode(id).length > contract.cardinality.policyIdMaxUtf8Bytes)
      || new Set(policyIds).size !== policyIds.length) {
    throw new TypeError("policy ID vocabulary must be a bounded, canonical configuration allowlist");
  }
  const metric = Object.hasOwn(contract.metrics, metricKey) ? contract.metrics[metricKey] : null;
  if (!record(metric) || !Array.isArray(metric.allowedAttributes) || !record(attributes)) {
    throw new TypeError("unknown metric or invalid metric labels");
  }
  const allowed = new Set(metric.allowedAttributes);
  const forbidden = new Set([...contract.forbiddenAttributes, ...contract.attributes.traceOrLogOnly]);
  const actual = Object.entries(attributes);
  if (actual.length > allowed.size || actual.length > 12) {
    throw new TypeError("metric label count exceeds bounded metric contract");
  }
  for (const [key, value] of actual) {
    if (!allowed.has(key) || forbidden.has(key)) {
      throw new TypeError("high-cardinality or forbidden metric label");
    }
    if (key === "ores.rate_limit.policy_id") {
      if (!policyIds.includes(value)) throw new TypeError("policy ID is not from configuration vocabulary");
    } else if (key === "ores.rate_limit.observed_only") {
      if (typeof value !== "boolean") throw new TypeError("observed-only must be a boolean");
    } else {
      const suffix = key.replace(/^ores\.rate_limit\./, "");
      const enumName = ENUM_BY_SUFFIX[suffix];
      if (!enumName || !Array.isArray(contract.enums[enumName])
          || !contract.enums[enumName].includes(value)) {
        throw new TypeError("metric label is outside approved bounded vocabulary");
      }
    }
  }
  if (metricKey === "decisions") {
    for (const required of contract.attributes.requiredDecision) {
      if (!Object.hasOwn(attributes, required)) {
        throw new TypeError("required admission decision label is absent");
      }
    }
  }
  // A fresh frozen projection prevents mutable caller-supplied label maps
  // from changing after admission.
  return Object.freeze(Object.fromEntries(actual));
}
