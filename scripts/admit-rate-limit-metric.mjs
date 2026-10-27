/**
 * Schema-bound, pure low-cardinality metric admission. No runtime clock,
 * transport, PII logging or implicit high-cardinality fallback.
 * All metric labels must match the current independently-authored contract.
 */
const record = (value) => value !== null && typeof value === "object"
  && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));
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
const EXPECTED_ENUMS = Object.freeze({
  layer: Object.freeze(["edge", "load_balancer", "service", "authentication", "data_store"]),
  algorithm: Object.freeze(["token_bucket", "fixed_window", "sliding_window", "concurrency"]),
  outcome: Object.freeze(["allow", "deny", "observe_only_overage", "bypass", "degraded_allow"]),
  source: Object.freeze([
    "cloudflare_binding", "cloudflare_deny_cache", "ingress_nginx", "envoy_local",
    "traefik_local", "local_memory", "redis_authoritative", "redis_deny_cache", "data_store",
  ]),
  principalKind: Object.freeze([
    "anonymous_ip", "authenticated_subject", "service_identity", "tenant", "composite",
  ]),
  failureMode: Object.freeze(["fail_open", "fail_closed", "local_fallback", "not_applicable"]),
  retryBucket: Object.freeze(["none", "lt_1s", "1s_10s", "10s_60s", "1m_5m", "gt_5m"]),
});

// A mutable or spoofed "authority" object must not relax our fixed, finite
// attribute vocabulary. This is a v1-only guard, not a replacement for the
// independently-authored JSON Schema / peer-authority checks.
const REQUIRED_DECISION = Object.freeze([
  "ores.rate_limit.policy_id",
  "ores.rate_limit.layer",
  "ores.rate_limit.algorithm",
  "ores.rate_limit.outcome",
  "ores.rate_limit.source",
  "ores.rate_limit.principal_kind",
]);
const ALLOWED_ATTRIBUTE_NAMES = new Set([
  ...REQUIRED_DECISION,
  "ores.rate_limit.failure_mode",
  "ores.rate_limit.retry_bucket",
  "ores.rate_limit.observed_only",
]);

function trustedV1Contract(contract) {
  const card = contract.cardinality;
  const attr = contract.attributes;
  return card.policyIdIsStaticConfiguration === true
    && card.dynamicRouteLabelsAllowed === false
    && card.principalFingerprintAllowedInMetrics === false
    && card.policyIdMaxUtf8Bytes === 128
    && Array.isArray(contract.forbiddenAttributes)
    && ["authorization", "cookie", "email", "ip", "client_ip", "user_id",
      "tenant_id", "session_id", "subject", "token", "principal", "principal_digest",
      "rate_limit_key", "redis_key", "cache_key"].every((name) =>
      contract.forbiddenAttributes.includes(name))
    && Array.isArray(attr.traceOrLogOnly)
    && attr.traceOrLogOnly.includes("ores.rate_limit.principal_fingerprint")
    && attr.traceOrLogOnly.includes("trace_id")
    && attr.traceOrLogOnly.includes("http.request_id")
    && Array.isArray(attr.requiredDecision)
    && REQUIRED_DECISION.length === attr.requiredDecision.length
    && REQUIRED_DECISION.every((name) => attr.requiredDecision.includes(name))
    && Object.entries(EXPECTED_ENUMS).every(([name, expected]) =>
      Array.isArray(contract.enums[name])
        && expected.length === contract.enums[name].length
        && expected.every((value, index) => contract.enums[name][index] === value))
    && ["decisions", "backendErrors", "cacheEntries", "retryAfter"].every(
      (name) => record(contract.metrics[name])
        && Array.isArray(contract.metrics[name].allowedAttributes)
        && contract.metrics[name].allowedAttributes.every((label) =>
          ALLOWED_ATTRIBUTE_NAMES.has(label))
    );
}

export function admitRateLimitMetricAttributes(contract, metricKey, attributes, policyIds) {
  if (!record(contract) || contract.schema !== "ores-otel/rate-limit-telemetry/v1"
      || !record(contract.metrics) || !record(contract.attributes)
      || !record(contract.enums) || !record(contract.cardinality)) {
    throw new TypeError("rate-limit telemetry authority is missing or invalid");
  }
  if (!trustedV1Contract(contract)) {
    throw new TypeError("rate-limit telemetry contract violates fixed v1 privacy constraints");
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
