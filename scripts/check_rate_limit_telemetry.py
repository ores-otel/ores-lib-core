#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts/rate-limit-telemetry-v1.json"
SCHEMA_PATH = ROOT / "contracts/rate-limit-telemetry-v1.schema.json"
ASSURANCE_PATH = ROOT / "formal/rate-limit-telemetry-assurance.v1.json"

EXPECTED_ENUMS = {
    "layer": ["edge", "load_balancer", "service", "authentication", "data_store"],
    "algorithm": ["token_bucket", "fixed_window", "sliding_window", "concurrency"],
    "outcome": ["allow", "deny", "observe_only_overage", "bypass", "degraded_allow"],
    "source": [
        "cloudflare_binding",
        "cloudflare_deny_cache",
        "ingress_nginx",
        "envoy_local",
        "traefik_local",
        "local_memory",
        "redis_authoritative",
        "redis_deny_cache",
        "data_store",
    ],
    "principalKind": [
        "anonymous_ip",
        "authenticated_subject",
        "service_identity",
        "tenant",
        "composite",
    ],
    "failureMode": ["fail_open", "fail_closed", "local_fallback", "not_applicable"],
    "retryBucket": ["none", "lt_1s", "1s_10s", "10s_60s", "1m_5m", "gt_5m"],
}
EXPECTED_PROPERTIES = {
    "enum-exhaustiveness",
    "identity-noninterference",
    "low-cardinality-closure",
    "metric-trace-separation",
    "retry-bucket-totality",
}
EXPECTED_FORBIDDEN = {
    "authorization",
    "cookie",
    "email",
    "ip",
    "client_ip",
    "user_id",
    "tenant_id",
    "session_id",
    "subject",
    "token",
    "principal",
    "principal_digest",
    "rate_limit_key",
    "redis_key",
    "cache_key",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path} must contain an object")
    return value


def string_set(value: object, label: str) -> set[str]:
    require(isinstance(value, list), f"{label} must be a list")
    require(all(isinstance(item, str) for item in value), f"{label} must contain strings")
    result = set(value)
    require(len(result) == len(value), f"{label} must contain unique values")
    return result


def main() -> int:
    contract = load_object(CONTRACT_PATH)
    schema = load_object(SCHEMA_PATH)
    assurance = load_object(ASSURANCE_PATH)

    require(
        schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema",
        "telemetry schema must use JSON Schema 2020-12",
    )
    require(schema.get("additionalProperties") is False, "telemetry schema must be closed")
    require(
        contract.get("$schema") == "./rate-limit-telemetry-v1.schema.json",
        "contract schema reference drifted",
    )
    require(
        contract.get("schema") == "ores-otel/rate-limit-telemetry/v1",
        "contract identity drifted",
    )
    require(contract.get("eventName") == "ores.rate_limit.decision.v1", "event name drifted")

    enums = contract.get("enums")
    require(isinstance(enums, dict), "enums must be an object")
    require(enums == EXPECTED_ENUMS, "closed rate-limit enum set drifted")

    attributes = contract.get("attributes")
    require(isinstance(attributes, dict), "attributes must be an object")
    required = string_set(attributes.get("requiredDecision"), "requiredDecision")
    optional = string_set(attributes.get("optionalDecision"), "optionalDecision")
    trace_only = string_set(attributes.get("traceOrLogOnly"), "traceOrLogOnly")
    metric_allowed = required | optional
    require(not (metric_allowed & trace_only), "metric and trace-only attributes overlap")
    require(
        "ores.rate_limit.principal_fingerprint" in trace_only,
        "diagnostic fingerprint must remain trace/log only",
    )

    forbidden = string_set(contract.get("forbiddenAttributes"), "forbiddenAttributes")
    require(forbidden == EXPECTED_FORBIDDEN, "forbidden identity/secret roots drifted")

    metrics = contract.get("metrics")
    require(isinstance(metrics, dict), "metrics must be an object")
    require(
        set(metrics) == {"decisions", "backendErrors", "cacheEntries", "retryAfter"},
        "metric set drifted",
    )
    for metric_name, metric in metrics.items():
        require(isinstance(metric, dict), f"{metric_name} must be an object")
        allowed = string_set(metric.get("allowedAttributes"), f"{metric_name}.allowedAttributes")
        require(allowed <= metric_allowed, f"{metric_name} uses an undeclared metric attribute")
        require(not (allowed & trace_only), f"{metric_name} leaks a trace-only attribute")
        normalized = {name.rsplit(".", 1)[-1] for name in allowed}
        require(not (normalized & forbidden), f"{metric_name} permits identity/secret labels")

    cardinality = contract.get("cardinality")
    require(isinstance(cardinality, dict), "cardinality must be an object")
    require(cardinality.get("policyIdIsStaticConfiguration") is True, "policy IDs must be static")
    require(cardinality.get("dynamicRouteLabelsAllowed") is False, "dynamic routes are forbidden")
    require(
        cardinality.get("principalFingerprintAllowedInMetrics") is False,
        "fingerprints are forbidden in metric labels",
    )
    require(
        cardinality.get("principalFingerprintPattern") == "^[0-9a-f]{12}…$",
        "fingerprint shape drifted",
    )
    require(cardinality.get("policyIdMaxUtf8Bytes") == 128, "policy ID bound drifted")

    require(
        assurance.get("schema") == "ores-lib-core/rate-limit-telemetry-assurance/v1",
        "assurance identity drifted",
    )
    require(assurance.get("subject") == "rate-limit-telemetry", "assurance subject drifted")
    require(assurance.get("criticality") == "security", "assurance must remain security critical")
    properties = string_set(assurance.get("properties"), "assurance.properties")
    require(properties == EXPECTED_PROPERTIES, "formal property set is incomplete")

    domain = assurance.get("domain")
    require(isinstance(domain, dict), "assurance domain must be an object")
    require(domain.get("metricIdentityAttributesAllowed") is False, "metric identity labels enabled")
    require(domain.get("dynamicRouteLabelsAllowed") is False, "dynamic route labels enabled")
    require(domain.get("rawPrincipalMaterialAllowed") is False, "raw principals enabled")
    require(domain.get("traceFingerprintBytes") == 6, "fingerprint byte bound drifted")
    require(domain.get("policyIdMaxUtf8Bytes") == 128, "assurance policy bound drifted")

    refinements = assurance.get("refinements")
    require(isinstance(refinements, dict), "assurance refinements must be an object")
    require(set(refinements) == {"contract", "rust"}, "contract and Rust refinements are required")
    for name, refinement in refinements.items():
        require(isinstance(refinement, dict), f"{name} refinement must be an object")
        require(set(refinement) == {"source", "check"}, f"{name} refinement must be closed")
        require((ROOT / str(refinement["source"])).is_file(), f"missing {name} source")
        require((ROOT / str(refinement["check"])).is_file(), f"missing {name} check")

    print(
        "rate-limit telemetry assurance valid: "
        f"metrics={len(metrics)} enums={len(enums)} properties={len(properties)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
