# Rate-limit telemetry semantic convention

All ORE rate-limit implementations emit the versioned event `ores.rate_limit.decision.v1` and use the metric names defined in [`contracts/rate-limit-telemetry-v1.json`](../contracts/rate-limit-telemetry-v1.json).

## Metric boundary

Metric labels are deliberately low cardinality. A decision may label metrics with only:

- a static configuration policy ID;
- enforcement layer and algorithm;
- outcome and implementation source;
- coarse principal kind;
- failure mode, retry bucket, and observe-only flag.

A policy ID is not a route template assembled at runtime, request path, organization ID, tenant ID, user ID, or principal digest. It is a bounded static identifier such as `edge.login.v1` or `service.write.balanced.v1`.

Raw IP addresses, emails, Shared Auth subjects, tenant/user/session IDs, tokens, cookies, authorization headers, Redis keys, cache keys, and full HMAC principal digests are forbidden in metrics, logs, and traces.

## Trace and log correlation

Request and trace IDs remain ordinary bounded correlation fields. A six-byte diagnostic principal fingerprint may appear only in a trace or structured log as 12 lowercase hexadecimal characters plus an ellipsis, for example `abcdef012345…`. It must never be a metric label, cache key, access-control identifier, or unique security principal.

The full opaque HMAC key remains inside the enforcement backend. The short fingerprint is not sufficient for authorization or backend lookup and is redacted by the Rust type's `Debug` implementation.

## Sources and consistency

The `source` field tells operators which consistency boundary made the decision:

- `cloudflare_binding`, `ingress_nginx`, `envoy_local`, `traefik_local`, and `local_memory` are edge/replica/process-local controls;
- `cloudflare_deny_cache` and `redis_deny_cache` are non-authoritative short-circuit caches;
- `redis_authoritative` represents an atomic Redis decision;
- `data_store` represents a transactional business-quota decision.

Dashboards must not aggregate those sources as if they provide identical global accuracy. Outer layers protect capacity; strict billing, entitlement, scarce-resource, and irreversible-write quotas require an authoritative source.

## Failure semantics

A decision records one of `fail_open`, `fail_closed`, `local_fallback`, or `not_applicable`. Backend failures are counted separately with `ores.rate_limit.backend.errors`. Do not represent a backend failure as an ordinary limit denial unless the configured policy is explicitly fail-closed.

`retry_after` observations use milliseconds and the bounded buckets `none`, `lt_1s`, `1s_10s`, `10s_60s`, `1m_5m`, and `gt_5m`. Raw retry values are histogram observations, not labels.

## Formal assurance

`formal/rate-limit-telemetry-assurance.v1.json` declares five security properties:

1. every enum mapping is exhaustive;
2. raw identity does not influence emitted metric labels;
3. the allowed metric label set is closed and low-cardinality;
4. trace-only fields cannot become metric labels;
5. every retry duration maps to exactly one retry bucket.

The contract checker and Rust refinement tests execute these properties in CI. The rate-limit algorithm/state safety properties remain model-checked with TLC in `ores-rate-limit/ores-rl-lib-core`.
