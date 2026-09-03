use std::fmt;

pub const DECISION_EVENT_NAME: &str = "ores.rate_limit.decision.v1";
pub const DECISIONS_METRIC_NAME: &str = "ores.rate_limit.decisions";
pub const BACKEND_ERRORS_METRIC_NAME: &str = "ores.rate_limit.backend.errors";
pub const CACHE_ENTRIES_METRIC_NAME: &str = "ores.rate_limit.cache.entries";
pub const RETRY_AFTER_METRIC_NAME: &str = "ores.rate_limit.retry_after";
pub const POLICY_ID_MAX_UTF8_BYTES: usize = 128;
pub const PRINCIPAL_FINGERPRINT_HEX_BYTES: usize = 6;

pub const POLICY_ID_ATTRIBUTE: &str = "ores.rate_limit.policy_id";
pub const LAYER_ATTRIBUTE: &str = "ores.rate_limit.layer";
pub const ALGORITHM_ATTRIBUTE: &str = "ores.rate_limit.algorithm";
pub const OUTCOME_ATTRIBUTE: &str = "ores.rate_limit.outcome";
pub const SOURCE_ATTRIBUTE: &str = "ores.rate_limit.source";
pub const PRINCIPAL_KIND_ATTRIBUTE: &str = "ores.rate_limit.principal_kind";
pub const FAILURE_MODE_ATTRIBUTE: &str = "ores.rate_limit.failure_mode";
pub const RETRY_BUCKET_ATTRIBUTE: &str = "ores.rate_limit.retry_bucket";
pub const OBSERVED_ONLY_ATTRIBUTE: &str = "ores.rate_limit.observed_only";
pub const PRINCIPAL_FINGERPRINT_ATTRIBUTE: &str = "ores.rate_limit.principal_fingerprint";

pub const METRIC_ATTRIBUTES: &[&str] = &[
    POLICY_ID_ATTRIBUTE,
    LAYER_ATTRIBUTE,
    ALGORITHM_ATTRIBUTE,
    OUTCOME_ATTRIBUTE,
    SOURCE_ATTRIBUTE,
    PRINCIPAL_KIND_ATTRIBUTE,
    FAILURE_MODE_ATTRIBUTE,
    RETRY_BUCKET_ATTRIBUTE,
    OBSERVED_ONLY_ATTRIBUTE,
];

pub const TRACE_OR_LOG_ONLY_ATTRIBUTES: &[&str] = &[
    PRINCIPAL_FINGERPRINT_ATTRIBUTE,
    "http.request_id",
    "trace_id",
];

pub const FORBIDDEN_ATTRIBUTE_ROOTS: &[&str] = &[
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
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layer {
    Edge,
    LoadBalancer,
    Service,
    Authentication,
    DataStore,
}

impl Layer {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Edge => "edge",
            Self::LoadBalancer => "load_balancer",
            Self::Service => "service",
            Self::Authentication => "authentication",
            Self::DataStore => "data_store",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    TokenBucket,
    FixedWindow,
    SlidingWindow,
    Concurrency,
}

impl Algorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TokenBucket => "token_bucket",
            Self::FixedWindow => "fixed_window",
            Self::SlidingWindow => "sliding_window",
            Self::Concurrency => "concurrency",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Allow,
    Deny,
    ObserveOnlyOverage,
    Bypass,
    DegradedAllow,
}

impl Outcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::ObserveOnlyOverage => "observe_only_overage",
            Self::Bypass => "bypass",
            Self::DegradedAllow => "degraded_allow",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    CloudflareBinding,
    CloudflareDenyCache,
    IngressNginx,
    EnvoyLocal,
    TraefikLocal,
    LocalMemory,
    RedisAuthoritative,
    RedisDenyCache,
    DataStore,
}

impl Source {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CloudflareBinding => "cloudflare_binding",
            Self::CloudflareDenyCache => "cloudflare_deny_cache",
            Self::IngressNginx => "ingress_nginx",
            Self::EnvoyLocal => "envoy_local",
            Self::TraefikLocal => "traefik_local",
            Self::LocalMemory => "local_memory",
            Self::RedisAuthoritative => "redis_authoritative",
            Self::RedisDenyCache => "redis_deny_cache",
            Self::DataStore => "data_store",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalKind {
    AnonymousIp,
    AuthenticatedSubject,
    ServiceIdentity,
    Tenant,
    Composite,
}

impl PrincipalKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnonymousIp => "anonymous_ip",
            Self::AuthenticatedSubject => "authenticated_subject",
            Self::ServiceIdentity => "service_identity",
            Self::Tenant => "tenant",
            Self::Composite => "composite",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureMode {
    FailOpen,
    FailClosed,
    LocalFallback,
    NotApplicable,
}

impl FailureMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailOpen => "fail_open",
            Self::FailClosed => "fail_closed",
            Self::LocalFallback => "local_fallback",
            Self::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryBucket {
    None,
    LessThanOneSecond,
    OneToTenSeconds,
    TenToSixtySeconds,
    OneToFiveMinutes,
    GreaterThanFiveMinutes,
}

impl RetryBucket {
    pub const fn from_millis(retry_after_ms: Option<u64>) -> Self {
        match retry_after_ms {
            None => Self::None,
            Some(0..=999) => Self::LessThanOneSecond,
            Some(1_000..=9_999) => Self::OneToTenSeconds,
            Some(10_000..=59_999) => Self::TenToSixtySeconds,
            Some(60_000..=300_000) => Self::OneToFiveMinutes,
            Some(300_001..) => Self::GreaterThanFiveMinutes,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::LessThanOneSecond => "lt_1s",
            Self::OneToTenSeconds => "1s_10s",
            Self::TenToSixtySeconds => "10s_60s",
            Self::OneToFiveMinutes => "1m_5m",
            Self::GreaterThanFiveMinutes => "gt_5m",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryError {
    EmptyPolicyId,
    PolicyIdTooLong,
    InvalidPolicyId,
    UnknownMetricAttribute,
    TraceOnlyMetricAttribute,
    SensitiveMetricAttribute,
    InvalidPrincipalFingerprint,
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPolicyId => formatter.write_str("rate-limit policy ID must not be empty"),
            Self::PolicyIdTooLong => {
                formatter.write_str("rate-limit policy ID exceeds 128 UTF-8 bytes")
            }
            Self::InvalidPolicyId => formatter.write_str(
                "rate-limit policy ID may contain only ASCII letters, digits, '.', ':', '_', and '-'",
            ),
            Self::UnknownMetricAttribute => {
                formatter.write_str("unknown rate-limit metric attribute")
            }
            Self::TraceOnlyMetricAttribute => {
                formatter.write_str("trace/log-only rate-limit attribute cannot label a metric")
            }
            Self::SensitiveMetricAttribute => {
                formatter.write_str("identity- or secret-bearing attribute cannot label a metric")
            }
            Self::InvalidPrincipalFingerprint => formatter.write_str(
                "principal fingerprint must contain 12 lowercase hex characters and one ellipsis",
            ),
        }
    }
}

impl std::error::Error for TelemetryError {}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PolicyId<'a>(&'a str);

impl<'a> PolicyId<'a> {
    pub fn new(value: &'a str) -> Result<Self, TelemetryError> {
        if value.is_empty() {
            return Err(TelemetryError::EmptyPolicyId);
        }
        if value.len() > POLICY_ID_MAX_UTF8_BYTES {
            return Err(TelemetryError::PolicyIdTooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-'))
        {
            return Err(TelemetryError::InvalidPolicyId);
        }
        Ok(Self(value))
    }

    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

impl fmt::Debug for PolicyId<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("PolicyId").field(&self.0).finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PrincipalFingerprint<'a>(&'a str);

impl<'a> PrincipalFingerprint<'a> {
    pub fn new(value: &'a str) -> Result<Self, TelemetryError> {
        let Some(hex) = value.strip_suffix('…') else {
            return Err(TelemetryError::InvalidPrincipalFingerprint);
        };
        if hex.len() != PRINCIPAL_FINGERPRINT_HEX_BYTES * 2
            || !hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(TelemetryError::InvalidPrincipalFingerprint);
        }
        Ok(Self(value))
    }

    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

impl fmt::Debug for PrincipalFingerprint<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrincipalFingerprint(<diagnostic>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitMetricLabels<'a> {
    pub policy_id: PolicyId<'a>,
    pub layer: Layer,
    pub algorithm: Algorithm,
    pub outcome: Outcome,
    pub source: Source,
    pub principal_kind: PrincipalKind,
    pub failure_mode: FailureMode,
    pub retry_bucket: RetryBucket,
    pub observed_only: bool,
}

pub fn validate_metric_attribute(name: &str) -> Result<(), TelemetryError> {
    if METRIC_ATTRIBUTES.contains(&name) {
        return Ok(());
    }
    if TRACE_OR_LOG_ONLY_ATTRIBUTES.contains(&name) {
        return Err(TelemetryError::TraceOnlyMetricAttribute);
    }
    if is_forbidden_attribute(name) {
        return Err(TelemetryError::SensitiveMetricAttribute);
    }
    Err(TelemetryError::UnknownMetricAttribute)
}

pub fn is_forbidden_attribute(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase().replace('-', "_");
    let leaf = normalized
        .rsplit(|character| matches!(character, '.' | '/' | ':'))
        .next()
        .unwrap_or(normalized.as_str());
    FORBIDDEN_ATTRIBUTE_ROOTS.iter().any(|forbidden| {
        leaf == *forbidden
            || leaf.ends_with(&format!("_{forbidden}"))
            || normalized == *forbidden
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_buckets_cover_boundaries() {
        assert_eq!(RetryBucket::from_millis(None), RetryBucket::None);
        assert_eq!(
            RetryBucket::from_millis(Some(999)),
            RetryBucket::LessThanOneSecond
        );
        assert_eq!(
            RetryBucket::from_millis(Some(1_000)),
            RetryBucket::OneToTenSeconds
        );
        assert_eq!(
            RetryBucket::from_millis(Some(10_000)),
            RetryBucket::TenToSixtySeconds
        );
        assert_eq!(
            RetryBucket::from_millis(Some(60_000)),
            RetryBucket::OneToFiveMinutes
        );
        assert_eq!(
            RetryBucket::from_millis(Some(300_001)),
            RetryBucket::GreaterThanFiveMinutes
        );
    }

    #[test]
    fn policy_ids_are_static_and_bounded() {
        assert_eq!(
            PolicyId::new("edge.login.v1").unwrap().as_str(),
            "edge.login.v1"
        );
        assert_eq!(PolicyId::new(""), Err(TelemetryError::EmptyPolicyId));
        assert_eq!(
            PolicyId::new("GET /users/0199e7bd-7c7d-7000-8000-000000000001"),
            Err(TelemetryError::InvalidPolicyId)
        );
        let too_long = "a".repeat(POLICY_ID_MAX_UTF8_BYTES + 1);
        assert_eq!(
            PolicyId::new(&too_long),
            Err(TelemetryError::PolicyIdTooLong)
        );
    }

    #[test]
    fn metric_labels_reject_identity_and_trace_fields() {
        assert_eq!(validate_metric_attribute(POLICY_ID_ATTRIBUTE), Ok(()));
        assert_eq!(
            validate_metric_attribute(PRINCIPAL_FINGERPRINT_ATTRIBUTE),
            Err(TelemetryError::TraceOnlyMetricAttribute)
        );
        for attribute in [
            "client_ip",
            "enduser.email",
            "auth.subject",
            "redis_key",
            "http.request.header.authorization",
        ] {
            assert_eq!(
                validate_metric_attribute(attribute),
                Err(TelemetryError::SensitiveMetricAttribute),
                "{attribute} was not rejected"
            );
        }
    }

    #[test]
    fn diagnostic_fingerprint_is_bounded_and_redacted_in_debug() {
        let value = PrincipalFingerprint::new("abcdef012345…").unwrap();
        assert_eq!(value.as_str(), "abcdef012345…");
        assert!(!format!("{value:?}").contains("abcdef012345"));
        assert_eq!(
            PrincipalFingerprint::new("ABCDEF012345…"),
            Err(TelemetryError::InvalidPrincipalFingerprint)
        );
    }
}
