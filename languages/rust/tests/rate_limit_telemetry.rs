use ores_lib_core::rate_limit::{
    validate_metric_attribute, Algorithm, FailureMode, Layer, Outcome, PrincipalKind, RetryBucket,
    Source, ALGORITHM_ATTRIBUTE, DECISION_EVENT_NAME, FAILURE_MODE_ATTRIBUTE, LAYER_ATTRIBUTE,
    OUTCOME_ATTRIBUTE, POLICY_ID_ATTRIBUTE, PRINCIPAL_KIND_ATTRIBUTE, RETRY_BUCKET_ATTRIBUTE,
    SOURCE_ATTRIBUTE,
};

const CONTRACT: &str = include_str!("../../../contracts/rate-limit-telemetry-v1.json");
const SCHEMA: &str = include_str!("../../../contracts/rate-limit-telemetry-v1.schema.json");
const ASSURANCE: &str = include_str!("../../../formal/rate-limit-telemetry-assurance.v1.json");

#[test]
fn rust_refinement_is_closed_over_contract_enums() {
    for value in [
        Layer::Edge.as_str(),
        Layer::LoadBalancer.as_str(),
        Layer::Service.as_str(),
        Layer::Authentication.as_str(),
        Layer::DataStore.as_str(),
        Algorithm::TokenBucket.as_str(),
        Algorithm::FixedWindow.as_str(),
        Algorithm::SlidingWindow.as_str(),
        Algorithm::Concurrency.as_str(),
        Outcome::Allow.as_str(),
        Outcome::Deny.as_str(),
        Outcome::ObserveOnlyOverage.as_str(),
        Outcome::Bypass.as_str(),
        Outcome::DegradedAllow.as_str(),
        Source::CloudflareBinding.as_str(),
        Source::CloudflareDenyCache.as_str(),
        Source::IngressNginx.as_str(),
        Source::EnvoyLocal.as_str(),
        Source::TraefikLocal.as_str(),
        Source::LocalMemory.as_str(),
        Source::RedisAuthoritative.as_str(),
        Source::RedisDenyCache.as_str(),
        Source::DataStore.as_str(),
        PrincipalKind::AnonymousIp.as_str(),
        PrincipalKind::AuthenticatedSubject.as_str(),
        PrincipalKind::ServiceIdentity.as_str(),
        PrincipalKind::Tenant.as_str(),
        PrincipalKind::Composite.as_str(),
        FailureMode::FailOpen.as_str(),
        FailureMode::FailClosed.as_str(),
        FailureMode::LocalFallback.as_str(),
        FailureMode::NotApplicable.as_str(),
        RetryBucket::None.as_str(),
        RetryBucket::LessThanOneSecond.as_str(),
        RetryBucket::OneToTenSeconds.as_str(),
        RetryBucket::TenToSixtySeconds.as_str(),
        RetryBucket::OneToFiveMinutes.as_str(),
        RetryBucket::GreaterThanFiveMinutes.as_str(),
    ] {
        assert!(CONTRACT.contains(&format!("\"{value}\"")), "missing {value}");
    }
}

#[test]
fn every_metric_attribute_is_contract_declared() {
    for attribute in [
        POLICY_ID_ATTRIBUTE,
        LAYER_ATTRIBUTE,
        ALGORITHM_ATTRIBUTE,
        OUTCOME_ATTRIBUTE,
        SOURCE_ATTRIBUTE,
        PRINCIPAL_KIND_ATTRIBUTE,
        FAILURE_MODE_ATTRIBUTE,
        RETRY_BUCKET_ATTRIBUTE,
        "ores.rate_limit.observed_only",
    ] {
        assert_eq!(validate_metric_attribute(attribute), Ok(()));
        assert!(CONTRACT.contains(&format!("\"{attribute}\"")));
    }
}

#[test]
fn formal_artifacts_bind_the_same_event_and_closed_schema() {
    assert!(CONTRACT.contains(DECISION_EVENT_NAME));
    assert!(SCHEMA.contains("https://json-schema.org/draft/2020-12/schema"));
    assert!(SCHEMA.contains("\"additionalProperties\": false"));
    for property in [
        "enum-exhaustiveness",
        "identity-noninterference",
        "low-cardinality-closure",
        "metric-trace-separation",
        "retry-bucket-totality",
    ] {
        assert!(ASSURANCE.contains(property));
    }
}
