use ores_lib_core::{
    is_sensitive_field, redact_value, valid_correlation_id, Secret, REDACTED, SENSITIVE_FIELDS,
};

const PREFIXES: &[&str] = &["", "oauth_", "x-vendor-", "telemetry."];
const SAFE_FIELDS: &[&str] = &[
    "request_id",
    "trace_id",
    "message",
    "organization_id",
    "status_code",
];

fn variants(root: &str, prefix: &str) -> Vec<String> {
    vec![
        format!("{prefix}{root}"),
        format!("{prefix}{}", root.to_ascii_uppercase()),
        format!("{prefix}{}", root.replace('_', "-")),
        format!("  {prefix}{}  ", root.replace('_', ".")),
    ]
}

#[test]
fn normalization_closure_and_sensitive_value_noninterference() {
    for root in SENSITIVE_FIELDS {
        for prefix in PREFIXES {
            for key in variants(root, prefix) {
                assert!(is_sensitive_field(&key), "{key}");
                assert_eq!(redact_value(&key, "secret-alpha"), REDACTED, "{key}");
                assert_eq!(
                    redact_value(&key, "secret-alpha"),
                    redact_value(&key, "secret-bravo"),
                    "{key}"
                );
            }
        }
    }
}

#[test]
fn idempotence_and_safe_field_preservation() {
    for key in SENSITIVE_FIELDS {
        let once = redact_value(key, "secret-alpha");
        assert_eq!(redact_value(key, once), once, "{key}");
    }
    for key in SAFE_FIELDS {
        assert!(!is_sensitive_field(key), "{key}");
        assert_eq!(redact_value(key, "safe-value"), "safe-value", "{key}");
    }
}

#[test]
fn secret_representation_is_opaque_and_reveal_is_explicit() {
    let secret = Secret::new("must-not-escape");
    assert_eq!(format!("{secret}"), REDACTED);
    assert_eq!(format!("{secret:?}"), REDACTED);
    assert_eq!(secret.expose(|value| value.len()), "must-not-escape".len());
}

#[test]
fn correlation_identifier_boundaries_are_closed() {
    assert!(!valid_correlation_id(&"a".repeat(7)));
    assert!(valid_correlation_id(&"a".repeat(8)));
    assert!(valid_correlation_id(&"z".repeat(128)));
    assert!(!valid_correlation_id(&"z".repeat(129)));
    assert!(!valid_correlation_id("bad space"));
}
