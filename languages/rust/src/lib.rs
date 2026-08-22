#![forbid(unsafe_code)]

use std::fmt::{Debug, Display, Formatter};

pub const REDACTED: &str = "[REDACTED]";
pub const SENSITIVE_FIELDS: &[&str] = &[
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
    "email",
    "normalized_email",
    "email_lookup_hmac",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "private_key",
    "totp_seed",
    "webauthn_challenge",
    "face_image",
    "face_template",
    "fingerprint_image",
    "fingerprint_template",
    "biometric_template",
    "voiceprint",
];

pub fn is_sensitive_field(key: &str) -> bool {
    let compact: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    SENSITIVE_FIELDS.iter().any(|field| {
        let expected: String = field
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .collect();
        compact == expected || compact.ends_with(&expected)
    })
}

pub fn redact_value<'a>(key: &str, value: &'a str) -> &'a str {
    if is_sensitive_field(key) {
        REDACTED
    } else {
        value
    }
}

pub fn valid_correlation_id(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

pub struct Secret<T>(T);
impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
    pub fn expose<R>(&self, action: impl FnOnce(&T) -> R) -> R {
        action(&self.0)
    }
}
impl<T> Debug for Secret<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}
impl<T> Display for Secret<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

pub trait SecurityLogSink: Send + Sync {
    fn emit(&self, action: &str, outcome: &str, reason_code: Option<&str>, fields: &[(&str, &str)]);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmailNormalizationError {
    Empty,
    TooLong,
    NonAscii,
    InvalidStructure,
    InvalidLocalPart,
    InvalidDomain,
}

/// Normalizes the intentionally narrow, portable Shared Auth lookup form. Unicode/IDNA
/// addresses must be canonicalized by the identity provider before this boundary.
pub fn normalize_email_for_revocation(value: &str) -> Result<String, EmailNormalizationError> {
    let trimmed = value.trim_matches(|character| matches!(character, ' ' | '\t' | '\r' | '\n'));
    if trimmed.is_empty() {
        return Err(EmailNormalizationError::Empty);
    }
    if trimmed.len() > 320 {
        return Err(EmailNormalizationError::TooLong);
    }
    if !trimmed.is_ascii() {
        return Err(EmailNormalizationError::NonAscii);
    }
    let normalized = trimmed.to_ascii_lowercase();
    let mut parts = normalized.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if parts.next().is_some() || local.is_empty() || domain.is_empty() {
        return Err(EmailNormalizationError::InvalidStructure);
    }
    if local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local.bytes().all(valid_email_local_byte)
    {
        return Err(EmailNormalizationError::InvalidLocalPart);
    }
    if domain.len() > 255 || !domain.contains('.') || !domain.split('.').all(valid_domain_label) {
        return Err(EmailNormalizationError::InvalidDomain);
    }
    Ok(normalized)
}

fn valid_email_local_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric()
        || matches!(
            value,
            b'.' | b'!'
                | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}

fn valid_domain_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || value == b'-')
}

pub trait EmailLookupHmac: Send + Sync {
    /// Implementations use HMAC-SHA-256 and a KMS-managed pepper; unkeyed hashes are forbidden.
    fn derive(&self, normalized_email: &str) -> [u8; 32];
    fn key_id(&self) -> &str;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationGrant {
    pub organization_id: String,
    pub sessions_revoke: bool,
}

pub const DIRECTORY_ADMIN_ROLE: &str = "directory_admin";
pub const DIRECTORY_REVOCATIONS_EXECUTE_SCOPE: &str = "directory.revocations.execute";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryAdminGrant {
    pub grant_id: String,
    pub organization_id: String,
    pub project_ids: Option<Vec<String>>,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub granted_at: String,
    pub expires_at: Option<String>,
}

impl DirectoryAdminGrant {
    pub fn allows(&self, required_scope: &str) -> bool {
        self.roles.iter().any(|role| role == DIRECTORY_ADMIN_ROLE)
            && self.scopes.iter().any(|scope| scope == required_scope)
            && !required_scope.contains('*')
    }
}

/// Returns only exact organization-wide grants with a canonical directory-admin role and scope.
/// Project-bounded grants must never be elevated to organization-wide authority.
pub fn authorized_directory_organizations(
    requested: Option<&[String]>,
    required_scope: &str,
    grants: &[DirectoryAdminGrant],
) -> Vec<String> {
    let mut authorized: Vec<String> = grants
        .iter()
        .filter(|grant| grant.allows(required_scope))
        .filter(|grant| grant.project_ids.is_none())
        .filter(|grant| requested.map_or(true, |ids| ids.contains(&grant.organization_id)))
        .map(|grant| grant.organization_id.clone())
        .collect();
    authorized.sort();
    authorized.dedup();
    authorized
}

/// Returns the sorted, de-duplicated intersection only. Callers must not expose rejected IDs.
pub fn authorized_organizations(
    requested: Option<&[String]>,
    grants: &[RevocationGrant],
) -> Vec<String> {
    let mut authorized: Vec<String> = grants
        .iter()
        .filter(|grant| grant.sessions_revoke)
        .filter(|grant| requested.map_or(true, |ids| ids.contains(&grant.organization_id)))
        .map(|grant| grant.organization_id.clone())
        .collect();
    authorized.sort();
    authorized.dedup();
    authorized
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdempotencyDisposition {
    New,
    Replay,
    Conflict,
}

pub fn classify_idempotency(
    existing_request_digest: Option<&[u8; 32]>,
    incoming_request_digest: &[u8; 32],
) -> IdempotencyDisposition {
    match existing_request_digest {
        None => IdempotencyDisposition::New,
        Some(existing) if constant_time_eq(existing, incoming_request_digest) => {
            IdempotencyDisposition::Replay
        }
        Some(_) => IdempotencyDisposition::Conflict,
    }
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (*a ^ *b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secrets_redact() {
        assert_eq!(format!("{:?}", Secret::new("abc")), REDACTED);
    }
    #[test]
    fn sensitive_suffixes_redact() {
        assert_eq!(redact_value("oauth_access-token", "abc"), REDACTED);
    }
    #[test]
    fn ids_are_bounded() {
        assert!(valid_correlation_id("req-12345678"));
        assert!(!valid_correlation_id("bad space"));
    }
    #[test]
    fn email_normalization_is_portable_and_strict() {
        assert_eq!(
            normalize_email_for_revocation("  Alex+Ops@Example.COM\n"),
            Ok("alex+ops@example.com".into())
        );
        assert_eq!(
            normalize_email_for_revocation("a..b@example.com"),
            Err(EmailNormalizationError::InvalidLocalPart)
        );
        assert_eq!(
            normalize_email_for_revocation("alex@localhost"),
            Err(EmailNormalizationError::InvalidDomain)
        );
        assert_eq!(
            redact_value("normalizedEmail", "alex@example.com"),
            REDACTED
        );
    }
    #[test]
    fn organization_authorization_is_an_intersection() {
        let grants = vec![
            RevocationGrant {
                organization_id: "org-b".into(),
                sessions_revoke: true,
            },
            RevocationGrant {
                organization_id: "org-a".into(),
                sessions_revoke: false,
            },
            RevocationGrant {
                organization_id: "org-c".into(),
                sessions_revoke: true,
            },
        ];
        let requested = vec!["org-a".into(), "org-b".into(), "org-unknown".into()];
        assert_eq!(
            authorized_organizations(Some(&requested), &grants),
            vec!["org-b".to_string()]
        );
    }
    #[test]
    fn directory_authorization_requires_exact_role_and_scope() {
        let grants = vec![DirectoryAdminGrant {
            grant_id: "20000000-0000-4000-8000-000000000001".into(),
            organization_id: "10000000-0000-4000-8000-000000000001".into(),
            project_ids: None,
            scopes: vec![DIRECTORY_REVOCATIONS_EXECUTE_SCOPE.into()],
            roles: vec![DIRECTORY_ADMIN_ROLE.into()],
            granted_at: "2026-08-11T21:00:00Z".into(),
            expires_at: None,
        }];
        assert_eq!(
            authorized_directory_organizations(None, DIRECTORY_REVOCATIONS_EXECUTE_SCOPE, &grants,),
            vec!["10000000-0000-4000-8000-000000000001".to_string()]
        );
        assert!(authorized_directory_organizations(None, "directory.*", &grants).is_empty());
        let mut project_bounded = grants[0].clone();
        project_bounded.project_ids = Some(vec!["30000000-0000-4000-8000-000000000001".into()]);
        assert!(authorized_directory_organizations(
            None,
            DIRECTORY_REVOCATIONS_EXECUTE_SCOPE,
            &[project_bounded],
        )
        .is_empty());
    }
    #[test]
    fn idempotency_replays_only_an_identical_digest() {
        assert_eq!(
            classify_idempotency(None, &[1; 32]),
            IdempotencyDisposition::New
        );
        assert_eq!(
            classify_idempotency(Some(&[1; 32]), &[1; 32]),
            IdempotencyDisposition::Replay
        );
        assert_eq!(
            classify_idempotency(Some(&[1; 32]), &[2; 32]),
            IdempotencyDisposition::Conflict
        );
    }
}
