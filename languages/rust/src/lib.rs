#![forbid(unsafe_code)]

use std::fmt::{Debug, Display, Formatter};

pub const REDACTED: &str = "[REDACTED]";
pub const SENSITIVE_FIELDS: &[&str] = &[
    "authorization", "cookie", "password", "secret", "token", "access_token",
    "refresh_token", "id_token", "client_secret", "private_key", "totp_seed",
    "webauthn_challenge", "face_image", "face_template", "fingerprint_image",
    "fingerprint_template", "biometric_template", "voiceprint",
];

pub fn is_sensitive_field(key: &str) -> bool {
    let compact: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    SENSITIVE_FIELDS.iter().any(|field| {
        let expected: String = field.chars().filter(|character| character.is_ascii_alphanumeric()).collect();
        compact == expected || compact.ends_with(&expected)
    })
}

pub fn redact_value<'a>(key: &str, value: &'a str) -> &'a str {
    if is_sensitive_field(key) { REDACTED } else { value }
}

pub fn valid_correlation_id(value: &str) -> bool {
    (8..=128).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

pub struct Secret<T>(T);
impl<T> Secret<T> {
    pub fn new(value: T) -> Self { Self(value) }
    pub fn expose<R>(&self, action: impl FnOnce(&T) -> R) -> R { action(&self.0) }
}
impl<T> Debug for Secret<T> { fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result { f.write_str(REDACTED) } }
impl<T> Display for Secret<T> { fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result { f.write_str(REDACTED) } }

pub trait SecurityLogSink: Send + Sync {
    fn emit(&self, action: &str, outcome: &str, reason_code: Option<&str>, fields: &[(&str, &str)]);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn secrets_redact() { assert_eq!(format!("{:?}", Secret::new("abc")), REDACTED); }
    #[test] fn sensitive_suffixes_redact() { assert_eq!(redact_value("oauth_access-token", "abc"), REDACTED); }
    #[test] fn ids_are_bounded() { assert!(valid_correlation_id("req-12345678")); assert!(!valid_correlation_id("bad space")); }
}
