//! Pure RPC retry policy shared with browser JS and Flutter/Dart.
//!
//! The host owns networking, monotonic time, jitter sampling, authentication and cancellation.
//! `replay_safe` is trusted method metadata, not a client-supplied authorization assertion.
//! A key alone does not make a write idempotent. Recheck deadline/cancellation before each send.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Includes the initial call; one means no retries.
    pub max_attempts: u32,
    pub timeout_ms: u32,
    pub initial_backoff_ms: u32,
    pub max_backoff_ms: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryAttempt {
    pub attempts_completed: u32,
    /// Monotonic elapsed time, never a wall-clock timestamp.
    pub elapsed_ms: u32,
    /// gRPC/Connect status number. Only 8 and 14 are retry candidates.
    pub code: u32,
    pub cancelled: bool,
    pub replay_safe: bool,
    /// Injected full-jitter sample in 0..=1000.
    pub jitter_permille: u32,
    /// Server minimum, not a hint that may be shortened to fit a client deadline.
    pub retry_after_ms: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RetryReason {
    Retry = 1,
    InvalidInput = 2,
    Cancelled = 3,
    UnsafeReplay = 4,
    AttemptsExhausted = 5,
    DeadlineExhausted = 6,
    NonRetryable = 7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryDecision {
    pub retry: bool,
    pub delay_ms: u32,
    pub reason: RetryReason,
}

fn stop(reason: RetryReason) -> RetryDecision {
    RetryDecision { retry: false, delay_ms: 0, reason }
}

/// Returns a plan after a failed attempt; never sleeps, performs I/O, mutates state, or logs.
/// Numeric bounds keep all intermediates exact in Rust, Dart web, and JavaScript.
pub fn plan_rpc_retry(policy: &RetryPolicy, attempt: &RetryAttempt) -> RetryDecision {
    let valid = (1..=8).contains(&policy.max_attempts)
        && (1..=3_600_000).contains(&policy.timeout_ms)
        && (1..=60_000).contains(&policy.initial_backoff_ms)
        && (policy.initial_backoff_ms..=60_000).contains(&policy.max_backoff_ms)
        && (1..=8).contains(&attempt.attempts_completed)
        && attempt.elapsed_ms <= 3_600_000
        && attempt.code <= 16
        && attempt.jitter_permille <= 1000
        && attempt.retry_after_ms.map_or(true, |minimum| minimum <= 3_600_000);
    if !valid { return stop(RetryReason::InvalidInput); }
    if attempt.cancelled { return stop(RetryReason::Cancelled); }
    if !attempt.replay_safe { return stop(RetryReason::UnsafeReplay); }
    if attempt.attempts_completed >= policy.max_attempts { return stop(RetryReason::AttemptsExhausted); }
    if attempt.elapsed_ms >= policy.timeout_ms { return stop(RetryReason::DeadlineExhausted); }
    if !matches!(attempt.code, 8 | 14) { return stop(RetryReason::NonRetryable); }
    // Validation above bounds the shift to 0..=7 and every product below u32::MAX.
    let cap = policy.max_backoff_ms.min(policy.initial_backoff_ms * (1 << (attempt.attempts_completed - 1)));
    let jittered = cap * attempt.jitter_permille / 1000;
    let delay_ms = jittered.max(attempt.retry_after_ms.unwrap_or(0));
    if delay_ms >= policy.timeout_ms - attempt.elapsed_ms { return stop(RetryReason::DeadlineExhausted); }
    RetryDecision { retry: true, delay_ms, reason: RetryReason::Retry }
}

/// ORM-neutral semantic categories. Diesel/SeaORM adapters classify typed errors server-side;
/// driver text, SQL and connection strings must not cross the public RPC boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseFailure {
    Unavailable,
    Overloaded,
    NotFound,
    AlreadyExists,
    TransactionConflict,
    PermissionDenied,
    Internal,
}

/// A transaction conflict requires transaction-level handling, NOT automatic whole-RPC replay.
/// Authorization remains the resource API's responsibility, irrespective of ORM error mapping.
pub fn database_failure_status(failure: DatabaseFailure) -> u32 {
    match failure {
        DatabaseFailure::Unavailable => 14,
        DatabaseFailure::Overloaded => 8,
        DatabaseFailure::NotFound => 5,
        DatabaseFailure::AlreadyExists => 6,
        DatabaseFailure::TransactionConflict => 10,
        DatabaseFailure::PermissionDenied => 7,
        DatabaseFailure::Internal => 13,
    }
}
