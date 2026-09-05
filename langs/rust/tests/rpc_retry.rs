use ores_lib_core::rpc_retry::{
    database_failure_status, plan_rpc_retry, DatabaseFailure, RetryAttempt, RetryPolicy, RetryReason,
};

#[test]
fn cross_runtime_conformance_corpus() {
    let csv = include_str!("../../../contracts/rpc-retry-v1.csv");
    let mut count = 0;
    for line in csv.lines().skip(1) {
        let row: Vec<&str> = line.split(',').collect();
        assert_eq!(row.len(), 15);
        let number = |index: usize| row[index].parse::<u32>().expect("unsigned fixture integer");
        let boolean = |index: usize| row[index].parse::<bool>().expect("fixture boolean");
        let policy = RetryPolicy { max_attempts: number(1), timeout_ms: number(2),
            initial_backoff_ms: number(3), max_backoff_ms: number(4) };
        let attempt = RetryAttempt { attempts_completed: number(5), elapsed_ms: number(6),
            code: number(7), cancelled: boolean(8), replay_safe: boolean(9),
            jitter_permille: number(10), retry_after_ms: if row[11].is_empty() { None } else { Some(number(11)) } };
        let result = plan_rpc_retry(&policy, &attempt);
        assert_eq!((result.retry, result.delay_ms, result.reason as u32),
            (boolean(12), number(13), number(14)), "{}", row[0]);
        count += 1;
    }
    assert!(count >= 50, "the corpus must not be silently emptied");
}

#[test]
fn bounded_exhaustive_safety_properties() {
    let policy = RetryPolicy { max_attempts: 4, timeout_ms: 1000, initial_backoff_ms: 100, max_backoff_ms: 400 };
    for attempts_completed in 1..=8 {
        for elapsed_ms in [0, 1, 500, 999, 1000, 1001] {
            for jitter_permille in [0, 1, 499, 500, 999, 1000] {
                for code in 0..=16 {
                    let attempt = RetryAttempt { attempts_completed, elapsed_ms, code,
                        cancelled: false, replay_safe: true, jitter_permille, retry_after_ms: None };
                    let result = plan_rpc_retry(&policy, &attempt);
                    if result.retry {
                        assert!(matches!(code, 8 | 14));
                        assert!(attempts_completed < policy.max_attempts);
                        assert!(result.delay_ms < policy.timeout_ms - elapsed_ms);
                        assert_eq!(result.reason, RetryReason::Retry);
                    } else { assert_eq!(result.delay_ms, 0); }
                    assert!(!plan_rpc_retry(&policy, &RetryAttempt { cancelled: true, ..attempt }).retry);
                    assert!(!plan_rpc_retry(&policy, &RetryAttempt { replay_safe: false, ..attempt }).retry);
                }
            }
        }
    }
}

#[test]
fn orm_semantics_do_not_expose_driver_errors_or_retry_transactions() {
    let cases = [(DatabaseFailure::Unavailable, 14), (DatabaseFailure::Overloaded, 8),
        (DatabaseFailure::NotFound, 5), (DatabaseFailure::AlreadyExists, 6),
        (DatabaseFailure::TransactionConflict, 10), (DatabaseFailure::PermissionDenied, 7),
        (DatabaseFailure::Internal, 13)];
    for (failure, code) in cases { assert_eq!(database_failure_status(failure), code); }
}
