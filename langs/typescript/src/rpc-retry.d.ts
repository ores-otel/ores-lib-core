export type RetryReason = 1 | 2 | 3 | 4 | 5 | 6 | 7;
export interface RpcRetryPolicy {
  readonly max_attempts: number;
  readonly timeout_ms: number;
  readonly initial_backoff_ms: number;
  readonly max_backoff_ms: number;
}
export interface RpcRetryAttempt {
  readonly attempts_completed: number;
  readonly elapsed_ms: number;
  readonly code: number;
  readonly cancelled: boolean;
  /** Derived from reviewed method semantics and server-enforced deduplication, never untrusted input. */
  readonly replay_safe: boolean;
  readonly jitter_permille: number;
  readonly retry_after_ms?: number;
}
export type RpcRetryDecision =
  | Readonly<{ retry: true; delay_ms: number; reason: 1 }>
  | Readonly<{ retry: false; delay_ms: 0; reason: 2 | 3 | 4 | 5 | 6 | 7 }>;
export declare const RETRY_REASON: Readonly<{
  retry: 1; invalid_input: 2; cancelled: 3; unsafe_replay: 4;
  attempts_exhausted: 5; deadline_exhausted: 6; non_retryable: 7;
}>;
/** Pure, bounded, fail-closed planner. The host owns transport and cancellation. */
export declare function planRpcRetry(policy: RpcRetryPolicy, attempt: RpcRetryAttempt): RpcRetryDecision;
