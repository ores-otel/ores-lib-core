import { planRpcRetry, type RpcRetryPolicy, type RpcRetryAttempt } from '../src/rpc-retry.js';
const policy: RpcRetryPolicy = { max_attempts: 4, timeout_ms: 1000, initial_backoff_ms: 100, max_backoff_ms: 400 };
const attempt: RpcRetryAttempt = { attempts_completed: 1, elapsed_ms: 0, code: 14, cancelled: false, replay_safe: false, jitter_permille: 500 };
const decision = planRpcRetry(policy, attempt);
if (decision.retry) { const reason: 1 = decision.reason; void reason; }
else { const delay: 0 = decision.delay_ms; void delay; }
// @ts-expect-error policies are immutable
policy.max_attempts = 99;
// @ts-expect-error decisions are immutable
decision.retry = true;
// @ts-expect-error replay safety is mandatory, not inferred from a key
planRpcRetry(policy, { attempts_completed: 1, elapsed_ms: 0, code: 14, cancelled: false, jitter_permille: 0 });
