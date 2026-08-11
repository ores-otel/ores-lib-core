# Security model

`ores-lib-core` is a narrow dependency, not an authorization engine.

It may normalize identifiers, redact values, and pass already-sanitized events to an
injected `ores.otel.log` sink. It must not infer tenant membership, convert Kerberos groups
or SSH key comments into application roles, interpret OpenPGP signatures as login proof,
or handle raw biometric material. Shared Auth owns those policy decisions and issues
short-lived, audience-bound credentials after online policy evaluation.

For revocation-by-email, the core accepts only a strict ASCII canonical form, passes it to an
injected HMAC-SHA-256 implementation backed by a KMS pepper, and requires the caller to discard
the address immediately. An unkeyed hash is not sufficient. Authorization is an explicit
intersection of requested organization IDs with active `DirectoryAdminGrant` values carrying
`directory_admin` and the exact requested directory scope. Project-bounded grants must never
become organization-wide authority. The result must never identify rejected or inaccessible
organizations. Global revocation additionally requires the service-bound token exchange,
opaque selection/commit-authorization handoffs, a central auth-epoch/not-before fence, and
per-provider target state defined by `ores-interfaces`; the current SQL draft does not yet
satisfy those requirements and remains disabled for production.
