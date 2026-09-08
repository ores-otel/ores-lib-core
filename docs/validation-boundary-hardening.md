# Validation boundary hardening (DEN-3958)

The ASCII email revocation policy rejects non-ASCII input before lowercasing.
Previously TypeScript and Dart lowercased first: U+212A KELVIN SIGN became ASCII
`k`, admitting an address Rust rejects. Keep the existing ASCII whitespace trim,
length bounds and normalized ASCII output; do not broaden this narrow identity
lookup policy into Unicode/IDNA normalization without a versioned contract.

Dart idempotency accepts exactly 32 integers in 0..255, checking both incoming
and stored digests before comparison. Length alone is not byte validation.
Out-of-range integers must not enter native XOR or dart2js bitwise conversion.
Rust's `[u8; 32]` and TypeScript's 32-byte `Uint8Array` already impose that domain.
Do not coerce a number list into a typed array before validating its original
values: that can truncate or wrap invalid inputs. No constant-time claim is made
for managed-runtime validation or comparison.

Regression tests exercise the production entrypoints, compare accepted output,
reject invalid input, verify every digest byte position and preserve inputs.
Dart's same dependency-free test executes on the VM and compiled JavaScript;
it does not rely on assertions, which may be disabled. This is finite regression
evidence, not a proof of language equivalence or an authentication review.

Shared source contracts are being duplicated, not moved, to
`ORESoftware/ores-interfaces`. Existing zed dependencies and original interfaces
remain unchanged until peer-authority TJSV receipts and genuine resolver locks
are available. Client-side checks never replace server-side validation or
verified tenant authorization.
