# Formal assurance

`ores-lib-core` is mostly stateless, so temporal model checking would add little
value here. Its critical behavior is credential redaction. The assurance
manifest and language refinements check algebraic security properties instead:

- **idempotence:** `redact(redact(record)) = redact(record)`;
- **sensitive-value noninterference:** changing only a sensitive value cannot
  change the observable redacted record;
- **safe-field preservation:** fields outside the sensitive-key domain retain
  their values;
- **normalization closure:** case, separator, whitespace, and namespaced suffix
  variants remain sensitive;
- **secret representation opacity:** ordinary string/debug/JSON surfaces never
  reveal wrapped secret values; access remains an explicit operation.

[`redaction-assurance.v1.json`](redaction-assurance.v1.json) declares the finite
input domain and the TypeScript, Rust, and Dart refinement checks. Its closed
Draft 2020-12 JSON Schema prevents silent coverage-field drift. The generated
domain is exhaustive for the declared roots, prefixes, case transforms, and
separator transforms; it is not a proof over all possible Unicode strings.

Run the complete local slice with:

```sh
python3 scripts/check_formal_assurance.py
(cd languages/typescript && npm test)
(cd languages/rust && cargo test)
(cd languages/dart && dart pub get && dart run tool/formal_check.dart)
```

The canonical temporal models for telemetry buffering, retries, flush, and
shutdown live in `ores-otel/ores.otel.log`. Authentication/session authority
belongs to `shared-auth-server.rs`; this repository must not invent a competing
authorization state machine.
