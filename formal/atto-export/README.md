# Bounded OTel exporter safety model / AttoLang oracle

This extension models one sensitive batch, a queue capacity of one, redaction before enqueue, transient transport outage, ambiguous-ack retry and acknowledgement only after delivery. A finite 12-step state explorer demands witnesses for successful delivery, redaction denial, backpressure, outage, retry and acknowledgement. It injects invalid-state mutations to keep the safety checks observable.

Run `node formal/atto-export/model.cjs`.

- The model **permits duplicate delivery** following ambiguous acknowledgements: it does not promise exactly-once telemetry.
- It does not read or contain real span payloads, customer identifiers, credentials or secrets.
- `export_policy.atto` is a pure AttoLang **source** oracle; this workflow does not compile or run an AttoLang guest.
- Existing TypeSpec/authored JSON Schema peer authorities and redaction assurance contracts remain canonical.

Required refinement before stronger claims: test the real exporter redaction and retry pipeline under concurrent producers and bounded quotas, compare to native backend trace, record exact head, executed job steps, negative-mutation results and independent review.
