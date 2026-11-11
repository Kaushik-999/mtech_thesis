# Research roadmap

“Phase” below means an implementation milestone. It does not rename the thesis's
separate problems P1 (status), P2 (accountability), and P3 (freshness).

| Phase | Scope and expected deliverables | Evidence gate |
|---|---|---|
| 1 — complete | Synthetic QR/signature foundation, modular parser boundary, trust separation, identifier analysis, tests, beginner and technical docs, PPT content | 79 original tests; historical reports/documents preserved; real formats unsupported |
| 2 — complete, current P1 milestone | Private simulated issuer lifecycle, signed credential/index sidecars, full signed bitmaps, durable verifier cache, rollback/freshness checks, offline demo, privacy analysis and benchmarks | 90 new cases; 169 combined tests; four measured populations through ten million positions; no real UIDAI claim |
| 3 — future P1 | Compare an accumulator non-membership approach against the same baseline; examine authenticated Merkle approaches only if justified | Common datasets, threat model, witness-update assumptions, defensible performance methodology |
| 4 — future P1 evaluation | Measure storage, bandwidth, verification cost, update delivery, and constrained-device behavior | Working mechanisms and reproducible experimental design; Android only here or a separately authorized milestone |
| Later separately scoped work | Thesis P2 auditability and P3 quantitative freshness analysis | Explicit scope, literature validation, privacy review and own implementation plans |

Phases 1 and 2 are implemented. Phase 2 is a **Research Bitstring Status List — Not W3C
Conformant**. The [Phase 2 report](phase-02/04_testing_and_results.md) separates full
snapshot validation from already authenticated bitmap access and preserves actual raw
results. Its four-day clock experiment enforces minimal age/expiry policy; it is not
thesis P3's empirical use-case freshness analysis.

The real legacy binding gate remains unresolved. Later results must remain conditional
or simulated-issuer research unless independent issuer evidence establishes compatibility.
The exact-message digest in the signed sidecar only matches an artefact; it does not
derive an identity or status index from a QR, suffix or demographic similarity.

Before Phase 3, select and review an accumulator construction, its security/setup
assumptions and non-membership statement. Specify witness generation/update/recovery,
revoked-holder behavior, key lifecycle and information visible to each party. Compare
against the same synthetic ownership/reissuance policy, trust model, offline behavior
and complete cost accounting. Do not compare only proof verification against a bitmap
operation while omitting witness, distribution or authentication costs.

Durable issuer recovery, authorized key rotation, list partitioning/privacy padding,
trusted time, stronger local rollback protection and transport design remain explicit
future engineering questions. The current cache handles ordinary verifier restarts;
the issuer registry and signing keys deliberately remain ephemeral. No accumulator,
Android application, accountability engine or empirical freshness study is implemented.

For every implemented phase, populate the [phase documentation template](PHASE_DOCUMENTATION_TEMPLATE.md)
with actual tests and measurements. Update the source/evidence table when assumptions
change. A shorter list of established findings is more useful than unsupported claims
about compatibility or national-scale performance.

