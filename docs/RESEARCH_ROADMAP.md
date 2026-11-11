# Research roadmap

“Phase” below means an implementation milestone. It does not rename the thesis's
separate problems P1 (status), P2 (accountability), and P3 (freshness).

| Phase | Scope and expected deliverables | Evidence gate |
|---|---|---|
| 1 — current | Synthetic QR/signature foundation, modular parser boundary, trust separation, identifier analysis, tests, beginner and technical docs, PPT content | Reproducible synthetic checks; real support honestly labelled unsupported |
| 2 — future P1 | Specify a simulated issuer binding contract; prototype signed cached status-list experiments under explicit identity/artefact semantics | Decide binding lifecycle and privacy assumptions; establish real compatibility separately if evidence becomes available |
| 3 — future P1 | Compare an accumulator non-membership approach against the same baseline; examine authenticated Merkle approaches only if justified | Common datasets, threat model, witness-update assumptions, defensible performance methodology |
| 4 — future P1 evaluation | Measure storage, bandwidth, verification cost, update delivery, and constrained-device behavior | Working mechanisms and reproducible experimental design; Android only here or a separately authorized milestone |
| Later separately scoped work | Thesis P2 auditability and P3 quantitative freshness analysis | Explicit scope, literature validation, privacy review and own implementation plans |

Only Phase 1 is implemented. No future mechanism is scaffolded as a misleading working
engine. If the unchanged legacy binding gate remains unresolved, later results must be
presented as conditional or simulated-issuer research. Do not use an artefact hash or
demographic similarity as an undocumented substitute for identity binding.

For every implemented phase, populate the [phase documentation template](PHASE_DOCUMENTATION_TEMPLATE.md)
with actual tests and measurements. Update the source/evidence table when assumptions
change. A shorter list of established findings is more useful than unsupported claims
about compatibility or national-scale performance.

