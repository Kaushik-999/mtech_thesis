# Phase 2 research findings and open questions

This document separates prior techniques, implementation facts, observed results and
possible future contributions. The subject is a **simulated issuer contract**. Phase 1's
unresolved real Aadhaar identity-level binding is not resolved by writing this registry.

## A. Existing techniques from published work

Batch status distribution, signed issuer statements and compact bit representations
are established ideas. W3C Bitstring Status List v1.0 defines a standardized VC-oriented
representation and processing model. Its published privacy discussion makes clear that
status-list use still requires care about correlation and observation.
([W3C Recommendation, 15 May 2025](https://www.w3.org/TR/2025/REC-vc-bitstring-status-list-20250515/))

The consulted IETF Token Status List draft addresses status lists for tokens, including
packing, authenticated representations, caching, trust and privacy considerations.
It is a draft, not a published RFC at the checked date. This prototype implements a
separate envelope and does not claim conformance to that work.
([draft-ietf-oauth-status-list-21](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html))

CRLite studies distributing TLS revocation information to browsers using compact
filter-based structures. It is a useful peer-reviewed antecedent for asking what
proactive distribution costs and what local checking avoids. TLS certificate status,
its data sources and its filter construction differ from our subject/credential lifecycle;
we neither implement CRLite nor transfer its performance results to Aadhaar.
([Larisch et al., IEEE S&P 2017](https://www.cs.umd.edu/users/dml/papers/crlite_oakland17.pdf))

Consequently, “we use one bit per credential” and “we cache a signed list” are not novelty
claims. Epoch-based local ordering and atomic database transactions are engineering
techniques, also not new cryptographic constructions. Exact source versions, sections and
the limits of the comparison are listed in [sources and assumptions](07_sources_and_assumptions.md).

## B. Our engineering implementation

The implementation makes the binding assumption concrete instead of treating an
artefact identifier as an identity. A private issuer mapping relates one subject to
all its credential UUIDs and distinct list positions. A signed sidecar tells the verifier
which position belongs to the presented exact signed message. The holder carries that
sidecar; there is no online per-person resolution service.

The registry has an explicit permanent deactivation policy. Reissuance for an enabled
subject obtains a fresh UUID/index without deleting history. Subject deactivation sets
every owned bit and blocks subsequent issuance. Single-credential revocation affects only
one bit. These are experimental semantics, not a characterization of actual UIDAI rules.

Three separately authorized key roles sign credentials, sidecars and snapshots.
The verifier distinguishes mathematical authenticity from local key authorization.
Snapshots authenticate issuer/list context, epoch, time window, count, bitmap and signing
metadata. Bounded strict parsing rejects ambiguous or excessive inputs.

The verifier cache atomically stores the snapshot and its epoch/digest history. It
rejects ordinary rollback, encountered same-epoch conflict and regressions incompatible
with permanent revocation. Deletion/corruption does not silently reset history. Complete
trusted-storage restoration and unseen issuer equivocation remain outside the guarantee.

Finally, the integration returns independent evidence fields and as-of status, with
explicit failure codes. Revalidation occurs on every normal call. A benchmark helper
can time already authenticated bitmap access separately; this is not an optimization
secretly assumed by the integrated API.

## C. Experimentally established results

The original 79 tests passed before changes. They remain byte-for-byte unchanged,
together with Phase 1 documents/results, and continue to pass. The combined suite has
169 passing cases, including 90 Phase 2 cases covering T201–T230 and additional boundaries.
The network-guarded demo verifies repeated operations with socket connection and DNS functions
blocked. This supports the claim about the implemented local verification path.

The four-day experiment establishes a limited, precise fact: the same original
credential has a valid signature before and after subject deactivation; the status
decision changes only after a new authenticated snapshot arrives. With an old acceptable
snapshot, the result remains explicitly tied to the old epoch. A stricter maximum age
returns STALE_SNAPSHOT. This demonstrates the information limit of offline checking,
not an empirical estimate of acceptable outage duration in a real use case.

On the measured Apple M2/CPython 3.12.16 environment, ten million assigned entries require
1,250,000 raw bitmap bytes, 2,223,153 signed envelope bytes and 2,232,320 bytes in the
quiescent cache database. Median full snapshot validation is 69.426 ms; creation/signing
is 34.798 ms; cache reload/validation is 70.334 ms. These are seven-run observations
with 1% revoked positions. All samples and environment metadata are saved.

Across four population sizes, authenticated lookup batch means were about 119–125 ns/op
at the median. This tiny primitive excludes all snapshot and credential/binding validation.
Full snapshot processing grows with N, and the integrated verifier currently pays that
cost per check. There is no full end-to-end verifier latency distribution in these results.

Small real registry measurements show increasing deactivation work for 1/5/25 sibling
credentials and confirm all sibling bits are changed. They do not establish giant-registry
throughput. No compression, signed delta, mobile, HTTP, UIDAI or accumulator experiment
was performed. The [testing report](04_testing_and_results.md) gives exact tables and caveats.

## Privacy analysis by observer

| Observer | Information available in this design | Reduced exposure | Remaining leakage or uncertainty |
|---|---|---|---|
| Simulated issuer | Private subject ownership, UUIDs, assigned positions, issuance and lifecycle events | No implemented callback on each local verification | Issuer already knows mapping; future list-download logs can reveal verifier activity |
| Offline verifier | Presented credential, sidecar UUID/digest/index, list, signed snapshots and presentation context | Need not contact issuer about the holder | Stable credentials/indices link repeated presentations; original credential fields remain visible |
| Network observer during future updates | Depending on transport: endpoints, timing, size; plaintext contents if unprotected | Full-list request need not encode one credential/index | Update frequency, list selection and metadata may reveal context; transport is not implemented/measured |
| Holder/presenter | Their credential/sidecar and, if distributed publicly, full list | Can carry binding without an online identity lookup | A copied bundle remains linkable; no proof of possession or liveness |
| Attacker with published snapshots | Assigned counts, revoked positions/counts, epochs, time windows, differences between releases | No internal subject UUID or explicit demographic mapping in snapshot | Auxiliary information can label slots; simultaneous changes can suggest related credentials |

The implementation achieves **no per-person issuer query in verification** and
**omission of issuer-private subject IDs from public status data and ordinary output**.
It does not achieve zero knowledge, anonymous presentation, collusion resistance or
cross-verifier unlinkability. Replacing a name with a UUID or integer is not a proof of
privacy. Tests for absent subject-ID strings establish data minimization, not anonymity.

Several less obvious observations matter:

- Dense sequential positions reveal relative allocation order and the signed count
  reveals the size of the assigned population. This research format has no privacy
  padding or randomized index-allocation scheme.
- A revocation count is obtained by counting set bits. Differences across epochs reveal
  changed positions and approximate event batches. Simultaneous deactivation of sibling
  credentials may support correlation, though simultaneity alone does not prove ownership.
- Sidecars deliberately expose an authenticated credential/index association to their
  recipients. Globally publishing all sidecars would create a much more informative
  mapping than publishing only a bitmap; the design does not require such publication.
- A list shared by many holders can obscure which bit a local verifier reads, but a
  narrowly partitioned list can reveal group membership. List partitioning is not
  evaluated here; one list per registry is a simplifying assumption.
- Reissuing with a fresh UUID/index prevents slot reuse, but does not promise unlinkability:
  the issuer retains ownership, credential attributes may correlate, and batch revocation
  or colluding verifiers may expose relationships.
- Full downloads avoid explicit person-specific requests only while retrieval remains
  decoupled from a particular presentation. Fetching a rare list immediately after every
  scan could reveal timing correlations even if the URL has no person's identifier.

## Trade-offs established by the design

| Dimension | Benefit | Cost or qualification |
|---|---|---|
| Local lookup | Simple indexed bit access after authentication | Full validation is O(N); current verifier repeats it |
| Storage | One raw bit per assigned credential | Double base64, metadata, cache pages, bundles and local history add space |
| Distribution | One full snapshot can serve many local checks | Every update transfers the full envelope; no delta/compression |
| Revocation visibility | New trusted snapshot changes decisions without rewriting credentials | Visibility waits for publication and delivery; missed updates remain unknown |
| Freshness policy | Explicit maximum age and expiry prevent accepting overly old evidence | Strict policy reduces offline availability; local time remains an assumption |
| Reissuance | Fresh slots preserve permanent history and allow sibling propagation | List grows; issuer needs private ownership history |
| Privacy | No verification callback, no public subject mapping | Stable slot/bundle linkability and population/change leakage remain |
| Key separation | Explicit authorization for three roles | Distribution, rotation, compromise recovery and persistent issuer state need future design |
| Cache integrity | Atomic epoch/document updates and ordinary restart checks | Cannot defeat rollback of all trusted local history |

These are system trade-offs. An optimization must preserve the same semantics before
its timing can be compared. For example, reusing a validated in-memory bitmap must not
silently ignore a newly synchronized cache epoch or skip current freshness checks.

## D. Candidate research contributions, not established novelty

1. **A lifecycle-aware comparison framework.** Evaluate bitstrings and a reviewed
   accumulator under identical subject deactivation, credential reissuance, binding,
   trust, missed-update and adversarial cases. A contribution would require explaining
   what existing evaluations omit and providing evidence across realistic conditions.
2. **Quantified binding/distribution trade-offs.** Compare holder-carried sidecars with
   other authenticated delivery contracts, including bundle size, retrieval metadata,
   offline availability and correlation. No alternative is implemented here yet.
3. **An explicit leakage model for identity-level fan-out.** Study what synchronized
   changes to sibling slots reveal under different outside knowledge and issuance
   patterns. The observations above motivate a study; they are not a proof or measured attack.
4. **A reproducible systems artefact.** Tests, bounded formats, clear failure states and
   raw experimental outputs support repeatable evaluation. Reproducibility is useful
   without asserting a new cryptographic primitive.

A broader literature review and comparative experiment are prerequisites for claiming
academic novelty. Implementing an existing standards-inspired mechanism is not sufficient.

## E. Unresolved limitations

Real UIDAI status authority, stable identity binding, sidecar issuance authorization,
actual deactivation/death semantics and key-distribution rules remain unestablished.
The simulated issuer knows a private mapping because this experiment creates it.
That does not demonstrate the same mapping is available in unchanged legacy credentials.

The issuer and its keys are ephemeral. There is no durable issuer restore/backup,
multi-process allocation, authorized key rotation, compromise recovery, cache migration
across keys, production distribution service or trusted clock. Explicit namespace reuse
after losing state is outside the supported lifecycle. Whole-cache restoration and a
malicious trusted issuer are stronger adversaries than the implemented controls solve.

Benchmarks are one-machine measurements with a small repetition count. National-scale
extrapolation, power-loss durability, reliable tail latency, energy use, constrained
device performance and update-transport privacy have not been established. The project
does not check presenter possession or prevent copying of a valid credential bundle.

## F. Dependencies for the next implementation phase

Before an accumulator comparison, specify the construction and its reviewed assumptions;
membership versus non-membership statement; setup and key lifecycle; witness issuance,
update and missed-update recovery; malicious/revoked holder behavior; and the exact
privacy information revealed to each participant. Keep the current issuer lifecycle and
decision semantics as the common baseline.

Extend the benchmark harness to compare complete verification, issuer update cost,
full distribution cost, holder/verifier state, memory and recovery after outages. Use
multiple independent runs and machines before inferring general trends. Any optimization
to this baseline should retain separate results so later comparisons remain reproducible.

Real Aadhaar compatibility remains a separate evidence gate. Android deployment,
thesis P2 accountability and thesis P3 empirical freshness require their own authorized
scope and evaluation plans; no placeholders are presented as implementations here.
