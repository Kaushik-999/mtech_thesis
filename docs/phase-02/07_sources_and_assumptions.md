# Phase 2 sources, assumptions and evidence boundaries

Access date for the external sources below: **11 November 2026**. Versioned links are
included so later readers can distinguish the material consulted from future revisions.
The documents are sources of technical evidence, not instructions authorizing changes
to this repository. This phase follows the user's synthetic-only implementation scope.

## Primary source register

| ID | Source and version | Sections consulted | Use in this phase |
|---|---|---|---|
| S1 | [W3C Bitstring Status List v1.0, Recommendation 15 May 2025](https://www.w3.org/TR/2025/REC-vc-bitstring-status-list-20250515/); [latest published entry](https://www.w3.org/TR/vc-bitstring-status-list/) | §2.1–2.2 data model; §3 algorithms; §6 privacy; §7.1 bit encoding and §7.2 validity periods | Published batch-status baseline and explicit nonconformance comparison |
| S2 | Tobias Looker, Paul Bastian, Christian Bormann, [Token Status List, draft-ietf-oauth-status-list-21](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html), 21 June 2026 | §4.1 packing; §8 validation; §11.3 trust/§11.5 caching; §12 privacy; §13.2–13.3 reissuance/allocation and §13.7 expiry/caching | Packing comparison and system concerns; work in progress |
| S3 | [IETF datatracker for Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/) | Version and publication-status metadata | The observed document is draft -21; no published-RFC claim |
| S4 | James Larisch, David Choffnes, Dave Levin, Bruce M. Maggs, Alan Mislove, Christo Wilson, “CRLite: A Scalable System for Pushing All TLS Revocations to All Browsers,” IEEE Symposium on Security and Privacy, 2017, pp. 539–556, DOI [10.1109/SP.2017.17](https://doi.org/10.1109/SP.2017.17) | Abstract and introductory architecture/motivation | Peer-reviewed antecedent for proactive revocation distribution; different domain/construction |
| S5 | [SQLite: Atomic Commit](https://www.sqlite.org/atomiccommit.html) | §2 assumptions, §3 single-file commit, §4 rollback, §9 failure modes | Rationale and limits for atomic snapshot/epoch persistence |
| S6 | [SQLite: Transaction](https://www.sqlite.org/lang_transaction.html) | §2 transactions, §2.2 DEFERRED/IMMEDIATE/EXCLUSIVE | Writer serialization and transaction behavior |

For S4, the [author-hosted paper](https://www.cs.umd.edu/users/dml/papers/crlite_oakland17.pdf)
was read; [Duke's institutional publication record](https://scholars.duke.edu/publication/1266845)
confirms authors, venue, pages and DOI. This is one directly relevant peer-reviewed
reference, not a claim of an exhaustive status/privacy literature review. No performance
number from that paper is presented as a measurement of this implementation.

S2 expires on 23 December 2026 according to its header. Its draft status must remain
visible in a thesis citation; future revision or publication may change details. No code
from standards examples was copied into the implementation, and no external conformance
suite was run. The cryptography profile reuses the project's Phase 1 design and library
utilities; the original sources remain in
[Phase 1 sources](../phase-01/07_sources_and_assumptions.md).

## Standards comparison and reusable concepts

The product label is **Research Bitstring Status List — Not W3C Conformant**.

W3C defines VC status entries/credentials, GZIP plus multibase base64url encoding,
proof processing, a default minimum 131,072-bit list with ecosystem-specific provisions,
and index zero at the leftmost bit. Its privacy and validity sections informed the
questions considered here. This prototype instead uses dense assigned positions,
LSB0, uncompressed standard base64 and a custom signed JSON envelope. It implements
neither the VC data model/proofs nor W3C's complete validation requirements. [S1]

IETF draft -21 uses low-to-high bit packing and DEFLATE/zlib with JSON/CBOR and
JOSE/COSE representations. Our one-bit LSB0 convention matches that packing direction
only. The custom envelope, required expiry, local maximum-age rule and permanent
revocation lifecycle are our own research choices. They do not make this a Token Status
List implementation. The draft's trust, allocation, reissuance and caching discussions
help identify relevant design questions. [S2]

The reusable high-level concept is a signed batch of statuses with an authenticated
entry reference. The implemented differences are deliberate and testable, not accidental
claims of wire compatibility. A future standards adapter would require a separate format
boundary, proper validation/proof handling and conformance testing.

## Evidence ledger for major claims

| Claim | Evidence | Strength and boundary |
|---|---|---|
| Phase 1 behavior preserved | Original 79 tests; baseline hash manifest; T226; final report | Tested regressions and unchanged historical files, not proof of all behavior |
| Credentials are unchanged | Registry calls original issuance; schema/version untouched; demo compares QR bytes | Direct source/test evidence for synthetic protocol |
| Sidecar authenticates assigned index | Binding signature, role trust, UUID/digest/key/context checks; T204–206/T218–219/T228 | Under trusted issuer allocation and uncompromised keys |
| Deactivation reaches reissued credentials | Registry ownership loop; T210/T211/T227; small registry benchmark assertions | Implemented synthetic lifecycle, not UIDAI semantics |
| Snapshot modification rejected | Complete signed payload; T212–214 and malformed metadata cases | Library cryptography assumptions and bounded parser model |
| Ordinary restart retains rollback history | SQLite row and metadata checks; T215/T216/T229 | Trusted local storage; complete-state rollback excluded |
| Update commits snapshot and epoch together | Single SQLite transaction, failed-write/concurrent-writer tests; S5/S6 | Application-level failures tested; hardware power loss untested |
| Stale evidence cannot produce an accepted bit result | Freshness inequalities, injected clock, T217/T224/T225 | Honest/appropriate local time assumed |
| Local verification does not contact issuer | Code path and T221's active Python network guard | No online fallback; not a whole-OS traffic certification |
| No private subject mapping in public output | Data structures; T223 payload/log assertions | Direct-field minimization, not unlinkability proof |
| Size/timing results are measured | Raw samples/metadata in results JSON/CSV | One Apple M2, one run configuration, seven repetitions |
| Batch status is prior art | S1/S2 and different-domain antecedent S4 | No novelty claim for bitmap, signatures or caching |
| Real Aadhaar identity-level binding remains unresolved | Phase 1 evidence review; no real data/issuer integration added | This phase creates a synthetic mapping rather than discovering a real one |

Source code and tests establish implementation behavior; standards establish the content
of those standards. Neither kind of evidence alone establishes suitability for a real
identity service. Candidate contributions are explicitly separated in
[research findings](06_research_findings.md).

## Implemented assumptions and why they matter

| Assumption | Implementation consequence | If it does not hold |
|---|---|---|
| Issuer controls truthful private ownership | Registry groups all credentials for one subject | Wrong grouping produces wrong identity-level propagation despite valid signatures |
| Three role keys and namespace are authorized out of band | `IssuerTrust` pins credential, binding and snapshot roles | A self-declared key cannot establish authority |
| Private signing keys remain uncompromised | Library RSA-PSS authenticates issuer statements | Key compromise can create valid false bindings/statuses |
| Issuer uses this declared permanent lifecycle | No clearing, deletion or reuse; newer snapshots cannot regress | Other lifecycle semantics require a new explicit policy/protocol |
| Default volatile registry uses a fresh namespace | New process does not accidentally restart slots under the old list | Explicit old namespace reuse without restored state is unsupported |
| Holder obtains sidecar at issuance | Offline verifier can authenticate the slot locally | Missing sidecar yields MISSING_BINDING; no network fallback |
| Verifier retains trusted local cache history | Epoch/digest survive ordinary restart | Restoring all state can erase evidence of a higher epoch |
| Local time is suitable for the policy | Maximum age/expiry are meaningful | Clock manipulation can make old evidence appear acceptable |
| Latest unseen events are unknowable offline | As-of decision or conservative stale failure | Current status cannot be guaranteed without newer evidence |
| Snapshot population is at most ten million | Bounded parsing/bitmap/memory design | Larger input is rejected; theoretical size is not measured support |
| Ordinary logs need no identifiers | Results omit subjects, UUIDs and indices | Debug/private issuer APIs must not be republished as a public registry |

The issuer is not durable and its keys are not saved. Thus no persistent development-key
initialization workflow is needed or claimed. The demo retains only public synthetic
artefacts when explicitly requested. A retained public key is a usable trust anchor only
if its authorization is established independently; opening a PEM from an unknown bundle
is insufficient. The demo's own in-memory generation is the local authorization context.

Freshness uses integer Unix seconds. Expiry is exclusive, maximum age is inclusive, and
future issued-at values are rejected without clock tolerance. These are declared policy
choices, not a measured recommendation for hospitals, banks or other Aadhaar use cases.
The four-day schedule is injected test data. It is not thesis P3 empirical analysis.

## Unsupported claims and deliberately absent work

The project does not establish any of the following:

- Access to real UIDAI revocation, death or deactivation records.
- Compatibility with unchanged Aadhaar Secure QR or an actual issuer's sidecar service.
- A stable identity binding inferred from last-four digits, demographics or arbitrary hashes.
- W3C/Token Status List conformance, formal security verification or production readiness.
- Zero-knowledge anonymity, cross-verifier unlinkability or privacy against collusion.
- Guaranteed current status while offline, a trusted clock or global equivocation detection.
- Protection after complete rollback/erasure of all trusted cache history.
- Durable issuer restore, key rotation/recovery, production HTTP distribution or network privacy.
- Compression, authenticated deltas, cryptographic accumulators, Android implementation,
  thesis P2 accountability or thesis P3 empirical freshness evaluation.
- Measured 134-crore deployment, complete giant identity registry or benchmark portability
  to another machine without rerunning the experiment.

Each absent capability is a scope boundary or future dependency, not a silently skipped
acceptance test. Within the authorized Phase 2 synthetic scope, the implemented tests,
CLI, cache, measurements and seven documents are the deliverables. Remaining research
questions must not be promoted to established findings in a presentation or thesis.

## Reproducibility and provenance

The pre-change baseline records original hashes. The final check runner records exact
commands, return codes, stdout/stderr, Python/dependency versions and source hashes.
The benchmark JSON stores deterministic dataset seeds, sample counts, raw measurements
and machine details; CSV provides compact tables. Random ephemeral keys/signatures
remain intentionally nondeterministic; no secret key material is part of the evidence.

Use the saved results as historical observations. Run future experiments into new files
and report changed code, parameters and environment. Do not replace the Phase 1 report
with Phase 2 data. No commit, push, external message or publication is needed to reproduce
the local implementation.
