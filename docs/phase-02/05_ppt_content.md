# Phase 2 presentation: 15 slides with speaker notes and viva answers

Suggested duration: 18–22 minutes plus the short live CLI demonstration. Put
**Synthetic issuer experiment — no real UIDAI status check** on the title and results
slides. Numerical results below come from [the saved measurements](results/benchmarks.json).
“Phase 2” is the implementation milestone; it is not thesis problem P2 accountability.

## Slide 1 — Research problem: status checking while disconnected

**Technical bullets**

- P1 asks for offline detection of credentials belonging to a deactivated identity.
- Per-person issuer requests can reveal who a verifier is checking.
- A public identity-to-status directory can enable surveillance.
- Work with a simulated issuer because real identity-level binding remains unconfirmed.

**Suggested diagram:** holder → disconnected verifier; issuer → periodic full snapshot;
draw the private subject mapping only inside the issuer boundary.

**Speaker notes:** Start with two separate questions: “Was this credential signed?” and
“What status information do we possess now?” The original signature cannot change when
an event happens later. The research challenge includes delivery, freshness and privacy,
not only cryptographic computation. Our implementation investigates a conditional issuer
contract; it does not invent undocumented UIDAI behavior.

**Viva question:** Why not simply contact the issuer for each presentation?

**Suggested answer:** Connectivity may be unavailable, and a person-specific query
reveals an interaction to the issuer. A full cached list lets the implemented verifier
read a bit locally, though stable identifiers and update metadata still leak information.

## Slide 2 — Phase 1 foundation and its binding limit

**Technical bullets**

- Synthetic RSA-signed credentials, QR generation and bounded decoding.
- Original message bytes verified; key trust reported separately.
- Last-four suffixes collide; credential UUIDs identify artefacts, not necessarily subjects.
- All 79 original tests and historical documentation preserved.

**Suggested diagram:** QR → exact bytes → parser → signature state + signer trust;
show an unresolved arrow from real credential artefact to identity-level lifecycle.

**Speaker notes:** Phase 1 gives a reliable local credential-processing foundation.
It does not establish that a real UIDAI credential exposes a suitable stable status
binding. Phase 2 reuses its unchanged synthetic credential and adds an explicit signed
sidecar. This keeps the new assumption visible and testable.

**Viva question:** Can SHA-256 of an arbitrary QR serve as an Aadhaar identity ID?

**Suggested answer:** No. Reissuance can change the artefact, and a digest alone does
not authenticate a relation to an issuer's identity-level status record. Here a digest
only matches a sidecar to the exact signed synthetic message.

## Slide 3 — Why a valid signature can accompany revocation

**Technical bullets**

- A signature authenticates a fixed message under a key.
- Later deactivation does not alter that message or its signature.
- Current decisions need separately authenticated, time-bounded status evidence.
- NOT_REVOKED_AS_OF_SNAPSHOT is intentionally weaker than current identity validity.

**Suggested diagram:** unchanged credential/signature across a timeline; status bit
changes from zero in epoch 1 to one in epoch 2.

**Speaker notes:** Use the library-card analogy: the seal on a card remains genuine
after the library closes the account. The librarian needs a newer cancellation sheet.
There is no contradiction between VALID signature and REVOKED status. Each answers a
different question and is returned in a separate field.

**Viva question:** Why not call zero “ACTIVE”?

**Suggested answer:** Zero says only that this assigned position is not revoked in a
particular accepted snapshot. Unknown later events, a missing entry or stale evidence
cannot justify a present-day identity claim.

## Slide 4 — Phase 2 objectives and acceptance gates

**Technical bullets**

- Private synthetic ownership registry and irreversible subject deactivation.
- Authenticated credential-to-index binding without changing Phase 1 credentials.
- Signed full bitmaps, durable cache, epoch rollback checks and freshness policy.
- Offline integration, adversarial tests, measured benchmarks and privacy analysis.

**Suggested diagram:** five gates: credential signature → signer trust → binding →
snapshot acceptability → status bit.

**Speaker notes:** Emphasize that a failed gate stops processing and produces an explicit
reason. Parsing alone does not authenticate. A valid binding does not excuse an expired
snapshot. The implementation has no per-person network fallback. Accumulators, Android,
P2 accountability and P3 empirical freshness are later work.

**Viva question:** Are these five gates just one boolean in the API?

**Suggested answer:** No. `OfflineResult` contains separate signature/trust/match/
acceptability fields, a decision code and authenticated snapshot metadata when available.
An expired snapshot can have a valid signature while remaining unacceptable.

## Slide 5 — Simulated issuer architecture and lifecycle

**Technical bullets**

- Internal subject ID is private; credential UUID and status index are distinct.
- One subject can own many credential/index pairs.
- ENABLED → DEACTIVATED is permanent in this synthetic policy.
- Reissuance uses a fresh UUID/index; deactivation revokes every sibling and blocks issuance.

**Suggested diagram:** Subject A → C1/index 0 and C2/index 1; Subject B → C3/index 2.
Draw the subject layer inside a shaded private registry box.

**Speaker notes:** Single-credential revocation and subject deactivation differ. Revoking
C1 alone leaves C2 unchanged. Deactivating A sets both bits. The registry is volatile and
single-process; each fresh default registry gets a fresh list namespace. We do not claim
production recovery, nor real death-record or Aadhaar suspension semantics.

**Viva question:** Could reissuance reactivate a deactivated subject?

**Suggested answer:** Not through this API. Issuance checks subject state before signing.
Reissuance calls the same path. Old slots are never cleared or recycled, and tests cover
deactivation across siblings while leaving another subject unaffected.

## Slide 6 — Issuer-authenticated binding sidecar

**Technical bullets**

- Signed fields: protocol, issuer/list, credential UUID, exact-message digest and key ID, index.
- Binding role has a separately configured public-key trust anchor.
- Holder receives the sidecar at issuance and presents it with the credential offline.
- No index derived from demographics, suffixes, unsigned mapping or arbitrary hashes.

**Suggested diagram:** original Phase 1 message ↔ signed sidecar → list namespace/index;
put a signature check over the entire sidecar arrow.

**Speaker notes:** The sidecar is an explicit new presentation artefact. Its digest
prevents a sidecar for one message being reused with another message sharing a UUID.
The binding verifier checks all context fields after authenticating the role key.
An unchanged printed Aadhaar QR does not magically acquire this assertion. Sidecars
also expose a stable association to anyone who receives them.

**Viva question:** Does a signed sidecar prove globally unique allocation?

**Suggested answer:** It authenticates the issuer's statement. Our registry enforces
uniqueness locally, but a malicious issuer can sign conflicting assignments. A lone
verifier without a global issuer audit cannot establish that no such statement exists.

## Slide 7 — Research Bitstring Status List — Not W3C Conformant

**Technical bullets**

- One bit per assigned credential: 0 not revoked in snapshot; 1 revoked.
- Index `i`: byte `i // 8`, mask `1 << (i % 8)`; LSB0 ordering.
- Raw size `ceil(N/8)`; unused padding is zero and never a valid entry.
- Reuses published batch-status concepts, with a deliberately separate research wire format.

**Suggested diagram:** two bytes with positions 0…8; mark 0, 7 and 8 revoked, producing
hex `81 01`. State that conventional binary text displays the most significant bit first.

**Speaker notes:** Explain how eight yes/no values fit in one byte. Direct access to a
validated byte array is constant-time in index computation. Our ordering differs from
the W3C convention and matches only the one-bit packing direction of the consulted IETF
draft. We implement neither standard's complete envelope, compression or validation model.

**Viva question:** Why must assigned count be signed too?

**Suggested answer:** The last byte can have unused zero padding. Without an authenticated
range, an attacker might claim an unassigned zero slot as evidence of non-revocation.
The verifier rejects every index at or beyond the signed count.

## Slide 8 — Complete signed snapshot

**Technical bullets**

- Protocol, issuer/list, monotonic epoch, issued-at, expiry, assigned count, bit order.
- Encoded bitmap, bitmap digest, algorithm and key ID are all signed.
- RSA-2048/PSS/SHA-256 through `cryptography`; original signed bytes verified.
- Snapshot role is independently trusted; no key self-authorization from the document.

**Suggested diagram:** one box enclosing all signed fields, with a signature below;
outside it show the independently configured snapshot public key.

**Speaker notes:** A signature over only the bitmap would leave critical metadata
unprotected. This implementation signs the complete state and imposes strict JSON,
base64, numeric and size limits. The bitmap digest is a consistency field, not an extra
source of trust. PSS signatures are randomized even for the same message.

**Viva question:** Does a signed expiry establish trustworthy time?

**Suggested answer:** It authenticates an issuer statement about a deadline. The verifier
still needs an appropriate local time source. A manipulated clock can undermine age
checks; this phase uses an injected clock for tests and local wall time by default.

## Slide 9 — Offline verification algorithm

**Technical bullets**

- Parse and verify original credential; establish credential-role trust.
- Verify sidecar; match UUID, message digest, key, issuer/list; recover authenticated index.
- Reload/authenticate cache; check metadata and time; range-check and read bit.
- Return explicit evidence and result without issuer contact.

**Suggested diagram:** flowchart with failure exits for invalid signature, missing
binding, missing/stale snapshot and out-of-range index.

**Speaker notes:** Freshness accepts only `issued_at <= t < expires_at` and
`t - issued_at <= maximum_age`. An empty or corrupt cache is not an all-zero list.
The current integration revalidates the complete snapshot on every call. A primitive
bit-lookup benchmark is therefore not an end-to-end verification benchmark.

**Viva question:** What if the credential is valid but the binding is missing?

**Suggested answer:** Return MISSING_BINDING. The credential signature/trust can still
be reported, but the status stages remain unchecked. Guessing a slot would break the
authenticated association the protocol requires.

## Slide 10 — Cache persistence and rollback protection

**Technical bullets**

- SQLite transaction stores signed bytes, highest epoch and message digest together.
- Lower epoch rejected; same-epoch different message rejected as equivocation.
- Higher epoch cannot reduce count/time or clear permanently revoked bits.
- Missing/corrupt state fails; ordinary restart preserves history.

**Suggested diagram:** epoch 1 → atomic commit epoch 2; replay epoch 1 hits rejection;
show the database as the trusted local-history boundary.

**Speaker notes:** `BEGIN IMMEDIATE` serializes cache writers. One transaction avoids
a snapshot file and a separate epoch file disagreeing after an interrupted write.
Same message with a new randomized signature is idempotent. Tests simulate failed writes
and concurrent synchronization. Full trusted-storage rollback and unseen issuer forks
remain outside the guarantee.

**Viva question:** Can the verifier detect restoration of the entire database to yesterday?

**Suggested answer:** Not with this local history alone. The high-water record would
also be restored. An independently protected monotonic state or other trusted evidence
is needed to address that stronger attacker.

## Slide 11 — Privacy achievements and remaining leakage

**Technical bullets**

- No per-person issuer query in normal verification; no private subject IDs in lists/logs.
- Offline verifier sees credential UUID, sidecar index and presentation information.
- Public snapshots expose assigned count, revoked counts and change patterns.
- Future downloads reveal metadata; colluding verifiers may link stable presentations.

**Suggested diagram:** five actors—issuer, verifier, network observer, holder, public-list
observer—with a small label for the information each can see.

**Speaker notes:** Batch distribution reduces one channel of issuer observation. It
does not give zero-knowledge anonymity. Simultaneous changes may suggest sibling groups;
outside data can associate an opaque index with a person. Sequential allocation can
expose relative issuance order. The implemented demo uses local byte transfer, so network
metadata is a design threat, not a measured network experiment.

**Viva question:** Is hiding names enough to guarantee unlinkability?

**Suggested answer:** No. Stable UUIDs, index/list pairs, sidecars and repeated status
patterns can link observations. Privacy claims must name the observer and available
auxiliary information rather than rely only on removal of direct identity fields.

## Slide 12 — Live demonstration: same credential, changed status

**Technical bullets**

- Run `python -m p1qr phase2-demo`.
- Day 1 epoch 1: NOT_REVOKED_AS_OF_SNAPSHOT.
- Day 2 deactivation; Day 3 old evidence still zero, or STALE under stricter age policy.
- Day 4 epoch 2: original signature VALID, status REVOKED; tampering/rollback rejected.

**Suggested diagram:** four-day timeline showing issuer event and verifier knowledge
on different rows. Avoid displaying private IDs or full payloads on slides.

**Speaker notes:** The clock is simulated; no system-clock changes or waiting occur.
Default files are temporary. For a retained public example, use a new directory with
`--output phase2_output/demo`. The demo includes reissuance, so subject deactivation
sets both applicable positions. Point to the unchanged signature result after the update.

**Viva question:** Is the Day 3 zero a software bug?

**Suggested answer:** No. It is correct about epoch 1. The failure would be presenting
that evidence as knowledge of Day 3's current identity state. Maximum age controls when
the verifier must refuse an outdated decision, but cannot communicate an unseen event.

## Slide 13 — Tests and measured synthetic results

**Technical bullets**

- 169 passing tests: 79 original + 90 Phase 2; T201–T230 covered.
- Tampering, wrong trust/context, range/time, rollback, cache failures and network guard tested.
- At 10 million entries: raw 1,250,000 B; signed full update 2,223,153 B.
- Apple M2 median full snapshot validation 69.426 ms; seven runs, 1% revoked, fixed seed.

**Suggested diagram:** storage versus 10k/100k/1m/10m entries, beside full validation
latency. A separate tiny chart may show authenticated lookup batch means (~120 ns/op).

**Speaker notes:** State units and timed boundaries. Signing median at 10 million is
34.798 ms; SQLite reload plus validation is 70.334 ms. The lookup excludes parsing,
signatures, disk and binding, so never put it beside a claim of complete verification
speed. p95 is the nearest rank of seven batch means, with limited statistical strength.

**Viva question:** Did you simulate ten million complete identities?

**Suggested answer:** No. Large tests allocate a bitmap and an oracle set. Separate
small registry tests measure real issuance and fan-out 1/5/25. This avoids an artificial
object explosion and keeps claims aligned with the component actually measured.

## Slide 14 — Findings, limitations and contribution boundaries

**Technical bullets**

- Established batch-status techniques can support this explicit synthetic issuer contract.
- Working integration preserves credential bytes and separates all evidence decisions.
- Storage/distribution and snapshot parsing grow with list size; indexed access is small.
- No real UIDAI compatibility, production key recovery, global equivocation detection or anonymity claim.

**Suggested diagram:** evidence ladder: published mechanism → implemented contract →
tested synthetic behavior → candidate research questions requiring further evidence.

**Speaker notes:** Implementation is a research artefact, not proof of a novel primitive.
The useful experimental result is a reproducible baseline with visible assumptions.
Privacy, lifecycle binding and stale evidence are as important as timing. One host and
one configuration do not establish broad deployment suitability.

**Viva question:** What is the candidate contribution beyond implementing a bitmap?

**Suggested answer:** A rigorously specified and evaluated lifecycle/binding/privacy
comparison could become a systems contribution. Novelty needs broader literature review
and comparative evidence; the bitmap and signed-cache mechanisms themselves are prior art.

## Slide 15 — Next milestone: a fair accumulator comparison

**Technical bullets**

- Keep the same synthetic lifecycle, binding contract, trust model and result semantics.
- Select a reviewed accumulator construction and explicit security assumptions.
- Define witness issuance, update delivery, missed-update recovery and revoked-holder behavior.
- Measure complete verification, issuer updates, storage, bandwidth and privacy together.

**Suggested diagram:** shared dataset/lifecycle harness branching to current bitstring
baseline and a future accumulator implementation, feeding the same metrics table.

**Speaker notes:** Accumulators are not implemented in this phase. Smaller verifier
state may shift cost into witnesses, setup or updates. Do not assume an accumulator
automatically hides holders or solves stale data. Android, accountability and empirical
use-case freshness remain separately scoped work. Real legacy compatibility remains a
separate issuer-evidence gate for either mechanism.

**Viva question:** What must be settled before writing accumulator code?

**Suggested answer:** Construction and assumptions, trusted setup requirements, precise
membership/non-membership statement, witness lifecycle, offline update model and a fair
benchmark plan. Otherwise a comparison might omit the mechanism's most expensive or
privacy-sensitive operations.
