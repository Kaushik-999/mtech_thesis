# Phase 1 presentation: ten slides with speaker notes

Use the actual demo and [testing report](04_testing_and_results.md) for screenshots and
counts. Keep `SYNTHETIC / NOT UIDAI` visible on every demonstration slide. The word
“verified” should always identify what was checked. This is content for a presentation,
not a claim that a `.pptx` file was generated.

## Slide 1 — Phase 1: a trustworthy verification foundation

**Suggested bullets**

- Privacy-Preserving Offline Aadhaar Credential Status Verification.
- P1 focus: prepare the credential and trust foundation.
- Synthetic implementation plus evidence-led identifier analysis.
- No real Aadhaar status checking in this phase.

**Visual:** A three-stage diagram: credential → signature/trust foundation → future
status mechanism, with the final stage labelled future work.

**Speaker notes:** “The full thesis studies offline status. Before selecting a status
data structure, we need to know which authenticated object identifies the subject.
Phase 1 implements the pieces we can validate and documents the evidence gaps. Our
credentials are deliberately fictional.”

**Viva question:** Why is a synthetic prototype useful for a real-world problem?

**Suggested answer:** It lets us test byte handling, cryptographic correctness, failure
semantics and reproducibility without resident data. It does not establish UIDAI
interoperability; that requires separate specifications, trusted keys and vectors.

## Slide 2 — A signature is not a current status answer

**Suggested bullets**

- A signature protects a fixed message.
- Database lifecycle changes do not change already printed bytes.
- Key trust, holder identity and current status are different decisions.
- Offline status needs authenticated binding and sufficiently recent evidence.

**Visual:** Timeline: issue and sign → later hypothetical deactivation → presentation.
Keep the original signature unchanged along the timeline. Label deactivation as a
conceptual scenario, not an executed status-engine test.

**Speaker notes:** “Cryptography can continue to validate a historical statement even
after its facts become stale. This follows from what a signature checks. Phase 1 does
not measure actual UIDAI reader behavior or assert that every reader accepts every
historical card indefinitely.”

**Viva question:** Why not use a stronger hash or a longer RSA key to solve this?

**Suggested answer:** Stronger cryptography protects the signed bytes more strongly.
It cannot add later lifecycle information or an absent identity-to-status mapping.

## Slide 3 — Objectives and completion boundaries

**Suggested bullets**

- Generate, sign, render, decode and verify synthetic credentials.
- Preserve exact bytes and separate trust from signature validity.
- Handle malformed, oversized, unsupported and missing-key inputs.
- Investigate the identity-level identifier before status design.

**Visual:** A compact checklist with “implemented/tested” for the synthetic path and
“evidence gate” for real compatibility and stable binding.

**Speaker notes:** “The engineering completion criterion is reproducible behavior under
both good and bad inputs. The research criterion permits an honest unconfirmed result.
No accumulator, status list, Merkle tree, mobile application, P2 or P3 engine is built.”

**Viva question:** What counts as success if real QR remains unsupported?

**Suggested answer:** A tested foundation and a defensible feasibility finding satisfy
this phase. Pretending a guessed parser is established would weaken both the engineering
and the thesis. Real support has explicit prerequisites.

## Slide 4 — What the evidence says about Secure QR

**Suggested bullets**

- Official sources describe a signed QR and a reference field.
- The annual report describes suffix/time composition.
- Paperless XML has its own format and reference description.
- Exact legacy parser and lifecycle assumptions remain unconfirmed here.

**Visual:** Three separate labelled boxes: legacy Secure QR, Paperless Offline XML,
and app-based credentials. Put “do not transfer layouts automatically” under the boxes.
Add small source references to the [evidence table](07_sources_and_assumptions.md).

**Speaker notes:** “Our evidence is claim-specific. A high-level list of fields is not a
complete binary parsing specification. A reference that contains a time component is
not automatically stable or globally unique. We do not import XML timestamp encoding
into QR or claim app-based standards describe the legacy printed QR.”

**Viva question:** Did you find an official reference-ID description?

**Suggested answer:** Yes, at a high level in the report-era Secure QR description.
What we did not establish is its complete versioned encoding, lifecycle semantics,
uniqueness guarantee, or authenticated connection to an issuer status registry.

## Slide 5 — Modular architecture

**Suggested bullets**

- Synthetic issuer produces envelope and labelled image.
- Reader separates image decoding from message interpretation.
- Parser returns unverified structured data and original bytes.
- Crypto and trust modules return independent decisions.

**Visual:** Use the architecture Mermaid diagram in the technical design. Highlight the
real-format adapter ending at UNSUPPORTED_FORMAT.

**Speaker notes:** “The raw payload path and image path meet at the same parser. The
native image decoder is optional and isolated. Verification does not need to know
whether bytes arrived from a QR or a local file. This separation makes unit tests and
future evidence-supported adapters easier.”

**Viva question:** Why not put scanning and verification in one function?

**Suggested answer:** They fail for different reasons and prove different properties.
Separating them lets us distinguish an unreadable image, unsupported format, malformed
record, bad signature, and untrusted key without claiming one implies another.

## Slide 6 — Exact-byte digital signature workflow

**Suggested bullets**

- Restricted record → deterministic JSON bytes M.
- Synthetic RSA-2048/PSS with SHA-256 signs M.
- QR carries base64(M) and base64(signature).
- Verify original M; independently compare the public-key pin.

**Visual:** Two lanes: issuer private-key signing and verifier public-key checking.
Add a separate trust-policy box; put `status = NOT_CHECKED_PHASE_1` beneath both.

**Speaker notes:** “PSS uses MGF1-SHA256 and a 32-byte salt. Those are our educational
choices, not claimed UIDAI settings. The message encoding is deterministic, while
PSS signatures use randomness. The cryptography library performs the algorithm.
Base64 makes bytes transportable and provides no confidentiality.”

**Viva question:** Why is the public key not automatically trusted?

**Suggested answer:** An attacker can create a key and sign their own message. A
valid signature proves consistency with the supplied key. Trust needs independent
provenance; our demo knows its own key and real UIDAI trust is not implemented.

## Slide 7 — Implementation and defensive boundaries

**Suggested bullets**

- Python `src/` package; small typed modules.
- `cryptography`, `qrcode`, Pillow and optional `zxing-cpp`.
- Strict schema, duplicate-key rejection and bounded decoding.
- Fixed errors and logs without demographics or credential IDs.

**Visual:** Small module map from the README and a resource-limit table: 8 KiB payload,
2 KiB signed record, 8 MiB image, four million pixels, ten-second worker timeout.

**Speaker notes:** “The parser does not guess real-format decompression or turn a long
numeric QR into a big integer. The worker contains image-library failures. These are
tested controls, not a formal guarantee against every native vulnerability. This is a
local prototype, not a public upload service.”

**Viva question:** What happens if image decoding is not installed?

**Suggested answer:** Image commands return DECODER_UNAVAILABLE. Raw payload parsing
and verification remain available. The demo requires actual image decoding and never
silently substitutes a payload-only path.

## Slide 8 — Demonstration and measured tests

**Suggested bullets**

- Original synthetic image decodes to identical envelope bytes.
- Correct signature: VALID; modified signed field: INVALID.
- Wrong key, wrong signature and untrusted-key cases are distinct.
- All T01–T15 implemented; use recorded suite result and environment.

**Visual:** Screenshot your local `python -m p1qr demo` output and a second cropped
terminal screenshot showing the recorded pytest/Ruff results. The
[JSON report](results/verification.json) contains measured outputs. Do not replace
test counts with a guessed number or present suite time as a benchmark.

**Speaker notes:** “The tamper case remains valid JSON and satisfies the schema. That
means its failure demonstrates cryptographic integrity, not merely a parsing failure.
Network-guard tests disable Python socket APIs in both the CLI and image worker. No
real UIDAI QR was tested.”

**Viva question:** Do all passing tests prove security?

**Suggested answer:** No. They provide evidence for stated behaviors on the recorded
environment. They do not prove absence of every vulnerability, anonymity, status
freshness, or compatibility with a format we did not implement.

## Slide 9 — Identifier-binding feasibility

**Suggested bullets**

- Last four: at most 10,000 values; cannot be a universal unique key.
- QR hash: identifies bytes, not automatically a persistent subject.
- Demographic hash: ambiguity, changes, guessing and linkability risks.
- Reference-ID lifecycle and issuer mapping remain UNCONFIRMED.

**Visual:** Two different synthetic credentials pointing to one suffix. Alongside,
show one fictional subject reissued as two artefact hashes. Use the research matrix
for speaker backup rather than cramming every column onto the slide.

**Speaker notes:** “We deliberately create two signed credentials with the same
suffix. The general claim follows from the pigeonhole principle. Hashing cannot
restore missing identity information. We do not attempt to identify holders through
demographic similarities.”

**Viva question:** Could UIDAI still map a changing QR reference to a status record?

**Suggested answer:** Possibly, if it maintains a complete authenticated relation
from issued artefacts to identities and exposes suitable status evidence. We have not
established that contract. A changing identifier is not proof that such a registry is
impossible, but we cannot assume it exists.

## Slide 10 — Findings, limits and the next evidence gate

**Suggested bullets**

- Tested synthetic verification foundation is complete.
- Real-format verification remains explicitly unsupported.
- Stable legacy identity-level status binding is not established.
- Phase 2: explicit simulated binding contract, then status-mechanism experiments.

**Visual:** Decision gate: “authoritative format + vectors + trust + binding” leading
to real compatibility research; a separate labelled simulated-issuer path leads to
controlled P1 experiments.

**Speaker notes:** “The key contribution of this phase is both engineering and
feasibility analysis. We know which properties we demonstrated and which issuer facts
remain missing. Future comparisons must keep binding, privacy and freshness assumptions
constant. The project does not currently decide whether any Aadhaar identity is active.”

**Viva question:** What exactly would you ask UIDAI for next?

**Suggested answer:** A versioned legacy wire/signature specification, authorized
synthetic vectors, appropriate verification-key provenance/rotation rules, and a
documented identifier lifecycle and identity/status mapping. If a new status handle is
required, that must be an explicit issuer-side change and separately analyzed for privacy.

