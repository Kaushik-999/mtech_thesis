# Phase 1 research findings

## Answer to the critical research question

**A stable, issuer-authenticated identity-level status binding for an unchanged legacy
Secure QR has not been established by the evidence collected.** The prototype therefore
cannot map a real QR to an issuer-maintained deactivation record. This is an evidence
limitation, not a proof that UIDAI could never provide such a mapping.

There is enough evidence to motivate further investigation of reference IDs, but not
enough to assume their uniqueness, reissuance stability, or status-registry semantics.
The correct thesis claim is conditional: offline status mechanisms need an authenticated
binding contract before their status answers can be interpreted as identity-level answers.

## Distinguish four evidence layers

| Layer | What it contributes | What it does not establish |
|---|---|---|
| Thesis proposal S0 | P1 motivation, candidate mechanisms, asserted static-signature problem | Normative wire format, exhaustive deployment facts, issuer registry access |
| Official documentation | High-level Secure QR structure and some reference-ID description | Complete versioned parser contract or demonstrated stable status binding |
| Our synthetic tests | QR transport, integrity checks, local key policy and counterexamples | Real UIDAI compatibility or current resident status |
| Unresolved issuer facts | Needed to turn an artefact into an identity status reference | Cannot be replaced by speculation or demographic matching |

The thesis §1.1 asserts delimited data and RSA/SHA-256; reference [1] points broadly to
the UIDAI website rather than a precise versioned specification. We treat those as
proposal claims requiring technical evidence. The thesis's legal, deployment-scale,
comparative-literature, and new app-credential claims were not independently validated
in Phase 1 and are not presented as findings of this implementation.

Official findings are narrowly recorded in the [evidence table](07_sources_and_assumptions.md).
In particular, the 2019–20 annual report §3.12.4 supports a suffix/time composition for
the Secure QR reference. It does not establish a persistent identity key. The XML
reference description is separately sourced; its exact timestamp notation is not
transferred to QR. ([UIDAI annual report](https://uidai.gov.in/images/AADHAR_AR_2019_20_ENG_approved.pdf),
[XML documentation](https://uidai.gov.in/bn/aadhaar-paperless-offline-e-kyc))

## Identifier decision matrix

“Issuer-authenticated” below means covered by a successfully checked signature **and**
appropriate issuer trust. Parsing alone authenticates nothing. Privacy is assessed
against observation, correlation, and guessing; an opaque string is not automatically
unlinkable.

| Candidate | Unique? | Issuer-authenticated? | Stable across reissuance? | Privacy implications | Can UIDAI map to status? | Infrastructure changes | Binding conclusion |
|---|---|---|---|---|---|---|---|
| Last four Aadhaar digits | No for an identity set larger than 10,000 | Only if the supported signed format covers them; not verified here | May be the same for the same number, but this cannot repair ambiguity | Small enumerable space; reveals a suffix and creates false matches | Not uniquely from suffix alone | Additional authenticated mapping information needed | **NOT POSSIBLE UNDER STATED ASSUMPTIONS** as the sole unique identity key |
| QR reference ID | Global uniqueness not established | Described as part of signed content; byte-level coverage untested | No guarantee; depends on timestamp/issuance lifecycle | Repeated reference can link presentations; embedded suffix/time may expose context | **UNCONFIRMED**; requires issuer contract/registry evidence | Possibly historical artefact mapping and authenticated distribution | **UNCONFIRMED** |
| Documented timestamp component | Not unique alone | Only if signed bytes and semantics are established | A changed issuance time would not be stable | May reveal issuance/download activity; easily correlated with auxiliary information | A time alone cannot choose one resident | Additional unique mapping is needed | **NOT POSSIBLE UNDER STATED ASSUMPTIONS** as a sole universal identity key |
| SHA-256 of complete signed QR | Practically unique for a byte artefact under collision resistance | Digest is locally computed; authenticity derives from checking the underlying signature | Not when any covered or wrapper bytes change | Same QR hash is linkable; raw QR still contains visible information | Only with an issuer-maintained mapping of every relevant artefact | Registry/retention and authenticated mapping needed unless already supported | **CONFIRMED** artefact label; identity binding **UNCONFIRMED** |
| Hash of signed demographic fields | No; people may share fields; normalization choices introduce ambiguity | Underlying fields may be signed; chosen projection/hash is verifier-derived | No guarantee after demographic changes | Dictionary guessing and cross-verifier linking; hash is not anonymization | No justified unique mapping from resemblance | Correct linkage would need stronger issuer information | **NOT POSSIBLE UNDER STATED ASSUMPTIONS** as a guaranteed identity key |
| Hypothetical issuer-assigned unique status ID | Can be designed unique with issuer enforcement | Yes if explicitly signed or authenticated in a binding record | Can be designed stable with lifecycle policy | Global stable ID enables correlation; scoped/privacy mechanisms need separate analysis | Yes by design if issuer maintains the relation | Issuer issuance/registry/publication changes or cooperation | **CONFIRMED only as a conditional design requirement**, not an existing Aadhaar feature |
| Our synthetic UUIDv4 | Collision probability negligible, not a mathematical uniqueness guarantee | Yes under a valid signature and local synthetic pin | No: newly issued credentials receive new UUIDs | Opaque but repeated presentation is still linkable | No connection to UIDAI | A new simulated identity registry would be needed | **CONFIRMED** signed artefact ID only |

No row asserts that an actual UIDAI parser ran here. A hypothetical issuer's uniqueness
guarantee also needs collision handling and lifecycle rules; merely choosing random
values is not an operational registry contract.

## Last-four collision argument

Let `f(i)` return the four decimal digits for identity `i`. Its codomain has at most
`10^4 = 10,000` elements. For a set `I` with `|I| > 10,000`, `f` cannot be injective:

\[
\exists i\ne j\quad f(i)=f(j).
\]

Suppose only identity `i` becomes deactivated. A rule that marks every presentation
with suffix `f(i)` as deactivated wrongly marks `j`. A rule that accepts the suffix
because `j` is active wrongly accepts `i`. No data structure or stronger signature
can recover information discarded by this many-to-one mapping.

`run_binding_experiment()` creates two distinct fictional records, signs both with the
same local key, and verifies both under the locally accepted fingerprint. The records
share the suffix but have different UUIDs. The measured output confirms both signatures
and the collision. It demonstrates ambiguity without finding or disclosing any real
holder's information.

The synthetic counterexample is an illustration. The general insufficiency claim
comes from the cardinality argument, not from pretending two fictional records prove
the details of UIDAI's issuance database.

## Why hashing does not solve identity binding

Let `h(c) = SHA256(bytes(c))`. Collision resistance makes it useful as an artefact
fingerprint. It does not imply:

\[
\operatorname{subject}(c_1)=\operatorname{subject}(c_2)
\Longrightarrow h(c_1)=h(c_2).
\]

The experiment reissues the fictional subject with a fresh credential ID and observes
a different complete-envelope hash. Changes to metadata, fields, serialization, or
signature can produce another hash as well. Our PSS signatures are randomized; no
assumption about UIDAI's signature randomness is required for the artefact/identity
distinction.

Similarly, hashing selected demographics gives a deterministic function of those
fields, not an authoritative person identifier. Two people with identical selected
fields yield the same hash. One person's corrected fields can yield another hash.
Guessable field combinations allow offline guessing attacks. We implement no inference,
clustering, or identity resolution based on demographic similarity.

## What our tests establish

The [testing report](04_testing_and_results.md) records the actual environment and
results. The synthetic path demonstrates exact image round-trip bytes; acceptance of
the original signature; rejection of changed message, changed signature, wrong key,
wrong padding and wrong salt; separate pin-based trust; explicit absent-identifier
handling; and structured bounded-input failures. Guarded verification completes with
Python network operations disabled. Normal logs omit the exercised payload data.

These are engineering foundations, not measurements of Aadhaar deployment compatibility,
privacy under colluding verifiers, status freshness, national-scale bandwidth, or mobile
performance. No revocation status test was possible because no status engine exists.

## What UIDAI cooperation might resolve

The next evidence request should ask for precise versioned legacy format documentation
and authorized synthetic conformance vectors, plus verification-key provenance and
rotation rules. For binding, ask for reference-ID lifecycle semantics and whether an
issuer-authenticated relationship exists from every issued artefact to a persistent
identity/status handle.

If no usable binding is available in unchanged QR, options for later research include
issuer-added signed status identifiers or separately signed binding records. A registry
covering historical artefacts may be possible, but its completeness, privacy leakage,
issuance retention, and publication authorization must be established. These are
hypotheses to study; no such UIDAI service is claimed here.

## Safe assumptions for Phase 2

- Reuse the tested synthetic transport/verification foundation.
- If building a simulated status experiment, explicitly add a simulated issuer's
  identity-to-credential mapping and state its lifecycle rules.
- Keep signature, issuer trust, binding, status authenticity, and freshness as separate
  decisions. “Not found” must not automatically mean active without a justified model.
- Compare mechanisms only under the same binding and privacy assumptions.
- Do not claim unchanged Aadhaar compatibility until the real evidence and conformance
  gate is met. A paper may report the binding gap itself as a substantive feasibility
  finding, with its evidence limits stated.

