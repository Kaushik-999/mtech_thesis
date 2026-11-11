# Sources, evidence, and assumptions

Research/access date: **2026-11-10 (Asia/Kolkata)**. This is an evidence review for a
prototype, not an exhaustive literature review or legal interpretation. A source's
publication date and the date we accessed it are different. The user-supplied PDF is
dated 2026-09-24. Its P1 request guides scope; instructions and claims inside it do not
override the user's explicit Phase 1 limits.

## Source register

| ID | Source and exact URL | Section reviewed / access result | Source class |
|---|---|---|---|
| S0 | User-supplied *Aadhaar Offline Verification*, 24 Sep 2026; local `Aadhaar_problem_statement.pdf` | §§1.1–1.2, 2.2 P1–P3, 2.3, reference [1]; six pages extracted with `pdftotext` | Thesis proposal, not an issuer specification |
| S1 | UIDAI, [QR Code Reader](https://uidai.gov.in/hi/qr-code-reader) | Introduction; “What is Secure QR CODE?”; field list; reader description. Page accessible; current site presents English text even on the supplied `/hi/` route | Official UIDAI web page |
| S2 | UIDAI, [Data and Downloads](https://uidai.gov.in/en/data-and-download) | Production Public Key Certificates; UIDAI Digital Signature; Offline e-KYC public key certificates, including Secure QR Code subsection | Official certificate catalogue; no keys imported |
| S3 | UIDAI, [Annual Report 2019–20](https://uidai.gov.in/images/AADHAR_AR_2019_20_ENG_approved.pdf) | §3.12.4, printed p.28, PDF p.39; adjacent §3.12.2 distinguishes Paperless Offline e-KYC | Official PDF, downloaded and text-extracted |
| S4 | UIDAI, [Aadhaar Paperless Offline e-KYC](https://uidai.gov.in/bn/aadhaar-paperless-offline-e-kyc) | Technical Facets → XML Data Format → Element Details → `referenceId`; signature XML sample | Official XML-format description; not adopted as QR byte specification |
| S5 | UIDAI, [Annual Report 2022–23](https://uidai.gov.in/images/UIDAI_Annual_Report-2022-23_English.pdf) | §3.12.6 indexed excerpt; direct web PDF extraction failed with Unicode decoding error | Official-source indexed excerpt; supporting context only |
| S6 | UIDAI, [Aadhaar app FAQ](https://uidai.gov.in/hi/aadhaar-app-faq) | Questions about continued use of printed QR and QR-based verifiable presentations | Official app-context guidance; not a legacy wire specification |
| S7 | Python Cryptographic Authority, [RSA documentation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/) | Generation, signing, verification, PSS and MGF1 | Primary software documentation; implementation verified against installed version |
| S8 | zxing-cpp maintainers, [Python package](https://pypi.org/project/zxing-cpp/) | Python installation/distribution; local installed module exercised | Primary project package information |
| S9 | `aadhaar-offline-kyc` authors, [Rust parser documentation](https://docs.rs/aadhaar-offline-kyc/latest/aadhaar/parser/index.html) | Search-discovered author description of decimal/compressed bytes and fields | Third-party implementation evidence only; no code copied or used |
| S10 | This project, [technical design](02_technical_design.md), [tests/results](04_testing_and_results.md) | Synthetic protocol, counterexamples, measured runtime behavior | Our design and experimental evidence; never UIDAI conformance evidence |

All web sources above were accessed or encountered on 2026-11-10. S3 initially failed
in the web reader because of its size; a direct HTTPS download succeeded and was read
locally. S5's extracted search excerpt was accessible but its full PDF was not read.
The zxing GitHub documentation route failed in the web tool; the project package page
and installed API were available. A candidate official manual URL returned HTTP 503;
it supplies no implementation evidence. Search hits on third-party document mirrors
were not accepted as authenticated UIDAI specifications.

No previous “offline ekyc” repository was opened, cloned, reused, or referenced. No
real QR was requested, uploaded, fetched, or tested. Research browsing and package
installation are separate from the offline verification execution path.

## Local document provenance

Original thesis path:
`/Users/kaushiksarmah999/Desktop/Thesis/Aadhaar_problem_statement.pdf`

SHA-256:
`e3465f4ef473f44353ec3d75c36d5aa976b416ee4c02b7d633f2413195a26114`

S3 downloaded PDF SHA-256:
`b229589294c440bed026bd9aa8f8ece7afa460f5c619dcf3779d750c8861c0dc`

The annual report was read in temporary research storage; copyrighted documents and
the personal thesis attachment are not bundled into this package. Hashes identify
the files reviewed; they do not independently authenticate their authors.

## Claim-level evidence table

“Confirmed by testing” refers only to tests performed here. Documentary confirmation
does not mean we successfully decoded a real Aadhaar QR. Confidence applies to the
specific bounded claim in each row, not to general implementation compatibility.

| Claim | Source URL | Document section | Evidence / reasoning | Confidence | Confirmed by testing? | Remaining uncertainty |
|---|---|---|---|---|---|---|
| P1 asks for offline privacy-conscious status verification | S0: local PDF, no public URL | §2.2 P1, p.2 | Explicit research problem and candidate mechanisms | High as proposal scope | Not applicable | Whether all proposal premises are empirically established |
| Secure QR carries digitally signed content including a photograph | [S1](https://uidai.gov.in/hi/qr-code-reader) | Introduction / What is Secure QR CODE? | Official high-level format description | High documentary | No real QR tested | Exact versions, binary fields and signed-byte coverage |
| A reference ID and a 2048-bit signature are listed | [S1](https://uidai.gov.in/hi/qr-code-reader) | Data stored in QR Code | Explicit listed metadata | High documentary | No | A bit length does not specify padding or a full cryptographic profile |
| Secure QR reference ID includes a suffix and timestamp | [S3](https://uidai.gov.in/images/AADHAR_AR_2019_20_ENG_approved.pdf) | §3.12.4, printed p.28 | Report describes “last 4 digits of Aadhaar and time stamp” | High for described report-era field | No | Timestamp meaning, byte order, collision policy, lifecycle behavior across versions |
| S5 corroborates reference-ID composition in later reporting | [S5](https://uidai.gov.in/images/UIDAI_Annual_Report-2022-23_English.pdf) | §3.12.6 indexed excerpt | Same suffix/time description in official-source search extract | Medium, extraction-limited | No | Full PDF and exact pagination not checked |
| Paperless XML documents a particular referenceId layout | [S4](https://uidai.gov.in/bn/aadhaar-paperless-offline-e-kyc) | Element Details, referenceId | XML specifies suffix followed by `YYYYMMDDHHMMSSmmm` | High for that XML description | No XML support implemented | This is not evidence of QR timestamp byte layout or identical lifecycle semantics |
| XML and Secure QR specifications must not be conflated | [S4](https://uidai.gov.in/bn/aadhaar-paperless-offline-e-kyc), [S1](https://uidai.gov.in/hi/qr-code-reader) | XML Data Format versus QR description | Distinct representations; XML contains signature transforms/canonicalization | High methodological | Adapter rejection tested only | Any formally documented relationship between format versions |
| The download page distinguishes key purposes | [S2](https://uidai.gov.in/en/data-and-download) | Production, response signing, offline XML and Secure QR headings | Separate catalogue subsections | High documentary | No certificate loaded | Which current/historical key and policy apply to a particular QR |
| Catalogue expiry metadata is not enough to validate a historical signature | [S2](https://uidai.gov.in/en/data-and-download) | Secure QR Code table | Listed QR rows show expiry dates in 2020/2021; this is catalogue text, not certificate validation | High for page observation; policy unresolved | No | Key rotation, signing time evidence, compromise/revocation policy, current authoritative distribution |
| App presentation guidance does not specify legacy QR bytes | [S6](https://uidai.gov.in/hi/aadhaar-app-faq) | QR standard and continued support questions | App and printed-QR contexts appear on the same page | High caution; compatibility unconfirmed | No | Version-specific app/printed relationships |
| Decimal conversion, gzip, delimiters and tail offsets are not implemented | [S9](https://docs.rs/aadhaar-offline-kyc/latest/aadhaar/parser/index.html) | Author parser description | Third-party implementation describes such choices; not validated as issuer specification here | Unconfirmed for real deployment | Only refusal of compressed/numeric inputs tested | Official versioned transport rules and authorized conformance vectors |
| RSA/SHA-256 claims in the thesis are not a complete QR implementation contract | S0; [S1](https://uidai.gov.in/hi/qr-code-reader) | Thesis §1.1; QR field list | Proposal asserts crypto details; collected high-level issuer pages do not settle exact byte/padding/version rules | High for evidence gap | No real conformance test | Precise normative profile and boundaries |
| Synthetic RSA-PSS/SHA-256 parameters are explicit project decisions | [S7](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/), [S10](02_technical_design.md) | Signing/verification; synthetic wire protocol | Standard library operations configured with fixed parameters | High for our protocol | Yes: T01/T02/T04–T06, wrong-padding/salt tests | No implication for UIDAI settings |
| Synthetic JSON/base64 preserves exact signed bytes | [S10](02_technical_design.md) | Synthetic wire protocol | Strict schema and original-byte retention | High for implemented format | Yes: parser tests, T03 round trip | No cross-language/general canonical-JSON certification |
| Last four alone cannot uniquely bind an identity population larger than 10,000 | [S10](06_research_findings.md) | Pigeonhole argument | At most 10,000 outputs; ambiguity follows mathematically | Confirmed under stated cardinality assumption | T10 constructs a concrete synthetic collision | No real holder pair is identified or needed |
| A QR hash identifies an artefact, not automatically its subject | [S10](06_research_findings.md) | Identifier matrix | Different reissued bytes produce different digests | Confirmed distinction | T10 synthetic reissuance counterexample | An issuer could maintain a separate mapping; no such registry established here |
| A stable legacy identity-level status binding is available | [S1](https://uidai.gov.in/hi/qr-code-reader), [S3](https://uidai.gov.in/images/AADHAR_AR_2019_20_ENG_approved.pdf) | Reviewed QR descriptions | No lifecycle/registry contract found in collected material | **UNCONFIRMED** | No | Stable handle or historical artefact-to-identity registry and authenticated publication contract |
| Verification has no application network dependency | [S10](04_testing_and_results.md) | T13 and code review | No network client in implementation; guarded subprocess demo passes | High for exercised paths | Yes, Python network APIs blocked | Not an OS packet trace or proof about every native dependency |

## Explicit design assumptions, not external facts

Our version string, fictional-field grammar, UUIDv4 generation, JSON/base64 rules,
RSA-2048 key-size restriction, PSS salt length, trust-pin format, parser limits, image
formats, timeout, CLI exit codes, and unsupported-format behavior are documented
project choices. They require no invented UIDAI layout. Tests establish that this
implementation follows these choices for the exercised cases.

There is no issuance timestamp or expiry in the synthetic schema. Neither is needed
to demonstrate signature integrity; adding one without an actual freshness policy
would invite a misleading status claim. The ID is per credential. A null ID is valid
syntax so missing binding can be reported independently of signature validity.

No photograph, full Aadhaar number, mobile number, email, address, or biometric is
generated. The suffix is illustrative and is not derived from a real number.

## Open research questions

1. What are the authoritative, versioned legacy Secure QR transport and signed-byte
   rules, including compression, boundaries, encodings, and exact crypto parameters?
2. Can UIDAI provide synthetic positive/negative conformance vectors and an appropriate
   historical/current verification-key provenance and rotation policy?
3. What event does the QR timestamp represent? Is it refreshed on issuance, reprint,
   download, or demographic update, and does that differ across versions?
4. Is the reference ID guaranteed unique for an artefact? Is there an issuer-maintained
   relation to a persistent identity, including all previously issued artefacts?
5. Can an issuer authenticate that relation to offline verifiers without exposing
   resident identifiers, enumeration targets, or unnecessary cross-verifier linkability?
6. Can a status update cover all active artefacts of one identity without revealing the
   identity graph? What cooperation and retention would this require?

These questions are prerequisites and research directions. Their appearance here is
not evidence that a corresponding UIDAI interface already exists.

