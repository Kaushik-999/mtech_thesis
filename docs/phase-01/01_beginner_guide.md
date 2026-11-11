# Phase 1 beginner guide

## What you are building

Imagine a university issues a signed paper certificate. Checking its seal answers,
“Does this match a certificate signed with this key?” It does not answer, “Is the
student still enrolled?” Current enrollment needs a separate, sufficiently recent
source. This project studies the same distinction for offline credentials.

Phase 1 builds the seal-checking foundation with fictional data. It deliberately does
not invent the missing connection between a legacy Aadhaar QR and a current identity
status record. Your thesis PDF, §2.2 P1, motivates later offline status research. Its
claims are research input, not an executable protocol specification.

There are four useful questions:

1. Can I read the QR pixels and recover bytes?
2. Do those bytes follow a format I understand?
3. Does the signature match, and do I trust the signing key?
4. Can the authenticated credential be connected to a current issuer status record?

Only the first three are implemented, using our synthetic protocol. The fourth is
investigated, with a negative evidence finding: a real identity-level binding has not
been established.

## Python terms before you begin

A **module** is one Python file, such as `crypto/keys.py`. A **function** is a named
operation, such as `generate_private_key()`. A **package** groups modules; here it is
`p1qr`. `__init__.py` marks each package and explains its role. `__main__.py` makes
`python -m p1qr` run our command-line entry point.

The `src/` layout puts importable application code under `src/p1qr`. Installation
tells Python where it is. This avoids accidentally testing an uninstalled package
just because your terminal is in the repository directory. `tests/` contains examples
that assert behavior. `docs/` contains the reasoning you can use in a presentation.

A **virtual environment** is a private shelf of Python packages for this project.
It keeps our dependency versions separate from other projects. `pyproject.toml` is the
installation recipe. An **extra**, such as `scanner`, adds optional dependencies.
`uv.lock` records a complete dependency resolution for repeatable setup.

A type hint such as `data: bytes` explains the expected input. It helps a reader and
development tools; it is not automatic runtime validation. The parser still explicitly
checks lengths, field types, and allowed values.

## QR codes, bytes, and encoding

A QR code is a way of printing a message as black and white modules. A barcode decoder
recovers the message; it does not know whether the message is truthful or signed.
An attacker can generate a perfectly readable QR containing a lie.

Computer signatures operate on **bytes**, not the visual meaning of text. For example,
ASCII text `A` is the byte with decimal value 65. The character sequence `AB` has two
bytes. Different spaces or character encodings can produce different byte strings,
even when a person reads the same words.

Our protocol uses JSON, a structured text representation. The educational record has
fields like `"fictional_name":"Fictional Resident A"`. We sort field names and remove
unnecessary spaces so the same valid record always produces the same message bytes.
We allow only narrowly constrained strings and null; numbers are not protocol fields.
This avoids floating-point and numeric representation questions.

**Base64** turns binary data into printable characters. For example, the bytes for
`AB` become `QUI=`. Anyone can reverse this. Base64 is packaging, not encryption.
The signature bytes and the exact signed message are both base64-encoded inside an
outer JSON envelope.

| Stage | Input | Output | What it proves |
|---|---|---|---|
| Scanning/capture | Printed QR | Image pixels | Nothing about authenticity |
| Decoding | PNG/JPEG pixels | Raw message bytes | A QR was readable |
| Parsing | Message bytes | Structured, untrusted fields | Schema is understood |
| Signature verification | Exact signed bytes, signature, public key | Valid/invalid | Key/message consistency |
| Trust evaluation | Key and independently accepted fingerprint | Trusted/untrusted | Local synthetic signer policy |
| Status verification | Bound identifier and fresh issuer status evidence | Future work | Not performed in Phase 1 |

The prototype reads existing images; it does not implement camera capture.

## Digital signatures without hand-written cryptography

A **private key** is the issuer's signing secret. A **public key** is the corresponding
verification material. People who receive the public key can check signatures but
cannot feasibly create valid signatures for changed messages under ordinary security
assumptions. Think of a seal whose public inspection pattern is shareable while its
manufacturing secret stays with the issuer.

**RSA** is the asymmetric cryptographic system used here. We ask the maintained
`cryptography` library to create a 2048-bit RSA key with public exponent 65537. We do
not implement prime generation or RSA arithmetic ourselves. Our key is temporary and
unrelated to UIDAI. The program exports only its public part.

**SHA-256** maps a message to a 256-bit digest. A digest is like a compact fingerprint
of bytes. It is not an identity number, and hashing does not automatically hide
guessable information. A bare message hash is not a signature: anybody can hash a
changed message. The private-key operation is what prevents an attacker from creating
the corresponding signature.

RSA signing needs a carefully defined encoding called **padding**. Our protocol uses
RSA-PSS, with SHA-256, MGF1 using SHA-256, and a 32-byte salt. The library implements
this. Salt makes signatures probabilistic: signing the same record twice can produce
different signatures. The *message encoding* is deterministic; the signatures are not.
We do not infer UIDAI's padding from our educational choice.

The verifier passes the original message bytes to `key.verify(...)`. The library
hashes and checks them. Changing `Fictional Resident A` to `Fictional Resident Z` while
keeping the old signature fails. Replacing both data and signature with ones made using
an attacker's key can be mathematically valid under the attacker's public key, which
is why key trust is a separate check.

## Certificates and trust

A **digital certificate** is a signed statement linking a public key to an entity and
usually specifying validity dates and allowed uses. Possession of a certificate file
does not establish that it is the right certificate for this credential. Provenance,
certificate chain, purpose, rotation history, compromise handling, and local trust
policy matter.

This prototype accepts a synthetic public key in PEM SubjectPublicKeyInfo format,
not an X.509 certificate. PEM is a text wrapping format; it is not a proof of trust.
We compute SHA-256 of the DER-encoded public key to obtain a fingerprint. If you
independently accept that fingerprint, the verifier can label the key
`TRUSTED_SYNTHETIC`.

In the demo, trust is straightforward: the program has just generated the private
key in memory, so it knows which public key it intends to trust. With someone else's
credential, copying a pin from the same untrusted bundle would not solve the trust
problem. An attacker could replace both files.

Real UIDAI verification would additionally need a justified parser and independently
validated, format-appropriate issuer key material. No key is silently fetched. The
prototype does not decide whether an old certificate remains suitable for a historical
signature. That requires a documented policy and evidence about signing time and key
compromise.

## Run the project step by step

Open a terminal in the project root:

```sh
cd /Users/kaushiksarmah999/Desktop/mtech_thesis
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[scanner,dev]'
python -m p1qr --help
python -m p1qr demo
```

If using the already prepared workspace, activate `.venv`; no reinstall is necessary.
For a locked setup use the `uv sync --frozen` command in the README. Internet may be
needed during setup but is not needed for local verification.

The demo's successful output includes:

```text
Signature: VALID
Signer trust: TRUSTED_SYNTHETIC
Identifier binding: SIGNED_CREDENTIAL_ONLY
Aadhaar status: NOT_CHECKED_PHASE_1
3. Modified payload with unchanged signature: INVALID
```

These lines were observed during testing. The [testing report](04_testing_and_results.md)
records the complete run and environment. No timing here is a performance claim.

To inspect the generated image yourself:

```sh
python -m p1qr generate-synthetic --output synthetic_output
python -m p1qr inspect --image synthetic_output/credential.png
python -m p1qr inspect --input synthetic_output/credential.p1qr
```

Open `synthetic_output/credential.png` in an ordinary local image viewer. It is visibly
labelled `SYNTHETIC / NOT UIDAI`. Inspection reports only metadata, never decoded
demographics. Inspecting is not verification.

To observe the trust distinction:

```sh
python -m p1qr verify-synthetic --input synthetic_output/credential.p1qr \
  --public-key synthetic_output/public_key.pem
```

It reports a valid signature but untrusted signer and returns exit code 1. To trust
your own freshly generated research key, repeat the command with
`--trusted-fingerprint` followed by the fingerprint printed during generation. The
successful result still does not check Aadhaar status.

If the output directory already exists, choose another name. Files are not silently
overwritten. Without the optional decoder, image commands report `DECODER_UNAVAILABLE`;
raw payload verification still works. The full test suite and demo need the scanner
extra and do not silently fall back to raw input.

Run the experiments and checks:

```sh
python -m p1qr analyze-binding
python -m pytest -q
ruff check .
ruff format --check .
python scripts/check_phase1.py
```

## Why identifiers are the research bottleneck

The synthetic UUID is an **artefact identifier**: a label for one issued credential.
It has no backing resident database. A second credential issued for the same fictional
subject gets another UUID. No function in this project associates those UUIDs with a
real identity.

Last four digits have at most 10,000 possible values. If more than 10,000 distinct
identities must be represented, at least two share a value. This is the pigeonhole
principle: 10,001 envelopes cannot occupy 10,000 pigeonholes with at most one per hole.
The experiment constructs two correctly signed fictional records with the same suffix
and different IDs. A good signature authenticates an ambiguous suffix; it does not
make it unique.

Hashing a complete QR can identify its bytes. A reissued QR can have different bytes,
so its hash changes. Hashing name/address-like fields has another problem: two people
can share those fields, and one person's fields can change. We never infer a person's
identity from demographic resemblance.

The official evidence and the distinctions between Secure QR, older QR, XML, and app
credentials are collected in [sources and assumptions](07_sources_and_assumptions.md).
Do not borrow a field layout from one format and assume it belongs to another.

## A short self-check

1. A QR image decodes successfully. Is its signature valid?
2. What does a valid signature under an arbitrary supplied key establish?
3. Is base64 encryption?
4. Why preserve exact signed bytes instead of rebuilding JSON before verification?
5. Can last four digits uniquely identify every Aadhaar identity?
6. Does a SHA-256 hash of a QR stay stable across all reissuances?
7. What happens when the synthetic credential ID is null?
8. Does `TRUSTED_SYNTHETIC` establish UIDAI issuance?
9. Is a valid signature evidence of current active status?
10. What must be resolved before making a real status lookup?

Answers: (1) No, decoding is only transport recovery. (2) Mathematical consistency
with that key, not its provenance. (3) No, anyone can decode it. (4) Signatures cover
bytes, and reserialization can change them. (5) No. (6) No guarantee; changed bytes
change the hash except for negligible cryptographic collision probability. (7) A
valid, trusted signature can coexist with `IDENTIFIER_UNAVAILABLE`. (8) No. (9) No.
(10) Establish an issuer-authenticated mapping with lifecycle semantics, suitable key
trust, and then obtain sufficiently fresh issuer status evidence in a privacy-conscious
way. These are distinct requirements.

