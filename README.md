# Privacy-Preserving Offline Aadhaar Credential Status Verification

An M.Tech research implementation of **Phase 1: the credential verification foundation**.
It creates fictional signed credentials, puts them in QR images, reads those images,
verifies signatures locally, and demonstrates why a credential identifier does not
automatically identify an Aadhaar status record.

**This project does not check real Aadhaar revocation, deactivation, or death status.**
It does not implement UIDAI Secure QR generation or claim compatibility with real QR
payloads. All real Aadhaar formats return `UNSUPPORTED_FORMAT`.

The main research finding is **identity-level binding is not established by the
evidence collected**. The [research findings](docs/phase-01/06_research_findings.md)
explain what additional issuer information is needed. A correct signature and a trusted
key are separate from a current status decision.

## Quick start

From this directory, with Python 3.12 installed:

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[scanner,dev]'
python -m p1qr demo
python -m pytest -q
ruff check .
ruff format --check .
```

Dependency installation may require internet; verification does not. The full suite
requires the `scanner` extra. `zxing-cpp` 3.1.1 installed successfully on the tested
macOS/Apple Silicon system. No system Java, camera, or cloud service is needed.

For the checked-in dependency versions, use [uv](https://docs.astral.sh/uv/) if it is
already installed:

```sh
uv sync --frozen --python 3.12 --extra scanner --extra dev
uv run --frozen --extra scanner --extra dev python -m p1qr demo
```

`uv.lock` fixes dependency resolution. The pip editable install above uses the version
ranges in `pyproject.toml`; it can resolve newer versions. Python 3.12.16 was tested.

The demo generates an ephemeral key, signs a fictional record, writes a labelled QR,
decodes it, verifies it, changes one signed field, rejects the modified message, and
demonstrates two credentials with the same last-four suffix. It deletes its temporary
files on completion. To retain a presentation example, choose a **new** directory:

```sh
python -m p1qr demo --output demo_output
```

No private key is written. Existing output directories are refused to avoid overwriting.
Default logs omit names, suffixes, UUIDs, QR bytes, and file paths.

## Explore the commands

```sh
python -m p1qr --help
python -m p1qr generate-synthetic --output synthetic_output
python -m p1qr inspect --input synthetic_output/credential.p1qr
python -m p1qr inspect --image synthetic_output/credential.png
python -m p1qr verify-synthetic --input synthetic_output/credential.p1qr \
  --public-key synthetic_output/public_key.pem
python -m p1qr analyze-binding
```

The verification command above intentionally reports `VALID` and `UNTRUSTED` and exits
with code 1: a supplied key alone does not establish trust. For a credential **you just
generated locally**, copy the 64-character fingerprint printed by generation:

```sh
python -m p1qr verify-synthetic --image synthetic_output/credential.png \
  --public-key synthetic_output/public_key.pem \
  --trusted-fingerprint YOUR_LOCALLY_ACCEPTED_64_CHARACTER_FINGERPRINT
```

Replace that placeholder; it is not a literal valid pin. Do not treat a fingerprint
bundled with an unknown credential as independent trust. This flag can establish only
`TRUSTED_SYNTHETIC`, never UIDAI trust. The built-in demo accepts its own in-memory key
and needs no manual pin.

| Result | Meaning |
|---|---|
| `PARSED_UNVERIFIED` | Structure understood, no authenticated claim yet |
| `VALID` / `INVALID` | Mathematical signature outcome for the supplied key |
| `UNTRUSTED` | Key was supplied but has no matching independently accepted pin |
| `MISSING_KEY` | No usable verification key was supplied |
| `SIGNED_CREDENTIAL_ONLY` | Locally trusted synthetic signature covers a credential ID |
| `IDENTIFIER_UNAVAILABLE` | Valid/trusted record has no credential ID |
| `UNSUPPORTED_FORMAT` | This implementation cannot interpret the real/unknown format |
| `NOT_CHECKED_PHASE_1` | Aadhaar status is always undetermined |

Exit codes: **0** completed inspection/experiment or accepted synthetic signature;
**1** invalid signature or untrusted key; **2** input/format/algorithm/decoder failure;
**3** missing/unreadable key. Exit 0 does not mean a resident is active or identified.

## Layout and reading order

```text
.
├── pyproject.toml             # packaging, dependencies, pytest and Ruff settings
├── uv.lock                   # resolved dependency versions
├── src/p1qr/
│   ├── cli.py, models.py, errors.py, protocol.py
│   ├── synthetic/issuer.py    # fictional records, signing, QR and public-only export
│   ├── scanner/              # bounded file reading and isolated optional decoder
│   ├── parser/payload.py      # strict synthetic schema; exact signed bytes
│   ├── crypto/               # ephemeral RSA keys, verification, trust pin comparison
│   ├── binding/analysis.py    # collision and reissuance counterexamples
│   └── adapters/uidai.py      # explicit unsupported real-format boundary
├── tests/                    # all T01–T15 plus security and regression cases
├── docs/phase-01/             # seven learning, research, and presentation documents
├── docs/RESEARCH_ROADMAP.md
├── docs/GLOSSARY.md
├── docs/PHASE_DOCUMENTATION_TEMPLATE.md
├── examples/README.md
└── scripts/check_phase1.py    # reproduction check runner
```

1. [Beginner guide](docs/phase-01/01_beginner_guide.md): concepts, commands, quiz.
2. [Technical design](docs/phase-01/02_technical_design.md): protocol, diagrams, threats.
3. [Code walkthrough](docs/phase-01/03_code_walkthrough.md): functions and failure paths.
4. [Testing and results](docs/phase-01/04_testing_and_results.md): measured evidence and limits.
5. [PPT content](docs/phase-01/05_ppt_content.md): ten slides, notes, viva questions.
6. [Research findings](docs/phase-01/06_research_findings.md): identifier decision matrix.
7. [Sources and assumptions](docs/phase-01/07_sources_and_assumptions.md): claim-level evidence.

Read the [glossary](docs/GLOSSARY.md) alongside these documents. The
[roadmap](docs/RESEARCH_ROADMAP.md) describes future work without implementing it.

## Boundaries and privacy

The synthetic protocol uses RSA-2048, SHA-256, RSA-PSS/MGF1-SHA256 with a 32-byte salt,
and deterministic JSON message encoding. These are **our choices, not UIDAI settings**.
QRs and base64 provide no secrecy. Public keys, signatures, and opaque IDs do not by
themselves make a protocol anonymous.

Payloads are bounded at 8 KiB; signed records at 2 KiB; image files at 8 MiB and
4,000,000 pixels; JSON nesting at eight levels. Image decoding runs in a subprocess
with a ten-second timeout. These controls are tested; they are not a formal guarantee
against every native-library vulnerability. This is a local research CLI, not a hardened
public upload service. See the technical threat model before extending it.

Use only synthetic data. Keep any future sensitive inputs outside version control;
`private_inputs/`, generated output directories, and private-key patterns are ignored.
Do not put real credentials, photographs, extracted payloads, or secrets in the project.
No network request, certificate download, or status lookup occurs in verification.


