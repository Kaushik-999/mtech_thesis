# Privacy-Preserving Offline Aadhaar Credential Status Verification

An M.Tech research implementation covering **Phase 1: credential verification** and
**Phase 2: simulated issuer binding and cached offline revocation**. It creates fictional
signed QR credentials, authenticates a separate credential-to-status binding, caches
signed bitmaps, and detects synthetic revocation after synchronization.

**This project does not check real Aadhaar revocation, deactivation, or death status.**
It does not implement UIDAI Secure QR generation or claim compatibility with real QR
payloads. All real Aadhaar formats return `UNSUPPORTED_FORMAT`.

Phase 1's finding remains: **real identity-level binding is not established by the
evidence collected**. Phase 2 creates an explicit synthetic issuer mapping and a signed
sidecar; it does not discover that mapping in unchanged Aadhaar QR codes.
The status format is **Research Bitstring Status List — Not W3C Conformant**.
A valid signature, trusted signer, authenticated binding, acceptable snapshot and status
bit are separate decisions. See the [Phase 2 findings](docs/phase-02/06_research_findings.md).

## Quick start

From this directory, with Python 3.12 installed:

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[scanner,dev]'
python -m p1qr demo
python -m p1qr phase2-demo
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

The Phase 1 `demo` generates an ephemeral key, signs a fictional record, writes a labelled QR,
decodes it, verifies it, changes one signed field, rejects the modified message, and
demonstrates two credentials with the same last-four suffix. It deletes its temporary
files on completion. To retain a presentation example, choose a **new** directory:

```sh
python -m p1qr demo --output demo_output
```

No private key is written. Existing output directories are refused to avoid overwriting.
Default logs omit names, suffixes, UUIDs, QR bytes, and file paths.

## Phase 2: same credential, updated status

```sh
python -m p1qr phase2-demo
python -m p1qr status-demo
```

These are aliases for the same complete experiment. Three ephemeral signing keys cover
credentials, binding assertions and status snapshots. The demo issues two credentials
for one fictional subject, then uses an injected four-day clock:

| Step | Evidence and result |
|---|---|
| Day 1 | Synchronize epoch 1; NOT_REVOKED_AS_OF_SNAPSHOT |
| Day 2 | Issuer deactivates subject and revokes both credential positions |
| Day 3 | Old cache still reports epoch 1's status; a stricter age policy returns STALE_SNAPSHOT |
| Day 4 | Synchronize epoch 2; the same original credential has a VALID signature and REVOKED status |
| Adversarial checks | Altered snapshot signature and lower-epoch replay rejected |

No private subject mapping enters the snapshot or ordinary output. The holder presents
the signed binding sidecar with the credential. All synchronization in this demo passes
local bytes; no HTTP service or per-person lookup is implemented. To retain **public
synthetic artefacts** and the verifier cache, explicitly choose a new directory:

```sh
python -m p1qr phase2-demo --output phase2_output/demo
```

Default temporary files are deleted. Private keys and issuer ownership state remain
in memory, so this is a complete single-process issuer experiment rather than a persistent
issuer administration service. Verifier cache persistence is independently tested across
reopening. Existing output directories are refused.

Run the measured workload or the separate Phase 2 reproduction checks:

```sh
python -m p1qr benchmark-status --output phase2_benchmarks/benchmarks.json \
  --sizes 10000 100000 1000000 10000000 \
  --repetitions 7 --queries 10000 --seed 20261111
python scripts/check_phase2.py --output phase2_output/verification.json
```

Benchmark destinations must be unused; JSON and CSV are written. The checked-in
[actual results](docs/phase-02/04_testing_and_results.md) cover all four sizes. At ten
million entries on the tested Apple M2: 1,250,000 raw bitmap bytes, 2,223,153 signed
snapshot bytes and 69.426 ms median full snapshot validation. An already authenticated
bit-access timing is reported separately; it is not complete verification latency.
No compression, deltas or giant in-memory identity registry are used.

The final suite has **169 passing cases: 79 unchanged Phase 1 + 90 Phase 2**.
The [Phase 2 report](docs/phase-02/results/verification.json) records actual check outputs;
the [baseline](docs/phase-02/results/baseline.json) preserves hashes of the original
tests and Phase 1 documentation/results. The historical Phase 1 report is unchanged.

## Phase 1 commands

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
│   ├── adapters/uidai.py      # explicit unsupported real-format boundary
│   ├── issuer_registry/      # private subject ownership and synthetic lifecycle
│   ├── status_binding/       # separately signed credential/index sidecar
│   ├── status/               # bounded encoding, bitmaps, snapshots, role trust
│   ├── cache/                # transactional snapshot and epoch persistence
│   ├── offline/              # integrated verifier and four-day demo
│   ├── benchmarks/           # measured bitmaps and small registry operations
│   └── phase2_cli.py         # additional commands; original CLI retained
├── tests/                    # original Phase 1 tests
│   └── phase2/               # T201–T230 and adversarial/boundary cases
├── docs/phase-01/             # seven learning, research, and presentation documents
├── docs/phase-02/             # seven detailed documents plus separate actual results
├── docs/RESEARCH_ROADMAP.md
├── docs/GLOSSARY.md
├── docs/PHASE_DOCUMENTATION_TEMPLATE.md
├── examples/README.md
└── scripts/                  # separate check_phase1.py and check_phase2.py runners
```

| Reading order | Phase 1, historical foundation | Phase 2, current milestone |
|---|---|---|
| 1. Beginner guide | [QRs and signatures](docs/phase-01/01_beginner_guide.md) | [Revocation, cache, exercises](docs/phase-02/01_beginner_guide.md) |
| 2. Technical design | [Original protocol](docs/phase-01/02_technical_design.md) | [Binding, lifecycle, trust and sequence diagrams](docs/phase-02/02_technical_design.md) |
| 3. Code walkthrough | [Original modules](docs/phase-01/03_code_walkthrough.md) | [New modules, APIs and failure paths](docs/phase-02/03_code_walkthrough.md) |
| 4. Testing/results | [Original measurements](docs/phase-01/04_testing_and_results.md) | [Tests, benchmark tables and methodology](docs/phase-02/04_testing_and_results.md) |
| 5. Presentation | [Ten slides](docs/phase-01/05_ppt_content.md) | [Fifteen slides, notes and viva answers](docs/phase-02/05_ppt_content.md) |
| 6. Research findings | [Identifier evidence](docs/phase-01/06_research_findings.md) | [Prior work, implementation, measured findings and privacy](docs/phase-02/06_research_findings.md) |
| 7. Sources | [Original evidence](docs/phase-01/07_sources_and_assumptions.md) | [W3C, IETF, paper, assumptions and claim ledger](docs/phase-02/07_sources_and_assumptions.md) |

Read the [glossary](docs/GLOSSARY.md) alongside these documents. The
[roadmap](docs/RESEARCH_ROADMAP.md) distinguishes completed milestones from future work.

## Boundaries and privacy

The synthetic protocol uses RSA-2048, SHA-256, RSA-PSS/MGF1-SHA256 with a 32-byte salt,
and deterministic JSON message encoding. These are **our choices, not UIDAI settings**.
QRs and base64 provide no secrecy. Public keys, signatures, and opaque IDs do not by
themselves make a protocol anonymous.

Phase 1 payloads are bounded at 8 KiB; signed records at 2 KiB; image files at 8 MiB and
4,000,000 pixels; JSON nesting at eight levels. Image decoding runs in a subprocess
with a ten-second timeout. These controls are tested; they are not a formal guarantee
against every native-library vulnerability. This is a local research CLI, not a hardened
public upload service. See the technical threat model before extending it.

Phase 2 uses separate bounds: 8 KiB sidecars, 3 MiB snapshot envelopes, 2 MiB signed
messages and ten million assigned positions. It adds no decompressor. The verifier
rejects missing, invalid, stale and out-of-range evidence; zero means only
NOT_REVOKED_AS_OF_SNAPSHOT. SQLite preserves epoch history across ordinary restarts,
but cannot detect an attacker restoring **all** trusted cache history. Signed timestamps
do not create a trusted clock, and offline verifiers cannot learn unseen events.

Full-list distribution removes the implemented per-person callback; stable UUIDs/indices,
counts, update patterns and potential transport metadata still permit correlation.
This is not zero-knowledge anonymity or production key management. Accumulators,
Android, thesis P2 accountability and thesis P3 empirical freshness are not implemented.

Use only synthetic data. Keep any future sensitive inputs outside version control;
`private_inputs/`, generated output directories, and private-key patterns are ignored.
Do not put real credentials, photographs, extracted payloads, or secrets in the project.
No network request, certificate download, or status lookup occurs in verification.


