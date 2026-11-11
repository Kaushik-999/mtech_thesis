# Phase 1 testing and measured results

## Environment and reproducibility

Validation date: **2026-11-10**, Asia/Kolkata. The machine-readable
[verification report](results/verification.json) records the exact final check timestamp,
command outputs, return codes, and dependency versions. Read that file for the measured
suite duration; it is not a performance benchmark.

| Component | Observed version / environment |
|---|---|
| Python | CPython 3.12.16 |
| Platform string | `macOS-26.6.2-arm64-arm-64bit` |
| Project | 0.1.0 |
| cryptography | 50.0.2 |
| qrcode | 8.2 |
| Pillow | 13.0.0 |
| zxing-cpp | 3.1.1 |
| pytest | 9.2.0 |
| Ruff | 0.17.4 |
| build | 1.6.1 |
| Isolated build backend | hatchling 1.33.0 |

Install a locked development environment from the root:

```sh
uv sync --frozen --python 3.12 --extra scanner --extra dev
source .venv/bin/activate
python scripts/check_phase1.py --output docs/phase-01/results/verification.json
```

Or use standard `python3.12 -m venv .venv` and `python -m pip install -e '.[scanner,dev]'`
as in the README. The latter follows dependency ranges rather than pinning every
version. Both the native scanner and development extra are needed for the full suite.
The code treats a missing scanner as an explicit error; T03 does not silently skip.

## Commands executed

The implementation session ran these substantive commands from the project root:

```sh
uv sync --python 3.12 --extra scanner --extra dev
.venv/bin/python -m p1qr demo
.venv/bin/python -m p1qr demo --output demo_output
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python -m build
.venv/bin/python scripts/check_phase1.py --output docs/phase-01/results/verification.json
```

Ruff formatting was applied during development with `.venv/bin/ruff format .`; final
lint and formatting checks are validation-only. Research used `pdftotext` on the
supplied thesis and an HTTPS-downloaded official annual report. Those source-review
commands are unrelated to the offline runtime.

A fresh environment was also created under `/tmp/p1qr-wheel-smoke.*` with
`uv venv --python 3.12`. The built wheel was installed there using
`uv pip install --python <fresh-env>/bin/python '<absolute-wheel-path>[scanner]'`.
From `/tmp`, the fresh interpreter successfully ran `python -m p1qr demo` and
`python -m p1qr --help`. An import-path check showed the package loading from that
environment's `site-packages`, not the editable workspace.

This verifies installation and the demo on the tested platform. It is not a claim
that offline installation works without cached/downloaded dependencies or that all
operating systems were tested. Installation/building can access package indexes;
normal verification makes no network request.

## Final outcomes

| Check | Actual outcome |
|---|---|
| Full pytest suite | **79 passed**, no failed or skipped tests in the final recorded run |
| Demo | Completed; exact image byte round trip, valid original, invalid tampered message |
| Ruff lint | `All checks passed!` |
| Ruff formatting | Check passes after formatting source and documentation code blocks |
| Packaging | Source distribution and pure-Python application wheel built successfully |
| Fresh wheel install | Scanner dependencies installed; demo/help succeeded outside workspace |
| Application docstrings/type hints | AST audit confirmed module docstrings, public-function docstrings, parameter and return annotations |
| Real UIDAI parsing/verification | **Not executed; intentionally unsupported** |
| Real Aadhaar status check | **Not implemented or tested** |

The wheel contains Python application code; its dependencies include native components.
Calling the application wheel pure Python does not mean cryptography or the decoder
is implemented purely in Python.

## Mandatory test matrix

| ID | Test / location | Expected result | Actual result |
|---|---|---|---|
| T01 | `test_synthetic.py::test_t01_generate_signed_credential` | Signed synthetic record with 256-byte signature and opaque ID | Pass |
| T02 | `test_signature.py::test_t02_valid_original` | VALID plus trusted local key; credential-only binding | Pass |
| T03 | `test_synthetic.py::test_t03_image_roundtrip` | Generated PNG decodes to exactly the original envelope bytes | Pass; native zxing-cpp installed |
| T04 | `test_signature.py::test_t04_modified_payload` | Schema-valid changed name with old signature yields INVALID | Pass |
| T05 | `test_signature.py::test_t05_altered_signature` | Bit-flipped signature yields INVALID | Pass |
| T06 | `test_signature.py::test_t06_wrong_key` | Wrong RSA key yields INVALID even if locally pinned | Pass |
| T07 | `test_parser.py::test_t07_malformed_input` and schema tests | Structured MALFORMED_PAYLOAD for malformed supported syntax | Pass |
| T08 | `test_scanner.py::test_t08_unreadable_image` | Blank PNG and invalid image bytes yield UNREADABLE_IMAGE | Pass |
| T09 | `test_signature.py::test_t09_missing_key`; CLI key tests | NOT_CHECKED/MISSING_KEY and exit 3; no downloaded fallback | Pass |
| T10 | `test_binding.py::test_t10_suffix_collision_and_reissuance` | Valid signed credentials with same suffix, distinct IDs/hashes | Pass |
| T11 | `test_signature.py::test_t11_missing_identifier` | Good signature/trusted key with null ID yields IDENTIFIER_UNAVAILABLE | Pass |
| T12 | `test_parser.py::test_t12_unestablished_formats_are_unsupported` | Numeric, XML, app-like and unknown formats explicitly unsupported | Pass; these are synthetic format probes, not real QR compatibility tests |
| T13 | `test_cli.py::test_t13_full_demo_with_python_network_disabled` | Full subprocess demo succeeds under an active Python network guard | Pass; guard probe also tested |
| T14 | `test_cli.py::test_t14_no_demographics_identifiers_or_payload_in_logs`, canary test | Normal logs omit names/IDs/suffix/payload; malformed canary not echoed | Pass; no actual PII was used |
| T15 | `test_parser.py` and `test_scanner.py` size/depth/bomb tests | Oversize/numeric/nested/compressed/image-bomb inputs fail safely | Pass |

Parameterization expands several named tests into multiple cases. The recorded total
is 79 test cases, not 15; the 15 labels are user requirements.

Additional tests check duplicate keys, base64 validation, canonical signed bytes,
Unicode lookalikes, key types/size, multiple PEM objects, incorrect PSS salt, incorrect
padding, invalid algorithm, absent scanner behavior, multiple QR symbols, worker crash
and timeout containment, special files, non-overwriting export, no private-key files,
fictional-only schema, arbitrary-byte corpus, and CLI trust/inspection behavior.

## Actual demonstration output

The recorded demo produced:

```text
1. Generated and signed a SYNTHETIC / NOT UIDAI credential.
2. QR image decoded; exact envelope bytes match.
Signature: VALID
Signer trust: TRUSTED_SYNTHETIC
Identifier binding: SIGNED_CREDENTIAL_ONLY
Aadhaar status: NOT_CHECKED_PHASE_1
3. Modified payload with unchanged signature: INVALID
4. Identifier-binding counterexample:
Both synthetic signatures accepted: True
Distinct credential IDs: True
Same last four digits: True
Distinct artefact hashes: True
Hash changed on reissuance: True
Last-four matching is insufficient; real identity binding: UNCONFIRMED.
Aadhaar status: NOT_CHECKED_PHASE_1
```

Random keys, UUIDs and PSS signatures vary between runs. The boolean/state outcomes
should remain the same. The generated `demo_output/credential.png` was also visually
inspected: its synthetic footer is outside the QR and remains visible.

## Failures found and corrected during development

The first complete test run reported **1 failed, 77 passed**. The deeply nested JSON
case expected MALFORMED_PAYLOAD, but Python accepted the nesting and the unknown-format
branch returned UNSUPPORTED_FORMAT. The implementation now checks an explicit depth
limit before JSON parsing, independent of interpreter recursion behavior. A deterministic
arbitrary-byte corpus was then added, bringing the final suite to 79 cases.

Ruff initially flagged line formatting in source/tests, then in the new check runner
and a Markdown Python snippet. Formatting was applied and final checks rerun. None of
these development failures was ignored or represented as a successful final run.

## What these results do and do not establish

The network guard blocks Python socket connection/name-resolution APIs in the main
test process and, in T13, both the CLI and decoder worker. A deliberate connection
probe verifies that the guard is active. Source review finds no network client in
`src/p1qr`. This supports the offline runtime claim; it is not a packet capture,
network namespace isolation, or a proof about arbitrary native-library behavior.

The privacy checks use fictional values and marker strings. They test data suppression
on the exercised paths, not secrecy of QR contents: anyone holding the QR can decode
its unencrypted fields. No real PII was available or required, so no report can claim
that real datasets were tested.

The bounds and worker checks limit ordinary malformed-input processing. Native-library
exploitation, an adversarial operating system, hard process memory quotas, secure memory
erasure, production concurrency/load behavior, and general fuzzing coverage are not
proven. Only PNG round trips are in T03; acceptance of JPEG is implemented but not a
claim of exhaustive image-format testing. Linux, Windows, alternate Python versions,
damaged printed QR photos, mobile devices and cameras were not tested in this session.

No throughput, latency distribution, national-scale storage/bandwidth, revocation,
privacy formalism, real key rotation, certificate-chain validation, or real UIDAI
interoperability benchmark is reported. The suite's elapsed time is simply a test-run
observation. Future performance claims require a dedicated controlled methodology.

