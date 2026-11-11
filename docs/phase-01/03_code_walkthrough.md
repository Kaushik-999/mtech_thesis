# Phase 1 code walkthrough

All paths below are relative to the project root. Read the
[technical design](02_technical_design.md) for the wire rules before changing parser
or cryptographic code. Public application functions have type hints and docstrings;
security-sensitive comments explain what a check does and what it does not prove.

## Entry points and packaging

`pyproject.toml` declares the package, Python range, dependencies, optional scanner/dev
extras, `p1qr` console entry point, and test/lint settings. Hatch builds the wheel from
`src/p1qr`. `uv.lock` records resolved versions. The tested interpreter is Python
3.12.16; the broader declared range is not a statement of testing every interpreter.

`src/p1qr/__init__.py` contains the version and scope statement. `__main__.py` calls
`cli.main()` and returns its exit code to the shell. Subpackage `__init__.py` files
explain each component's role and perform no network or key-loading side effects.

`cli.build_parser()` takes no arguments and returns an `argparse.ArgumentParser`.
It declares five commands, requires an explicit subcommand, and makes `--input` and
`--image` mutually exclusive. Verify accepts an optional public key and trust pin.
`--help` is the executable reference for supported syntax. Invalid argument syntax is
handled by argparse with exit code 2.

`cli.main(argv=None)` takes optional argument strings and returns an integer. It
dispatches to generation, inspection, verification, the demo, or the binding experiment.
It catches `P1QRError` at the command boundary and prints only its fixed explanation.
Credential contents and user filenames are not incorporated into normal messages.

Private helpers `_print_verification()` and `_print_binding()` output independent
decision states and experiment booleans. `_demo_in_directory()` checks every demo
stage before reporting success. `main()` wraps the default demo in
`TemporaryDirectory`; `--output` explicitly retains the synthetic artefacts.

Tests: `test_cli.py` checks full demo execution, generation, raw/image inspection,
key absence, untrusted validity, output privacy, and a network-disabled subprocess.

## Shared protocol, models, and errors

`src/p1qr/protocol.py` names all size/algorithm/label constants. Keeping them together
prevents a parser and issuer from silently disagreeing. The constants are educational
protocol choices, not discovered Aadhaar parameters.

`canonical_json(value)` accepts a controlled dictionary and returns ASCII bytes:

```python
json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
    "ascii"
)
```

The function is an encoder, not a schema validator. The issuer validates its envelope
before signing. The parser checks every allowed field before comparing the message
with its canonical encoding. This restricted schema is important: blindly claiming
canonical JSON for arbitrary numbers and Unicode would be incorrect.

Tests: reversed dictionary insertion order produces the same message bytes;
noncanonical inner JSON is rejected; exact parsed signed bytes match the original.

`src/p1qr/models.py` contains frozen dataclasses and enums:

- `ParsedCredential` is unverified syntax. It carries original bytes and metadata;
  byte/identifier fields use `repr=False` to reduce accidental disclosure.
- `VerificationResult` separates signature, trust, binding, detail, and fixed unchecked
  status. `accepted_synthetic` returns true only for VALID plus TRUSTED_SYNTHETIC.
  It intentionally does not claim identity or current status.
- Enum values prevent ad hoc strings such as “verified” from ambiguously combining
  multiple decisions.

`src/p1qr/errors.py` defines `ErrorCode` and `P1QRError(code, message)`. The exception
stores a machine-readable category and a safe developer-authored explanation. Callers
must not use raw exception text or parsed values as its message. This is why file
errors are replaced with fixed messages instead of being printed directly.

Tests: parser and scanner failures assert exact codes; CLI tests assert safe output.

## Keys: `src/p1qr/crypto/keys.py`

| Function | Inputs → output | Algorithm / important choice | Failure or limitation | How tested |
|---|---|---|---|---|
| `generate_private_key()` | None → RSA private-key object | Library RNG; 2048 bits; exponent 65537 | Memory secret, not securely wiped; no UIDAI relation | T01 and signing fixtures |
| `public_key_pem(key)` | Public key → PEM bytes | SPKI public-key serialization | Serialization does not confer trust | Export/load round trip |
| `load_public_key(data)` | Bounded PEM bytes → RSA public key | Reject excess bytes; parse with library; enforce type, size, exponent and one canonical object | INVALID_KEY for certificate/private/EC/weak/multiple keys; INPUT_TOO_LARGE for large material | Key-negative cases in `test_signature.py` |
| `key_fingerprint(key)` | Public key → lowercase SHA-256 hex | Hash DER SPKI, not PEM formatting | Comparing untrusted key/pin files does not establish independent provenance | Public export equality and trust tests |

No function exports private keys. The manifest records public metadata only. Certificate
validation is absent by design; accepting a certificate-shaped file without chain/purpose
checks would blur the trust boundary.

## Issuer: `src/p1qr/synthetic/issuer.py`

`create_record(variant="A", last_four="4242", include_identifier=True)` returns a
dictionary with the signed label, algorithm, fresh UUIDv4, suffix, and constrained
fictional name. Invalid controls raise `ValueError`. The caller cannot supply arbitrary
name/address/photo input. With `include_identifier=False`, the ID is null, which lets
tests distinguish a good signature from an unavailable identifier.

`sign_record(record, private_key)` returns complete envelope bytes. It checks the key
profile, encodes the record, builds a provisional envelope with a correctly sized dummy
signature, and passes that envelope through the same schema parser used by verifiers.
The provisional parse checks syntax only; it does not claim a dummy signature is valid.
Only then does the library sign the exact message and replace the dummy bytes.

```python
signature = private_key.sign(message, signature_padding(), hashes.SHA256())
```

The library applies hashing inside the signature operation. We do not implement RSA
arithmetic or hash the message a second time in application code. PSS signatures can
differ between runs even if the message is identical.

`render_qr(envelope, output)` validates the input, generates a QR with medium error
correction, six-pixel modules and a four-module quiet zone, and adds the visible
synthetic footer below it. The PNG is written exclusively (`xb`) so an existing file
is not overwritten. The footer is outside the QR quiet zone. Because valid records
have tightly constrained short fields, issued envelopes fit within supported QR
capacity; schema-invalid arbitrary data is not a generation target.

`export_bundle(envelope, public_key, output)` creates a new directory and writes the
payload, PNG, public key, and manifest. It returns no secret. Directory/file errors
become OUTPUT_ERROR. A failed multi-file export can leave partial synthetic files;
it is not an atomic transaction. Retry in another new directory. The export helper
packages supplied values; callers should verify their association when accepting a
bundle from another source. The CLI generates both from the same in-memory key.

Tests: T01, T03, no-private-key export, no overwrite, fictional-name restriction,
canonical encoding, and null-identifier issuance.

## Input reader: `src/p1qr/scanner/reader.py`

`read_bounded_file(path, limit=8192)` opens a file without blocking on a FIFO. It checks
the opened file descriptor is a regular file, checks its reported size, and reads at
most `limit + 1` bytes. The extra byte detects a file that grew after the size check.
Missing, empty, special, inaccessible, and oversized inputs have structured failures.
An invalid programmer-supplied nonpositive limit raises `ValueError`.

`decode_qr_image(path)` reads at most 8 MiB and invokes the installed interpreter with
`-m p1qr.scanner.worker`. Image bytes travel on stdin; no filename or image copy is
retained by the worker. A ten-second timeout bounds waiting. The parent rejects worker
crashes, nonzero exit, excess output, malformed responses, empty payloads, and excessive
decoded length. Successful base64 transport returns exact bytes, not a potentially
normalized decoder `.text` string.

Tests: file limits, missing paths, nonblocking FIFO rejection, image round trip,
unreadable images, ambiguity, malicious PNG header, simulated timeout and native crash.

## Image worker: `src/p1qr/scanner/worker.py`

`decode_image_bytes(data)` returns raw QR bytes. It imports optional `zxingcpp` locally,
so payload-only usage does not require the decoder. Pillow opens only PNG/JPEG inputs.
The code checks frame count and dimensions before converting pixels to grayscale.
`read_barcodes(..., formats=QRCode)` is restricted to QR and rejects multiple detected
symbols. Images are closed with context managers.

`worker.main()` reads bounded stdin and writes one JSON response. P1QRError becomes
an error code; Pillow bomb warnings/errors become INPUT_TOO_LARGE. Other Python decoder
exceptions become UNREADABLE_IMAGE without printing exception text. The broad exception
handler is appropriate at this isolated native-library boundary, not inside the
signature verifier. A segmentation fault cannot be caught by Python, so the parent
also checks process termination.

The worker is not a security sandbox. Read the threat-model limits before exposing it
to public uploads. Tests exercise library failures and explicit bounds; they cannot
prove every native implementation safe.

## Parser: `src/p1qr/parser/payload.py`

`parse_payload(data)` takes bounded envelope bytes and returns `ParsedCredential`.
Its sequence is deliberately explicit:

1. Reject excessive or empty input. Non-JSON-object formats go to the unsupported
   adapter without integer conversion or decompression.
2. `_json_object()` scans nesting outside strings before invoking the JSON parser.
   Escapes are tracked so braces inside strings are not mistaken for structure.
3. `_unique_object()` rejects duplicate keys. `_reject_number()` rejects every numeric
   literal/NaN before a large integer can be constructed.
4. Require the known outer format and exact outer key set.
5. `_base64()` validates length/alphabet and re-encoding equality, including pad bits.
6. Parse the original signed bytes and require the exact signed schema and constants.
7. Validate UUIDv4/null, ASCII suffix, and fictional name. Reject unsupported algorithms.
8. Require canonical signed encoding; retain the original signed bytes in the result.

The private `_malformed()` helper makes all malformed-data explanations constant.
Unknown formats are UNSUPPORTED_FORMAT rather than “invalid signature”: no signature
check was possible. A malformed known synthetic payload is MALFORMED_PAYLOAD. This
distinction matters in thesis reporting.

Tests: T07, T12, T15; duplicate keys; bad base64; unsupported algorithm; Unicode digit
lookalikes; wrong types; deep nesting; huge numeric literal; compressed input; and a
deterministic 100-input arbitrary-byte corpus. No test uses real resident data.

## Unsupported real adapter: `src/p1qr/adapters/uidai.py`

`reject_unestablished_format()` takes no untrusted contents and never returns. It raises
UNSUPPORTED_FORMAT with the missing requirements: established byte-level rules,
authorized test vectors, and independently trusted keys. This small module is a
deliberate future boundary, not a partially working real parser. Its return annotation
`NoReturn` tells readers and tooling that execution ends in a failure.

Do not insert a guessed delimiter/compression/signature offset here just to accept more
inputs. Add real support only after satisfying the documented evidence gate.

## Verification: `src/p1qr/crypto/verification.py`

`signature_padding()` returns a new library PSS configuration using MGF1-SHA256 and
32-byte salt. Both issuer and verifier call it to avoid parameter drift.

`verify_signature(message, signature, key, algorithm=ALGORITHM)` validates the selected
algorithm, message bound and key profile. Wrong signature length is INVALID. It then
calls `key.verify` on the supplied original message bytes. Only `InvalidSignature`
becomes INVALID; unsupported parameters are explicit failures. It never silently tries
another padding or digest algorithm.

`verify_credential(envelope, public_key=None, trusted_fingerprint=None)` parses the
envelope itself. It rejects malformed pins, reports NOT_CHECKED/MISSING_KEY when no
key exists, otherwise performs the mathematical signature check and the independent
fingerprint comparison. The comparison uses `hmac.compare_digest`; fingerprints are
public, but using a fixed comparison operation is straightforward and consistent.

Binding is UNAUTHENTICATED unless both signature and local key policy pass. It is then
SIGNED_CREDENTIAL_ONLY for an ID or IDENTIFIER_UNAVAILABLE for null. Status remains
NOT_CHECKED_PHASE_1 in every case.

Tests: T02, T04–T06, T09, T11, valid-but-untrusted key, wrong pin, unsupported algorithm,
wrong PSS salt, and wrong RSA padding. These tests check distinct security properties.

## Binding experiment: `src/p1qr/binding/analysis.py`

`BindingExperiment` contains booleans and the constant real-binding limitation.
`run_binding_experiment()` takes no input. It creates fictional variants A and B with
the same suffix, plus a reissued A with a new credential ID, and signs all three. It
verifies the signatures under the local key and compares credential IDs and SHA-256
artefact hashes. It returns results without revealing names, suffix values, or UUIDs.

The reissuance relationship is a fact of how this synthetic experiment is constructed,
not an inference about real people. T10 checks the measured counterexample. The formal
pigeonhole proof and real-world limitations are in the research findings.

## Trace a successful verification

Run `python -m p1qr demo`. The issuer creates record A and key K. Deterministic encoding
produces M; signing produces σ. The envelope holds base64(M) and base64(σ). QR generation
prints the envelope; decoding returns identical bytes, which the demo explicitly checks.

The parser validates the restricted schema and stores M unchanged. The verifier checks
σ with K's public key. The demo accepts the fingerprint of the key it just generated.
The result is VALID, TRUSTED_SYNTHETIC, SIGNED_CREDENTIAL_ONLY, and
NOT_CHECKED_PHASE_1. The final field prevents this success being mistaken for a status
answer. Temporary artefacts are removed when the default demo finishes.

## Trace a tampered-message failure

The demo decodes its own envelope, changes only the fictional name to variant Z, and
re-encodes the message canonically. It retains the old signature. Parsing still succeeds:
variant Z is syntactically valid. Cryptographic verification fails because the signature
was for the original M, not the new M′. The result is INVALID even though the public key
is still trusted. Binding becomes UNAUTHENTICATED and current status remains unchecked.

This is stronger evidence than merely corrupting JSON: it demonstrates rejection of a
well-formed modified signed record. `test_t04_modified_payload` asserts this path.

## Reproduction script and tests

`scripts/check_phase1.py:main()` runs the demo, pytest, Ruff lint, and formatting checks
using the active interpreter. It records exact command outputs and installed versions
when `--output` is supplied. It returns nonzero if any command failed; it does not
invent results. The report's timestamp uses Asia/Kolkata.

`tests/conftest.py` shares ephemeral RSA fixtures and a record-mutation helper and blocks
Python network operations during tests. `test_cli.py` separately installs a network
guard in subprocess startup so the demo and image worker are both exercised offline.
The guard itself is probed to ensure it is active. This is not an OS packet-capture test.

