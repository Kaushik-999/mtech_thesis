# Phase 2 code walkthrough

Read this beside [the technical design](02_technical_design.md). All examples refer to
the simulated issuer. Public Python APIs are typed; their docstrings explain the trust
and persistence assumptions. Tests live in `tests/phase2/`, with `__init__.py` keeping
their module names distinct from the original tests.

## 1. How Phase 1 connects

The original path is still `synthetic.issuer.create_record()` → `sign_record()` →
`parser.payload.parse_payload()` → `crypto.verification.verify_credential()`.
The registry calls those functions rather than constructing a second credential format.
The QR renderer and bounded decoder are also reused by the demonstration.

`P1QR-SYNTHETIC-1`, its field schema, signature profile, exact-byte verification,
limits, and missing-identifier behavior remain unchanged. New sidecars and snapshots
have separate version labels and parsers. In particular, accepting a large bitmap does
not enlarge the Phase 1 credential limit. `protocol.canonical_json()` is a shared encoder;
each protocol validates its own permitted types before using it. Only that encoder's
docstring needed clarification.

The original `cli.py` registers and dispatches the new commands through `phase2_cli.py`.
Original command handlers remain in place. The package version is now 0.2.0; dependency
requirements did not need new libraries. SQLite is in Python's standard library.
T226 compares original test/document bytes with the pre-change SHA-256 manifest, and
the final check runner executes the original 79 tests separately.

## 2. Errors and role-specific trust

**Files:** `src/p1qr/status/errors.py`, `src/p1qr/status/trust.py`.

`StatusCode` enumerates decisions and failure reasons. `StatusError` carries a safe
message, mathematical signature state, independent trust state, and optional authenticated
snapshot metadata. Exceptions carry no public subject mapping. For example, stale evidence
can have a VALID signature while its acceptability is STALE_SNAPSHOT.

`KeyTrust(key, fingerprint)` represents independently configured public material for
one role. `state()` compares the supplied public key's SPKI fingerprint with the accepted
pin. A fingerprint inside an untrusted document never changes local policy.
`IssuerTrust(issuer_id, list_id, credential, binding, snapshot)` binds three such roles
to one namespace. Identifier syntax and pin shape are checked at construction.

`IssuerKeys.generate()` creates three ephemeral RSA private keys through the existing
cryptography utility. `local_trust()` makes a demo policy for those keys that the caller
has just generated. This convenience is valid inside the synthetic issuer experiment;
it is not a procedure for trusting arbitrary externally supplied keys. Private fields
are omitted from object representations, and no private-key export is implemented.

**Failures/tests:** malformed policy is INVALID_POLICY; an absent key remains MISSING_KEY;
a valid signature under an unpinned key remains UNTRUSTED. Binding and snapshot tests
exercise wrong role keys and valid mathematics with missing trust.

## 3. Bounded signed-document encoding

**File:** `src/p1qr/status/encoding.py`.

| API | Inputs → output | Purpose |
|---|---|---|
| `unsigned_integer()` | object, bound → int | Reject bool, float, negative and excessive integers |
| `hex_digest()` | object → hex string | Require a canonical SHA-256 identifier |
| `flat_json()` | bytes, limit → dict | Bound input and reject nested/duplicate/invalid numeric JSON |
| `decode_base64()` | value, decoded limit → bytes | Strict alphabet, size, padding and canonical pad bits |
| `parse_document()` | envelope bytes → `SignedDocument` | Preserve exact decoded message and signature bytes |
| `sign_document()` | validated record, RSA key → envelope bytes | Canonically encode and sign complete message |
| `check_signature()` | parsed document, role policy → signature/trust pair | Verify original bytes under the configured role key |

Before JSON parsing, a quoted-string-aware scan rejects nesting. JSON hooks reject
duplicate keys, floating point and oversized numbers. The signed message must match
the protocol's canonical encoding; verification still uses the original decoded bytes.
Canonical equality is a syntax check, not a replacement for the signature check.

The outer object has only `payload` and `signature`. Base64 is reversible encoding.
RSA-PSS signs the payload using the Phase 1 padding helper and SHA-256. A signed algorithm
and key ID must match policy; keys are never fetched from message URLs or embedded claims.
No custom RSA arithmetic, decompressor, or certificate discovery is introduced.

**Failures/tests:** T222 exercises malformed and oversized inputs. Signed metadata tests
cover bools, ranges, unknown fields and timestamps. Tampering tests distinguish malformed
encoding from a syntactically valid message with an invalid signature. Limits are constants
in this module and are documented in the technical design.

## 4. Bitmap allocation and reading

**File:** `src/p1qr/status/bitstring.py`.

`BitstringStatusList()` starts empty. `register()` appends one zero bit and returns its
index. An explicitly supplied index must equal the next dense position. `revoke(i)`
sets its mask with OR, so repeating revocation is harmless. There is no clear or reuse
operation. `is_revoked(i)` delegates to `read_bit(bitmap, count, i)`.

The algorithm is `byte_number = i // 8`, `mask = 1 << (i % 8)`. A nonzero
`bitmap[byte_number] & mask` means revoked. LSB0 means the rightmost numerical bit has
index zero within each byte. Thus positions 0, 7 and 8 produce raw hexadecimal `81 01`.
Changing this ordering would silently answer the wrong status question.

`serialize()` returns immutable bytes. `from_bytes(raw, count)` checks the exact length
`ceil(count/8)` and zero unused high bits. Reading requires `0 <= i < count`, even if
the final byte has unused zero padding. An empty list cannot answer any credential.

**Failures/tests:** T203/T227 and the bitmap tests cover duplicates, gaps, reuse, byte
crossings, 0/7/8/last index, full `ff`, empty state, bad padding, wrong length and
idempotence. This class guarantees unique allocation within its own lifetime; persistence
and issuer ownership are responsibilities of the registry and namespace policy.

## 5. Private issuer registry and lifecycle

**File:** `src/p1qr/issuer_registry/registry.py`.

`Subject` stores a private subject UUID, state and owned credential UUIDs.
`RegistryEntry` stores the private subject/credential/index relation. `IssuedCredential`
is the public presentation bundle: credential bytes, binding bytes, credential UUID
and index. It contains no subject ID. Frozen records prevent accidental field mutation.

| Method | Inputs → output | Algorithm and failure conditions |
|---|---|---|
| `create_subject()` | optional UUID → private subject ID | Canonical UUIDv4; reject duplicate |
| `subject()` / `entry()` | private lookup ID → immutable record | Explicit issuer debugging; absent record is error |
| `issue()` | subject ID, optional credential UUID → bundle | Check lifecycle/duplicates; sign credential and sidecar; append slot and ownership |
| `reissue()` | old credential UUID → new bundle | Find same subject; call issuance with new UUID/slot |
| `revoke_credential()` | credential UUID → None | Set one owned bit, leave sibling bits alone |
| `deactivate_subject()` | subject ID → owned credential count | Revoke all siblings, set DEACTIVATED |
| `is_revoked()` | credential UUID → bool | Issuer-private lookup; missing never means zero |
| `publish()` | issued-at/expiry → signed snapshot | Sign next epoch, advance counter only after success |

Issuance prepares signatures before mutating allocation state. Registry ownership and
the bitmap both check index allocation. A deactivated subject cannot issue or reissue.
Reissuing for an enabled subject does not clear an old revoked credential. Publication
rejects backward issuer time and creates a complete snapshot, not a delta.

The default list ID is fresh for every new volatile registry. Reusing an explicitly
chosen list ID requires complete issuer-state restoration, which this phase does not
implement. This is single-process issuer code, not a concurrent durable database.

**Tests:** T201–203, T208, T210–211, T220, T227; duplicate subject/credential IDs;
failed publication preserving epoch; fresh namespace for a restarted empty registry.

## 6. Authenticated binding assertion

**File:** `src/p1qr/status_binding/assertion.py`.

`issue_binding()` accepts a parsed Phase 1 credential, issuer/list IDs, allocated index,
credential public key, and binding private key. It signs the UUID, exact-message digest,
credential key ID, namespace and index using `P1QR-STATUS-BINDING-1`.

`verify_binding()` accepts sidecar bytes, the already authenticated parsed credential,
and issuer trust. It requires the exact schema, authenticates the binding-role signature,
establishes role trust, checks namespace and compares the credential UUID/digest/key.
Only then does it return a `StatusBinding`. Its numeric index is bounded by protocol
capacity; the snapshot later checks whether that position was actually assigned.

The digest matches a specific signed artefact; it does not derive an identity or index.
The registry owns allocation. Calling a low-level signing helper does not prove that a
malicious issuer has not signed duplicate allocations elsewhere.

**Failures/tests:** missing sidecar is handled by the integrated verifier. T204–206,
T218–219 and T228 cover valid, modified, mismatched, missing and out-of-range bindings.
Additional cases cover a different signed message sharing a UUID, untrusted binding
keys, wrong role keys and invalid numeric types. The sidecar is delivered with the
credential; no network lookup is hidden in this component.

## 7. Snapshot signing, authentication and time

**File:** `src/p1qr/status/snapshot.py`.

`create_snapshot()` receives an allocated bitmap, namespace, epoch, times and private
snapshot key. It checks structural constraints, encodes the bitmap, adds its SHA-256,
and signs all fields. `authenticate_snapshot()` takes untrusted bytes and issuer trust,
checks schema/signature/trust/context, validates the bitmap and returns immutable
`Snapshot` state. Authentication deliberately does not consult a clock.

`check_freshness(snapshot, now, max_age_seconds)` applies the separate time policy:
`issued_at <= now < expires_at` and `now - issued_at <= max_age_seconds`.
`Snapshot.is_revoked(i)` reads an authenticated position; callers must establish current
acceptability first. `authenticated_error()` preserves successful signature/trust evidence
when a later policy check fails. Stale/future errors also retain epoch/time metadata.

**Tests:** T212–214 and T217; wrong context, count/digest/padding, signed malformed
metadata, missing/untrusted keys, exact expiry and maximum-age boundaries. T212 modifies
bitmap bytes without resigning; separate signed-invalid cases show that possession of
a trusted signing key does not excuse malformed structure.

## 8. Durable verifier cache

**File:** `src/p1qr/cache/storage.py`.

`SnapshotCache.initialize(new_directory, trust)` explicitly creates a policy-bound
SQLite cache. `SnapshotCache(directory)` merely selects an existing cache. There is
no automatic initialization after failure. Private directory/database permissions reduce
incidental local access on POSIX; permissions are not an external monotonic counter.

`synchronize(data, trust, now=..., max_age_seconds=...)` authenticates the candidate,
checks time, starts a serialized write transaction, validates the stored state, rejects
rollback/equivocation/regression, and commits snapshot bytes and epoch/digest together.
The comments explain why two independent files could become inconsistent after failure.
Same-message PSS resigning is allowed: random signature differences are not equivocation.

`load()` reopens the existing database, authenticates cached bytes, compares them with
the recorded high-water metadata, then applies freshness. `_connection()` uses SQLite
`mode=rw`, so a missing database is not silently created. `_read()` refuses missing,
ambiguous, malformed or inconsistent state. Closing an uncommitted transaction rolls
it back. Failures become safe `StatusError` values.

**Tests:** T215–216 and T229, same-epoch conflicts, nondecreasing count/time/permanent
bits, stale-cache replacement, two concurrent synchronizations and a failing SQLite
trigger. Tests cover application persistence failures, not physical power loss or an
attacker restoring the entire trusted database together with its epoch history.

## 9. Integrated verifier and demonstration

**Files:** `src/p1qr/offline/verifier.py`, `src/p1qr/offline/demo.py`.

`verify_offline(credential, binding, cache, trust, clock=..., max_age_seconds=...)`
returns `OfflineResult`. Its stages are credential signature/trust, binding
signature/trust/match, snapshot signature/trust/acceptability, then status. Each stage
must succeed before proceeding. A missing earlier stage never causes a default zero bit.
`unix_time()` is the default local clock; tests inject integer seconds instead.

The immutable result includes epoch, issued-at and expiry when available, but no UUID,
subject ID or index. Normal output therefore explains evidence without publishing
issuer-private relations. T207/T209, T224/T225 and early-exit tests assert exact decisions.

`run_demo()` creates two credentials for one fictional subject, renders and decodes the
original QR, synchronizes epoch 1, simulates deactivation and missed updates, synchronizes
epoch 2, then verifies the same original credential. It also rejects tampering and rollback.
Without `--output`, its temporary directory is deleted. With a new explicit output path,
only public synthetic artefacts and verifier cache are retained, never private keys.

T221 runs the entire demo in a subprocess whose socket connection and DNS functions are
actively blocked; a probe proves the guard is engaged. T223 checks public data and logs.
This establishes the implemented local path needs no network, not a claim about all
possible future transports or operating-system traffic.

## 10. CLI, measurements and reproduction

**Files:** `src/p1qr/phase2_cli.py`, `src/p1qr/benchmarks/measure.py`,
`scripts/check_phase2.py`.

`add_commands()` registers `phase2-demo` (alias `status-demo`) and `benchmark-status`.
`run_command()` validates arguments and dispatches lazily. Demo success is exit 0;
input/status failures are exit 2 with safe messages. Original command exit semantics
remain unchanged. There is no persistent issuer administration CLI because the issuer
and signing keys intentionally live for one experiment process.

`generate_bitmap()` uses a deterministic seed and an independent revoked-position set
as an oracle. `measure_population()` measures signing, complete snapshot validation,
cache reload/validation, and batches of already authenticated bitmap lookups separately.
`summarize()` reports median and nearest-rank p95 from raw samples.
`measure_registry()` measures actual small issuer operations, including deactivation of
reissued siblings. `run_benchmarks()` writes JSON and CSV plus environment, parameters,
methodology and limitations; it refuses to overwrite prior result files.

T230 checks known small bitmaps, seeded reproducibility, statistics, lookup correctness,
and benchmark output metadata. Large measurements allocate bitmaps, not millions of
Python subject objects. Key generation is outside timed population operations.

The reproduction script executes the old tests, new tests, combined tests, both demos,
lint and formatting; its optional JSON records actual stdout/stderr/return codes,
environment and source hashes. It rejects a report destination inside `docs/phase-01/`.
For exact measurements and commands, continue to [testing and results](04_testing_and_results.md).
