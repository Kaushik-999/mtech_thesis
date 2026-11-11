# Phase 2 testing and measured results

All identities, bindings and status events are synthetic. Measurements were executed
locally on 11 November 2026; they do not measure UIDAI systems or national deployment.
The machine-readable evidence is in [results/](results/):
[baseline.json](results/baseline.json), [verification.json](results/verification.json),
[benchmarks.json](results/benchmarks.json), [benchmarks.csv](results/benchmarks.csv), and
[packaging.json](results/packaging.json).

## Environment and baseline

| Item | Observed environment |
|---|---|
| Host | Apple M2, arm64, 8 logical CPUs |
| OS | macOS 26.6.2; Python platform `macOS-26.6.2-arm64-arm-64bit` |
| Python | CPython 3.12.16 |
| Project | 0.2.0 after implementation |
| Cryptography | 50.0.2 |
| QR/image | qrcode 8.2, Pillow 13.0.0, zxing-cpp 3.1.1 |
| Quality/build | pytest 9.2.0, Ruff 0.17.4, build 1.6.1 |

Before changing code, `.venv/bin/python -m pytest -q` reported **79 passed in 1.10s**.
`baseline.json` records that command, actual output/environment and hashes of every
Phase 1 document/result and original test file. The historical Phase 1 report was not
regenerated. The final Phase 2 runner records separate regression, new-test and combined
runs; elapsed times are observations, not acceptance thresholds.

The completed suite contains **79 original tests + 90 Phase 2 cases = 169 passing cases**.
Parameterized boundaries contribute to this count. T201–T230 are requirement identifiers,
not a promise that there are exactly thirty pytest functions. No skips or expected
failures substitute for these requirements. Both demos, Ruff lint and Ruff formatting
are included in the final verification report.

| Final recorded check | Observed result |
|---|---|
| Original Phase 1 tests, separate run | 79 passed in 2.70s |
| Phase 2 tests, separate run | 90 passed in 1.41s |
| Combined suite | 169 passed in 2.79s |
| Phase 1 demo | Exit 0; QR exact-byte match and altered-message rejection |
| Phase 2 demo | Exit 0; four-day status, stale, tampering and rollback results |
| Ruff lint | Exit 0; all checks passed |
| Ruff format check | Exit 0; 73 files already formatted |
| Historical Phase 1 hashes | All matched the pre-change baseline |

Packaging was also checked with `.venv/bin/python -m build --wheel`, producing
`aadhaar_offline_status_research-0.2.0-py3-none-any.whl` using isolated Hatchling 1.33.0.
The wheel was installed with `uv pip install --target ... --no-deps` into a temporary
directory. Imports were asserted to come from that installed target, and `demo`,
`phase2-demo` and `status-demo` all exited 0 from outside the checkout, using the existing
virtual environment's dependencies. This is an installed-package smoke check, not a
second clean dependency-resolution test. The archive contains package code/metadata,
with no retained credentials, keys or cache files. `packaging.json` records its hash
and actual command outputs. The beginner Python API example ran successfully, and local
Markdown links were checked after the report files were generated.

During implementation the first combined collection exposed the same test-module name
in both directories. Adding `tests/phase2/__init__.py` resolved that namespace collision;
the original tests were not renamed or edited. A passing report is the later complete
run, not the initial collection attempt.

## Commands and reproduction

From the project root, use the existing activated environment or install the documented
extras. Installation may need a network; the experiments below use local synthetic data.

```sh
uv sync --frozen --python 3.12 --extra scanner --extra dev
.venv/bin/python scripts/check_phase2.py --output phase2_output/verification.json
.venv/bin/python -m p1qr phase2-demo
.venv/bin/python -m p1qr status-demo
.venv/bin/python -m p1qr benchmark-status \
  --output phase2_benchmarks/benchmarks.json \
  --sizes 10000 100000 1000000 10000000 \
  --repetitions 7 --queries 10000 --seed 20261111
```

Choose unused benchmark destinations. The measured run in this repository used the same
benchmark arguments with `--output docs/phase-02/results/benchmarks.json`.
The final recorded quality run uses
`.venv/bin/python scripts/check_phase2.py --output docs/phase-02/results/verification.json`.
The runner writes only the selected report; it does not rerun or overwrite benchmarks.
Do not overwrite historical evidence merely to obtain a newer timestamp.

Individual checks are `python -m pytest -q tests/phase2`, `python -m pytest -q`,
`python -m ruff check .`, and `python -m ruff format --check .`.
For the exact list of original test paths and all command output, read `verification.json`.

## Required test coverage

| Requirement | Observed assertion | Test module |
|---|---|---|
| T201 | Subject created in ENABLED synthetic state | `test_registry.py` |
| T202 | Signed credential owns a unique first slot | registry |
| T203 | Duplicate index allocation is rejected | registry/bitmap |
| T204 | Valid sidecar authenticates and matches credential | `test_binding.py` |
| T205 | Changed sidecar does not authenticate | binding |
| T206 | Different credential cannot borrow sidecar | binding |
| T207 | Epoch 1 returns NOT_REVOKED_AS_OF_SNAPSHOT | `test_cache_offline.py` |
| T208 | Single revocation changes only that credential; repeat is harmless | registry |
| T209 | New cached snapshot reveals single revocation | cache/offline |
| T210 | Reissuance creates fresh UUID and index under same private subject | registry |
| T211 | Deactivation revokes all siblings, preserves other subject, blocks reissue | registry |
| T212 | Modified bitmap fails signature verification | `test_snapshot.py` |
| T213 | Altered signature fails | snapshot |
| T214 | Wrong signing key fails | snapshot |
| T215 | Older valid epoch rejected after newer one | cache/offline |
| T216 | Reopened cache retains accepted epoch and snapshot | cache/offline |
| T217 | Expiry and maximum age enforced at exact boundaries | snapshot |
| T218 | Missing index is explicit, never default index zero | binding |
| T219 | Index outside signed assigned count is rejected | binding |
| T220 | Missing issuer entry raises an error | registry |
| T221 | Repeated demo checks succeed with active socket guard | `test_cli_benchmark.py` |
| T222 | Malformed/oversized snapshots rejected | snapshot |
| T223 | Subject IDs absent from public payloads and ordinary logs | CLI/privacy |
| T224 | Old snapshot cannot reveal the later event; strict age rejects it | cache/offline |
| T225 | Updated snapshot reports REVOKED for unchanged credential | cache/offline |
| T226 | Original test/document hashes match baseline; old suite still passes | CLI/regression |
| T227 | Revoked slots never reused; next credential gets next index | registry |
| T228 | Wrong issuer/list cannot supply a binding | binding |
| T229 | Missing/corrupt/rolled-back state and failed writes handled safely | cache/offline |
| T230 | Seeded bitmap, statistics and small benchmark agree with oracle | CLI/benchmark |

Additional checks cover bit positions 0/7/8/last, empty lists, full revoked byte,
padding, bool/float/negative/count/time limits, missing keys, independent trust,
same-UUID different signed messages, same-epoch equivocation, randomized PSS resigning,
permanent-bit/count/time regression, concurrent cache writers, cache permissions,
expired-cache replacement and default fresh issuer namespaces.

The injected database trigger verifies that a failed update leaves the prior committed
snapshot readable. It is not a physical power-loss experiment. Socket blocking exercises
the Python network paths used by this implementation; it is not a whole-OS traffic audit.

## Observed four-day demonstration

The clock is injected: Day 1 is 2026-01-01 UTC, independent of the host clock.
Two credentials are issued for one fictional subject. The original QR bytes are preserved.

| Simulated step | Cache/evidence | Decision for original credential |
|---|---|---|
| Day 1 | Epoch 1, zero at bound index | NOT_REVOKED_AS_OF_SNAPSHOT |
| Day 2 | Issuer deactivates subject; verifier receives nothing | No new local evidence |
| Day 3, maximum age 3 days | Still epoch 1, age 2 days | NOT_REVOKED_AS_OF_SNAPSHOT |
| Day 3, maximum age 1 day | Still epoch 1, age 2 days | STALE_SNAPSHOT |
| Day 4, synchronization | Epoch 2 with both sibling bits set | REVOKED |
| Altered snapshot | Signature invalid | INVALID_SNAPSHOT_SIGNATURE |
| Replay original still-fresh snapshot after epoch 2 | Epoch decreases | SNAPSHOT_ROLLBACK |

The credential signature remains VALID before and after deactivation. Output reports
separate trust/binding/snapshot states and authenticated epoch/times. Day 3 is not evidence
that the real current subject remains enabled. These are deterministic functional tests
of a minimal policy, not thesis P3's empirical freshness study.

## Benchmark methodology

The seed is **20261111**, revoked fraction **1%**, repetitions **7**, and lookup batch
length **10,000**. Each population uses raw bitmap bytes plus an independently generated
set of revoked positions as a correctness oracle. It does not allocate millions of
issuer subject/credential objects. Keys are ephemeral and generation is excluded from
timed population operations. RSA-PSS randomness means byte-for-byte snapshot signatures
vary even with a fixed data seed; fixed-size signatures preserve size comparisons.

Timing uses `time.perf_counter_ns()`. Warm-up runs are excluded. Signing includes full
snapshot construction, hashing, encoding and RSA signing. Validation includes strict
parsing, original-byte signature verification, bitmap/digest/schema checks and freshness.
Cache reload additionally reads SQLite and verifies durable metadata. No artificial
network delay or HTTP transport cost is measured.

For lookup, the immutable snapshot is authenticated **before** timing. Each sample is
one batch's elapsed nanoseconds divided by 10,000; it includes Python iteration/call
overhead. Reported p95 is the nearest-rank percentile of **seven batch means**, not a
per-request tail latency and not end-to-end credential verification. With seven samples,
nearest-rank p95 is the largest sample. No confidence interval or robust tail estimate
is claimed. Raw samples remain in JSON.

## Measured issuer and verifier timing

All entries below are median / p95. Millisecond and nanosecond columns deliberately
use different units because they measure different operations.

| Assigned entries | Snapshot creation/signing (ms) | Full snapshot validation (ms) | Cache reload + validation (ms) | Authenticated bit lookup batch mean (ns/op) |
|---:|---:|---:|---:|---:|
| 10,000 | 0.575 / 0.637 | 0.134 / 0.148 | 0.251 / 0.278 | 119.94 / 129.32 |
| 100,000 | 0.868 / 0.928 | 0.747 / 0.765 | 0.893 / 0.912 | 118.88 / 127.45 |
| 1,000,000 | 3.936 / 3.967 | 6.916 / 7.045 | 7.171 / 7.247 | 124.99 / 137.71 |
| 10,000,000 | 34.798 / 35.206 | 69.426 / 70.151 | 70.334 / 70.604 | 121.27 / 125.37 |

The bit-access primitive remains approximately constant across these samples; full
validation grows with serialized input. **The integrated verifier currently validates
the complete cached snapshot on each call.** Its latency is not the roughly 120 ns
primitive measurement and also includes credential/binding verification. No complete
per-credential latency distribution was measured in this run.

## Measured bytes and memory

| Assigned entries | Raw bitmap bytes | Signed envelope / full update bytes | SQLite cache file bytes | Python validation peak bytes |
|---:|---:|---:|---:|---:|
| 10,000 | 1,250 | 3,149 | 8,192 | 14,424 |
| 100,000 | 12,500 | 23,149 | 28,672 | 98,283 |
| 1,000,000 | 125,000 | 223,149 | 229,376 | 935,636 |
| 10,000,000 | 1,250,000 | 2,223,153 | 2,232,320 | 9,310,420 |

Full-update bandwidth equals the exact envelope byte count because a complete document
is synchronized. It excludes transport headers, TLS, retransmission and update frequency.
Cache size is the quiescent main database file; a transaction may temporarily need journal
space. It excludes credential bundles, trust configuration, backups and the issuer registry.

There is **no compression** and no authenticated delta protocol. JSON records compressed
size as null/NOT_IMPLEMENTED. Bitmap base64 inside the signed message and envelope base64
around that message add two encoding layers, approaching 16/9 of raw size plus metadata.
No compressed-size result should be inferred from these measurements.

`tracemalloc` measures peak Python-tracked allocations in a separate validation pass,
excluding existing inputs and allocations inside native libraries. Process RSS high-water
was **148,520,960 bytes for the complete run** on this macOS host. That cumulative figure
includes prior operations and is not a per-population memory measurement. These distinct
metrics must not be plotted as interchangeable quantities.

## Small registry operations

These measurements use real issuer objects and actual sibling credentials, independently
of the large bitmap populations. Setup and sibling issuance are excluded from deactivation
timing. Each measured deactivation checks that every applicable bit is set.

| Issuer operation | Median (ms) | p95 (ms) |
|---|---:|---:|
| Issue credential plus signed binding | 1.154125 | 1.170209 |
| Revoke one credential | 0.000541 | 0.000833 |
| Deactivate subject with 1 credential | 0.001583 | 0.002333 |
| Deactivate subject with 5 credentials | 0.003000 | 0.004125 |
| Deactivate subject with 25 credentials | 0.007625 | 0.010792 |

Sub-microsecond results are especially sensitive to timer/loop/host noise. Seven samples
do not establish a production throughput claim. Deactivation scales with the number of
owned credentials; dissemination still requires publishing and synchronizing a snapshot.

## Suggested graphs for a thesis presentation

1. **Storage versus entries:** log-scaled entry axis; separate raw bitmap, envelope and
   cache-file byte lines from the measured table. Explain fixed metadata/page overhead
   at small sizes and linear raw `ceil(N/8)` growth.
2. **Issuer/verifier work versus entries:** separate median signing and validation lines
   in milliseconds, with min/max or clearly labeled p95 markers from raw samples. Do
   not label seven runs as statistical confidence intervals.
3. **Already authenticated access:** lookup batch mean median/p95 on a nanosecond axis.
   Title must include “already authenticated bitmap”; no claim of full verifier speed.
4. **Deactivation fan-out:** x-axis 1, 5, 25 credentials; y-axis observed median time.
   Use this as a small implementation observation, not an extrapolation to a giant registry.
5. **Freshness timeline:** Day 1–4 sequence annotated with cached epoch and result. This
   is a functional illustration, not measured outage/freshness behavior in real deployments.

## Limits and interpretation

This is one host, one runtime, one revoked fraction and one timed run per population
configuration. CPU scheduling, thermal state, interpreter, native-library versions and
filesystem cache can change results. No Android, cold-device benchmark, real network,
production key store, full identity registry or genuine Aadhaar dataset was used.

Theoretical 134 crore (=1.34 billion) positions need 167,500,000 raw bitmap bytes under
one-bit encoding. **That is arithmetic, not a measured result**, and exceeds this
implementation's 10-million-entry limit. It excludes encoding, signatures, distribution,
privacy partitioning and state-management costs. No national-scale readiness is inferred.

The evidence supports correctness under the tested synthetic lifecycle and the stated
storage/clock/trust model. A later comparison should add multiple machines/runs, baseline
equivalence, key-management costs and explicit measurement of full verification and
update distribution before stronger performance conclusions.
