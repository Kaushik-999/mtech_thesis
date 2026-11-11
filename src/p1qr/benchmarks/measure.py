"""Reproducible size/timing measurements; bitmap scale is not population registry scale."""

import csv
import importlib.metadata
import json
import math
import os
import platform
import random
import resource
import statistics
import subprocess
import tempfile
import time
import tracemalloc
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from p1qr.cache.storage import SnapshotCache
from p1qr.issuer_registry.registry import IssuerRegistry
from p1qr.status.bitstring import BitstringStatusList
from p1qr.status.encoding import MAX_ENTRIES
from p1qr.status.snapshot import authenticate_snapshot, check_freshness, create_snapshot
from p1qr.status.trust import IssuerKeys

BENCHMARK_TIME = 1767225600


def generate_bitmap(count: int, rate: float, seed: int) -> tuple[BitstringStatusList, set[int]]:
    """Return a deterministic synthetic bitmap and independent revoked-index oracle.

    Bulk allocation creates count assigned bits, not count resident/credential records.
    Bounds prevent accidentally allocating a huge Python identity registry.
    """
    if type(count) is not int or not 0 <= count <= MAX_ENTRIES or not 0 <= rate <= 1:
        raise ValueError("Use a bounded population and revocation rate between zero and one.")
    bitmap = BitstringStatusList.from_bytes(bytes((count + 7) // 8), count)
    revoked = set(random.Random(seed).sample(range(count), int(count * rate)))
    for index in revoked:
        bitmap.revoke(index)
    return bitmap, revoked


def summarize(samples: list[float]) -> dict[str, float]:
    """Return median and nearest-rank p95 for nonempty measured ``samples``."""
    if not samples:
        raise ValueError("Timing samples cannot be empty.")
    ordered = sorted(samples)
    return {
        "median": statistics.median(ordered),
        "p95": ordered[math.ceil(0.95 * len(ordered)) - 1],
    }


def _timings(operation: Callable[[], object], repetitions: int) -> list[float]:
    operation()  # Warm-up is deliberately excluded from reported timings.
    samples = []
    for _ in range(repetitions):
        start = time.perf_counter_ns()
        operation()
        samples.append((time.perf_counter_ns() - start) / 1_000_000)
    return samples


def measure_population(
    count: int,
    *,
    rate: float = 0.01,
    seed: int = 20261111,
    repetitions: int = 7,
    queries: int = 10000,
) -> dict[str, object]:
    """Measure one bitmap population with separate signing, validation, I/O and lookup scopes.

    Cached lookup numbers are batch mean nanoseconds per bit query, NOT complete
    credential/binding verification. Memory tracing runs separately from timings and
    measures Python allocations during validation, not all native memory.
    """
    if count < 1 or repetitions < 2 or queries < 1:
        raise ValueError("Use positive population/queries and at least two repetitions.")
    keys = IssuerKeys.generate()
    trust = keys.local_trust("benchmark-issuer", "benchmark-list")
    bitmap, oracle = generate_bitmap(count, rate, seed)

    def publish() -> bytes:
        """Encode and sign the prepared bitmap; key generation is outside this timing."""
        return create_snapshot(
            bitmap,
            issuer_id=trust.issuer_id,
            list_id=trust.list_id,
            epoch=1,
            issued_at=BENCHMARK_TIME,
            expires_at=BENCHMARK_TIME + 86400,
            key=keys.snapshot,
        )

    encoded = publish()

    def validate() -> object:
        """Measure full snapshot parsing, authentication and fixed-clock freshness checks."""
        snapshot = authenticate_snapshot(encoded, trust)
        check_freshness(snapshot, now=BENCHMARK_TIME, max_age_seconds=86400)
        return snapshot

    verified = authenticate_snapshot(encoded, trust)
    assert sum(byte.bit_count() for byte in verified.bitmap) == len(oracle)
    randomizer = random.Random(seed + 1)
    indexes = [randomizer.randrange(count) for _ in range(queries)]
    assert all(verified.is_revoked(index) == (index in oracle) for index in indexes)
    signing = _timings(publish, repetitions)
    validation = _timings(validate, repetitions)

    def lookup_batch() -> int:
        """Query pre-authenticated immutable bytes; include Python loop overhead."""
        return sum(verified.is_revoked(index) for index in indexes)

    expected_hits = sum(index in oracle for index in indexes)
    assert lookup_batch() == expected_hits
    lookup = [
        milliseconds * 1_000_000 / queries for milliseconds in _timings(lookup_batch, repetitions)
    ]
    with tempfile.TemporaryDirectory(prefix="p1qr-benchmark-") as temporary:
        cache = SnapshotCache.initialize(Path(temporary) / "cache", trust)
        cache.synchronize(encoded, trust, now=BENCHMARK_TIME, max_age_seconds=86400)
        cache_load = _timings(
            lambda: cache.load(trust, now=BENCHMARK_TIME, max_age_seconds=86400), repetitions
        )
        cache_size = cache.database.stat().st_size
    tracemalloc.start()
    try:
        validate()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return {
        "assigned_entries": count,
        "revoked_entries": len(oracle),
        "rate": rate,
        "seed": seed,
        "repetitions": repetitions,
        "queries_per_batch": queries,
        "raw_bitmap_bytes": len(bitmap.serialize()),
        "encoded_snapshot_bytes": len(encoded),
        "full_update_bandwidth_bytes": len(encoded),
        "cache_database_bytes": cache_size,
        "compressed_snapshot_bytes": None,
        "compression": "NOT_IMPLEMENTED",
        "snapshot_signing_ms": summarize(signing),
        "snapshot_validation_ms": summarize(validation),
        "cache_reload_validation_ms": summarize(cache_load),
        "cached_lookup_batch_ns_per_op": summarize(lookup),
        "validation_python_peak_bytes": peak,
        "oracle_hits_per_batch": expected_hits,
        "samples": {
            "signing_ms": signing,
            "validation_ms": validation,
            "cache_load_ms": cache_load,
            "lookup_batch_ns_per_op": lookup,
        },
    }


def measure_registry(*, repetitions: int = 7) -> dict[str, object]:
    """Measure actual small-registry issuance, one-bit revoke, and reissuance propagation.

    Keys and subjects are prepared before timings; issuance includes two signatures.
    Propagation timing excludes creation/signing of the credential family.
    """
    keys = IssuerKeys.generate()
    issue_samples, revoke_samples = [], []
    warmup = IssuerRegistry(keys)
    warmup_subject = warmup.create_subject()
    warmup_credential = warmup.issue(warmup_subject)
    warmup.revoke_credential(warmup_credential.credential_id)
    warmup.deactivate_subject(warmup_subject)
    propagation = {}
    for _ in range(repetitions):
        registry = IssuerRegistry(keys)
        subject = registry.create_subject()
        start = time.perf_counter_ns()
        credential = registry.issue(subject)
        issue_samples.append((time.perf_counter_ns() - start) / 1_000_000)
        start = time.perf_counter_ns()
        registry.revoke_credential(credential.credential_id)
        revoke_samples.append((time.perf_counter_ns() - start) / 1_000_000)
        assert registry.is_revoked(credential.credential_id)
    for family_size in (1, 5, 25):
        samples = []
        for _ in range(repetitions):
            registry = IssuerRegistry(keys)
            subject = registry.create_subject()
            first = registry.issue(subject)
            family = [
                first,
                *[registry.reissue(first.credential_id) for _ in range(family_size - 1)],
            ]
            start = time.perf_counter_ns()
            affected = registry.deactivate_subject(subject)
            samples.append((time.perf_counter_ns() - start) / 1_000_000)
            assert affected == family_size and all(
                registry.is_revoked(c.credential_id) for c in family
            )
        propagation[str(family_size)] = {**summarize(samples), "samples_ms": samples}
    return {
        "repetitions": repetitions,
        "issuance_with_binding_ms": summarize(issue_samples),
        "single_credential_revocation_ms": summarize(revoke_samples),
        "subject_deactivation_ms_by_credential_count": propagation,
        "issue_samples_ms": issue_samples,
        "revoke_samples_ms": revoke_samples,
    }


def run_benchmarks(
    output: Path,
    *,
    sizes: tuple[int, ...] = (10000, 100000, 1000000, 10000000),
    repetitions: int = 7,
    queries: int = 10000,
    seed: int = 20261111,
) -> dict[str, object]:
    """Measure all sizes and save JSON plus adjacent CSV; return the measured report.

    Output is synthetic aggregate performance data. Existing result files are refused
    so an earlier thesis experiment is not silently overwritten.
    """
    csv_path = output.with_suffix(".csv")
    if output.exists() or csv_path.exists():
        raise ValueError("Choose a new benchmark output path.")
    if (
        not sizes
        or any(type(n) is not int or not 1 <= n <= MAX_ENTRIES for n in sizes)
        or not 2 <= repetitions <= 100
        or not 1 <= queries <= 1_000_000
    ):
        raise ValueError("Invalid bounded benchmark parameters.")
    measurements = []
    for count in sizes:
        print(f"Measuring synthetic bitmap population {count:,} ...", flush=True)
        measurements.append(
            measure_population(count, seed=seed, repetitions=repetitions, queries=queries)
        )
    registry = measure_registry(repetitions=repetitions)
    hardware = platform.processor() or platform.machine()
    if platform.system() == "Darwin":
        hardware = subprocess.check_output(
            ["sysctl", "-n", "machdep.cpu.brand_string"], text=True
        ).strip()
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    report = {
        "protocol": "Research Bitstring Status List — Not W3C Conformant",
        "recorded_at": datetime.now(ZoneInfo("Asia/Kolkata")).isoformat(),
        "command": f"python -m p1qr benchmark-status --output {output} --sizes "
        + " ".join(map(str, sizes))
        + f" --repetitions {repetitions} --queries {queries} --seed {seed}",
        "environment": {
            "python": platform.python_version(),
            "os": platform.platform(),
            "hardware": hardware,
            "logical_cpus": os.cpu_count(),
            "dependencies": {
                p: importlib.metadata.version(p)
                for p in ("cryptography", "Pillow", "qrcode", "zxing-cpp", "pytest", "ruff")
            },
        },
        "methodology": "perf_counter_ns; warm-up excluded; median and nearest-rank p95; "
        "lookup statistics are per-batch mean ns/op, not per-request tail latency; "
        "tracemalloc separately measures validation Python allocations; no compression/deltas.",
        "process_high_water_rss_bytes": rss if platform.system() == "Darwin" else rss * 1024,
        "populations": measurements,
        "small_registry": registry,
        "limitations": "Bulk bitmaps simulate assigned slots; "
        "no millions-of-subjects registry is allocated. "
        "RSS is process-wide high-water, not per-size peak. Synthetic, one host, no UIDAI checks.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    columns = [
        "assigned_entries",
        "revoked_entries",
        "raw_bitmap_bytes",
        "encoded_snapshot_bytes",
        "cache_database_bytes",
        "validation_python_peak_bytes",
    ]
    timing = [
        "snapshot_signing_ms",
        "snapshot_validation_ms",
        "cache_reload_validation_ms",
        "cached_lookup_batch_ns_per_op",
    ]
    with csv_path.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=columns
            + [f"{name}_{stat}" for name in timing for stat in ("median", "p95")],
        )
        writer.writeheader()
        for row in measurements:
            flat = {name: row[name] for name in columns}
            flat.update(
                {f"{name}_{stat}": row[name][stat] for name in timing for stat in ("median", "p95")}
            )
            writer.writerow(flat)
    return report
