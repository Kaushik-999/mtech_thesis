"""T221/T223/T226/T230: offline CLI, private mapping suppression and benchmark correctness."""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from p1qr.benchmarks.measure import generate_bitmap, measure_population, summarize
from p1qr.cli import main
from p1qr.status.encoding import parse_document


def test_t221_phase2_demo_under_active_network_guard(tmp_path):
    (tmp_path / "sitecustomize.py").write_text(
        "import socket\n"
        "def deny(*a,**kw):\n    raise RuntimeError('PHASE2_NETWORK_DISABLED')\n"
        "socket.socket.connect=deny\nsocket.socket.connect_ex=deny\n"
        "socket.create_connection=deny\nsocket.getaddrinfo=deny\n"
    )
    environment = dict(os.environ, PYTHONPATH=str(tmp_path))
    probe = subprocess.run(
        [sys.executable, "-c", "import socket; socket.create_connection(('example.invalid',443))"],
        env=environment,
        capture_output=True,
        timeout=10,
    )
    assert probe.returncode != 0 and b"PHASE2_NETWORK_DISABLED" in probe.stderr
    result = subprocess.run(
        [sys.executable, "-m", "p1qr", "phase2-demo"],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "REVOKED" in result.stdout and "STALE_SNAPSHOT" in result.stdout
    assert "SNAPSHOT_ROLLBACK" in result.stdout
    assert not result.stderr


def test_t223_public_data_omits_internal_subject_mapping(issuer, subject, issued, snapshot):
    for data in (issued.credential, issued.binding, snapshot):
        decoded = base64.b64decode(json.loads(data)["payload"])
        assert subject.encode() not in decoded
        assert b"subject_id" not in decoded
    snapshot_record = parse_document(snapshot).record
    assert "credential_id" not in snapshot_record
    assert "fictional_name" not in snapshot_record


def test_t223_cli_demo_logs_and_retained_files(tmp_path, capsys):
    output = tmp_path / "demo"
    assert main(["phase2-demo", "--output", str(output)]) == 0
    captured = capsys.readouterr()
    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-", captured.out)
    assert "Fictional Resident" not in captured.out
    assert not captured.err
    for path in output.rglob("*"):
        if path.is_file():
            assert b"-----BEGIN PRIVATE KEY-----" not in path.read_bytes()
            assert b"-----BEGIN RSA PRIVATE KEY-----" not in path.read_bytes()


def test_t226_phase1_documents_and_tests_unchanged():
    baseline = json.loads(Path("docs/phase-02/results/baseline.json").read_text())
    for name, digest in baseline["phase1_sha256"].items():
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest, name


def test_t230_known_bitmap_case_and_seed():
    bits, oracle = generate_bitmap(8, 0.5, 7)
    again, repeated_oracle = generate_bitmap(8, 0.5, 7)
    assert bits.serialize() == again.serialize()
    assert oracle == repeated_oracle
    assert sum(byte.bit_count() for byte in bits.serialize()) == 4
    for index in range(8):
        assert bits.is_revoked(index) == (index in oracle)
    assert summarize([1, 2, 3, 4, 100]) == {"median": 3, "p95": 100}


def test_t230_small_measured_case():
    report = measure_population(16, rate=0.5, repetitions=2, queries=32, seed=7)
    assert report["raw_bitmap_bytes"] == 2
    assert report["revoked_entries"] == 8
    assert report["full_update_bandwidth_bytes"] == report["encoded_snapshot_bytes"]
    assert report["compressed_snapshot_bytes"] is None
    assert report["snapshot_validation_ms"]["median"] > 0
    assert len(report["samples"]["lookup_batch_ns_per_op"]) == 2


def test_benchmark_cli_writes_reproducible_metadata(tmp_path, capsys):
    output = tmp_path / "bench.json"
    assert (
        main(
            [
                "benchmark-status",
                "--output",
                str(output),
                "--sizes",
                "8",
                "--repetitions",
                "2",
                "--queries",
                "16",
            ]
        )
        == 0
    )
    result = json.loads(output.read_text())
    assert result["populations"][0]["assigned_entries"] == 8
    assert result["small_registry"]["repetitions"] == 2
    assert output.with_suffix(".csv").is_file()
    assert main(["benchmark-status", "--output", str(output)]) == 2
    assert "PHASE2_INPUT_OUTPUT_ERROR" in capsys.readouterr().err
