"""Record separate Phase 2 checks while preserving historical Phase 1 evidence byte-for-byte."""

import argparse
import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


def main() -> int:
    """Run old/new tests, both demos, lint and formatting; optionally save actual outputs.

    ``--output`` selects a Phase 2 JSON report. Writing inside phase-01 is refused.
    A report records failures as failures and returns nonzero; no result is fabricated.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.output and args.output.resolve().is_relative_to(root / "docs/phase-01"):
        parser.error("Historical Phase 1 reports must not be overwritten.")
    baseline = json.loads((root / "docs/phase-02/results/baseline.json").read_text())
    preserved = all(
        hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
        for name, digest in baseline["phase1_sha256"].items()
    )
    old_tests = sorted(str(path.relative_to(root)) for path in (root / "tests").glob("test_*.py"))
    commands = [
        ["-m", "pytest", "-q", *old_tests],
        ["-m", "pytest", "-q", "tests/phase2"],
        ["-m", "pytest", "-q"],
        ["-m", "p1qr", "demo"],
        ["-m", "p1qr", "phase2-demo"],
        ["-m", "ruff", "check", "."],
        ["-m", "ruff", "format", "--check", "."],
    ]
    results = []
    for command in commands:
        run = subprocess.run(
            [sys.executable, *command], cwd=root, capture_output=True, text=True, timeout=120
        )
        label = "python " + " ".join(command)
        print(f"{label}: exit {run.returncode}", flush=True)
        print(run.stdout, end="", flush=True)
        print(run.stderr, end="", file=sys.stderr)
        results.append(
            {
                "command": label,
                "returncode": run.returncode,
                "stdout": run.stdout,
                "stderr": run.stderr,
            }
        )
    report = {
        "recorded_at": datetime.now(ZoneInfo("Asia/Kolkata")).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "phase1_historical_files_unchanged": preserved,
        "dependencies": {
            package: importlib.metadata.version(package)
            for package in (
                "aadhaar-offline-status-research",
                "cryptography",
                "qrcode",
                "Pillow",
                "zxing-cpp",
                "pytest",
                "ruff",
                "build",
            )
        },
        "checks": results,
        "source_sha256": {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((root / "src/p1qr").rglob("*.py"))
        },
        "scope": "Simulated issuer; no real UIDAI compatibility or revocation claim.",
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if preserved and all(result["returncode"] == 0 for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
