"""Run reproducible Phase 1 checks and optionally save measured, non-PII results."""

import argparse
import importlib.metadata
import json
import platform
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


def main() -> int:
    """Execute demo, tests, lint, and format checks; return nonzero if any fails.

    ``--output`` optionally writes a JSON report containing exact captured outputs
    and package versions. Run inside an environment with the scanner and dev extras.
    Filesystem/dependency errors are explicit failures, not synthesized success.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional path for a measured JSON report.")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    commands = [
        [sys.executable, "-m", "p1qr", "demo"],
        [sys.executable, "-m", "pytest", "-q"],
        [sys.executable, "-m", "ruff", "check", "."],
        [sys.executable, "-m", "ruff", "format", "--check", "."],
    ]
    results = []
    for command in commands:
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=120)
        label = "python " + " ".join(command[1:])
        print(f"{label}: exit {result.returncode}")
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        results.append(
            {
                "command": label,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        )
    report = {
        "recorded_at": datetime.now(ZoneInfo("Asia/Kolkata")).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "dependencies": {
            package: importlib.metadata.version(package)
            for package in (
                "cryptography",
                "qrcode",
                "Pillow",
                "zxing-cpp",
                "pytest",
                "ruff",
                "build",
            )
        },
        "commands": results,
        "limitations": "Synthetic only; no real UIDAI conformance or revocation testing.",
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if all(result["returncode"] == 0 for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
