"""Add isolated Phase 2 commands without changing the behavior of Phase 1 commands."""

import argparse
import sys
from pathlib import Path

from p1qr.status.errors import StatusError


def add_commands(commands: argparse._SubParsersAction) -> None:
    """Register the synthetic lifecycle demo and bounded benchmark command."""
    demo = commands.add_parser(
        "phase2-demo",
        aliases=["status-demo"],
        help="Run synthetic binding, cached revocation, freshness and rollback.",
    )
    demo.add_argument(
        "--output", type=Path, help="New directory to retain synthetic/public demo files."
    )
    benchmark = commands.add_parser(
        "benchmark-status", help="Measure research bitmaps and small issuer registries."
    )
    benchmark.add_argument(
        "--output", type=Path, required=True, help="New JSON output path; CSV is also written."
    )
    benchmark.add_argument(
        "--sizes", type=int, nargs="+", default=[10000, 100000, 1000000, 10000000]
    )
    benchmark.add_argument("--repetitions", type=int, default=7)
    benchmark.add_argument(
        "--queries", type=int, default=10000, help="Queries in each timed lookup batch."
    )
    benchmark.add_argument("--seed", type=int, default=20261111)


def run_command(args: argparse.Namespace) -> int:
    """Run Phase 2 arguments and return 0 on completed checks or 2 on safe failure."""
    try:
        if args.command in ("phase2-demo", "status-demo"):
            from p1qr.offline.demo import run_demo

            run_demo(args.output)
        else:
            from p1qr.benchmarks.measure import run_benchmarks

            report = run_benchmarks(
                args.output,
                sizes=tuple(args.sizes),
                repetitions=args.repetitions,
                queries=args.queries,
                seed=args.seed,
            )
            print(
                f"Measured {len(report['populations'])} synthetic populations; "
                "JSON and CSV written."
            )
        return 0
    except StatusError as exc:
        print(f"{exc.code.value}: {exc.message}", file=sys.stderr)
    except (OSError, ValueError):
        print(
            "PHASE2_INPUT_OUTPUT_ERROR: Check bounded arguments "
            "and choose a new writable output path.",
            file=sys.stderr,
        )
    return 2
