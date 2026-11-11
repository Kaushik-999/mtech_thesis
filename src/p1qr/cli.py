"""Provide a privacy-conscious teaching CLI with explicit outcomes and exit codes."""

import argparse
import base64
import json
import sys
import tempfile
from pathlib import Path

from p1qr.binding.analysis import run_binding_experiment
from p1qr.crypto.keys import generate_private_key, key_fingerprint, load_public_key
from p1qr.crypto.verification import verify_credential
from p1qr.errors import ErrorCode, P1QRError
from p1qr.models import SignatureState, VerificationResult
from p1qr.parser.payload import parse_payload
from p1qr.phase2_cli import add_commands, run_command
from p1qr.protocol import MAX_KEY_BYTES, canonical_json
from p1qr.scanner.reader import decode_qr_image, read_bounded_file
from p1qr.synthetic.issuer import create_record, export_bundle, sign_record


def _print_verification(result: VerificationResult) -> None:
    print(f"Signature: {result.signature.value}")
    print(f"Signer trust: {result.trust.value}")
    print(f"Identifier binding: {result.binding.value}")
    print(f"Aadhaar status: {result.status}")


def _print_binding() -> bool:
    experiment = run_binding_experiment()
    print(f"Both synthetic signatures accepted: {experiment.signatures_valid_and_trusted}")
    print(f"Distinct credential IDs: {experiment.distinct_credential_ids}")
    print(f"Same last four digits: {experiment.same_last_four}")
    print(f"Distinct artefact hashes: {experiment.distinct_artefact_hashes}")
    print(f"Hash changed on reissuance: {experiment.reissued_artefact_hash_changed}")
    print("Last-four matching is insufficient; real identity binding: UNCONFIRMED.")
    print("Aadhaar status: NOT_CHECKED_PHASE_1")
    return all(
        (
            experiment.signatures_valid_and_trusted,
            experiment.distinct_credential_ids,
            experiment.same_last_four,
            experiment.distinct_artefact_hashes,
            experiment.reissued_artefact_hash_changed,
        )
    )


def _demo_in_directory(output: Path) -> int:
    key = generate_private_key()
    original = sign_record(create_record(), key)
    export_bundle(original, key.public_key(), output)
    print("1. Generated and signed a SYNTHETIC / NOT UIDAI credential.")
    decoded = decode_qr_image(output / "credential.png")
    if decoded != original:
        raise P1QRError(ErrorCode.DEMO_FAILED, "QR round trip changed the envelope bytes.")
    print("2. QR image decoded; exact envelope bytes match.")
    pin = key_fingerprint(key.public_key())
    result = verify_credential(decoded, key.public_key(), pin)
    if not result.accepted_synthetic:
        raise P1QRError(ErrorCode.DEMO_FAILED, "Original synthetic verification failed.")
    _print_verification(result)
    envelope = json.loads(original)
    record = json.loads(base64.b64decode(envelope["payload"]))
    record["fictional_name"] = "Fictional Resident Z"
    envelope["payload"] = base64.b64encode(canonical_json(record)).decode("ascii")
    # Deliberately retain the old signature after changing a schema-valid signed field.
    tampered = verify_credential(canonical_json(envelope), key.public_key(), pin)
    print(f"3. Modified payload with unchanged signature: {tampered.signature.value}")
    if tampered.signature is not SignatureState.INVALID:
        raise P1QRError(ErrorCode.DEMO_FAILED, "Tampering was not rejected.")
    print("4. Identifier-binding counterexample:")
    if not _print_binding():
        raise P1QRError(ErrorCode.DEMO_FAILED, "Binding counterexample did not match expectations.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Return the CLI argument parser with mutually exclusive payload/image input paths."""
    parser = argparse.ArgumentParser(
        prog="p1qr",
        description="Synthetic QR and offline status research. Never checks real Aadhaar status.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser(
        "demo", help="Run generation, image round trip, tampering and binding."
    )
    demo.add_argument(
        "--output", type=Path, help="New directory to retain synthetic demo artifacts."
    )
    generate = commands.add_parser(
        "generate-synthetic", help="Export a SYNTHETIC / NOT UIDAI bundle."
    )
    generate.add_argument("--output", type=Path, required=True, help="New output directory.")
    for name, help_text in (
        ("inspect", "Parse without authentication; print no demographic fields."),
        ("verify-synthetic", "Report signature validity and explicit local key trust separately."),
    ):
        command = commands.add_parser(name, help=help_text)
        source = command.add_mutually_exclusive_group(required=True)
        source.add_argument("--input", type=Path, help="Local raw envelope file.")
        source.add_argument("--image", type=Path, help="Local PNG/JPEG containing exactly one QR.")
        if name == "verify-synthetic":
            command.add_argument(
                "--public-key", type=Path, help="Local synthetic SPKI PEM public key."
            )
            command.add_argument(
                "--trusted-fingerprint",
                help="Independently accepted SHA-256 public-key fingerprint.",
            )
    commands.add_parser(
        "analyze-binding", help="Demonstrate suffix collision and artefact instability."
    )
    add_commands(commands)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run commands from ``argv`` (default: process arguments) and return an exit code.

    Codes: 0 completed experiment/inspection or accepted synthetic signature;
    1 invalid/untrusted signature; 2 input/format/decoder failure; 3 missing key.
    Neither exit 0 nor any output claims current Aadhaar status.
    """
    args = build_parser().parse_args(argv)
    if args.command in ("phase2-demo", "status-demo", "benchmark-status"):
        return run_command(args)
    try:
        if args.command == "demo":
            if args.output is not None:
                return _demo_in_directory(args.output)
            with tempfile.TemporaryDirectory(prefix="p1qr-synthetic-") as temporary:
                return _demo_in_directory(Path(temporary) / "bundle")
        if args.command == "generate-synthetic":
            key = generate_private_key()
            export_bundle(sign_record(create_record(), key), key.public_key(), args.output)
            print("Created SYNTHETIC / NOT UIDAI payload, QR, public key, and manifest.")
            print(f"Public key SHA-256: {key_fingerprint(key.public_key())}")
            print("Private key was not exported. Aadhaar status: NOT_CHECKED_PHASE_1")
            return 0
        if args.command == "analyze-binding":
            return 0 if _print_binding() else 1
        payload = decode_qr_image(args.image) if args.image else read_bounded_file(args.input)
        if args.command == "inspect":
            parsed = parse_payload(payload)
            print(f"Format: {parsed.credential_format}")
            print(f"Parse state: {parsed.parsing_status}")
            print(f"Identifier field present: {parsed.credential_id is not None}")
            print("Signature: NOT_CHECKED; signer trust: UNTRUSTED")
            print("Aadhaar status: NOT_CHECKED_PHASE_1")
            return 0
        public_key = None
        if args.public_key is not None:
            try:
                key_data = read_bounded_file(args.public_key, MAX_KEY_BYTES)
            except P1QRError as exc:
                if exc.code is ErrorCode.INPUT_ERROR:
                    raise P1QRError(
                        ErrorCode.MISSING_KEY, "Cannot read the supplied key file."
                    ) from exc
                raise
            public_key = load_public_key(key_data)
        result = verify_credential(payload, public_key, args.trusted_fingerprint)
        _print_verification(result)
        if public_key is None:
            return 3
        return 0 if result.accepted_synthetic else 1
    except P1QRError as exc:
        print(f"{exc.code.value}: {exc.message}", file=sys.stderr)
        return 3 if exc.code is ErrorCode.MISSING_KEY else 2
