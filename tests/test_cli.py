"""T13/T14 plus CLI behavior: offline demo, safe logs, and meaningful exit codes."""

import os
import subprocess
import sys

from p1qr.cli import main
from p1qr.crypto.keys import key_fingerprint, public_key_pem
from p1qr.parser.payload import parse_payload


def test_cli_demo(capsys):
    assert main(["demo"]) == 0
    output = capsys.readouterr().out
    assert "exact envelope bytes match" in output
    assert "Signature: VALID" in output
    assert "unchanged signature: INVALID" in output
    assert "Same last four digits: True" in output


def test_t13_full_demo_with_python_network_disabled(tmp_path):
    # sitecustomize also runs inside the image worker: both subprocesses get the guard.
    (tmp_path / "sitecustomize.py").write_text(
        "import socket\n"
        "def denied(*args, **kwargs):\n"
        "    raise RuntimeError('NETWORK_DISABLED_FOR_TEST')\n"
        "socket.socket.connect = denied\n"
        "socket.socket.connect_ex = denied\n"
        "socket.create_connection = denied\n"
        "socket.getaddrinfo = denied\n",
        encoding="utf-8",
    )
    environment = dict(os.environ, PYTHONPATH=str(tmp_path))
    # First prove that the guard is loaded; this must fail without accessing a network.
    probe = subprocess.run(
        [sys.executable, "-c", "import socket; socket.create_connection(('example.invalid',443))"],
        capture_output=True,
        env=environment,
        timeout=5,
    )
    assert probe.returncode != 0
    assert b"NETWORK_DISABLED_FOR_TEST" in probe.stderr
    result = subprocess.run(
        [sys.executable, "-m", "p1qr", "demo"],
        capture_output=True,
        env=environment,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode()
    assert b"Signature: VALID" in result.stdout
    assert not result.stderr


def test_t14_no_demographics_identifiers_or_payload_in_logs(
    envelope, private_key, tmp_path, capsys
):
    payload = tmp_path / "payload"
    key = tmp_path / "public.pem"
    payload.write_bytes(envelope)
    key.write_bytes(public_key_pem(private_key.public_key()))
    args = [
        "verify-synthetic",
        "--input",
        str(payload),
        "--public-key",
        str(key),
        "--trusted-fingerprint",
        key_fingerprint(private_key.public_key()),
    ]
    assert main(args) == 0
    output = capsys.readouterr().out
    parsed = parse_payload(envelope)
    assert "Fictional Resident" not in output
    assert parsed.credential_id not in output
    assert parsed.last_four not in output
    assert envelope.decode() not in output


def test_t14_invalid_personal_data_is_not_echoed(tmp_path, capsys):
    canary = "UNTRUSTED_PERSONAL_DATA_CANARY"
    path = tmp_path / canary
    path.write_text('{"format":"P1QR-SYNTHETIC-1","payload":"' + canary + '"}')
    assert main(["inspect", "--input", str(path)]) == 2
    output = capsys.readouterr()
    assert canary not in output.out + output.err
    assert "MALFORMED_PAYLOAD" in output.err


def test_inspect_does_not_authenticate(envelope, tmp_path, capsys):
    path = tmp_path / "payload"
    path.write_bytes(envelope)
    assert main(["inspect", "--input", str(path)]) == 0
    output = capsys.readouterr().out
    assert "PARSED_UNVERIFIED" in output
    assert "Signature: NOT_CHECKED" in output


def test_cli_no_key(envelope, tmp_path, capsys):
    path = tmp_path / "payload"
    path.write_bytes(envelope)
    assert main(["verify-synthetic", "--input", str(path)]) == 3
    assert "Signer trust: MISSING_KEY" in capsys.readouterr().out


def test_cli_absent_key_file(envelope, tmp_path, capsys):
    path = tmp_path / "payload"
    path.write_bytes(envelope)
    assert (
        main(["verify-synthetic", "--input", str(path), "--public-key", str(tmp_path / "absent")])
        == 3
    )
    assert "MISSING_KEY" in capsys.readouterr().err


def test_cli_untrusted_valid_key(envelope, private_key, tmp_path, capsys):
    path = tmp_path / "payload"
    key = tmp_path / "key.pem"
    path.write_bytes(envelope)
    key.write_bytes(public_key_pem(private_key.public_key()))
    assert main(["verify-synthetic", "--input", str(path), "--public-key", str(key)]) == 1
    output = capsys.readouterr().out
    assert "Signature: VALID" in output
    assert "Signer trust: UNTRUSTED" in output


def test_cli_generation_and_image_inspection(tmp_path, capsys):
    output = tmp_path / "bundle"
    assert main(["generate-synthetic", "--output", str(output)]) == 0
    assert main(["inspect", "--image", str(output / "credential.png")]) == 0
    assert "PARSED_UNVERIFIED" in capsys.readouterr().out


def test_cli_binding(capsys):
    assert main(["analyze-binding"]) == 0
    assert "real identity binding: UNCONFIRMED" in capsys.readouterr().out
