"""T01/T03: exercise signing, public-only export, and exact QR byte round trips."""

import json
from pathlib import Path

import pytest

from p1qr.crypto.keys import key_fingerprint, load_public_key
from p1qr.errors import ErrorCode, P1QRError
from p1qr.parser.payload import parse_payload
from p1qr.protocol import canonical_json
from p1qr.scanner.reader import decode_qr_image
from p1qr.synthetic.issuer import create_record, export_bundle, render_qr, sign_record


def test_t01_generate_signed_credential(envelope, private_key):
    parsed = parse_payload(envelope)
    assert len(parsed.signature) == 256
    assert parsed.credential_id
    assert parsed.parsing_status == "PARSED_UNVERIFIED"
    assert parsed.issuer_label == "SYNTHETIC / NOT UIDAI"
    assert private_key.key_size == 2048


def test_serialization_is_order_independent():
    record = create_record()
    assert canonical_json(record) == canonical_json(dict(reversed(list(record.items()))))


def test_t03_image_roundtrip(envelope, tmp_path):
    path = tmp_path / "synthetic.png"
    render_qr(envelope, path)
    assert decode_qr_image(path) == envelope


def test_export_contains_no_private_key(envelope, private_key, tmp_path):
    output = tmp_path / "bundle"
    export_bundle(envelope, private_key.public_key(), output)
    assert {path.name for path in output.iterdir()} == {
        "credential.p1qr",
        "credential.png",
        "public_key.pem",
        "manifest.json",
    }
    loaded = load_public_key((output / "public_key.pem").read_bytes())
    assert key_fingerprint(loaded) == key_fingerprint(private_key.public_key())
    for path in output.iterdir():
        assert b"PRIVATE KEY" not in path.read_bytes()
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["label"] == "SYNTHETIC / NOT UIDAI"


def test_export_refuses_overwriting(envelope, private_key, tmp_path):
    with pytest.raises(P1QRError) as error:
        export_bundle(envelope, private_key.public_key(), tmp_path)
    assert error.value.code == ErrorCode.OUTPUT_ERROR


def test_fictional_schema_rejects_arbitrary_names(private_key):
    record = create_record()
    record["fictional_name"] = "UNTRUSTED_PERSONAL_DATA_CANARY"
    with pytest.raises(P1QRError):
        sign_record(record, private_key)


def test_missing_identifier_can_be_issued(private_key):
    parsed = parse_payload(sign_record(create_record(include_identifier=False), private_key))
    assert parsed.credential_id is None


def test_generation_never_requires_a_real_number():
    record = create_record()
    assert "aadhaar_number" not in record
    assert len(record["last_four"]) == 4
    assert "Fictional" in record["fictional_name"]


def test_render_refuses_existing_file(envelope, tmp_path: Path):
    destination = tmp_path / "existing.png"
    destination.write_bytes(b"keep this")
    with pytest.raises(FileExistsError):
        render_qr(envelope, destination)
    assert destination.read_bytes() == b"keep this"
