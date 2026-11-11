"""T07/T12/T15: enforce format boundaries and adversarial-input bounds."""

import base64
import gzip
import json
import random

import pytest

from p1qr.errors import ErrorCode, P1QRError
from p1qr.parser.payload import parse_payload
from p1qr.protocol import FORMAT, MAX_PAYLOAD_BYTES, canonical_json


@pytest.mark.parametrize("raw", [b"", b"   ", b"{", b'{"format":', b'{"x":NaN}'])
def test_t07_malformed_input(raw):
    with pytest.raises(P1QRError) as error:
        parse_payload(raw)
    assert error.value.code == ErrorCode.MALFORMED_PAYLOAD


@pytest.mark.parametrize(
    "raw",
    [
        b"1234567890",
        b'<PrintLetterBarcodeData uid="REDACTED"/>',
        b"<OfflinePaperlessKyc/>",
        b"app.jwt.credential",
        b'{"format":"unknown"}',
    ],
)
def test_t12_unestablished_formats_are_unsupported(raw):
    with pytest.raises(P1QRError) as error:
        parse_payload(raw)
    assert error.value.code == ErrorCode.UNSUPPORTED_FORMAT


def test_duplicate_outer_key_rejected(envelope):
    duplicate = envelope[:-1] + b',"format":"P1QR-SYNTHETIC-1"}'
    with pytest.raises(P1QRError) as error:
        parse_payload(duplicate)
    assert error.value.code == ErrorCode.MALFORMED_PAYLOAD


def test_duplicate_signed_key_rejected(envelope):
    outer = json.loads(envelope)
    record = base64.b64decode(outer["payload"])
    record = record[:-1] + b',"last_four":"4242"}'
    outer["payload"] = base64.b64encode(record).decode("ascii")
    with pytest.raises(P1QRError):
        parse_payload(canonical_json(outer))


@pytest.mark.parametrize("field", ["payload", "signature"])
def test_invalid_base64(envelope, field):
    outer = json.loads(envelope)
    outer[field] = "!!!!"
    with pytest.raises(P1QRError):
        parse_payload(canonical_json(outer))


def test_noncanonical_signed_bytes_are_not_reserialized(envelope):
    outer = json.loads(envelope)
    original = base64.b64decode(outer["payload"])
    assert parse_payload(envelope).signed_payload == original
    outer["payload"] = base64.b64encode(b" " + original).decode("ascii")
    with pytest.raises(P1QRError):
        parse_payload(canonical_json(outer))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("last_four", "１２３４"),
        ("credential_id", "not-a-uuid"),
        ("issuer", "UIDAI"),
        ("fictional_name", "Personal-data-canary"),
        ("extra", "field"),
        ("credential_id", True),
        ("last_four", []),
        ("fictional_name", {"nested": "object"}),
    ],
)
def test_schema_violations(envelope, alter_record, field, value):
    with pytest.raises(P1QRError) as error:
        parse_payload(alter_record(envelope, field, value))
    assert error.value.code == ErrorCode.MALFORMED_PAYLOAD


def test_algorithm_confusion_rejected(envelope, alter_record):
    with pytest.raises(P1QRError) as error:
        parse_payload(alter_record(envelope, "algorithm", "none"))
    assert error.value.code == ErrorCode.UNSUPPORTED_ALGORITHM


def test_t15_oversized_raw_payload():
    with pytest.raises(P1QRError) as error:
        parse_payload(b"9" * (MAX_PAYLOAD_BYTES + 1))
    assert error.value.code == ErrorCode.INPUT_TOO_LARGE


def test_t15_deep_nesting_is_contained():
    data = b'{"x":' + b"[" * 1800 + b"]" * 1800 + b"}"
    with pytest.raises(P1QRError) as error:
        parse_payload(data)
    assert error.value.code == ErrorCode.MALFORMED_PAYLOAD


def test_t15_huge_integer_never_converted():
    data = b'{"x":' + b"9" * 6000 + b"}"
    with pytest.raises(P1QRError) as error:
        parse_payload(data)
    assert error.value.code == ErrorCode.MALFORMED_PAYLOAD


def test_t15_no_gzip_guessing():
    with pytest.raises(P1QRError) as error:
        parse_payload(gzip.compress(b"a" * 1_000_000))
    assert error.value.code == ErrorCode.UNSUPPORTED_FORMAT


def test_non_ascii_bytes_handled():
    with pytest.raises(P1QRError):
        parse_payload(b'{"format":"' + FORMAT.encode() + b'","x":"\xff"}')


def test_deterministic_malformed_corpus_has_no_uncontrolled_exceptions():
    generator = random.Random(20261110)
    for size in (1, 8, 64, 1024, 8192):
        for _ in range(20):
            data = generator.randbytes(size)
            with pytest.raises(P1QRError):
                parse_payload(data)
