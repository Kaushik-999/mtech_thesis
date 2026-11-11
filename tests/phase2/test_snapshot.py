"""T212–T214/T217/T222 plus exact LSB bit layout, schema and clock boundaries."""

import base64
import json
from dataclasses import replace

import pytest

from p1qr.models import SignatureState, TrustState
from p1qr.protocol import canonical_json
from p1qr.status.bitstring import BitstringStatusList
from p1qr.status.encoding import MAX_ENTRIES, MAX_SNAPSHOT_BYTES, parse_document
from p1qr.status.errors import StatusCode, StatusError
from p1qr.status.snapshot import authenticate_snapshot, check_freshness, create_snapshot

NOW = 1767225600


def test_bit_boundaries_and_wire_order():
    bits = BitstringStatusList()
    for i in range(9):
        assert bits.register(i) == i
    for i in (0, 7, 8):
        bits.revoke(i)
    assert bits.serialize() == bytes([0x81, 0x01])
    recovered = BitstringStatusList.from_bytes(bits.serialize(), 9)
    assert [recovered.is_revoked(i) for i in range(9)] == [
        True,
        False,
        False,
        False,
        False,
        False,
        False,
        True,
        True,
    ]


def test_full_byte_and_idempotence():
    bits = BitstringStatusList.from_bytes(bytes(1), 8)
    for i in range(8):
        bits.revoke(i)
        bits.revoke(i)
    assert bits.serialize() == b"\xff"
    assert all(bits.is_revoked(i) for i in range(8))


@pytest.mark.parametrize("index", [-1, 0, 7, True, 1.0])
def test_empty_list_has_no_valid_index(index):
    with pytest.raises(StatusError) as error:
        BitstringStatusList().is_revoked(index)
    assert error.value.code == StatusCode.STATUS_INDEX_OUT_OF_RANGE


@pytest.mark.parametrize(
    ("raw", "count"), [(b"\x80", 1), (b"", 1), (b"\0\0", 8), (b"\0", 0), (b"", True)]
)
def test_invalid_bitmap_lengths_padding_count(raw, count):
    with pytest.raises(StatusError):
        BitstringStatusList.from_bytes(raw, count)


def test_no_duplicate_gap_or_padding_allocation():
    bits = BitstringStatusList()
    bits.register()
    for index in (0, 2, True):
        with pytest.raises(StatusError) as error:
            bits.register(index)
        assert error.value.code == StatusCode.INDEX_ALLOCATION_ERROR
    with pytest.raises(StatusError):
        bits.is_revoked(1)


def test_empty_snapshot_is_valid_but_cannot_answer_a_credential(issuer, issuer_keys):
    data = create_snapshot(
        BitstringStatusList(),
        issuer_id=issuer.trust.issuer_id,
        list_id=issuer.trust.list_id,
        epoch=1,
        issued_at=NOW,
        expires_at=NOW + 100,
        key=issuer_keys.snapshot,
    )
    snapshot = authenticate_snapshot(data, issuer.trust)
    assert snapshot.assigned_count == 0
    with pytest.raises(StatusError):
        snapshot.is_revoked(0)


def test_t212_tampered_bitmap(issuer, snapshot, change_document):
    changed = change_document(snapshot, {"bitmap": base64.b64encode(b"\1").decode()})
    with pytest.raises(StatusError) as error:
        authenticate_snapshot(changed, issuer.trust)
    assert error.value.code == StatusCode.INVALID_SNAPSHOT_SIGNATURE


def test_t213_altered_signature(issuer, snapshot):
    outer = json.loads(snapshot)
    signature = bytearray(base64.b64decode(outer["signature"]))
    signature[-1] ^= 1
    outer["signature"] = base64.b64encode(signature).decode()
    with pytest.raises(StatusError) as error:
        authenticate_snapshot(canonical_json(outer), issuer.trust)
    assert error.value.code == StatusCode.INVALID_SNAPSHOT_SIGNATURE


def test_t214_wrong_key(issuer, issuer_keys, snapshot, change_document):
    changed = change_document(snapshot, {}, issuer_keys.credential)
    with pytest.raises(StatusError) as error:
        authenticate_snapshot(changed, issuer.trust)
    assert error.value.code == StatusCode.INVALID_SNAPSHOT_SIGNATURE


def test_untrusted_snapshot_signer_and_missing_key(issuer, snapshot):
    for role in (
        replace(issuer.trust.snapshot, fingerprint=None),
        replace(issuer.trust.snapshot, key=None),
    ):
        with pytest.raises(StatusError) as error:
            authenticate_snapshot(snapshot, replace(issuer.trust, snapshot=role))
        assert error.value.code == StatusCode.UNTRUSTED_STATUS_ISSUER


def test_signature_validity_separate_from_snapshot_trust(issuer, snapshot):
    trust = replace(issuer.trust, snapshot=replace(issuer.trust.snapshot, fingerprint=None))
    with pytest.raises(StatusError) as error:
        authenticate_snapshot(snapshot, trust)
    assert error.value.signature == SignatureState.VALID
    assert error.value.trust == TrustState.UNTRUSTED


def test_t217_expiry_and_age_boundaries(issuer, snapshot):
    verified = authenticate_snapshot(snapshot, issuer.trust)
    check_freshness(verified, now=NOW + 10, max_age_seconds=10)
    for now, age in ((NOW + 11, 10), (verified.expires_at, 10**6)):
        with pytest.raises(StatusError) as error:
            check_freshness(verified, now=now, max_age_seconds=age)
        assert error.value.code == StatusCode.STALE_SNAPSHOT
    with pytest.raises(StatusError) as error:
        check_freshness(verified, now=NOW - 1, max_age_seconds=10)
    assert error.value.code == StatusCode.FUTURE_SNAPSHOT


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("epoch", 0),
        ("epoch", True),
        ("issued_at", "yesterday"),
        ("expires_at", NOW),
        ("assigned_count", MAX_ENTRIES + 1),
        ("assigned_count", True),
        ("bit_order", "MSB0"),
        ("bitmap_sha256", "0" * 64),
    ],
)
def test_signed_invalid_metadata(issuer, issuer_keys, snapshot, change_document, name, value):
    changed = change_document(snapshot, {name: value}, issuer_keys.snapshot)
    with pytest.raises(StatusError) as error:
        authenticate_snapshot(changed, issuer.trust)
    assert error.value.code == StatusCode.INVALID_SNAPSHOT


@pytest.mark.parametrize("name", ["issuer_id", "list_id"])
def test_snapshot_wrong_context(issuer, issuer_keys, snapshot, change_document, name):
    changed = change_document(snapshot, {name: "wrong-context"}, issuer_keys.snapshot)
    with pytest.raises(StatusError) as error:
        authenticate_snapshot(changed, issuer.trust)
    assert error.value.code == StatusCode.CONTEXT_MISMATCH


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{",
        b'{"x":1e999}',
        b'{"x":NaN}',
        b'{"x":' + b"9" * 6000 + b"}",
        b'{"x":' + b"[" * 1000 + b"]" * 1000 + b"}",
        b'{"x":1,"x":2}',
        b'{"x":"\xff"}',
    ],
)
def test_t222_malformed_snapshot(raw):
    with pytest.raises(StatusError):
        parse_document(raw)


def test_t222_oversized_snapshot():
    with pytest.raises(StatusError) as error:
        parse_document(b"x" * (MAX_SNAPSHOT_BYTES + 1))
    assert error.value.code == StatusCode.INPUT_TOO_LARGE
