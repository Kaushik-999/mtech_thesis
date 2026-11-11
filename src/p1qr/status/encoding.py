"""Bounded, flat signed JSON for Phase 2, separate from the unchanged Phase 1 format."""

import base64
import binascii
import json
import re
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from p1qr.crypto.verification import signature_padding
from p1qr.models import SignatureState, TrustState
from p1qr.protocol import ALGORITHM, canonical_json
from p1qr.status.errors import StatusCode, StatusError
from p1qr.status.trust import KeyTrust

MAX_ENTRIES = 10_000_000
MAX_MESSAGE_BYTES = 2 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 3 * 1024 * 1024
MAX_BINDING_BYTES = 8192
MAX_INTEGER = 2**53 - 1
MAX_TIMESTAMP = 4_102_444_800  # Unix seconds through 2100-01-01, inclusive.


def unsigned_integer(value: object, maximum: int = MAX_INTEGER) -> int:
    """Return bounded ``value`` as an integer; reject bool, floats and negatives."""
    if type(value) is not int or not 0 <= value <= maximum:
        raise StatusError(StatusCode.MALFORMED_STATUS, "Invalid bounded integer field.")
    return value


def hex_digest(value: object) -> str:
    """Return a canonical SHA-256 hex string or raise a safe schema error."""
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise StatusError(StatusCode.MALFORMED_STATUS, "Invalid digest or key identifier.")
    return value


def _number(text: str) -> int:
    if len(text) > 16 or not text.isascii() or not text.isdecimal():
        raise StatusError(StatusCode.MALFORMED_STATUS, "Invalid numeric encoding.")
    return unsigned_integer(int(text))


def _no_float(_: str) -> None:
    raise StatusError(StatusCode.MALFORMED_STATUS, "Floating point values are unsupported.")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StatusError(StatusCode.MALFORMED_STATUS, "Duplicate JSON key.")
        result[key] = value
    return result


def flat_json(data: bytes, limit: int) -> dict[str, object]:
    """Parse a bounded flat ASCII object with no floats, nesting, or duplicate keys.

    Security fields use restricted ASCII strings and bounded nonnegative integers.
    A pre-scan ignores quoted delimiters and rejects nesting before JSON allocation.
    """
    if len(data) > limit:
        raise StatusError(StatusCode.INPUT_TOO_LARGE, "Status input exceeds its byte limit.")
    if not data or not data.isascii():
        raise StatusError(StatusCode.MALFORMED_STATUS, "Expected ASCII status JSON.")
    inside = escaped = False
    depth = 0
    for byte in data:
        if inside:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                inside = False
        elif byte == 34:
            inside = True
        elif byte in (123, 91):
            depth += 1
            if depth > 1 or byte == 91:
                raise StatusError(StatusCode.MALFORMED_STATUS, "Nested status JSON is forbidden.")
        elif byte in (125, 93):
            depth -= 1
    try:
        record = json.loads(
            data,
            object_pairs_hook=_unique,
            parse_int=_number,
            parse_float=_no_float,
            parse_constant=_no_float,
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise StatusError(StatusCode.MALFORMED_STATUS, "Malformed status JSON.") from exc
    if not isinstance(record, dict):
        raise StatusError(StatusCode.MALFORMED_STATUS, "Expected a status JSON object.")
    return record


def decode_base64(value: object, limit: int) -> bytes:
    """Decode canonical standard base64 under ``limit``; no compression is accepted."""
    if not isinstance(value, str) or len(value) > 4 * ((limit + 2) // 3):
        raise StatusError(StatusCode.INPUT_TOO_LARGE, "Encoded status field exceeds its limit.")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise StatusError(StatusCode.MALFORMED_STATUS, "Malformed status base64.") from exc
    if len(decoded) > limit or base64.b64encode(decoded).decode("ascii") != value:
        raise StatusError(StatusCode.MALFORMED_STATUS, "Noncanonical status base64.")
    return decoded


@dataclass(frozen=True)
class SignedDocument:
    """Untrusted parsed metadata with exact original message/signature bytes."""

    record: dict[str, object] = field(repr=False)
    message: bytes = field(repr=False)
    signature: bytes = field(repr=False)


def parse_document(data: bytes, *, wire_limit: int = MAX_SNAPSHOT_BYTES) -> SignedDocument:
    """Return an unverified envelope; reject noncanonical signed JSON and unknown fields."""
    envelope = flat_json(data, wire_limit)
    if set(envelope) != {"payload", "signature"}:
        raise StatusError(StatusCode.MALFORMED_STATUS, "Invalid signed-envelope fields.")
    message = decode_base64(envelope["payload"], min(wire_limit, MAX_MESSAGE_BYTES))
    signature = decode_base64(envelope["signature"], 256)
    record = flat_json(message, MAX_MESSAGE_BYTES)
    if len(signature) != 256 or canonical_json(record) != message:
        raise StatusError(StatusCode.MALFORMED_STATUS, "Invalid signed-envelope encoding.")
    return SignedDocument(record, message, signature)


def sign_document(record: dict[str, object], key: rsa.RSAPrivateKey) -> bytes:
    """Sign deterministic Phase 2 bytes with an ephemeral RSA-2048 key.

    PSS protects all metadata and bitmap bytes together. It does not make timestamps
    truthful, authorize the key, hide fields, or prove current status after issuance.
    """
    if key.key_size != 2048 or key.public_key().public_numbers().e != 65537:
        raise StatusError(StatusCode.INVALID_POLICY, "Phase 2 requires RSA-2048 / e=65537.")
    message = canonical_json(record)
    flat_json(message, MAX_MESSAGE_BYTES)
    signature = key.sign(message, signature_padding(), hashes.SHA256())
    return canonical_json(
        {
            "payload": base64.b64encode(message).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
        }
    )


def check_signature(document: SignedDocument, role: KeyTrust) -> tuple[SignatureState, TrustState]:
    """Return mathematical validity and independent role trust for original signed bytes.

    Enforce the signed algorithm and key ID; do not resolve keys from the document.
    The larger Phase 2 message bound does not modify Phase 1's 2 KiB bound.
    """
    from p1qr.crypto.keys import key_fingerprint

    trust = role.state()
    if role.key is None:
        return SignatureState.NOT_CHECKED, trust
    if (
        role.key.key_size != 2048
        or role.key.public_numbers().e != 65537
        or document.record.get("algorithm") != ALGORITHM
        or document.record.get("key_id") != key_fingerprint(role.key)
    ):
        return SignatureState.INVALID, trust
    try:
        role.key.verify(document.signature, document.message, signature_padding(), hashes.SHA256())
    except InvalidSignature:
        return SignatureState.INVALID, trust
    return SignatureState.VALID, trust
