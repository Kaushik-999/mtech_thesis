"""Parse a bounded synthetic envelope and preserve its exact signed message bytes."""

import base64
import binascii
import json
import re
from uuid import UUID

from p1qr.adapters.uidai import reject_unestablished_format
from p1qr.errors import ErrorCode, P1QRError
from p1qr.models import ParsedCredential
from p1qr.protocol import (
    ALGORITHM,
    FORMAT,
    ISSUER,
    MAX_JSON_DEPTH,
    MAX_PAYLOAD_BYTES,
    MAX_SIGNED_BYTES,
    SIGNATURE_BYTES,
    canonical_json,
)


def _malformed() -> P1QRError:
    return P1QRError(ErrorCode.MALFORMED_PAYLOAD, "Malformed synthetic envelope or signed record.")


def _reject_number(_: str) -> object:
    # This protocol has no numeric fields. Refuse huge integer and NaN conversions.
    raise _malformed()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _malformed()
        result[key] = value
    return result


def _json_object(data: bytes) -> dict[str, object]:
    # Bound nesting before the library parser runs, independent of Python's recursion
    # implementation. Brackets inside escaped JSON strings do not count as nesting.
    depth = 0
    inside_string = False
    escaped = False
    for byte in data:
        if inside_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                inside_string = False
        elif byte == ord('"'):
            inside_string = True
        elif byte in (ord("{"), ord("[")):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise _malformed()
        elif byte in (ord("}"), ord("]")):
            depth -= 1
    try:
        value = json.loads(
            data.decode("ascii"),
            object_pairs_hook=_unique_object,
            parse_int=_reject_number,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise _malformed() from exc
    if not isinstance(value, dict):
        raise _malformed()
    return value


def _base64(value: object, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > 4 * ((maximum + 2) // 3):
        raise _malformed()
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise _malformed() from exc
    # Re-encoding rejects noncanonical pad bits and redundant encodings.
    if len(decoded) > maximum or base64.b64encode(decoded).decode("ascii") != value:
        raise _malformed()
    return decoded


def parse_payload(data: bytes) -> ParsedCredential:
    """Return an unauthenticated ParsedCredential from exact envelope ``data``.

    Raise P1QRError for size/schema/encoding violations or unsupported formats and
    algorithms. No decompression, XML parsing, or decimal-to-bigint conversion occurs.
    A missing credential identifier is allowed so its limitation can be reported.
    """
    if len(data) > MAX_PAYLOAD_BYTES:
        raise P1QRError(ErrorCode.INPUT_TOO_LARGE, "QR payload exceeds its byte limit.")
    if not data or not data.strip():
        raise _malformed()
    if not data.lstrip().startswith(b"{"):
        reject_unestablished_format()
    envelope = _json_object(data)
    if envelope.get("format") != FORMAT:
        reject_unestablished_format()
    if set(envelope) != {"format", "payload", "signature"}:
        raise _malformed()
    signed = _base64(envelope["payload"], MAX_SIGNED_BYTES)
    signature = _base64(envelope["signature"], SIGNATURE_BYTES)
    if len(signature) != SIGNATURE_BYTES:
        raise _malformed()
    record = _json_object(signed)
    if set(record) != {
        "format",
        "issuer",
        "algorithm",
        "credential_id",
        "last_four",
        "fictional_name",
    }:
        raise _malformed()
    if record["format"] != FORMAT or record["issuer"] != ISSUER:
        raise _malformed()
    if record["algorithm"] != ALGORITHM:
        raise P1QRError(
            ErrorCode.UNSUPPORTED_ALGORITHM, "Synthetic signature algorithm unsupported."
        )
    credential_id = record["credential_id"]
    if credential_id is not None:
        if not isinstance(credential_id, str) or len(credential_id) != 36:
            raise _malformed()
        try:
            identifier = UUID(credential_id)
        except ValueError as exc:
            raise _malformed() from exc
        if identifier.version != 4 or str(identifier) != credential_id:
            raise _malformed()
    last_four = record["last_four"]
    name = record["fictional_name"]
    if not isinstance(last_four, str) or re.fullmatch(r"[0-9]{4}", last_four) is None:
        raise _malformed()
    if not isinstance(name, str) or re.fullmatch(r"Fictional Resident [A-Z]", name) is None:
        raise _malformed()
    if canonical_json(record) != signed:
        raise _malformed()
    return ParsedCredential(
        signed_payload=signed,
        signature=signature,
        algorithm=ALGORITHM,
        credential_id=credential_id,
        last_four=last_four,
        identifier_binding_confidence=(
            "UNAUTHENTICATED_CREDENTIAL_ONLY" if credential_id else "IDENTIFIER_UNAVAILABLE"
        ),
    )
