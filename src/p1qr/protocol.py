"""Specify OUR educational envelope; none of these constants describe UIDAI's protocol."""

import json

FORMAT = "P1QR-SYNTHETIC-1"
ISSUER = "SYNTHETIC / NOT UIDAI"
ALGORITHM = "RSA-PSS-SHA256-MGF1SHA256-SALT32"
RSA_BITS = 2048
SIGNATURE_BYTES = RSA_BITS // 8
MAX_PAYLOAD_BYTES = 8192
MAX_SIGNED_BYTES = 2048
MAX_JSON_DEPTH = 8
MAX_IMAGE_BYTES = 8 * 1024 * 1024
MAX_IMAGE_PIXELS = 4_000_000
MAX_IMAGE_SIDE = 8192
MAX_KEY_BYTES = 16 * 1024
DECODER_TIMEOUT_SECONDS = 10


def canonical_json(value: dict[str, object]) -> bytes:
    """Encode a controlled protocol object to deterministic ASCII JSON bytes.

    Keys are sorted, whitespace omitted, non-ASCII escaped, and NaN forbidden.
    This is a small Python-defined protocol, not general RFC 8785 canonical JSON.
    Callers must validate the restricted string/null schema before using it.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
