"""Explicitly decline real Aadhaar formats until versioned byte-level evidence exists."""

from typing import NoReturn

from p1qr.errors import ErrorCode, P1QRError


def reject_unestablished_format() -> NoReturn:
    """Raise UNSUPPORTED_FORMAT without guessing compression, fields, or signing keys.

    The available official evidence is insufficient for this implementation's
    versioned parser and test vectors. This is not proof that no specification exists.
    Old XML QR, Secure QR, Paperless XML, and app credentials are all unsupported.
    """
    raise P1QRError(
        ErrorCode.UNSUPPORTED_FORMAT,
        "Only P1QR-SYNTHETIC-1 is supported. Real Aadhaar formats require an established "
        "byte-level specification, authorized test vectors, and independently trusted keys.",
    )
