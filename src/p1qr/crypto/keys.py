"""Generate ephemeral research keys and import/export public material only."""

import hashlib

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from p1qr.errors import ErrorCode, P1QRError
from p1qr.protocol import MAX_KEY_BYTES, RSA_BITS


def generate_private_key() -> rsa.RSAPrivateKey:
    """Return a fresh in-memory RSA-2048 research key; never write private material.

    The library supplies cryptographic randomness. This key is unrelated to UIDAI.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)


def public_key_pem(key: rsa.RSAPublicKey) -> bytes:
    """Return ``key`` as PEM SubjectPublicKeyInfo, suitable for local verification."""
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(data: bytes) -> rsa.RSAPublicKey:
    """Parse bounded PEM public-key ``data`` or raise P1QRError INVALID_KEY.

    Only RSA-2048 with exponent 65537 is in this synthetic protocol. Certificates,
    private keys, and other key types are deliberately not accepted or trusted.
    """
    if len(data) > MAX_KEY_BYTES:
        raise P1QRError(ErrorCode.INPUT_TOO_LARGE, "Public key exceeds its byte limit.")
    if not data.strip().startswith(b"-----BEGIN PUBLIC KEY-----"):
        raise P1QRError(ErrorCode.INVALID_KEY, "Expected a synthetic PEM public key.")
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise P1QRError(ErrorCode.INVALID_KEY, "Cannot parse the synthetic public key.") from exc
    if (
        not isinstance(key, rsa.RSAPublicKey)
        or key.key_size != RSA_BITS
        or key.public_numbers().e != 65537
    ):
        raise P1QRError(ErrorCode.INVALID_KEY, "Synthetic protocol requires RSA-2048 / e=65537.")
    # Reject trailing/second PEM objects that could cause ambiguous key selection.
    if data.strip() != public_key_pem(key).strip():
        raise P1QRError(ErrorCode.INVALID_KEY, "Expected one canonical PEM public key.")
    return key


def key_fingerprint(key: rsa.RSAPublicKey) -> str:
    """Return SHA-256 hex of ``key``'s DER SubjectPublicKeyInfo.

    A fingerprint supports out-of-band pin comparison; the hash itself confers no trust.
    """
    encoded = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(encoded).hexdigest()
