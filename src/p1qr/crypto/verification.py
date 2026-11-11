"""Separate exact-byte signature verification from local trust and status decisions."""

import hmac
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from p1qr.crypto.keys import key_fingerprint
from p1qr.errors import ErrorCode, P1QRError
from p1qr.models import BindingState, SignatureState, TrustState, VerificationResult
from p1qr.parser.payload import parse_payload
from p1qr.protocol import ALGORITHM, MAX_SIGNED_BYTES, RSA_BITS, SIGNATURE_BYTES


def signature_padding() -> padding.PSS:
    """Return OUR protocol's RSA-PSS padding with SHA-256 MGF1 and a 32-byte salt.

    Fixed algorithm parameters avoid guessing at verification time. PSS randomizes
    signatures, while the serialized message remains deterministic.
    """
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def verify_signature(
    message: bytes, signature: bytes, key: rsa.RSAPublicKey, algorithm: str = ALGORITHM
) -> SignatureState:
    """Check ``signature`` on exact ``message`` using ``key`` and return VALID/INVALID.

    Raise P1QRError on unsupported parameters or excessive input. A VALID result
    means mathematical consistency only: it establishes neither UIDAI trust nor status.
    """
    if algorithm != ALGORITHM:
        raise P1QRError(ErrorCode.UNSUPPORTED_ALGORITHM, "Signature algorithm unsupported.")
    if len(message) > MAX_SIGNED_BYTES:
        raise P1QRError(ErrorCode.INPUT_TOO_LARGE, "Signed message exceeds its byte limit.")
    if (
        not isinstance(key, rsa.RSAPublicKey)
        or key.key_size != RSA_BITS
        or key.public_numbers().e != 65537
    ):
        raise P1QRError(ErrorCode.INVALID_KEY, "Synthetic protocol requires RSA-2048 / e=65537.")
    if len(signature) != SIGNATURE_BYTES:
        return SignatureState.INVALID
    try:
        # Verify original bytes, never a reserialized parsed object. SHA-256 is applied
        # once inside the library. This detects changes but cannot establish currency.
        key.verify(signature, message, signature_padding(), hashes.SHA256())
    except InvalidSignature:
        return SignatureState.INVALID
    return SignatureState.VALID


def verify_credential(
    envelope: bytes,
    public_key: rsa.RSAPublicKey | None = None,
    trusted_fingerprint: str | None = None,
) -> VerificationResult:
    """Parse and verify synthetic ``envelope`` under an optional local trust pin.

    ``public_key`` supplies verification material; ``trusted_fingerprint`` must be
    independently accepted by the caller. No pin means UNTRUSTED even if VALID.
    Return separate signature/trust/binding states; parsing errors raise P1QRError.
    """
    credential = parse_payload(envelope)
    if (
        trusted_fingerprint is not None
        and re.fullmatch(r"[0-9a-f]{64}", trusted_fingerprint) is None
    ):
        raise P1QRError(ErrorCode.INVALID_TRUST_PIN, "Trust pin must be 64 lowercase hex digits.")
    if public_key is None:
        return VerificationResult(
            SignatureState.NOT_CHECKED,
            TrustState.MISSING_KEY,
            BindingState.UNAUTHENTICATED,
            "Supply an independently selected synthetic public key; no key was downloaded.",
        )
    signature = verify_signature(
        credential.signed_payload, credential.signature, public_key, credential.algorithm
    )
    trust = TrustState.UNTRUSTED
    if trusted_fingerprint and hmac.compare_digest(
        key_fingerprint(public_key), trusted_fingerprint
    ):
        trust = TrustState.TRUSTED_SYNTHETIC
    if signature is not SignatureState.VALID or trust is not TrustState.TRUSTED_SYNTHETIC:
        binding = BindingState.UNAUTHENTICATED
    elif credential.credential_id is None:
        binding = BindingState.IDENTIFIER_UNAVAILABLE
    else:
        binding = BindingState.SIGNED_CREDENTIAL_ONLY
    return VerificationResult(
        signature,
        trust,
        binding,
        "Synthetic-only result. No resident identity or Aadhaar revocation status established.",
    )
