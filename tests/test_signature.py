"""T02/T04/T05/T06/T09/T11: test signature, key trust, and binding independently."""

import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from p1qr.crypto.keys import key_fingerprint, load_public_key, public_key_pem
from p1qr.crypto.verification import verify_credential, verify_signature
from p1qr.errors import ErrorCode, P1QRError
from p1qr.models import BindingState, SignatureState, TrustState
from p1qr.parser.payload import parse_payload
from p1qr.protocol import canonical_json
from p1qr.synthetic.issuer import create_record, sign_record


def test_t02_valid_original(envelope, private_key):
    result = verify_credential(
        envelope, private_key.public_key(), key_fingerprint(private_key.public_key())
    )
    assert result.signature == SignatureState.VALID
    assert result.trust == TrustState.TRUSTED_SYNTHETIC
    assert result.accepted_synthetic
    assert result.binding == BindingState.SIGNED_CREDENTIAL_ONLY
    assert result.status == "NOT_CHECKED_PHASE_1"


def test_t04_modified_payload(envelope, private_key, alter_record):
    altered = alter_record(envelope, "fictional_name", "Fictional Resident Z")
    result = verify_credential(
        altered, private_key.public_key(), key_fingerprint(private_key.public_key())
    )
    assert result.signature == SignatureState.INVALID
    assert result.binding == BindingState.UNAUTHENTICATED
    assert not result.accepted_synthetic


def test_t05_altered_signature(envelope, private_key):
    outer = json.loads(envelope)
    signature = bytearray(base64.b64decode(outer["signature"]))
    signature[0] ^= 1
    outer["signature"] = base64.b64encode(signature).decode("ascii")
    result = verify_credential(canonical_json(outer), private_key.public_key())
    assert result.signature == SignatureState.INVALID


def test_t06_wrong_key(envelope, other_key):
    result = verify_credential(
        envelope, other_key.public_key(), key_fingerprint(other_key.public_key())
    )
    assert result.signature == SignatureState.INVALID
    assert not result.accepted_synthetic


def test_t09_missing_key(envelope):
    result = verify_credential(envelope)
    assert result.signature == SignatureState.NOT_CHECKED
    assert result.trust == TrustState.MISSING_KEY


def test_valid_arbitrary_key_does_not_establish_trust(envelope, private_key):
    result = verify_credential(envelope, private_key.public_key())
    assert result.signature == SignatureState.VALID
    assert result.trust == TrustState.UNTRUSTED
    assert not result.accepted_synthetic
    assert result.binding == BindingState.UNAUTHENTICATED


def test_wrong_pin_does_not_establish_trust(envelope, private_key):
    result = verify_credential(envelope, private_key.public_key(), "0" * 64)
    assert result.signature == SignatureState.VALID
    assert result.trust == TrustState.UNTRUSTED


def test_t11_missing_identifier(private_key):
    data = sign_record(create_record(include_identifier=False), private_key)
    result = verify_credential(
        data, private_key.public_key(), key_fingerprint(private_key.public_key())
    )
    assert result.accepted_synthetic
    assert result.binding == BindingState.IDENTIFIER_UNAVAILABLE
    assert result.status == "NOT_CHECKED_PHASE_1"


def test_wrong_padding_is_not_accepted(envelope, private_key):
    parsed = parse_payload(envelope)
    signature = private_key.sign(parsed.signed_payload, padding.PKCS1v15(), hashes.SHA256())
    assert (
        verify_signature(parsed.signed_payload, signature, private_key.public_key())
        == SignatureState.INVALID
    )


def test_wrong_pss_salt_length_is_not_accepted(envelope, private_key):
    parsed = parse_payload(envelope)
    signature = private_key.sign(
        parsed.signed_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    assert (
        verify_signature(parsed.signed_payload, signature, private_key.public_key())
        == SignatureState.INVALID
    )


def test_verifier_rejects_unsupported_algorithm(private_key):
    with pytest.raises(P1QRError) as error:
        verify_signature(b"x", b"x", private_key.public_key(), "none")
    assert error.value.code == ErrorCode.UNSUPPORTED_ALGORITHM


@pytest.mark.parametrize("data", [b"", b"not a PEM key", b"-----BEGIN PRIVATE KEY-----"])
def test_invalid_key_material(data):
    with pytest.raises(P1QRError) as error:
        load_public_key(data)
    assert error.value.code == ErrorCode.INVALID_KEY


def test_unexpected_key_type_rejected():
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(P1QRError):
        load_public_key(public_key_pem(key))


def test_weak_rsa_key_rejected():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
    with pytest.raises(P1QRError):
        load_public_key(public_key_pem(key))


def test_multiple_pem_keys_rejected(private_key):
    pem = public_key_pem(private_key.public_key())
    with pytest.raises(P1QRError):
        load_public_key(pem + pem)


def test_bad_trust_pin_is_structured(envelope, private_key):
    with pytest.raises(P1QRError) as error:
        verify_credential(envelope, private_key.public_key(), "bad-pin")
    assert error.value.code == ErrorCode.INVALID_TRUST_PIN
