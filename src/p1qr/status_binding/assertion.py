"""Issue and verify minimal signed bindings; no private subject mapping is exposed."""

import hashlib
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import rsa

from p1qr.crypto.keys import key_fingerprint
from p1qr.models import ParsedCredential, SignatureState, TrustState
from p1qr.protocol import ALGORITHM
from p1qr.status.encoding import (
    MAX_BINDING_BYTES,
    MAX_ENTRIES,
    check_signature,
    hex_digest,
    parse_document,
    sign_document,
    unsigned_integer,
)
from p1qr.status.errors import StatusCode, StatusError
from p1qr.status.snapshot import authenticated_error
from p1qr.status.trust import IssuerTrust

BINDING_PROTOCOL = "P1QR-STATUS-BINDING-1"
BINDING_FIELDS = {
    "protocol",
    "issuer_id",
    "list_id",
    "credential_id",
    "credential_sha256",
    "credential_key_id",
    "status_index",
    "algorithm",
    "key_id",
}


@dataclass(frozen=True)
class StatusBinding:
    """A credential-specific slot assertion, not a public identity-to-credential registry."""

    credential_id: str = field(repr=False)
    status_index: int = field(repr=False)
    issuer_id: str
    list_id: str


def issue_binding(
    credential: ParsedCredential,
    *,
    issuer_id: str,
    list_id: str,
    status_index: int,
    credential_key: rsa.RSAPublicKey,
    binding_key: rsa.RSAPrivateKey,
) -> bytes:
    """Sign a registry-assigned slot for ``credential`` using the binding-role key.

    The digest compares exact signed message bytes; it does not derive an identity or
    index. Only the registry may authorize allocation. This low-level encoder cannot
    prove that an arbitrary caller's assignment is unique across the issuer's registry.
    """
    if credential.credential_id is None:
        raise StatusError(StatusCode.INVALID_BINDING, "Credential identifier is unavailable.")
    unsigned_integer(status_index, MAX_ENTRIES - 1)
    return sign_document(
        {
            "protocol": BINDING_PROTOCOL,
            "issuer_id": issuer_id,
            "list_id": list_id,
            "credential_id": credential.credential_id,
            "credential_sha256": hashlib.sha256(credential.signed_payload).hexdigest(),
            "credential_key_id": key_fingerprint(credential_key),
            "status_index": status_index,
            "algorithm": ALGORITHM,
            "key_id": key_fingerprint(binding_key.public_key()),
        },
        binding_key,
    )


def verify_binding(data: bytes, credential: ParsedCredential, trust: IssuerTrust) -> StatusBinding:
    """Return a binding only after signature, authorization and exact credential match.

    The integrated verifier first authenticates the credential. No missing, unsigned,
    mismatched, or arbitrary-index lookup fallback is provided.
    """
    document = parse_document(data, wire_limit=MAX_BINDING_BYTES)
    record = document.record
    if "status_index" not in record:
        raise StatusError(
            StatusCode.MISSING_STATUS_INDEX, "Binding has no authenticated status index."
        )
    if set(record) != BINDING_FIELDS or record.get("protocol") != BINDING_PROTOCOL:
        raise StatusError(StatusCode.INVALID_BINDING, "Unsupported binding schema or version.")
    signature, key_trust = check_signature(document, trust.binding)
    if signature is SignatureState.INVALID:
        raise StatusError(
            StatusCode.INVALID_BINDING,
            "Binding signature is invalid.",
            signature=signature,
            trust=key_trust,
        )
    if key_trust is not TrustState.TRUSTED_SYNTHETIC:
        raise StatusError(
            StatusCode.UNTRUSTED_BINDING_SIGNER,
            "Binding key lacks independent trust.",
            signature=signature,
            trust=key_trust,
        )
    if record["issuer_id"] != trust.issuer_id or record["list_id"] != trust.list_id:
        raise authenticated_error(
            StatusCode.CONTEXT_MISMATCH, "Binding issuer/list differs from policy."
        )
    if (
        credential.credential_id is None
        or record["credential_id"] != credential.credential_id
        or record["credential_sha256"] != hashlib.sha256(credential.signed_payload).hexdigest()
        or trust.credential.key is None
        or record["credential_key_id"] != key_fingerprint(trust.credential.key)
    ):
        raise authenticated_error(
            StatusCode.INVALID_BINDING, "Binding does not match this credential/key."
        )
    try:
        hex_digest(record["credential_sha256"])
        index = unsigned_integer(record["status_index"], MAX_ENTRIES - 1)
    except StatusError as exc:
        raise authenticated_error(StatusCode.INVALID_BINDING, "Invalid binding values.") from exc
    return StatusBinding(credential.credential_id, index, trust.issuer_id, trust.list_id)
