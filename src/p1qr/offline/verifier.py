"""Combine the unchanged Phase 1 verifier with sidecar and cached status checks."""

import time
from collections.abc import Callable
from dataclasses import dataclass, replace

from p1qr.cache.storage import SnapshotCache
from p1qr.crypto.verification import verify_credential
from p1qr.errors import P1QRError
from p1qr.models import SignatureState, TrustState
from p1qr.parser.payload import parse_payload
from p1qr.status.errors import StatusCode, StatusError
from p1qr.status.trust import IssuerTrust
from p1qr.status_binding.assertion import verify_binding


def unix_time() -> int:
    """Return local wall-clock Unix seconds; callers can inject a controlled test clock."""
    return int(time.time())


@dataclass(frozen=True)
class OfflineResult:
    """Independent evidence stages; no subject IDs, slot numbers, names, or ACTIVE label."""

    decision: StatusCode = StatusCode.STATUS_UNKNOWN
    credential_signature: SignatureState = SignatureState.NOT_CHECKED
    credential_trust: TrustState = TrustState.UNTRUSTED
    binding_signature: SignatureState = SignatureState.NOT_CHECKED
    binding_trust: TrustState = TrustState.UNTRUSTED
    binding: str = "NOT_CHECKED"
    snapshot_signature: SignatureState = SignatureState.NOT_CHECKED
    snapshot_trust: TrustState = TrustState.UNTRUSTED
    snapshot_acceptability: str = "NOT_CHECKED"
    epoch: int | None = None
    issued_at: int | None = None
    expires_at: int | None = None


def verify_offline(
    credential: bytes,
    binding: bytes | None,
    cache: SnapshotCache,
    trust: IssuerTrust,
    *,
    clock: Callable[[], int] = unix_time,
    max_age_seconds: int = 86400,
) -> OfflineResult:
    """Return explicit synthetic status evidence without network or lookup fallbacks.

    ``credential`` is raw Phase 1 envelope bytes (also obtained via its QR reader).
    ``binding`` is a separately delivered sidecar. Only a valid/trusted credential,
    matched authenticated sidecar, and acceptable cached snapshot permit reading a bit.
    """
    result = OfflineResult()
    try:
        credential_result = verify_credential(
            credential, trust.credential.key, trust.credential.fingerprint
        )
        parsed = parse_payload(credential)
    except P1QRError:
        return result
    result = replace(
        result,
        credential_signature=credential_result.signature,
        credential_trust=credential_result.trust,
    )
    if credential_result.signature is SignatureState.INVALID:
        return replace(result, decision=StatusCode.INVALID_CREDENTIAL_SIGNATURE)
    if not credential_result.accepted_synthetic:
        return replace(result, decision=StatusCode.UNTRUSTED_CREDENTIAL_SIGNER)
    if binding is None:
        return replace(result, decision=StatusCode.MISSING_BINDING, binding="MISSING")
    try:
        assertion = verify_binding(binding, parsed, trust)
    except StatusError as exc:
        code = (
            exc.code
            if exc.code not in (StatusCode.MALFORMED_STATUS, StatusCode.INPUT_TOO_LARGE)
            else StatusCode.INVALID_BINDING
        )
        return replace(
            result,
            decision=code,
            binding_signature=exc.signature,
            binding_trust=exc.trust,
            binding="REJECTED",
        )
    result = replace(
        result,
        binding_signature=SignatureState.VALID,
        binding_trust=TrustState.TRUSTED_SYNTHETIC,
        binding="AUTHENTICATED_MATCH",
    )
    try:
        snapshot = cache.load(trust, now=clock(), max_age_seconds=max_age_seconds)
    except StatusError as exc:
        epoch, issued_at, expires_at = exc.snapshot_metadata or (None, None, None)
        return replace(
            result,
            decision=exc.code,
            snapshot_signature=exc.signature,
            snapshot_trust=exc.trust,
            snapshot_acceptability=exc.code.value,
            epoch=epoch,
            issued_at=issued_at,
            expires_at=expires_at,
        )
    result = replace(
        result,
        snapshot_signature=SignatureState.VALID,
        snapshot_trust=TrustState.TRUSTED_SYNTHETIC,
        snapshot_acceptability="ACCEPTABLE",
        epoch=snapshot.epoch,
        issued_at=snapshot.issued_at,
        expires_at=snapshot.expires_at,
    )
    try:
        revoked = snapshot.is_revoked(assertion.status_index)
    except StatusError as exc:
        return replace(result, decision=exc.code)
    return replace(
        result, decision=StatusCode.REVOKED if revoked else StatusCode.NOT_REVOKED_AS_OF_SNAPSHOT
    )
