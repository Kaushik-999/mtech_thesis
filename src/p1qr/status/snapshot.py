"""Create and authenticate versioned snapshots; timestamps are claims, not a trusted clock."""

import base64
import hashlib
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import rsa

from p1qr.crypto.keys import key_fingerprint
from p1qr.models import SignatureState, TrustState
from p1qr.protocol import ALGORITHM
from p1qr.status.bitstring import BitstringStatusList, read_bit
from p1qr.status.encoding import (
    MAX_ENTRIES,
    MAX_INTEGER,
    MAX_TIMESTAMP,
    check_signature,
    decode_base64,
    hex_digest,
    parse_document,
    sign_document,
    unsigned_integer,
)
from p1qr.status.errors import StatusCode, StatusError
from p1qr.status.trust import IssuerTrust

SNAPSHOT_PROTOCOL = "P1QR-RESEARCH-STATUS-1"
SNAPSHOT_FIELDS = {
    "protocol",
    "issuer_id",
    "list_id",
    "epoch",
    "issued_at",
    "expires_at",
    "assigned_count",
    "bit_order",
    "bitmap",
    "bitmap_sha256",
    "algorithm",
    "key_id",
}


@dataclass(frozen=True)
class Snapshot:
    """Authenticated snapshot values; public APIs reconstruct these from signed input."""

    issuer_id: str
    list_id: str
    epoch: int
    issued_at: int
    expires_at: int
    assigned_count: int
    bitmap: bytes = field(repr=False)
    message_digest: str

    def is_revoked(self, index: int) -> bool:
        """Read a bound, assigned position; caller must also apply freshness policy."""
        return read_bit(self.bitmap, self.assigned_count, index)


def authenticated_error(
    code: StatusCode, message: str, snapshot: Snapshot | None = None
) -> StatusError:
    """Return a rejection preserving an already completed successful trust/signature check."""
    return StatusError(
        code,
        message,
        signature=SignatureState.VALID,
        trust=TrustState.TRUSTED_SYNTHETIC,
        snapshot_metadata=(snapshot.epoch, snapshot.issued_at, snapshot.expires_at)
        if snapshot is not None
        else None,
    )


def create_snapshot(
    bitmap: BitstringStatusList,
    *,
    issuer_id: str,
    list_id: str,
    epoch: int,
    issued_at: int,
    expires_at: int,
    key: rsa.RSAPrivateKey,
) -> bytes:
    """Return a signed full snapshot; no subject IDs, credentials, or names are included.

    ``epoch`` must be positive; timestamps are bounded Unix seconds with a nonempty
    validity interval. The issuer registry, not this pure encoder, increments epochs.
    """
    if unsigned_integer(epoch) == 0:
        raise StatusError(StatusCode.INVALID_SNAPSHOT, "Snapshot epochs start at one.")
    unsigned_integer(issued_at, MAX_TIMESTAMP)
    unsigned_integer(expires_at, MAX_TIMESTAMP)
    if expires_at <= issued_at:
        raise StatusError(StatusCode.INVALID_SNAPSHOT, "Expiry must be after issuance.")
    raw = bitmap.serialize()
    return sign_document(
        {
            "protocol": SNAPSHOT_PROTOCOL,
            "issuer_id": issuer_id,
            "list_id": list_id,
            "epoch": epoch,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "assigned_count": bitmap.count,
            "bit_order": "LSB0",
            "bitmap": base64.b64encode(raw).decode("ascii"),
            "bitmap_sha256": hashlib.sha256(raw).hexdigest(),
            "algorithm": ALGORITHM,
            "key_id": key_fingerprint(key.public_key()),
        },
        key,
    )


def authenticate_snapshot(data: bytes, trust: IssuerTrust) -> Snapshot:
    """Verify complete original signed bytes and configured issuer/list authorization.

    Return an immutable Snapshot only after all integrity, schema and trust checks.
    Freshness is a separate check, so an expired cached snapshot can still establish
    the historical high-water epoch while accepting a fresh replacement.
    """
    document = parse_document(data)
    record = document.record
    if set(record) != SNAPSHOT_FIELDS or record.get("protocol") != SNAPSHOT_PROTOCOL:
        raise StatusError(StatusCode.INVALID_SNAPSHOT, "Unsupported snapshot schema or version.")
    signature, key_trust = check_signature(document, trust.snapshot)
    if signature is SignatureState.INVALID:
        raise StatusError(
            StatusCode.INVALID_SNAPSHOT_SIGNATURE,
            "Snapshot signature is invalid.",
            signature=signature,
            trust=key_trust,
        )
    if key_trust is not TrustState.TRUSTED_SYNTHETIC:
        raise StatusError(
            StatusCode.UNTRUSTED_STATUS_ISSUER,
            "Snapshot key is not independently trusted.",
            signature=signature,
            trust=key_trust,
        )
    if record["issuer_id"] != trust.issuer_id or record["list_id"] != trust.list_id:
        raise authenticated_error(
            StatusCode.CONTEXT_MISMATCH, "Snapshot issuer/list differs from policy."
        )
    try:
        epoch = unsigned_integer(record["epoch"], MAX_INTEGER)
        issued = unsigned_integer(record["issued_at"], MAX_TIMESTAMP)
        expires = unsigned_integer(record["expires_at"], MAX_TIMESTAMP)
        count = unsigned_integer(record["assigned_count"], MAX_ENTRIES)
        if epoch == 0 or expires <= issued or record["bit_order"] != "LSB0":
            raise StatusError(
                StatusCode.INVALID_SNAPSHOT, "Invalid epoch, interval or bit ordering."
            )
        raw = decode_base64(record["bitmap"], (MAX_ENTRIES + 7) // 8)
        BitstringStatusList.from_bytes(raw, count)
        if hashlib.sha256(raw).hexdigest() != hex_digest(record["bitmap_sha256"]):
            raise StatusError(
                StatusCode.INVALID_SNAPSHOT, "Bitmap digest does not match signed state."
            )
    except StatusError as exc:
        raise authenticated_error(
            StatusCode.INVALID_SNAPSHOT, "Invalid authenticated snapshot values."
        ) from exc
    return Snapshot(
        trust.issuer_id,
        trust.list_id,
        epoch,
        issued,
        expires,
        count,
        raw,
        hashlib.sha256(document.message).hexdigest(),
    )


def check_freshness(snapshot: Snapshot, *, now: int, max_age_seconds: int) -> None:
    """Reject future/expired/over-age snapshots under the caller's clock and policy.

    Validity requires issued_at <= now < expires_at and age <= max_age_seconds.
    A correct local clock is an assumption; signed time does not supply one.
    """
    unsigned_integer(now, MAX_TIMESTAMP)
    unsigned_integer(max_age_seconds, MAX_TIMESTAMP)
    if now < snapshot.issued_at:
        raise authenticated_error(
            StatusCode.FUTURE_SNAPSHOT, "Snapshot is dated after the local clock.", snapshot
        )
    if now >= snapshot.expires_at or now - snapshot.issued_at > max_age_seconds:
        raise authenticated_error(
            StatusCode.STALE_SNAPSHOT, "Cached status evidence is too old or expired.", snapshot
        )
