"""Execute a synthetic four-day lifecycle experiment with an injected clock, never sleep."""

import base64
import json
import tempfile
from pathlib import Path

from p1qr.cache.storage import SnapshotCache
from p1qr.crypto.keys import public_key_pem
from p1qr.issuer_registry.registry import IssuerRegistry
from p1qr.offline.verifier import OfflineResult, verify_offline
from p1qr.protocol import canonical_json
from p1qr.scanner.reader import decode_qr_image
from p1qr.status.errors import StatusCode, StatusError
from p1qr.status.trust import IssuerKeys
from p1qr.synthetic.issuer import render_qr

DAY = 86400
DAY_ONE = 1767225600  # Fixed simulated 2026-01-01 UTC; not a claim about today's events.


def _show(label: str, result: OfflineResult, expected: StatusCode) -> None:
    if result.decision is not expected:
        raise StatusError(StatusCode.STATUS_UNKNOWN, "Synthetic demo assertion failed.")
    print(f"{label}: {result.decision.value}")
    print(
        f"  Credential signature={result.credential_signature.value}; "
        f"trust={result.credential_trust.value}"
    )
    print(
        f"  Binding={result.binding}; snapshot={result.snapshot_acceptability}; "
        f"epoch={result.epoch}"
    )
    if result.issued_at is not None:
        print(f"  Snapshot Unix seconds: issued={result.issued_at}; expires={result.expires_at}")


def _run(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    keys = IssuerKeys.generate()
    issuer = IssuerRegistry(keys)
    subject = issuer.create_subject()
    original = issuer.issue(subject)
    reissued = issuer.reissue(original.credential_id)
    render_qr(original.credential, output / "credential.png")
    decoded = decode_qr_image(output / "credential.png")
    if decoded != original.credential:
        raise StatusError(StatusCode.STATUS_UNKNOWN, "Synthetic QR round trip failed.")
    (output / "credential.p1qr").write_bytes(original.credential)
    (output / "binding.json").write_bytes(original.binding)
    for role in ("credential", "binding", "snapshot"):
        (output / f"{role}_public.pem").write_bytes(
            public_key_pem(getattr(keys, role).public_key())
        )
    first = issuer.publish(issued_at=DAY_ONE, expires_at=DAY_ONE + 5 * DAY)
    (output / "snapshot-1.json").write_bytes(first)
    cache = SnapshotCache.initialize(output / "cache", issuer.trust)
    cache.synchronize(first, issuer.trust, now=DAY_ONE, max_age_seconds=3 * DAY)

    def verify(now: int, age: int = 3 * DAY) -> OfflineResult:
        """Check the same credential using an explicit simulated time and age policy."""
        return verify_offline(
            decoded, original.binding, cache, issuer.trust, clock=lambda: now, max_age_seconds=age
        )

    print("SYNTHETIC / NOT UIDAI — Research Bitstring Status List — Not W3C Conformant")
    _show("Day 1, initial offline check", verify(DAY_ONE), StatusCode.NOT_REVOKED_AS_OF_SNAPSHOT)
    affected = issuer.deactivate_subject(subject)
    if affected != 2 or not issuer.is_revoked(reissued.credential_id):
        raise StatusError(StatusCode.STATUS_UNKNOWN, "Synthetic subject propagation failed.")
    print("Day 2: simulated subject deactivated; both issued credentials revoked internally.")
    _show(
        "Day 3, missed update, permissive age policy",
        verify(DAY_ONE + 2 * DAY),
        StatusCode.NOT_REVOKED_AS_OF_SNAPSHOT,
    )
    _show("Day 3, maximum age one day", verify(DAY_ONE + 2 * DAY, DAY), StatusCode.STALE_SNAPSHOT)
    newer = issuer.publish(issued_at=DAY_ONE + 3 * DAY, expires_at=DAY_ONE + 5 * DAY)
    (output / "snapshot-2.json").write_bytes(newer)
    cache.synchronize(newer, issuer.trust, now=DAY_ONE + 3 * DAY, max_age_seconds=3 * DAY)
    cache = SnapshotCache(output / "cache")  # Reopen, preserving the durable epoch.
    _show(
        "Day 4, same original credential after synchronization",
        verify(DAY_ONE + 3 * DAY),
        StatusCode.REVOKED,
    )
    outer = json.loads(newer)
    signature = bytearray(base64.b64decode(outer["signature"]))
    signature[0] ^= 1
    outer["signature"] = base64.b64encode(signature).decode("ascii")
    for label, data, expected in (
        ("Tampered snapshot", canonical_json(outer), StatusCode.INVALID_SNAPSHOT_SIGNATURE),
        ("Older authenticated snapshot", first, StatusCode.SNAPSHOT_ROLLBACK),
    ):
        try:
            cache.synchronize(data, issuer.trust, now=DAY_ONE + 3 * DAY, max_age_seconds=3 * DAY)
        except StatusError as exc:
            if exc.code is not expected:
                raise
            print(f"{label}: rejected as {exc.code.value}")
        else:
            raise StatusError(StatusCode.STATUS_UNKNOWN, "Unsafe snapshot was accepted.")
    print(
        "Same original bytes and valid credential signature; updated synthetic status is REVOKED."
    )
    print("No real Aadhaar status, subject identifiers, or private keys are emitted.")


def run_demo(output: Path | None = None) -> None:
    """Run all asserted lifecycle stages; retain synthetic/public files only with ``output``.

    Default temporary storage is deleted after the run. No private key or issuer
    subject registry is exported even when retention is explicitly requested.
    """
    if output is not None:
        _run(output)
    else:
        with tempfile.TemporaryDirectory(prefix="p1qr-phase2-") as temporary:
            _run(Path(temporary) / "bundle")
