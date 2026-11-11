"""T207/T209/T215/T216/T224/T225/T229: offline lifecycle, persistence, and rollback failures."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from p1qr.cache.storage import SnapshotCache
from p1qr.models import SignatureState, TrustState
from p1qr.offline.verifier import verify_offline
from p1qr.status.errors import StatusCode, StatusError

NOW = 1767225600
DAY = 86400


def verify(issuer, issued, cached, now=NOW, max_age=3 * DAY):
    return verify_offline(
        issued.credential,
        issued.binding,
        cached,
        issuer.trust,
        clock=lambda: now,
        max_age_seconds=max_age,
    )


def test_t207_initial_not_revoked(issuer, issued, cached):
    result = verify(issuer, issued, cached)
    assert result.decision == StatusCode.NOT_REVOKED_AS_OF_SNAPSHOT
    assert (
        result.credential_signature
        == result.binding_signature
        == result.snapshot_signature
        == SignatureState.VALID
    )
    assert (
        result.credential_trust
        == result.binding_trust
        == result.snapshot_trust
        == TrustState.TRUSTED_SYNTHETIC
    )
    assert result.binding == "AUTHENTICATED_MATCH"
    assert result.snapshot_acceptability == "ACCEPTABLE"
    assert result.epoch == 1 and result.issued_at == NOW


def test_t209_single_revocation_visible_after_new_snapshot(issuer, issued, cached):
    original = issued.credential
    issuer.revoke_credential(issued.credential_id)
    updated = issuer.publish(issued_at=NOW + 10, expires_at=NOW + DAY)
    cached.synchronize(updated, issuer.trust, now=NOW + 10, max_age_seconds=DAY)
    result = verify(issuer, issued, cached, NOW + 10)
    assert issued.credential == original
    assert result.credential_signature == SignatureState.VALID
    assert result.decision == StatusCode.REVOKED


def test_t224_t225_four_day_missed_update_scenario(issuer, subject, issued, cached):
    issuer.deactivate_subject(subject)
    assert (
        verify(issuer, issued, cached, NOW + 2 * DAY).decision
        == StatusCode.NOT_REVOKED_AS_OF_SNAPSHOT
    )
    stale = verify(issuer, issued, cached, NOW + 2 * DAY, DAY)
    assert stale.decision == StatusCode.STALE_SNAPSHOT
    assert stale.snapshot_signature == SignatureState.VALID
    assert stale.epoch == 1 and stale.issued_at == NOW
    updated = issuer.publish(issued_at=NOW + 3 * DAY, expires_at=NOW + 5 * DAY)
    cached.synchronize(updated, issuer.trust, now=NOW + 3 * DAY, max_age_seconds=DAY)
    result = verify(issuer, issued, cached, NOW + 3 * DAY)
    assert result.decision == StatusCode.REVOKED
    assert result.credential_signature == SignatureState.VALID
    assert result.epoch == 2


def test_t215_t216_rollback_after_restart(issuer, issued, cached, snapshot):
    issuer.revoke_credential(issued.credential_id)
    updated = issuer.publish(issued_at=NOW + 1, expires_at=NOW + DAY)
    cached.synchronize(updated, issuer.trust, now=NOW + 1, max_age_seconds=DAY)
    reopened = SnapshotCache(cached.directory)
    assert verify(issuer, issued, reopened, NOW + 1).decision == StatusCode.REVOKED
    with pytest.raises(StatusError) as error:
        reopened.synchronize(snapshot, issuer.trust, now=NOW + 1, max_age_seconds=DAY)
    assert error.value.code == StatusCode.SNAPSHOT_ROLLBACK
    assert reopened.load(issuer.trust, now=NOW + 1, max_age_seconds=DAY).epoch == 2


def test_same_epoch_same_message_resigning_is_idempotent(
    issuer, cached, snapshot, change_document, issuer_keys
):
    resigned = change_document(snapshot, {}, issuer_keys.snapshot)
    assert resigned != snapshot  # PSS randomness does not constitute equivocation.
    assert cached.synchronize(resigned, issuer.trust, now=NOW, max_age_seconds=DAY).epoch == 1


def test_conflicting_same_epoch_rejected(issuer, cached, snapshot, change_document, issuer_keys):
    changed = change_document(snapshot, {"expires_at": NOW + DAY}, issuer_keys.snapshot)
    with pytest.raises(StatusError) as error:
        cached.synchronize(changed, issuer.trust, now=NOW, max_age_seconds=DAY)
    assert error.value.code == StatusCode.SNAPSHOT_EQUIVOCATION


def test_newer_epoch_cannot_clear_revoked_bits(
    issuer, issued, cached, snapshot, change_document, issuer_keys
):
    issuer.revoke_credential(issued.credential_id)
    updated = issuer.publish(issued_at=NOW + 1, expires_at=NOW + DAY)
    cached.synchronize(updated, issuer.trust, now=NOW + 1, max_age_seconds=DAY)
    reset = change_document(snapshot, {"epoch": 3, "issued_at": NOW + 2}, issuer_keys.snapshot)
    with pytest.raises(StatusError) as error:
        cached.synchronize(reset, issuer.trust, now=NOW + 2, max_age_seconds=DAY)
    assert error.value.code == StatusCode.SNAPSHOT_REGRESSION


def test_newer_epoch_cannot_reduce_count_or_issuer_time(
    issuer, cached, snapshot, change_document, issuer_keys
):
    import hashlib

    changes = [
        {"epoch": 2, "issued_at": NOW - 1},
        {
            "epoch": 2,
            "assigned_count": 0,
            "bitmap": "",
            "bitmap_sha256": hashlib.sha256(b"").hexdigest(),
        },
    ]
    for change in changes:
        with pytest.raises(StatusError) as error:
            cached.synchronize(
                change_document(snapshot, change, issuer_keys.snapshot),
                issuer.trust,
                now=NOW,
                max_age_seconds=DAY,
            )
        assert error.value.code == StatusCode.SNAPSHOT_REGRESSION


def test_expired_cache_can_be_replaced_by_fresh_snapshot(issuer, issued, cached):
    issuer.revoke_credential(issued.credential_id)
    fresh = issuer.publish(issued_at=NOW + 6 * DAY, expires_at=NOW + 7 * DAY)
    cached.synchronize(fresh, issuer.trust, now=NOW + 6 * DAY, max_age_seconds=DAY)
    assert verify(issuer, issued, cached, NOW + 6 * DAY).decision == StatusCode.REVOKED


def test_missing_binding_and_snapshot(issuer, issued, tmp_path):
    cache = SnapshotCache.initialize(tmp_path / "empty", issuer.trust)
    assert verify(issuer, issued, cache).decision == StatusCode.MISSING_SNAPSHOT
    result = verify_offline(issued.credential, None, cache, issuer.trust, clock=lambda: NOW)
    assert result.decision == StatusCode.MISSING_BINDING


def test_untrusted_credential_does_not_reach_status_lookup(issuer, issued, cached):
    trust = replace(issuer.trust, credential=replace(issuer.trust.credential, fingerprint=None))
    result = verify_offline(issued.credential, issued.binding, cached, trust, clock=lambda: NOW)
    assert result.decision == StatusCode.UNTRUSTED_CREDENTIAL_SIGNER
    assert result.credential_signature == SignatureState.VALID
    assert result.snapshot_signature == SignatureState.NOT_CHECKED


def test_t229_deleted_cache_fails_without_reinitialization(issuer, issued, cached):
    cached.database.unlink()
    result = verify(issuer, issued, SnapshotCache(cached.directory))
    assert result.decision == StatusCode.CACHE_STATE_ERROR
    assert not cached.database.exists()
    with pytest.raises(StatusError):
        SnapshotCache.initialize(cached.directory, issuer.trust)


def test_t229_corrupt_database_fails_closed(issuer, issued, cached):
    cached.database.write_bytes(b"corrupt database")
    assert verify(issuer, issued, cached).decision == StatusCode.CACHE_STATE_ERROR


def test_t229_missing_highwater_row_fails_closed(issuer, issued, cached):
    with sqlite3.connect(cached.database) as connection:
        connection.execute("DELETE FROM state")
    assert verify(issuer, issued, cached).decision == StatusCode.CACHE_STATE_ERROR


def test_t229_blob_rollback_preserving_highwater_detected(issuer, issued, cached, snapshot):
    updated = issuer.publish(issued_at=NOW + 1, expires_at=NOW + DAY)
    cached.synchronize(updated, issuer.trust, now=NOW + 1, max_age_seconds=DAY)
    with sqlite3.connect(cached.database) as connection:
        connection.execute("UPDATE state SET snapshot=?", (snapshot,))
    assert verify(issuer, issued, cached, NOW + 1).decision == StatusCode.SNAPSHOT_ROLLBACK


def test_t229_failed_transaction_preserves_previous_state(issuer, cached):
    updated = issuer.publish(issued_at=NOW + 1, expires_at=NOW + DAY)
    with sqlite3.connect(cached.database) as connection:
        connection.execute(
            "CREATE TRIGGER stop_write BEFORE UPDATE ON state "
            "BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
        )
    with pytest.raises(StatusError) as error:
        cached.synchronize(updated, issuer.trust, now=NOW + 1, max_age_seconds=DAY)
    assert error.value.code == StatusCode.CACHE_STATE_ERROR
    assert cached.load(issuer.trust, now=NOW + 1, max_age_seconds=DAY).epoch == 1


def test_concurrent_synchronizations_never_lower_highwater(issuer, cached, snapshot):
    newer = issuer.publish(issued_at=NOW + 1, expires_at=NOW + DAY)

    def sync(data):
        try:
            return cached.synchronize(data, issuer.trust, now=NOW + 1, max_age_seconds=DAY).epoch
        except StatusError as exc:
            assert exc.code == StatusCode.SNAPSHOT_ROLLBACK
            return 0

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(sync, [newer, snapshot]))
    assert cached.load(issuer.trust, now=NOW + 1, max_age_seconds=DAY).epoch == 2


def test_cache_permissions(cached):
    assert cached.directory.stat().st_mode & 0o777 == 0o700
    assert cached.database.stat().st_mode & 0o777 == 0o600
