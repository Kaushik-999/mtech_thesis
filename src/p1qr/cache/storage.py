"""Fail-closed cache with transactional epoch/digest persistence across ordinary restarts."""

import hashlib
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from p1qr.protocol import canonical_json
from p1qr.status.encoding import MAX_SNAPSHOT_BYTES
from p1qr.status.errors import StatusCode, StatusError
from p1qr.status.snapshot import (
    Snapshot,
    authenticate_snapshot,
    authenticated_error,
    check_freshness,
)
from p1qr.status.trust import IssuerTrust


def _policy_tag(trust: IssuerTrust) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "issuer": trust.issuer_id,
                "list": trust.list_id,
                "snapshot_pin": trust.snapshot.fingerprint,
            }
        )
    ).hexdigest()


class SnapshotCache:
    """One issuer/list per cache with a durable highest-accepted epoch and payload digest.

    SQLite transactions replace a fragile two-file snapshot/high-water update. Never
    initialize on a read failure. The trusted-local-storage model excludes an attacker
    replacing or erasing the entire database/history; that needs external trusted state.
    """

    def __init__(self, directory: Path) -> None:
        """Select an existing cache directory without creating or resetting its database."""
        self.directory = directory
        self.database = directory / "status.sqlite3"

    @classmethod
    def initialize(cls, directory: Path, trust: IssuerTrust) -> "SnapshotCache":
        """Explicitly create a NEW cache, mode 0700 directory / 0600 database on POSIX.

        Initialization records policy even before the first snapshot. Existing or
        partially initialized directories are refused rather than wiping rollback history.
        """
        try:
            directory.mkdir(parents=True, mode=0o700, exist_ok=False)
            cache = cls(directory)
            connection = sqlite3.connect(cache.database)
            try:
                os.chmod(cache.database, 0o600)
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute(
                    "CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), "
                    "version INTEGER NOT NULL, policy TEXT NOT NULL, epoch INTEGER NOT NULL, "
                    "digest TEXT, snapshot BLOB)"
                )
                connection.execute(
                    "INSERT INTO state VALUES (1,1,?,0,NULL,NULL)", (_policy_tag(trust),)
                )
                connection.commit()
            finally:
                connection.close()
        except (OSError, sqlite3.Error) as exc:
            raise StatusError(
                StatusCode.CACHE_STATE_ERROR, "Cannot initialize a new verifier cache."
            ) from exc
        return cache

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            if (
                self.database.is_symlink()
                or not self.database.is_file()
                or self.database.stat().st_size > 4 * MAX_SNAPSHOT_BYTES
            ):
                raise StatusError(
                    StatusCode.CACHE_STATE_ERROR, "Cache is missing or exceeds its limit."
                )
            # mode=rw is essential: a missing database must NOT become a new epoch-zero cache.
            uri = self.database.resolve().as_uri() + "?mode=rw"
            connection = sqlite3.connect(uri, uri=True, timeout=5, isolation_level=None)
            connection.execute("PRAGMA synchronous=FULL")
            yield connection
        except (OSError, sqlite3.Error) as exc:
            raise StatusError(
                StatusCode.CACHE_STATE_ERROR, "Cache state is unavailable or corrupt."
            ) from exc
        finally:
            if connection is not None:
                connection.close()  # An uncommitted transaction rolls back on failure.

    def _read(self, connection: sqlite3.Connection, trust: IssuerTrust) -> Snapshot | None:
        rows = connection.execute(
            "SELECT version,policy,epoch,digest,snapshot FROM state"
        ).fetchall()
        if len(rows) != 1:
            raise StatusError(
                StatusCode.CACHE_STATE_ERROR, "Cache high-water record is missing or ambiguous."
            )
        version, policy, epoch, digest, raw = rows[0]
        if version != 1 or type(epoch) is not int or epoch < 0:
            raise StatusError(StatusCode.CACHE_STATE_ERROR, "Invalid cache high-water metadata.")
        if epoch == 0:
            if raw is not None or digest is not None or policy != _policy_tag(trust):
                raise StatusError(StatusCode.CACHE_STATE_ERROR, "Invalid initial cache state.")
            return None
        if not isinstance(raw, bytes) or len(raw) > MAX_SNAPSHOT_BYTES:
            raise StatusError(
                StatusCode.CACHE_STATE_ERROR, "Cached snapshot is missing or oversized."
            )
        snapshot = authenticate_snapshot(raw, trust)
        if snapshot.epoch < epoch:
            raise authenticated_error(
                StatusCode.SNAPSHOT_ROLLBACK, "Cached bytes precede the high-water epoch."
            )
        if (
            snapshot.epoch != epoch
            or snapshot.message_digest != digest
            or policy != _policy_tag(trust)
        ):
            raise authenticated_error(
                StatusCode.CACHE_STATE_ERROR, "Cached snapshot and high-water state disagree."
            )
        return snapshot

    def synchronize(
        self, data: bytes, trust: IssuerTrust, *, now: int, max_age_seconds: int
    ) -> Snapshot:
        """Accept a fresh authenticated snapshot atomically, or leave previous state unchanged.

        Reject lower epochs, different same-epoch signed payloads, decreasing counts,
        backward issuer time and cleared revoked bits. Identical payload re-signing is
        idempotent: randomized PSS signatures are not treated as issuer equivocation.
        """
        candidate = authenticate_snapshot(data, trust)
        check_freshness(candidate, now=now, max_age_seconds=max_age_seconds)
        with self._connection() as connection:
            # Serialize concurrent synchronizations so two writers cannot lower the epoch.
            connection.execute("BEGIN IMMEDIATE")
            previous = self._read(connection, trust)
            if previous is not None:
                if candidate.epoch < previous.epoch:
                    raise authenticated_error(
                        StatusCode.SNAPSHOT_ROLLBACK, "Older snapshot rejected."
                    )
                if candidate.epoch == previous.epoch:
                    if candidate.message_digest != previous.message_digest:
                        raise authenticated_error(
                            StatusCode.SNAPSHOT_EQUIVOCATION, "Conflicting same-epoch snapshot."
                        )
                    connection.commit()
                    return previous
                if (
                    candidate.issued_at < previous.issued_at
                    or candidate.assigned_count < previous.assigned_count
                    or any(
                        old & ~new
                        for old, new in zip(previous.bitmap, candidate.bitmap, strict=False)
                    )
                ):
                    raise authenticated_error(
                        StatusCode.SNAPSHOT_REGRESSION, "Permanent status state cannot regress."
                    )
            connection.execute(
                "UPDATE state SET epoch=?,digest=?,snapshot=? WHERE id=1",
                (candidate.epoch, candidate.message_digest, data),
            )
            connection.commit()  # Signature bytes and rollback metadata commit together.
        return candidate

    def load(self, trust: IssuerTrust, *, now: int, max_age_seconds: int) -> Snapshot:
        """Reauthenticate cache bytes and high-water metadata, then enforce current freshness.

        Reads need no network or private issuer key. Corruption/deletion never resets
        history. The caller may reuse the returned immutable snapshot for batched
        lookups only while reapplying its freshness policy and synchronization rules.
        """
        with self._connection() as connection:
            snapshot = self._read(connection, trust)
        if snapshot is None:
            raise StatusError(
                StatusCode.MISSING_SNAPSHOT, "No authenticated snapshot has been synchronized."
            )
        check_freshness(snapshot, now=now, max_age_seconds=max_age_seconds)
        return snapshot
