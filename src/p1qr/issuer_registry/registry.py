"""Maintain private subject ownership, unique credential slots, and irreversible revocation."""

from dataclasses import dataclass, field, replace
from enum import StrEnum
from uuid import UUID, uuid4

from p1qr.parser.payload import parse_payload
from p1qr.status.bitstring import BitstringStatusList
from p1qr.status.errors import StatusCode, StatusError
from p1qr.status.snapshot import create_snapshot
from p1qr.status.trust import IssuerKeys, IssuerTrust
from p1qr.status_binding.assertion import issue_binding
from p1qr.synthetic.issuer import create_record, sign_record


class SubjectState(StrEnum):
    """Synthetic lifecycle only: ENABLED may transition permanently to DEACTIVATED."""

    ENABLED = "ENABLED"
    DEACTIVATED = "DEACTIVATED"


@dataclass(frozen=True)
class Subject:
    """Issuer-private fictional subject record; never serialize into public status data."""

    subject_id: str = field(repr=False)
    state: SubjectState = SubjectState.ENABLED
    credential_ids: tuple[str, ...] = field(default=(), repr=False)


@dataclass(frozen=True)
class RegistryEntry:
    """Private ownership relation and assigned index; records are never deleted/reused."""

    credential_id: str = field(repr=False)
    subject_id: str = field(repr=False)
    status_index: int = field(repr=False)


@dataclass(frozen=True)
class IssuedCredential:
    """Public presentation bundle, with no internal subject identifier."""

    credential: bytes = field(repr=False)
    binding: bytes = field(repr=False)
    credential_id: str = field(repr=False)
    status_index: int = field(repr=False)


def _uuid(value: str) -> str:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise StatusError(
            StatusCode.MALFORMED_STATUS, "Expected a canonical synthetic UUIDv4."
        ) from exc
    if parsed.version != 4 or str(parsed) != value:
        raise StatusError(StatusCode.MALFORMED_STATUS, "Expected a canonical synthetic UUIDv4.")
    return value


class IssuerRegistry:
    """Single-process simulated issuer with three ephemeral signing keys.

    Public list positions are per credential; private subjects may own many positions.
    Reissuing after subject deactivation is refused. No activation/delete/reuse API exists.
    This research registry is not durable across issuer process restarts.
    """

    def __init__(
        self, keys: IssuerKeys, issuer_id: str = "synthetic-issuer", list_id: str | None = None
    ) -> None:
        """Initialize an empty private registry and its explicit local role-key policy."""
        self._keys = keys
        # Fresh namespaces prevent accidental slot reuse when a volatile registry restarts.
        # Explicit namespace reuse requires the caller to restore complete issuer state.
        self.trust: IssuerTrust = keys.local_trust(
            issuer_id, list_id if list_id is not None else "research-list-" + uuid4().hex
        )
        self._subjects: dict[str, Subject] = {}
        self._entries: dict[str, RegistryEntry] = {}
        self._owners: dict[int, str] = {}
        self._bits = BitstringStatusList()
        self._epoch = 0
        self._last_issued_at = 0

    def create_subject(self, subject_id: str | None = None) -> str:
        """Create a fictional private subject and return its internal UUID; reject duplicates."""
        identifier = _uuid(subject_id if subject_id is not None else str(uuid4()))
        if identifier in self._subjects:
            raise StatusError(StatusCode.DUPLICATE_ID, "Subject identifier already registered.")
        self._subjects[identifier] = Subject(identifier)
        return identifier

    def subject(self, subject_id: str) -> Subject:
        """Return immutable issuer-private debug state; missing records are explicit errors."""
        if subject_id not in self._subjects:
            raise StatusError(StatusCode.REGISTRY_ENTRY_MISSING, "Subject is not registered.")
        return self._subjects[subject_id]

    def entry(self, credential_id: str) -> RegistryEntry:
        """Return a private ownership record for debugging, never a public lookup fallback."""
        if credential_id not in self._entries:
            raise StatusError(StatusCode.REGISTRY_ENTRY_MISSING, "Credential is not registered.")
        return self._entries[credential_id]

    def issue(self, subject_id: str, *, credential_id: str | None = None) -> IssuedCredential:
        """Issue an unchanged Phase 1 credential plus authenticated slot sidecar.

        Check duplicates and lifecycle first; sign before mutating registry state.
        Every successful issuance appends one position. Caller cannot select the index.
        """
        subject = self.subject(subject_id)
        if subject.state is SubjectState.DEACTIVATED:
            raise StatusError(
                StatusCode.SUBJECT_DEACTIVATED, "Cannot issue for a deactivated subject."
            )
        record = create_record()
        identifier = _uuid(
            credential_id if credential_id is not None else str(record["credential_id"])
        )
        if identifier in self._entries:
            raise StatusError(StatusCode.DUPLICATE_ID, "Credential identifier already registered.")
        index = self._bits.count
        if index in self._owners:
            raise StatusError(
                StatusCode.INDEX_ALLOCATION_ERROR, "Status index already has an owner."
            )
        record["credential_id"] = identifier
        credential = sign_record(record, self._keys.credential)
        binding = issue_binding(
            parse_payload(credential),
            issuer_id=self.trust.issuer_id,
            list_id=self.trust.list_id,
            status_index=index,
            credential_key=self._keys.credential.public_key(),
            binding_key=self._keys.binding,
        )
        self._bits.register(index)
        self._entries[identifier] = RegistryEntry(identifier, subject_id, index)
        self._owners[index] = identifier
        self._subjects[subject_id] = replace(
            subject, credential_ids=subject.credential_ids + (identifier,)
        )
        return IssuedCredential(credential, binding, identifier, index)

    def reissue(self, credential_id: str) -> IssuedCredential:
        """Issue a fresh UUID/slot for the same private subject; never clear the old slot."""
        return self.issue(self.entry(credential_id).subject_id)

    def revoke_credential(self, credential_id: str) -> None:
        """Irreversibly revoke one registered credential, without deactivating its subject."""
        self._bits.revoke(self.entry(credential_id).status_index)

    def deactivate_subject(self, subject_id: str) -> int:
        """Revoke every issued credential and return affected count; repeat calls are idempotent."""
        subject = self.subject(subject_id)
        for credential_id in subject.credential_ids:
            self.revoke_credential(credential_id)
        self._subjects[subject_id] = replace(subject, state=SubjectState.DEACTIVATED)
        return len(subject.credential_ids)

    def is_revoked(self, credential_id: str) -> bool:
        """Query issuer-private state; absent credentials never default to not revoked."""
        return self._bits.is_revoked(self.entry(credential_id).status_index)

    def publish(self, *, issued_at: int, expires_at: int) -> bytes:
        """Sign a full snapshot with the next epoch; only successful publication advances it."""
        if type(issued_at) is not int or issued_at < self._last_issued_at:
            raise StatusError(StatusCode.INVALID_SNAPSHOT, "Issuer time cannot move backward.")
        data = create_snapshot(
            self._bits,
            issuer_id=self.trust.issuer_id,
            list_id=self.trust.list_id,
            epoch=self._epoch + 1,
            issued_at=issued_at,
            expires_at=expires_at,
            key=self._keys.snapshot,
        )
        self._epoch += 1
        self._last_issued_at = issued_at
        return data
