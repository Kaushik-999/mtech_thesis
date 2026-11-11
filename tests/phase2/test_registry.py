"""T201–T203/T208/T210/T211/T220/T227: private lifecycle and allocation invariants."""

from uuid import uuid4

import pytest

from p1qr.issuer_registry.registry import SubjectState
from p1qr.status.errors import StatusCode, StatusError


def test_t201_create_subject(issuer, subject):
    assert issuer.subject(subject).state == SubjectState.ENABLED
    assert issuer.subject(subject).credential_ids == ()


def test_t202_issue_and_allocate(issuer, subject, issued):
    assert issued.status_index == 0
    assert issuer.entry(issued.credential_id).subject_id == subject
    assert issuer.subject(subject).credential_ids == (issued.credential_id,)
    assert not issuer.is_revoked(issued.credential_id)


def test_t203_duplicate_index_detected(issuer, subject, issued):
    issuer._owners[1] = issued.credential_id  # Simulate inconsistent issuer-private state.
    with pytest.raises(StatusError) as error:
        issuer.issue(subject)
    assert error.value.code == StatusCode.INDEX_ALLOCATION_ERROR


def test_duplicate_subject_and_credential_ids(issuer, subject, issued):
    with pytest.raises(StatusError) as first:
        issuer.create_subject(subject)
    with pytest.raises(StatusError) as second:
        issuer.issue(subject, credential_id=issued.credential_id)
    assert first.value.code == second.value.code == StatusCode.DUPLICATE_ID
    assert issuer._bits.count == 1


def test_t208_single_revocation_is_idempotent(issuer, subject, issued):
    second = issuer.issue(subject)
    issuer.revoke_credential(issued.credential_id)
    issuer.revoke_credential(issued.credential_id)
    assert issuer.is_revoked(issued.credential_id)
    assert not issuer.is_revoked(second.credential_id)
    assert issuer.subject(subject).state == SubjectState.ENABLED


def test_t210_reissue_new_credential_and_slot(issuer, issued):
    replacement = issuer.reissue(issued.credential_id)
    assert replacement.credential_id != issued.credential_id
    assert replacement.status_index == issued.status_index + 1
    assert (
        issuer.entry(replacement.credential_id).subject_id
        == issuer.entry(issued.credential_id).subject_id
    )


def test_t211_deactivation_propagates_without_harming_other_subject(issuer, subject, issued):
    replacement = issuer.reissue(issued.credential_id)
    unrelated = issuer.issue(issuer.create_subject())
    assert issuer.deactivate_subject(subject) == 2
    assert issuer.is_revoked(issued.credential_id)
    assert issuer.is_revoked(replacement.credential_id)
    assert not issuer.is_revoked(unrelated.credential_id)
    assert issuer.deactivate_subject(subject) == 2
    for action in (lambda: issuer.issue(subject), lambda: issuer.reissue(issued.credential_id)):
        with pytest.raises(StatusError) as error:
            action()
        assert error.value.code == StatusCode.SUBJECT_DEACTIVATED


def test_t220_missing_registry_entry_never_means_not_revoked(issuer):
    identifier = str(uuid4())
    for action in (
        lambda: issuer.is_revoked(identifier),
        lambda: issuer.reissue(identifier),
        lambda: issuer.issue(identifier),
        lambda: issuer.deactivate_subject(identifier),
    ):
        with pytest.raises(StatusError) as error:
            action()
        assert error.value.code == StatusCode.REGISTRY_ENTRY_MISSING


def test_t227_revoked_slot_is_never_reused(issuer, issued):
    issuer.revoke_credential(issued.credential_id)
    replacement = issuer.reissue(issued.credential_id)
    assert replacement.status_index == 1
    assert issuer.is_revoked(issued.credential_id)
    assert not issuer.is_revoked(replacement.credential_id)


def test_failed_publication_does_not_consume_epoch(issuer, issued):
    from p1qr.status.snapshot import authenticate_snapshot

    with pytest.raises(StatusError):
        issuer.publish(issued_at=100, expires_at=99)
    result = authenticate_snapshot(issuer.publish(issued_at=100, expires_at=200), issuer.trust)
    assert result.epoch == 1
    with pytest.raises(StatusError):
        issuer.publish(issued_at=99, expires_at=200)


def test_new_volatile_registry_uses_a_new_list_namespace(issuer, issuer_keys):
    from p1qr.issuer_registry.registry import IssuerRegistry

    restarted = IssuerRegistry(issuer_keys)
    assert restarted.trust.list_id != issuer.trust.list_id
