"""T204–T206/T218/T219/T228: authentic slot assertions and wrong-context rejection."""

from dataclasses import replace
from uuid import uuid4

import pytest

from p1qr.models import SignatureState, TrustState
from p1qr.offline.verifier import verify_offline
from p1qr.parser.payload import parse_payload
from p1qr.status.errors import StatusCode, StatusError
from p1qr.status_binding.assertion import verify_binding
from p1qr.synthetic.issuer import create_record, sign_record

NOW = 1767225600


def test_t204_valid_binding(issuer, issued):
    binding = verify_binding(issued.binding, parse_payload(issued.credential), issuer.trust)
    assert binding.status_index == issued.status_index
    assert binding.credential_id == issued.credential_id


def test_t205_modified_binding(issuer, issued, change_document):
    modified = change_document(issued.binding, {"status_index": 5})
    with pytest.raises(StatusError) as error:
        verify_binding(modified, parse_payload(issued.credential), issuer.trust)
    assert error.value.code == StatusCode.INVALID_BINDING
    assert error.value.signature == SignatureState.INVALID


def test_t206_wrong_credential(issuer, issued):
    different = issuer.reissue(issued.credential_id)
    with pytest.raises(StatusError) as error:
        verify_binding(issued.binding, parse_payload(different.credential), issuer.trust)
    assert error.value.code == StatusCode.INVALID_BINDING


def test_signed_wrong_uuid_rejected(issuer, issuer_keys, issued, change_document):
    modified = change_document(issued.binding, {"credential_id": str(uuid4())}, issuer_keys.binding)
    with pytest.raises(StatusError) as error:
        verify_binding(modified, parse_payload(issued.credential), issuer.trust)
    assert error.value.signature == SignatureState.VALID
    assert error.value.code == StatusCode.INVALID_BINDING


def test_digest_rejects_other_message_even_with_same_uuid(issuer, issuer_keys, issued):
    record = create_record(variant="Z")
    record["credential_id"] = issued.credential_id
    changed = sign_record(record, issuer_keys.credential)
    with pytest.raises(StatusError):
        verify_binding(issued.binding, parse_payload(changed), issuer.trust)


def test_t218_missing_index(issuer, issuer_keys, issued, change_document, cached):
    modified = change_document(issued.binding, {"status_index": ...}, issuer_keys.binding)
    result = verify_offline(issued.credential, modified, cached, issuer.trust, clock=lambda: NOW)
    assert result.decision == StatusCode.MISSING_STATUS_INDEX


def test_t219_out_of_authenticated_range(issuer, issuer_keys, issued, change_document, cached):
    modified = change_document(issued.binding, {"status_index": 1}, issuer_keys.binding)
    result = verify_offline(issued.credential, modified, cached, issuer.trust, clock=lambda: NOW)
    assert result.decision == StatusCode.STATUS_INDEX_OUT_OF_RANGE


@pytest.mark.parametrize("field", ["issuer_id", "list_id"])
def test_t228_inconsistent_context(issuer, issuer_keys, issued, change_document, field):
    modified = change_document(issued.binding, {field: "different-context"}, issuer_keys.binding)
    with pytest.raises(StatusError) as error:
        verify_binding(modified, parse_payload(issued.credential), issuer.trust)
    assert error.value.code == StatusCode.CONTEXT_MISMATCH


def test_untrusted_binding_key_is_separate_from_math(issuer, issued, cached):
    trust = replace(issuer.trust, binding=replace(issuer.trust.binding, fingerprint=None))
    result = verify_offline(issued.credential, issued.binding, cached, trust, clock=lambda: NOW)
    assert result.decision == StatusCode.UNTRUSTED_BINDING_SIGNER
    assert result.binding_signature == SignatureState.VALID
    assert result.binding_trust == TrustState.UNTRUSTED


def test_wrong_binding_role_key(issuer, issuer_keys, issued, change_document):
    modified = change_document(issued.binding, {}, issuer_keys.snapshot)
    with pytest.raises(StatusError) as error:
        verify_binding(modified, parse_payload(issued.credential), issuer.trust)
    assert error.value.code == StatusCode.INVALID_BINDING


@pytest.mark.parametrize("value", [True, -1, "0", None])
def test_invalid_index_types_fail_safely(issuer, issuer_keys, issued, change_document, value):
    with pytest.raises(StatusError):
        modified = change_document(issued.binding, {"status_index": value}, issuer_keys.binding)
        verify_binding(modified, parse_payload(issued.credential), issuer.trust)
