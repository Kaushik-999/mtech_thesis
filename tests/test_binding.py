"""T10: demonstrate suffix ambiguity using correctly signed synthetic credentials."""

from p1qr.binding.analysis import run_binding_experiment


def test_t10_suffix_collision_and_reissuance():
    result = run_binding_experiment()
    assert result.signatures_valid_and_trusted
    assert result.distinct_credential_ids
    assert result.same_last_four
    assert result.distinct_artefact_hashes
    assert result.reissued_artefact_hash_changed
    assert result.real_identity_binding == "UNCONFIRMED"
