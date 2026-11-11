"""Run synthetic counterexamples without inferring any real person's identity."""

import hashlib
from dataclasses import dataclass

from p1qr.crypto.keys import generate_private_key, key_fingerprint
from p1qr.crypto.verification import verify_credential
from p1qr.synthetic.issuer import create_record, sign_record


@dataclass(frozen=True)
class BindingExperiment:
    """Report only booleans, keeping fictional demographics and identifiers out of logs."""

    signatures_valid_and_trusted: bool
    distinct_credential_ids: bool
    same_last_four: bool
    distinct_artefact_hashes: bool
    reissued_artefact_hash_changed: bool
    real_identity_binding: str = "UNCONFIRMED"


def run_binding_experiment() -> BindingExperiment:
    """Return measured counterexamples using two fictional subjects and one reissuance.

    Both subjects are intentionally assigned the same suffix. A reissued record
    keeps the fictional fields but gets a new artefact ID. No UIDAI mapping exists.
    """
    key = generate_private_key()
    first = create_record(variant="A")
    second = create_record(variant="B")
    reissued = create_record(variant="A")
    envelopes = [sign_record(record, key) for record in (first, second, reissued)]
    results = [
        verify_credential(envelope, key.public_key(), key_fingerprint(key.public_key()))
        for envelope in envelopes
    ]
    fingerprints = [hashlib.sha256(envelope).digest() for envelope in envelopes]
    return BindingExperiment(
        signatures_valid_and_trusted=all(result.accepted_synthetic for result in results),
        distinct_credential_ids=first["credential_id"] != second["credential_id"],
        same_last_four=first["last_four"] == second["last_four"],
        distinct_artefact_hashes=fingerprints[0] != fingerprints[1],
        reissued_artefact_hash_changed=fingerprints[0] != fingerprints[2],
    )
