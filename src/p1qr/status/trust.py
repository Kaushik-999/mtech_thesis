"""Define explicit local authorization of three separate synthetic signing roles."""

import re
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import rsa

from p1qr.crypto.keys import generate_private_key, key_fingerprint
from p1qr.models import TrustState
from p1qr.status.errors import StatusCode, StatusError


@dataclass(frozen=True)
class KeyTrust:
    """A candidate public key plus an independently configured fingerprint, if trusted."""

    key: rsa.RSAPublicKey | None = field(repr=False)
    fingerprint: str | None = None

    def __post_init__(self) -> None:
        """Validate local key/pin configuration before processing any credential."""
        if self.key is not None and not isinstance(self.key, rsa.RSAPublicKey):
            raise StatusError(StatusCode.INVALID_POLICY, "Role key must be an RSA public key.")
        if self.fingerprint is not None and (
            not isinstance(self.fingerprint, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.fingerprint) is None
        ):
            raise StatusError(StatusCode.INVALID_POLICY, "Invalid public-key trust pin.")

    def state(self) -> TrustState:
        """Return local key trust; a key or embedded key ID alone confers no trust."""
        if self.key is None:
            return TrustState.MISSING_KEY
        if self.fingerprint == key_fingerprint(self.key):
            return TrustState.TRUSTED_SYNTHETIC
        return TrustState.UNTRUSTED


@dataclass(frozen=True)
class IssuerTrust:
    """Trusted configuration authorizing role keys for exactly one issuer/list pair.

    This is an out-of-band policy input, not a self-authenticating downloaded object.
    No delegation is inferred from a credential, sidecar, or snapshot.
    """

    issuer_id: str
    list_id: str
    credential: KeyTrust
    binding: KeyTrust
    snapshot: KeyTrust

    def __post_init__(self) -> None:
        """Reject malformed namespace identifiers or noncanonical trust pins."""
        for value in (self.issuer_id, self.list_id):
            if not isinstance(value, str) or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value) is None:
                raise StatusError(
                    StatusCode.INVALID_POLICY, "Invalid synthetic issuer/list policy."
                )


@dataclass(frozen=True)
class IssuerKeys:
    """Three ephemeral private research keys; no private serialization or persistence."""

    credential: rsa.RSAPrivateKey = field(repr=False)
    binding: rsa.RSAPrivateKey = field(repr=False)
    snapshot: rsa.RSAPrivateKey = field(repr=False)

    @classmethod
    def generate(cls) -> "IssuerKeys":
        """Return independently generated signing keys for the three synthetic roles."""
        return cls(generate_private_key(), generate_private_key(), generate_private_key())

    def local_trust(self, issuer_id: str, list_id: str) -> IssuerTrust:
        """Return explicitly accepted demo policy for these locally generated keys.

        Only an issuer-controlled demonstration should bootstrap trust this way.
        Real deployments need independent provisioning, authorization, and rotation.
        """
        roles = [
            KeyTrust(key.public_key(), key_fingerprint(key.public_key()))
            for key in (self.credential, self.binding, self.snapshot)
        ]
        return IssuerTrust(issuer_id, list_id, *roles)
