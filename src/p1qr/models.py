"""Define immutable results so parsing, cryptographic validity, and trust stay distinct."""

from dataclasses import dataclass, field
from enum import StrEnum


class SignatureState(StrEnum):
    """State of the mathematical signature check, independent of key provenance."""

    VALID = "VALID"
    INVALID = "INVALID"
    NOT_CHECKED = "NOT_CHECKED"


class TrustState(StrEnum):
    """Local key policy; this prototype can never establish UIDAI issuer trust."""

    TRUSTED_SYNTHETIC = "TRUSTED_SYNTHETIC"
    UNTRUSTED = "UNTRUSTED"
    MISSING_KEY = "MISSING_KEY"


class BindingState(StrEnum):
    """Binding evidence available after verification, never a real identity mapping."""

    SIGNED_CREDENTIAL_ONLY = "SIGNED_CREDENTIAL_ONLY"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    IDENTIFIER_UNAVAILABLE = "IDENTIFIER_UNAVAILABLE"


@dataclass(frozen=True)
class ParsedCredential:
    """Represent syntactically valid, still UNAUTHENTICATED synthetic data.

    Byte fields preserve the signed message and signature exactly. Sensitive fields
    are excluded from repr; callers must not log the raw bytes or identifiers.
    ``credential_id`` identifies an artefact, never a resident across reissuance.
    """

    signed_payload: bytes = field(repr=False)
    signature: bytes = field(repr=False)
    algorithm: str
    credential_id: str | None = field(repr=False)
    last_four: str = field(repr=False)
    credential_format: str = "P1QR-SYNTHETIC-1"
    issuer_label: str = "SYNTHETIC / NOT UIDAI"
    parsing_status: str = "PARSED_UNVERIFIED"
    identifier_binding_confidence: str = "UNAUTHENTICATED_CREDENTIAL_ONLY"


@dataclass(frozen=True)
class VerificationResult:
    """Report independent decisions; ``status`` is always outside Phase 1 scope."""

    signature: SignatureState
    trust: TrustState
    binding: BindingState
    detail: str
    status: str = field(default="NOT_CHECKED_PHASE_1", init=False)

    @property
    def accepted_synthetic(self) -> bool:
        """Return whether signature and local synthetic-key policy both pass.

        This does not imply identifier availability, holder identity, or current status.
        """
        return self.signature is SignatureState.VALID and self.trust is TrustState.TRUSTED_SYNTHETIC
