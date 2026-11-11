"""Keep Phase 2 failures explicit without changing historical Phase 1 error semantics."""

from enum import StrEnum

from p1qr.models import SignatureState, TrustState


class StatusCode(StrEnum):
    """Precise offline outcomes and safe administrative failure categories."""

    INVALID_CREDENTIAL_SIGNATURE = "INVALID_CREDENTIAL_SIGNATURE"
    UNTRUSTED_CREDENTIAL_SIGNER = "UNTRUSTED_CREDENTIAL_SIGNER"
    MISSING_BINDING = "MISSING_BINDING"
    INVALID_BINDING = "INVALID_BINDING"
    UNTRUSTED_BINDING_SIGNER = "UNTRUSTED_BINDING_SIGNER"
    MISSING_STATUS_INDEX = "MISSING_STATUS_INDEX"
    MISSING_SNAPSHOT = "MISSING_SNAPSHOT"
    INVALID_SNAPSHOT = "INVALID_SNAPSHOT"
    INVALID_SNAPSHOT_SIGNATURE = "INVALID_SNAPSHOT_SIGNATURE"
    UNTRUSTED_STATUS_ISSUER = "UNTRUSTED_STATUS_ISSUER"
    CONTEXT_MISMATCH = "CONTEXT_MISMATCH"
    SNAPSHOT_ROLLBACK = "SNAPSHOT_ROLLBACK"
    SNAPSHOT_EQUIVOCATION = "SNAPSHOT_EQUIVOCATION"
    SNAPSHOT_REGRESSION = "SNAPSHOT_REGRESSION"
    STALE_SNAPSHOT = "STALE_SNAPSHOT"
    FUTURE_SNAPSHOT = "FUTURE_SNAPSHOT"
    STATUS_INDEX_OUT_OF_RANGE = "STATUS_INDEX_OUT_OF_RANGE"
    REVOKED = "REVOKED"
    NOT_REVOKED_AS_OF_SNAPSHOT = "NOT_REVOKED_AS_OF_SNAPSHOT"
    STATUS_UNKNOWN = "STATUS_UNKNOWN"
    CACHE_STATE_ERROR = "CACHE_STATE_ERROR"
    INPUT_TOO_LARGE = "INPUT_TOO_LARGE"
    MALFORMED_STATUS = "MALFORMED_STATUS"
    DUPLICATE_ID = "DUPLICATE_ID"
    INDEX_ALLOCATION_ERROR = "INDEX_ALLOCATION_ERROR"
    REGISTRY_ENTRY_MISSING = "REGISTRY_ENTRY_MISSING"
    SUBJECT_DEACTIVATED = "SUBJECT_DEACTIVATED"
    INVALID_POLICY = "INVALID_POLICY"


class StatusError(Exception):
    """Carry a fixed non-PII message and any completed signature/trust evidence."""

    def __init__(
        self,
        code: StatusCode,
        message: str,
        *,
        signature: SignatureState = SignatureState.NOT_CHECKED,
        trust: TrustState = TrustState.UNTRUSTED,
        snapshot_metadata: tuple[int, int, int] | None = None,
    ) -> None:
        """Store ``code``/safe ``message`` and independent verification states."""
        super().__init__(message)
        self.code = code
        self.message = message
        self.signature = signature
        self.trust = trust
        self.snapshot_metadata = snapshot_metadata
