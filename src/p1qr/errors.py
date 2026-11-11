"""Provide structured failures with fixed messages that never echo credential contents."""

from enum import StrEnum


class ErrorCode(StrEnum):
    """Machine-readable failure categories shared by input, parsing, and cryptography."""

    INPUT_ERROR = "INPUT_ERROR"
    INPUT_TOO_LARGE = "INPUT_TOO_LARGE"
    MALFORMED_PAYLOAD = "MALFORMED_PAYLOAD"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    UNREADABLE_IMAGE = "UNREADABLE_IMAGE"
    AMBIGUOUS_IMAGE = "AMBIGUOUS_IMAGE"
    DECODER_UNAVAILABLE = "DECODER_UNAVAILABLE"
    DECODER_TIMEOUT = "DECODER_TIMEOUT"
    INVALID_KEY = "INVALID_KEY"
    MISSING_KEY = "MISSING_KEY"
    INVALID_TRUST_PIN = "INVALID_TRUST_PIN"
    OUTPUT_ERROR = "OUTPUT_ERROR"
    DEMO_FAILED = "DEMO_FAILED"


class P1QRError(Exception):
    """Carry a failure code and a developer-authored, non-sensitive explanation."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        """Initialize a safe failure from ``code`` and a fixed, non-PII ``message``."""
        super().__init__(message)
        self.code = code
        self.message = message
