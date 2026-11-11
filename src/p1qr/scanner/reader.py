"""Load regular files and decode images locally without retaining decoded images."""

import base64
import binascii
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from p1qr.errors import ErrorCode, P1QRError
from p1qr.protocol import DECODER_TIMEOUT_SECONDS, MAX_IMAGE_BYTES, MAX_PAYLOAD_BYTES


def read_bounded_file(path: Path, limit: int = MAX_PAYLOAD_BYTES) -> bytes:
    """Return at most ``limit`` bytes from the local regular file ``path``.

    Raise P1QRError for missing, special, empty, inaccessible, or oversized files.
    Nonblocking open avoids hanging on FIFOs; fstat checks the opened descriptor.
    The bounded read also handles a file growing after the size check.
    """
    if limit <= 0:
        raise ValueError("File byte limit must be positive.")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise P1QRError(ErrorCode.INPUT_ERROR, "Input must be a regular local file.")
            if info.st_size > limit:
                raise P1QRError(ErrorCode.INPUT_TOO_LARGE, "Input exceeds its byte limit.")
            data = stream.read(limit + 1)
    except (OSError, ValueError) as exc:
        raise P1QRError(ErrorCode.INPUT_ERROR, "Cannot read the local input file.") from exc
    if len(data) > limit:
        raise P1QRError(ErrorCode.INPUT_TOO_LARGE, "Input exceeds its byte limit.")
    if not data:
        raise P1QRError(ErrorCode.MALFORMED_PAYLOAD, "Input is empty.")
    return data


def decode_qr_image(path: Path) -> bytes:
    """Return exact QR bytes from one PNG/JPEG image at ``path``.

    Run the native decoder in a disposable subprocess with a wall-clock timeout.
    Raise P1QRError for absent decoder, unsafe dimensions, unreadable images,
    multiple QR symbols, or worker failure. Nothing is uploaded or retained.
    """
    image_bytes = read_bounded_file(path, MAX_IMAGE_BYTES)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "p1qr.scanner.worker"],
            input=image_bytes,
            capture_output=True,
            timeout=DECODER_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise P1QRError(ErrorCode.DECODER_TIMEOUT, "QR decoding exceeded its time limit.") from exc
    except OSError as exc:
        raise P1QRError(ErrorCode.UNREADABLE_IMAGE, "Cannot start the local QR decoder.") from exc
    if result.returncode or len(result.stdout) > 2 * MAX_PAYLOAD_BYTES:
        raise P1QRError(ErrorCode.UNREADABLE_IMAGE, "The isolated QR decoder failed.")
    try:
        response = json.loads(result.stdout)
        if "error" in response:
            code = ErrorCode(response["error"])
            # Keep messages in the parent constant, even when the worker reports an error.
            messages = {
                ErrorCode.DECODER_UNAVAILABLE: "Install the optional scanner extra to read images.",
                ErrorCode.INPUT_TOO_LARGE: "Image or decoded QR exceeds its safety limits.",
                ErrorCode.AMBIGUOUS_IMAGE: "Supply an image containing exactly one QR code.",
            }
            raise P1QRError(code, messages.get(code, "Image does not contain one readable QR."))
        payload = base64.b64decode(response["payload"], validate=True)
    except (ValueError, TypeError, KeyError, binascii.Error) as exc:
        raise P1QRError(ErrorCode.UNREADABLE_IMAGE, "Invalid response from QR decoder.") from exc
    if not payload or len(payload) > MAX_PAYLOAD_BYTES:
        raise P1QRError(ErrorCode.INPUT_TOO_LARGE, "Decoded QR is empty or exceeds its byte limit.")
    return payload
