"""Isolate Pillow/zxing-cpp image processing; communicate only bounded bytes or codes."""

import base64
import io
import json
import sys
import warnings

from PIL import Image

from p1qr.errors import ErrorCode, P1QRError
from p1qr.protocol import (
    MAX_IMAGE_BYTES,
    MAX_IMAGE_PIXELS,
    MAX_IMAGE_SIDE,
    MAX_PAYLOAD_BYTES,
)


def decode_image_bytes(data: bytes) -> bytes:
    """Decode one QR from bounded PNG/JPEG ``data`` or raise a structured failure.

    Dimensions are checked before pixel loading. The caller must isolate this
    native operation; bounds and a timeout reduce risk but are not a full sandbox.
    """
    if not data or len(data) > MAX_IMAGE_BYTES:
        raise P1QRError(ErrorCode.INPUT_TOO_LARGE, "Image byte limit exceeded.")
    try:
        import zxingcpp
    except ImportError as exc:
        raise P1QRError(ErrorCode.DECODER_UNAVAILABLE, "Optional decoder is unavailable.") from exc
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with Image.open(io.BytesIO(data), formats=("PNG", "JPEG")) as picture:
            width, height = picture.size
            if (
                width * height > MAX_IMAGE_PIXELS
                or max(width, height) > MAX_IMAGE_SIDE
                or getattr(picture, "n_frames", 1) != 1
            ):
                raise P1QRError(ErrorCode.INPUT_TOO_LARGE, "Image dimensions exceed limits.")
            # Request raw bytes: text conversion could change the message being signed.
            with picture.convert("L") as grayscale:
                codes = zxingcpp.read_barcodes(grayscale, formats=zxingcpp.BarcodeFormat.QRCode)
    if len(codes) > 1:
        raise P1QRError(ErrorCode.AMBIGUOUS_IMAGE, "Multiple QR symbols found.")
    if not codes:
        raise P1QRError(ErrorCode.UNREADABLE_IMAGE, "No QR symbol found.")
    payload = codes[0].bytes
    if not payload or len(payload) > MAX_PAYLOAD_BYTES:
        raise P1QRError(ErrorCode.INPUT_TOO_LARGE, "Decoded byte limit exceeded.")
    return payload


def main() -> None:
    """Read bounded image bytes on stdin and emit one small JSON result on stdout.

    Contain decoder exceptions at this process boundary; no failure becomes success
    and exception text (which might include input) is never sent to the console.
    """
    try:
        data = sys.stdin.buffer.read(MAX_IMAGE_BYTES + 1)
        payload = decode_image_bytes(data)
        response = {"payload": base64.b64encode(payload).decode("ascii")}
    except P1QRError as exc:
        response = {"error": exc.code.value}
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        response = {"error": ErrorCode.INPUT_TOO_LARGE.value}
    except Exception:
        # This deliberate broad boundary contains malformed-image/native wrapper errors.
        # The parent also handles a native crash or timeout, which Python cannot catch.
        response = {"error": ErrorCode.UNREADABLE_IMAGE.value}
    print(json.dumps(response))


if __name__ == "__main__":
    main()
