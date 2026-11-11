"""Create, sign, render, and export our small educational credential format."""

import base64
import json
import re
from pathlib import Path
from uuid import uuid4

import qrcode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from PIL import Image, ImageDraw

from p1qr.crypto.keys import key_fingerprint, public_key_pem
from p1qr.crypto.verification import signature_padding
from p1qr.errors import ErrorCode, P1QRError
from p1qr.parser.payload import parse_payload
from p1qr.protocol import ALGORITHM, FORMAT, ISSUER, RSA_BITS, canonical_json


def create_record(
    *, variant: str = "A", last_four: str = "4242", include_identifier: bool = True
) -> dict[str, object]:
    """Return a fictional record with a fresh UUIDv4 artefact ID, or null when requested.

    ``variant`` is one uppercase letter; ``last_four`` is four synthetic digits.
    Raise ValueError for invalid controls. No full Aadhaar number is ever generated.
    """
    if re.fullmatch(r"[A-Z]", variant) is None or re.fullmatch(r"[0-9]{4}", last_four) is None:
        raise ValueError("Use one uppercase variant letter and four synthetic digits.")
    return {
        "format": FORMAT,
        "issuer": ISSUER,
        "algorithm": ALGORITHM,
        "credential_id": str(uuid4()) if include_identifier else None,
        "last_four": last_four,
        "fictional_name": f"Fictional Resident {variant}",
    }


def sign_record(record: dict[str, object], private_key: rsa.RSAPrivateKey) -> bytes:
    """Return a signed envelope for a schema-valid fictional ``record``.

    Sign deterministic JSON bytes with an in-memory RSA-2048 ``private_key``.
    Raise P1QRError on unsupported key/schema or ValueError for unencodable objects.
    This signs data; it neither encrypts fields nor checks anybody's status.
    """
    if private_key.key_size != RSA_BITS or private_key.public_key().public_numbers().e != 65537:
        raise P1QRError(ErrorCode.INVALID_KEY, "Synthetic issuer requires RSA-2048 / e=65537.")
    message = canonical_json(record)
    envelope: dict[str, object] = {
        "format": FORMAT,
        "payload": base64.b64encode(message).decode("ascii"),
        "signature": base64.b64encode(bytes(RSA_BITS // 8)).decode("ascii"),
    }
    # Check the protocol before signing: accidental arbitrary real data is not accepted.
    parse_payload(canonical_json(envelope))
    signature = private_key.sign(message, signature_padding(), hashes.SHA256())
    envelope["signature"] = base64.b64encode(signature).decode("ascii")
    return canonical_json(envelope)


def render_qr(envelope: bytes, output: Path) -> None:
    """Save a labelled synthetic QR PNG for ``envelope`` to new file ``output``.

    Preserve QR quiet zones and include a visible SYNTHETIC / NOT UIDAI footer.
    Raise P1QRError for bad input; filesystem failures propagate as OSError.
    """
    parse_payload(envelope)
    code = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=4)
    code.add_data(envelope, optimize=0)
    code.make(fit=True)
    picture = code.make_image(fill_color="black", back_color="white").convert("RGB")
    with picture, Image.new("RGB", (picture.width, picture.height + 36), "white") as labelled:
        labelled.paste(picture, (0, 0))
        ImageDraw.Draw(labelled).text((12, picture.height + 10), ISSUER, fill="black")
        with output.open("xb") as stream:
            labelled.save(stream, format="PNG")


def export_bundle(envelope: bytes, public_key: rsa.RSAPublicKey, output: Path) -> None:
    """Write only synthetic payload, QR, public key, and manifest in a NEW ``output`` directory.

    No private key is exported. Refuse existing paths rather than overwrite work.
    A failed write may leave partial synthetic files; retry with a new directory.
    """
    parse_payload(envelope)
    try:
        output.mkdir(parents=True, exist_ok=False)
        (output / "credential.p1qr").write_bytes(envelope)
        (output / "public_key.pem").write_bytes(public_key_pem(public_key))
        render_qr(envelope, output / "credential.png")
        manifest = {
            "label": ISSUER,
            "public_key_sha256": key_fingerprint(public_key),
            "trust_note": "A bundled fingerprint is metadata, not independent issuer trust.",
            "private_key": "Not exported; ephemeral only.",
            "status": "NOT_CHECKED_PHASE_1",
        }
        (output / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        raise P1QRError(
            ErrorCode.OUTPUT_ERROR, "Cannot create output bundle; choose a new writable directory."
        ) from exc
