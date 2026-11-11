"""T08/T15: contain image failures, malicious dimensions, and nonregular inputs."""

import builtins
import os
import struct
import subprocess
import zlib
from types import SimpleNamespace

import pytest
from PIL import Image

from p1qr.errors import ErrorCode, P1QRError
from p1qr.protocol import MAX_IMAGE_BYTES, MAX_PAYLOAD_BYTES
from p1qr.scanner.reader import decode_qr_image, read_bounded_file
from p1qr.scanner.worker import decode_image_bytes
from p1qr.synthetic.issuer import render_qr


@pytest.mark.parametrize("kind", ["blank", "garbage"])
def test_t08_unreadable_image(kind, tmp_path):
    path = tmp_path / "image.png"
    if kind == "blank":
        Image.new("RGB", (100, 100), "white").save(path)
    else:
        path.write_bytes(b"not an image")
    with pytest.raises(P1QRError) as error:
        decode_qr_image(path)
    assert error.value.code == ErrorCode.UNREADABLE_IMAGE


def test_t15_large_file(tmp_path):
    path = tmp_path / "oversized"
    with path.open("wb") as stream:
        stream.truncate(MAX_PAYLOAD_BYTES + 1)
    with pytest.raises(P1QRError) as error:
        read_bounded_file(path)
    assert error.value.code == ErrorCode.INPUT_TOO_LARGE


def test_t15_large_image_file(tmp_path):
    path = tmp_path / "oversized.png"
    with path.open("wb") as stream:
        stream.truncate(MAX_IMAGE_BYTES + 1)
    with pytest.raises(P1QRError) as error:
        decode_qr_image(path)
    assert error.value.code == ErrorCode.INPUT_TOO_LARGE


def test_t15_pixel_bomb_header(tmp_path):
    path = tmp_path / "large-header.png"
    Image.new("RGB", (2, 2), "white").save(path)
    data = bytearray(path.read_bytes())
    data[16:24] = struct.pack(">II", 100_000, 100_000)
    data[29:33] = struct.pack(">I", zlib.crc32(data[12:29]))
    path.write_bytes(data)
    with pytest.raises(P1QRError) as error:
        decode_qr_image(path)
    assert error.value.code == ErrorCode.INPUT_TOO_LARGE


def test_multiple_symbols_rejected(envelope, tmp_path):
    single = tmp_path / "single.png"
    render_qr(envelope, single)
    with Image.open(single) as original:
        with Image.new("RGB", (original.width * 2, original.height), "white") as canvas:
            canvas.paste(original, (0, 0))
            canvas.paste(original, (original.width, 0))
            canvas.save(tmp_path / "double.png")
    with pytest.raises(P1QRError) as error:
        decode_qr_image(tmp_path / "double.png")
    assert error.value.code == ErrorCode.AMBIGUOUS_IMAGE


def test_missing_decoder_is_explicit(monkeypatch):
    normal_import = builtins.__import__

    def limited_import(name, *args, **kwargs):
        if name == "zxingcpp":
            raise ImportError("test decoder unavailable")
        return normal_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", limited_import)
    with pytest.raises(P1QRError) as error:
        decode_image_bytes(b"test")
    assert error.value.code == ErrorCode.DECODER_UNAVAILABLE


def test_native_crash_contained(tmp_path, monkeypatch):
    path = tmp_path / "image"
    path.write_bytes(b"test")
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=-11, stdout=b"")
    )
    with pytest.raises(P1QRError) as error:
        decode_qr_image(path)
    assert error.value.code == ErrorCode.UNREADABLE_IMAGE


def test_timeout_contained(tmp_path, monkeypatch):
    path = tmp_path / "image"
    path.write_bytes(b"test")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("decoder", 10)

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(P1QRError) as error:
        decode_qr_image(path)
    assert error.value.code == ErrorCode.DECODER_TIMEOUT


def test_nonregular_file_rejected_without_blocking(tmp_path):
    path = tmp_path / "fifo"
    os.mkfifo(path)
    with pytest.raises(P1QRError) as error:
        read_bounded_file(path)
    assert error.value.code == ErrorCode.INPUT_ERROR


def test_missing_file_is_structured(tmp_path):
    with pytest.raises(P1QRError) as error:
        read_bounded_file(tmp_path / "absent")
    assert error.value.code == ErrorCode.INPUT_ERROR
