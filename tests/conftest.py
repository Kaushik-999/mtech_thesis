"""Share ephemeral synthetic material; prevent accidental Python network use in tests."""

import base64
import json
import socket
from collections.abc import Callable

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from p1qr.crypto.keys import generate_private_key
from p1qr.protocol import canonical_json
from p1qr.synthetic.issuer import create_record, sign_record


@pytest.fixture(scope="session")
def private_key() -> rsa.RSAPrivateKey:
    return generate_private_key()


@pytest.fixture(scope="session")
def other_key() -> rsa.RSAPrivateKey:
    return generate_private_key()


@pytest.fixture
def envelope(private_key: rsa.RSAPrivateKey) -> bytes:
    return sign_record(create_record(), private_key)


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*args: object, **kwargs: object) -> None:
        raise AssertionError("Tests must not use the network.")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


@pytest.fixture
def alter_record() -> Callable[[bytes, str, object], bytes]:
    def alter(data: bytes, key: str, value: object) -> bytes:
        outer = json.loads(data)
        record = json.loads(base64.b64decode(outer["payload"]))
        record[key] = value
        outer["payload"] = base64.b64encode(canonical_json(record)).decode("ascii")
        return canonical_json(outer)

    return alter
