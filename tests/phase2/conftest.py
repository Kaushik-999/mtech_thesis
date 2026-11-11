"""Share ephemeral role keys and fresh issuer/cache fixtures for Phase 2 adversarial tests."""

import base64
import json

import pytest

from p1qr.cache.storage import SnapshotCache
from p1qr.issuer_registry.registry import IssuerRegistry
from p1qr.protocol import canonical_json
from p1qr.status.encoding import sign_document
from p1qr.status.trust import IssuerKeys

NOW = 1767225600


@pytest.fixture(scope="session")
def issuer_keys():
    return IssuerKeys.generate()


@pytest.fixture
def issuer(issuer_keys):
    return IssuerRegistry(issuer_keys)


@pytest.fixture
def subject(issuer):
    return issuer.create_subject()


@pytest.fixture
def issued(issuer, subject):
    return issuer.issue(subject)


@pytest.fixture
def snapshot(issuer, issued):
    return issuer.publish(issued_at=NOW, expires_at=NOW + 86400 * 5)


@pytest.fixture
def cached(tmp_path, issuer, snapshot):
    cache = SnapshotCache.initialize(tmp_path / "cache", issuer.trust)
    cache.synchronize(snapshot, issuer.trust, now=NOW, max_age_seconds=86400 * 3)
    return cache


@pytest.fixture
def change_document():
    def change(data, changes, key=None):
        outer = json.loads(data)
        record = json.loads(base64.b64decode(outer["payload"]))
        for name, value in changes.items():
            if value is ...:
                record.pop(name)
            else:
                record[name] = value
        if key is not None:
            return sign_document(record, key)
        outer["payload"] = base64.b64encode(canonical_json(record)).decode("ascii")
        return canonical_json(outer)

    return change
