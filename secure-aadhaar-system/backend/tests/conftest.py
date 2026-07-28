"""Shared pytest fixtures for the API test suite."""
import base64

import pyotp
import pytest
from bson import ObjectId
from nacl.utils import random as nacl_random

from app import db
from app.crypto import identity, password_utils, totp_utils
from app.services import admin_identity_service, admin_management_service, admin_registration_service, admin_session


class InsertOneResult:
    def __init__(self, inserted_id):
        self.inserted_id = inserted_id


class FakeCursor:
    def __init__(self, docs):
        self._docs = list(docs)

    def sort(self, *args, **kwargs):
        return self

    def __aiter__(self):
        self._iter = iter(self._docs)
        return self

    async def __anext__(self):
        try:
            return next(self._iter)
        except StopIteration:
            raise StopAsyncIteration


class FakeAsyncCollection:
    """Minimal stand-in for a Motor collection, covering only what this app uses."""

    def __init__(self):
        self._docs: dict = {}

    async def insert_one(self, doc):
        _id = doc.get("_id") or ObjectId()
        self._docs[_id] = {**doc, "_id": _id}
        return InsertOneResult(_id)

    async def find_one(self, filt):
        for doc in self._docs.values():
            if all(doc.get(k) == v for k, v in filt.items()):
                return doc
        return None

    async def update_one(self, filt, update):
        doc = await self.find_one(filt)
        if doc is None:
            return
        for k, v in update.get("$set", {}).items():
            doc[k] = v
        for k in update.get("$unset", {}):
            doc.pop(k, None)

    def find(self, filt=None):
        filt = filt or {}
        docs = [doc for doc in self._docs.values() if all(doc.get(k) == v for k, v in filt.items())]
        return FakeCursor(docs)


@pytest.fixture(autouse=True)
def _reset_admin_sessions():
    admin_session.reset()
    yield
    admin_session.reset()


@pytest.fixture(autouse=True)
def _reset_admin_registrations():
    admin_registration_service.reset()
    admin_management_service.reset()
    yield
    admin_registration_service.reset()
    admin_management_service.reset()


@pytest.fixture(autouse=True)
def fake_containers(monkeypatch):
    """autouse: no test should ever be able to reach the real MongoDB by accident
    (e.g. by forgetting to request this fixture) — that already caused real
    cross-test event-loop breakage against leftover real data during development."""
    fake = FakeAsyncCollection()
    monkeypatch.setattr(db, "containers_collection", lambda: fake)
    return fake


@pytest.fixture(autouse=True)
def fake_audit_log(monkeypatch):
    fake = FakeAsyncCollection()
    monkeypatch.setattr(db, "audit_log_collection", lambda: fake)
    return fake


@pytest.fixture(autouse=True)
def fake_admins(monkeypatch):
    fake = FakeAsyncCollection()
    monkeypatch.setattr(db, "admins_collection", lambda: fake)
    return fake


@pytest.fixture(autouse=True)
def fake_users(monkeypatch):
    fake = FakeAsyncCollection()
    monkeypatch.setattr(db, "users_collection", lambda: fake)
    return fake


@pytest.fixture(autouse=True)
def _reset_user_sessions():
    from app.services import user_session

    user_session.reset()
    yield
    user_session.reset()


@pytest.fixture
def sender_identity(monkeypatch):
    """A real Ed25519 signing keypair, wired up as the server's sender identity."""
    sender_signing_key, sender_verify_key = identity.generate_signing_keypair()
    monkeypatch.setattr(admin_identity_service, "load_sender_signing_key", lambda: sender_signing_key)
    monkeypatch.setattr(admin_identity_service, "load_sender_verify_key", lambda: sender_verify_key)
    return {"signing_key": sender_signing_key, "verify_key": sender_verify_key}


@pytest.fixture
def app_totp_key(monkeypatch):
    key = nacl_random(32)
    monkeypatch.setenv("APP_TOTP_KEY", base64.b64encode(key).decode())
    return key


def _make_admin_doc(username: str, password: str, role: str, created_by: str | None, app_totp_key: bytes):
    from datetime import datetime, timezone

    admin_private_key, admin_public_key = identity.generate_encryption_keypair()
    encrypted_private_key = password_utils.encrypt_private_key(admin_private_key, password)
    totp_secret = totp_utils.generate_totp_secret()
    totp_secret_encrypted = totp_utils.encrypt_totp_secret(totp_secret, app_totp_key)

    doc = {
        "username": username,
        "role": role,
        "status": "active",
        "key_provider": "local",
        "public_key_b64": base64.b64encode(admin_public_key).decode(),
        "encrypted_private_key": encrypted_private_key,
        "totp_secret_encrypted": totp_secret_encrypted,
        "created_by": created_by,
        "created_at": datetime.now(timezone.utc),
    }
    return doc, admin_private_key, admin_public_key, totp_secret


@pytest.fixture
def master_admin(fake_admins, sender_identity, app_totp_key):
    """Inserts a real, usable master admin into fake_admins. Synchronous fixture —
    inserts directly via the fake collection's dict rather than awaiting insert_one,
    since pytest fixtures aren't async here."""
    username = "master"
    password = "master-admin-password-123"
    doc, admin_private_key, admin_public_key, totp_secret = _make_admin_doc(
        username, password, "master", None, app_totp_key
    )
    admin_id = ObjectId()
    doc["_id"] = admin_id
    fake_admins._docs[admin_id] = doc

    return {
        "id": str(admin_id),
        "username": username,
        "password": password,
        "totp_code": lambda: pyotp.TOTP(totp_secret).now(),
        "totp_secret": totp_secret,
        "private_key": admin_private_key,
        "public_key": admin_public_key,
        "doc": doc,
    }


@pytest.fixture
def kms_master_admin(fake_admins, sender_identity, app_totp_key, monkeypatch):
    """
    Inserts a real, usable *KMS-provider* master admin into fake_admins, with
    the boto3 KMS client mocked (see tests/test_kms_provider.py's module
    docstring for why this proves our own logic, not AWS's real API contract).
    """
    from unittest.mock import MagicMock

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from app.crypto import kms_provider, password_utils
    from datetime import datetime, timezone

    admin_private_key = ec.generate_private_key(ec.SECP256R1())
    public_der = admin_private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    fake_kms = MagicMock()
    fake_kms.get_public_key.return_value = {"PublicKey": public_der}

    def _derive_shared_secret(KeyId, KeyAgreementAlgorithm, PublicKey):
        peer_public_key = serialization.load_der_public_key(PublicKey)
        return {"SharedSecret": admin_private_key.exchange(ec.ECDH(), peer_public_key)}

    fake_kms.derive_shared_secret.side_effect = _derive_shared_secret
    monkeypatch.setattr(kms_provider.boto3, "client", lambda service_name: fake_kms)

    username = "kms-master"
    password = "kms-master-password-123"
    totp_secret = totp_utils.generate_totp_secret()
    totp_secret_encrypted = totp_utils.encrypt_totp_secret(totp_secret, app_totp_key)

    admin_id = ObjectId()
    doc = {
        "_id": admin_id,
        "username": username,
        "role": "master",
        "status": "active",
        "key_provider": "aws-kms",
        "kms_key_arn": "arn:aws:kms:ap-south-1:123456789012:key/test-key",
        "totp_secret_encrypted": totp_secret_encrypted,
        "password_hash": password_utils.hash_password(password),
        "created_by": None,
        "created_at": datetime.now(timezone.utc),
    }
    fake_admins._docs[admin_id] = doc

    return {
        "id": str(admin_id),
        "username": username,
        "password": password,
        "totp_code": lambda: pyotp.TOTP(totp_secret).now(),
    }


@pytest.fixture
def regular_user(fake_users):
    """Inserts a real, usable regular (non-admin) user into fake_users."""
    from app.crypto import password_utils

    username = "test-user"
    password = "test-user-password"
    user_id = ObjectId()
    from datetime import datetime, timezone

    doc = {
        "_id": user_id,
        "username": username,
        "password_hash": password_utils.hash_password(password),
        "status": "active",
        "created_at": datetime.now(timezone.utc),
    }
    fake_users._docs[user_id] = doc

    return {"id": str(user_id), "username": username, "password": password}


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    app.state.limiter.reset()
    return TestClient(app, base_url="https://testserver")


@pytest.fixture
def logged_in_client(client, regular_user):
    """A TestClient already logged in as a regular user — convenience for tests
    that need to submit an Aadhaar number without re-testing the login flow itself."""
    resp = client.post(
        "/api/auth/login", json={"username": regular_user["username"], "password": regular_user["password"]}
    )
    assert resp.status_code == 200
    return client
