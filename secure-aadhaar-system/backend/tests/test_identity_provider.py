"""Unit tests for the admin identity provider abstraction (app.providers.identity_provider)."""
import base64

import pytest

from app.crypto import envelope, identity, password_utils
from app.crypto.exceptions import BadTagError
from app.providers.identity_provider import LocalIdentityProvider, load_identity_provider


def _make_local_identity_doc(password: str):
    admin_priv, admin_pub = identity.generate_encryption_keypair()
    encrypted_private_key = password_utils.encrypt_private_key(admin_priv, password)
    doc = {
        "key_provider": "local",
        "public_key_b64": base64.b64encode(admin_pub).decode(),
        "encrypted_private_key": encrypted_private_key,
    }
    return doc, admin_priv, admin_pub


def test_load_identity_provider_returns_local():
    doc, _, _ = _make_local_identity_doc("pw")
    provider = load_identity_provider(doc)
    assert isinstance(provider, LocalIdentityProvider)


def test_public_key_matches_bootstrap():
    doc, _, admin_pub = _make_local_identity_doc("pw")
    provider = load_identity_provider(doc)
    assert provider.public_key() == admin_pub


def test_unlock_wrong_password_raises():
    doc, _, _ = _make_local_identity_doc("correct password")
    provider = load_identity_provider(doc)
    with pytest.raises(BadTagError):
        provider.unlock("wrong password")


def test_unlock_and_unwrap_roundtrip():
    doc, _, admin_pub = _make_local_identity_doc("correct password")
    sender_sign, _ = identity.generate_signing_keypair()

    container = envelope.encrypt_and_seal("123456789012", {"admin-1": admin_pub}, sender_sign)

    provider = load_identity_provider(doc)
    unlocked = provider.unlock("correct password")
    dek = unlocked.unwrap_dek(container["wrapped_deks"]["admin-1"])
    number = envelope.decrypt_number(base64.b64decode(container["sealed_number_b64"]), dek)
    assert number == "123456789012"


def test_close_prevents_further_use():
    doc, _, admin_pub = _make_local_identity_doc("pw")
    sender_sign, _ = identity.generate_signing_keypair()
    container = envelope.encrypt_and_seal("123456789012", {"admin-1": admin_pub}, sender_sign)

    provider = load_identity_provider(doc)
    unlocked = provider.unlock("pw")
    unlocked.close()

    with pytest.raises(Exception):
        unlocked.unwrap_dek(container["wrapped_deks"]["admin-1"])


def test_local_provider_wrap_dek_roundtrips_with_seal_dek():
    doc, admin_priv, admin_pub = _make_local_identity_doc("pw")
    provider = load_identity_provider(doc)

    dek = envelope.generate_dek()
    wrapped_b64 = provider.wrap_dek(dek)
    recovered = envelope.unseal_dek(base64.b64decode(wrapped_b64), admin_priv)
    assert recovered == dek


def test_local_provider_alg_matches_envelope_alg():
    doc, _, _ = _make_local_identity_doc("pw")
    provider = load_identity_provider(doc)
    assert provider.alg() == envelope.ALG


def test_unknown_provider_rejected():
    with pytest.raises(ValueError):
        load_identity_provider({"key_provider": "something-else"})


def test_load_identity_provider_returns_kms(monkeypatch):
    """
    Confirms the lazy-import wiring to kms_provider works and routes to the
    right class — the KMS client itself is mocked here (see
    tests/test_kms_provider.py for the provider's actual crypto logic).
    """
    from unittest.mock import MagicMock

    from app.crypto import kms_provider

    monkeypatch.setattr(kms_provider.boto3, "client", lambda service_name: MagicMock())

    provider = load_identity_provider(
        {
            "key_provider": "aws-kms",
            "kms_key_arn": "arn:aws:kms:ap-south-1:123456789012:key/test-key",
            "password_hash": password_utils.hash_password("pw"),
        }
    )
    assert isinstance(provider, kms_provider.KmsIdentityProvider)
    assert provider.alg() == kms_provider.ALG
