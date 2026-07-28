"""
Unit tests for the AWS KMS admin identity provider (app.crypto.kms_provider).
These mock the boto3 KMS client entirely: they verify this project's own
logic (parameter passing, wrap/unwrap round-trip, error handling), not that
AWS's actual API contract matches what's assumed here. See kms_provider.py's
module docstring and README Open Decisions — this needs a real KMS test
before being trusted in production.
"""
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.crypto import kms_provider, password_utils
from app.crypto.exceptions import BadTagError

TEST_ARN = "arn:aws:kms:ap-south-1:123456789012:key/test-key"


def _make_admin_keypair():
    """A real P-256 keypair standing in for the one that would live inside KMS."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_der


def _fake_kms_client(admin_private_key, public_der):
    """
    Stands in for boto3's KMS client. get_public_key returns the (test-only)
    public key; derive_shared_secret performs the *real* ECDH math using
    admin_private_key, exactly like the real KMS operation is documented to.
    This is what proves wrap/unwrap round-trips correctly, independent of
    whether the mocked call shape matches AWS's real one.
    """
    client = MagicMock()
    client.get_public_key.return_value = {"PublicKey": public_der}

    def _derive_shared_secret(KeyId, KeyAgreementAlgorithm, PublicKey):
        peer_public_key = serialization.load_der_public_key(PublicKey)
        shared_secret = admin_private_key.exchange(ec.ECDH(), peer_public_key)
        return {"SharedSecret": shared_secret}

    client.derive_shared_secret.side_effect = _derive_shared_secret
    return client


@pytest.fixture
def provider(monkeypatch):
    admin_private_key, public_der = _make_admin_keypair()
    fake_client = _fake_kms_client(admin_private_key, public_der)
    monkeypatch.setattr(kms_provider.boto3, "client", lambda service_name: fake_client)

    admin_identity = {
        "key_provider": "aws-kms",
        "kms_key_arn": TEST_ARN,
        "password_hash": password_utils.hash_password("kms-test-password"),
    }
    return kms_provider.KmsIdentityProvider(admin_identity)


def test_alg():
    assert kms_provider.ALG == "kms-ecdh-p256+secretbox-xsalsa20poly1305+ed25519-v3"


def test_public_key_is_fetched_and_cached(provider):
    pub1 = provider.public_key()
    pub2 = provider.public_key()
    assert pub1 == pub2
    provider._kms.get_public_key.assert_called_once()


def test_wrap_unwrap_roundtrip(provider):
    dek = b"x" * 32
    wrapped = provider.wrap_dek(dek)
    unlocked = provider.unlock("kms-test-password")
    recovered = unlocked.unwrap_dek(wrapped)
    assert recovered == dek


def test_wrap_produces_different_ciphertext_each_time(provider):
    dek = b"x" * 32
    assert provider.wrap_dek(dek) != provider.wrap_dek(dek)


def test_unlock_wrong_password_fails(provider):
    with pytest.raises(BadTagError):
        provider.unlock("wrong password")


def test_unwrap_with_wrong_key_fails(provider):
    dek = b"x" * 32
    wrapped = provider.wrap_dek(dek)

    other_admin_private, other_public_der = _make_admin_keypair()
    wrong_client = _fake_kms_client(other_admin_private, other_public_der)
    unlocked = kms_provider.KmsUnlockedIdentity(wrong_client, TEST_ARN)

    with pytest.raises(BadTagError):
        unlocked.unwrap_dek(wrapped)


def test_kms_client_error_becomes_bad_tag_error(provider):
    from botocore.exceptions import ClientError

    provider._kms.derive_shared_secret.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "nope"}}, "DeriveSharedSecret"
    )
    unlocked = provider.unlock("kms-test-password")
    with pytest.raises(BadTagError):
        unlocked.unwrap_dek(provider.wrap_dek(b"x" * 32))


def test_close_is_a_safe_noop(provider):
    unlocked = provider.unlock("kms-test-password")
    unlocked.close()  # must not raise
