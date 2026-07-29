"""Unit tests for Argon2id password unlock (app.crypto.password_utils)."""
import pytest

from app.crypto import password_utils
from app.crypto.exceptions import BadTagError

PRIVATE_KEY = b"x" * 32


def test_encrypt_decrypt_roundtrip():
    record = password_utils.encrypt_private_key(PRIVATE_KEY, "correct horse battery staple")
    recovered = password_utils.decrypt_private_key(record, "correct horse battery staple")
    assert recovered == PRIVATE_KEY


def test_wrong_password_fails():
    record = password_utils.encrypt_private_key(PRIVATE_KEY, "correct password")
    with pytest.raises(BadTagError):
        password_utils.decrypt_private_key(record, "wrong password")


def test_unsupported_kdf_rejected():
    record = password_utils.encrypt_private_key(PRIVATE_KEY, "pw")
    record["kdf"] = "scrypt"
    with pytest.raises(ValueError):
        password_utils.decrypt_private_key(record, "pw")


def test_salt_is_unique_per_call():
    record_a = password_utils.encrypt_private_key(PRIVATE_KEY, "same password")
    record_b = password_utils.encrypt_private_key(PRIVATE_KEY, "same password")
    assert record_a["salt_b64"] != record_b["salt_b64"]
    assert record_a["sealed_priv_b64"] != record_b["sealed_priv_b64"]


def test_hash_password_verify_roundtrip():
    hashed = password_utils.hash_password("kms admin password")
    assert password_utils.verify_password("kms admin password", hashed) is True


def test_verify_password_wrong_password_returns_false():
    hashed = password_utils.hash_password("correct password")
    assert password_utils.verify_password("wrong password", hashed) is False


def test_hash_password_is_salted():
    hash_a = password_utils.hash_password("same password")
    hash_b = password_utils.hash_password("same password")
    assert hash_a != hash_b
    assert password_utils.verify_password("same password", hash_a) is True
    assert password_utils.verify_password("same password", hash_b) is True
