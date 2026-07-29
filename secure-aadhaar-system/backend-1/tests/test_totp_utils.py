"""Unit tests for TOTP MFA (app.crypto.totp_utils)."""
import pyotp
import pytest
from nacl.utils import random as nacl_random

from app.crypto import totp_utils
from app.crypto.exceptions import BadTagError


@pytest.fixture
def app_key():
    return nacl_random(32)


def test_generate_and_verify_code():
    secret = totp_utils.generate_totp_secret()
    code = pyotp.TOTP(secret).now()
    assert totp_utils.verify_totp_code(secret, code) is True


def test_wrong_code_rejected():
    secret = totp_utils.generate_totp_secret()
    assert totp_utils.verify_totp_code(secret, "000000") is False


def test_provisioning_uri_contains_secret():
    secret = totp_utils.generate_totp_secret()
    uri = totp_utils.provisioning_uri(secret, account_name="admin")
    assert secret in uri
    assert uri.startswith("otpauth://totp/")


def test_encrypt_decrypt_roundtrip(app_key):
    secret = totp_utils.generate_totp_secret()
    sealed = totp_utils.encrypt_totp_secret(secret, app_key)
    recovered = totp_utils.decrypt_totp_secret(sealed, app_key)
    assert recovered == secret


def test_wrong_app_key_fails(app_key):
    secret = totp_utils.generate_totp_secret()
    sealed = totp_utils.encrypt_totp_secret(secret, app_key)
    other_key = nacl_random(32)
    with pytest.raises(BadTagError):
        totp_utils.decrypt_totp_secret(sealed, other_key)


def test_qr_code_png_base64_is_a_valid_png():
    import base64

    secret = totp_utils.generate_totp_secret()
    uri = totp_utils.provisioning_uri(secret, account_name="admin")
    png_b64 = totp_utils.qr_code_png_base64(uri)

    png_bytes = base64.b64decode(png_b64)
    assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")  # PNG magic bytes
