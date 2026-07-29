"""Unit tests for app.config environment loading."""
import base64

import pytest
from nacl.utils import random as nacl_random

from app import config


def test_get_app_totp_key_missing_raises(monkeypatch):
    monkeypatch.delenv("APP_TOTP_KEY", raising=False)
    with pytest.raises(EnvironmentError):
        config.get_app_totp_key()


def test_get_app_totp_key_valid(monkeypatch):
    raw = nacl_random(32)
    monkeypatch.setenv("APP_TOTP_KEY", base64.b64encode(raw).decode())
    assert config.get_app_totp_key() == raw


def test_get_app_totp_key_wrong_length_raises(monkeypatch):
    monkeypatch.setenv("APP_TOTP_KEY", base64.b64encode(b"too-short").decode())
    with pytest.raises(EnvironmentError):
        config.get_app_totp_key()


def test_get_app_totp_key_invalid_base64_raises(monkeypatch):
    monkeypatch.setenv("APP_TOTP_KEY", "not-valid-base64!!!")
    with pytest.raises(EnvironmentError):
        config.get_app_totp_key()


def test_get_admin_key_provider_defaults_to_local(monkeypatch):
    monkeypatch.delenv("ADMIN_KEY_PROVIDER", raising=False)
    assert config.get_admin_key_provider() == "local"


def test_get_admin_key_provider_reads_env(monkeypatch):
    monkeypatch.setenv("ADMIN_KEY_PROVIDER", "aws-kms")
    assert config.get_admin_key_provider() == "aws-kms"


def test_get_aws_kms_key_id_defaults_to_none(monkeypatch):
    monkeypatch.delenv("AWS_KMS_KEY_ID", raising=False)
    assert config.get_aws_kms_key_id() is None


def test_get_aws_kms_key_id_empty_string_is_none(monkeypatch):
    monkeypatch.setenv("AWS_KMS_KEY_ID", "")
    assert config.get_aws_kms_key_id() is None


def test_get_aws_kms_key_id_reads_env(monkeypatch):
    monkeypatch.setenv("AWS_KMS_KEY_ID", "arn:aws:kms:ap-south-1:123456789012:key/abc-123")
    assert config.get_aws_kms_key_id() == "arn:aws:kms:ap-south-1:123456789012:key/abc-123"


def test_get_admin_setup_token_missing_raises(monkeypatch):
    monkeypatch.delenv("ADMIN_SETUP_TOKEN", raising=False)
    with pytest.raises(EnvironmentError):
        config.get_admin_setup_token()


def test_get_admin_setup_token_empty_raises(monkeypatch):
    monkeypatch.setenv("ADMIN_SETUP_TOKEN", "")
    with pytest.raises(EnvironmentError):
        config.get_admin_setup_token()


def test_get_admin_setup_token_reads_env(monkeypatch):
    monkeypatch.setenv("ADMIN_SETUP_TOKEN", "my-setup-token")
    assert config.get_admin_setup_token() == "my-setup-token"
