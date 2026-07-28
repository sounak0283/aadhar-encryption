"""
Unit tests for sign & verify functionality.
"""
import pytest
from key_utils import generate_keys
from crypto_utils import sign_message, verify_message

def test_sign_verify_roundtrip():
    priv, pub = generate_keys(2048)
    msg = b"hello world"
    container = sign_message(msg, priv)
    assert verify_message(msg, pub, container) is True

def test_tamper_detection():
    priv, pub = generate_keys(2048)
    msg = b"original"
    container = sign_message(msg, priv)
    assert verify_message(b"changed", pub, container) is False
