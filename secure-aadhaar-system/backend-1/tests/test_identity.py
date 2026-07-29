"""Unit tests for Ed25519 signing (app.crypto.identity)."""
import pytest

from app.crypto import identity
from app.crypto.exceptions import BadSignatureError


def test_sign_verify_roundtrip():
    signing_key, verify_key = identity.generate_signing_keypair()
    payload = b"hello aadhaar"
    sig = identity.sign(payload, signing_key)
    assert identity.verify(payload, sig, verify_key) is True


def test_tampered_payload_fails():
    signing_key, verify_key = identity.generate_signing_keypair()
    sig = identity.sign(b"original", signing_key)
    assert identity.verify(b"tampered", sig, verify_key) is False


def test_wrong_verify_key_fails():
    signing_key, _ = identity.generate_signing_keypair()
    _, other_verify_key = identity.generate_signing_keypair()
    payload = b"hello"
    sig = identity.sign(payload, signing_key)
    assert identity.verify(payload, sig, other_verify_key) is False


def test_verify_or_raise_raises_on_bad_signature():
    signing_key, verify_key = identity.generate_signing_keypair()
    sig = identity.sign(b"original", signing_key)
    with pytest.raises(BadSignatureError):
        identity.verify_or_raise(b"tampered", sig, verify_key)


def test_verify_or_raise_passes_on_valid_signature():
    signing_key, verify_key = identity.generate_signing_keypair()
    sig = identity.sign(b"original", signing_key)
    identity.verify_or_raise(b"original", sig, verify_key)  # should not raise


def test_signing_keypair_shape():
    signing_key, verify_key = identity.generate_signing_keypair()
    assert len(signing_key) == 32
    assert len(verify_key) == 32


def test_encryption_keypair_shape():
    priv, pub = identity.generate_encryption_keypair()
    assert len(priv) == 32
    assert len(pub) == 32


def test_keypairs_are_random():
    a_priv, a_pub = identity.generate_encryption_keypair()
    b_priv, b_pub = identity.generate_encryption_keypair()
    assert a_priv != b_priv
    assert a_pub != b_pub
