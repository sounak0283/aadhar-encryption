"""
Unit tests for envelope encryption (app.crypto.envelope), now multi-recipient:
a DEK can be wrapped for more than one admin at once (wrapped_deks map),
with the signature covering the whole map. Mirrors the failure-mode table in
the project README / source PDF: wrong password (test_password_utils.py),
wrong admin container, tampered ciphertext, tampered signature/payload —
plus the new "admin has no entry in this container" case.
"""
import pytest

from app.crypto import identity, envelope
from app.crypto.exceptions import BadSignatureError, BadTagError

AADHAAR_NUMBER = "123456789012"


@pytest.fixture
def admin_keypair():
    return identity.generate_encryption_keypair()  # (private, public)


@pytest.fixture
def sender_keypair():
    return identity.generate_signing_keypair()  # (signing_key, verify_key)


def test_encrypt_decrypt_roundtrip(admin_keypair, sender_keypair):
    admin_priv, admin_pub = admin_keypair
    sender_sign, sender_verify = sender_keypair

    container = envelope.encrypt_and_seal(AADHAAR_NUMBER, {"admin-1": admin_pub}, sender_sign)
    assert container["alg"] == envelope.ALG

    recovered = envelope.decrypt_container(container, "admin-1", admin_priv, sender_verify)
    assert recovered == AADHAAR_NUMBER


def test_multiple_recipients_each_decrypt_with_their_own_key(sender_keypair):
    sender_sign, sender_verify = sender_keypair
    priv_a, pub_a = identity.generate_encryption_keypair()
    priv_b, pub_b = identity.generate_encryption_keypair()

    container = envelope.encrypt_and_seal(AADHAAR_NUMBER, {"a": pub_a, "b": pub_b}, sender_sign)

    assert envelope.decrypt_container(container, "a", priv_a, sender_verify) == AADHAAR_NUMBER
    assert envelope.decrypt_container(container, "b", priv_b, sender_verify) == AADHAAR_NUMBER


def test_admin_not_in_wrapped_deks_fails(admin_keypair, sender_keypair):
    admin_priv, admin_pub = admin_keypair
    sender_sign, sender_verify = sender_keypair
    other_priv, _ = identity.generate_encryption_keypair()

    container = envelope.encrypt_and_seal(AADHAAR_NUMBER, {"admin-1": admin_pub}, sender_sign)

    with pytest.raises(BadTagError):
        envelope.decrypt_container(container, "someone-else", other_priv, sender_verify)


def test_fresh_dek_per_message(admin_keypair, sender_keypair):
    _, admin_pub = admin_keypair
    sender_sign, _ = sender_keypair

    c1 = envelope.encrypt_and_seal(AADHAAR_NUMBER, {"admin-1": admin_pub}, sender_sign)
    c2 = envelope.encrypt_and_seal(AADHAAR_NUMBER, {"admin-1": admin_pub}, sender_sign)

    # same plaintext, same keys -> ciphertext and wrapped key must still differ
    assert c1["sealed_number_b64"] != c2["sealed_number_b64"]
    assert c1["wrapped_deks"]["admin-1"] != c2["wrapped_deks"]["admin-1"]


def test_wrong_admin_private_key_fails(admin_keypair, sender_keypair):
    _, admin_pub = admin_keypair
    other_admin_priv, _ = identity.generate_encryption_keypair()
    sender_sign, sender_verify = sender_keypair

    container = envelope.encrypt_and_seal(AADHAAR_NUMBER, {"admin-1": admin_pub}, sender_sign)

    with pytest.raises(BadTagError):
        envelope.decrypt_container(container, "admin-1", other_admin_priv, sender_verify)


def test_tampered_payload_caught_by_signature_check_first(admin_keypair, sender_keypair):
    admin_priv, admin_pub = admin_keypair
    sender_sign, sender_verify = sender_keypair

    container = envelope.encrypt_and_seal(AADHAAR_NUMBER, {"admin-1": admin_pub}, sender_sign)
    container["sealed_number_b64"] = container["sealed_number_b64"][:-4] + "AAAA"

    with pytest.raises(BadSignatureError):
        envelope.decrypt_container(container, "admin-1", admin_priv, sender_verify)


def test_tampered_wrapped_deks_map_caught_by_signature(admin_keypair, sender_keypair):
    """Tampering with *any* recipient's entry — even one that isn't being read
    right now — must invalidate the signature over the whole map."""
    admin_priv, admin_pub = admin_keypair
    sender_sign, sender_verify = sender_keypair

    container = envelope.encrypt_and_seal(AADHAAR_NUMBER, {"admin-1": admin_pub}, sender_sign)
    container["wrapped_deks"] = {**container["wrapped_deks"], "attacker": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}

    with pytest.raises(BadSignatureError):
        envelope.decrypt_container(container, "admin-1", admin_priv, sender_verify)


def test_wrong_sender_verify_key_fails(admin_keypair, sender_keypair):
    admin_priv, admin_pub = admin_keypair
    sender_sign, _ = sender_keypair
    _, other_verify_key = identity.generate_signing_keypair()

    container = envelope.encrypt_and_seal(AADHAAR_NUMBER, {"admin-1": admin_pub}, sender_sign)

    with pytest.raises(BadSignatureError):
        envelope.decrypt_container(container, "admin-1", admin_priv, other_verify_key)


def test_unsupported_alg_rejected(admin_keypair, sender_keypair):
    admin_priv, admin_pub = admin_keypair
    sender_sign, sender_verify = sender_keypair

    container = envelope.encrypt_and_seal(AADHAAR_NUMBER, {"admin-1": admin_pub}, sender_sign)
    container["alg"] = "some-future-scheme-v99"

    with pytest.raises(ValueError):
        envelope.decrypt_container(container, "admin-1", admin_priv, sender_verify)


def test_decrypt_number_wrong_dek_fails():
    dek = envelope.generate_dek()
    other_dek = envelope.generate_dek()
    sealed = envelope.encrypt_number(AADHAAR_NUMBER, dek)

    with pytest.raises(BadTagError):
        envelope.decrypt_number(sealed, other_dek)


def test_decrypt_number_tampered_ciphertext_fails():
    dek = envelope.generate_dek()
    sealed = bytearray(envelope.encrypt_number(AADHAAR_NUMBER, dek))
    sealed[-1] ^= 0xFF  # flip the last byte of the authentication tag

    with pytest.raises(BadTagError):
        envelope.decrypt_number(bytes(sealed), dek)


def test_unseal_dek_wrong_key_fails(admin_keypair):
    _, admin_pub = admin_keypair
    other_priv, _ = identity.generate_encryption_keypair()
    dek = envelope.generate_dek()
    wrapped = envelope.seal_dek(dek, admin_pub)

    with pytest.raises(BadTagError):
        envelope.unseal_dek(wrapped, other_priv)
