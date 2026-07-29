"""
envelope.py
Envelope encryption for a single Aadhaar number, wrapped to potentially
*multiple* admins (master + any sub-admins):
  1. a fresh random DEK (data encryption key) encrypts the number (SecretBox)
  2. the DEK is sealed to each admin's X25519 public key separately (SealedBox),
     producing one wrapped_dek per recipient, keyed by admin id
  3. the whole wrapped_deks map + sealed number are signed together with the
     sender's Ed25519 key

Decryption authenticates before it decrypts: the signature over the *entire*
wrapped_deks map is checked first (so tampering with any recipient's entry
is caught, not just the one being unwrapped), then that specific admin's DEK
copy is unsealed, then the number is decrypted. Any failure raises a specific
exception rather than returning corrupted or forged plaintext.
"""
import base64
import json
from typing import TypedDict

from nacl.public import SealedBox, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random
from nacl.exceptions import CryptoError as _NaclCryptoError

from . import identity
from .exceptions import BadTagError

ALG = "sealedbox-x25519+secretbox-xsalsa20poly1305+ed25519-v3"
DEK_SIZE = SecretBox.KEY_SIZE  # 32 bytes


class Container(TypedDict):
    alg: str
    wrapped_deks: dict[str, str]  # admin_id -> wrapped_dek_b64, one entry per admin who can read this
    sealed_number_b64: str
    signature_b64: str


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _ub64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def generate_dek() -> bytes:
    """Generate a fresh random 32-byte data encryption key. One per message, never reused."""
    return nacl_random(DEK_SIZE)


def seal_dek(dek: bytes, admin_public_key: bytes) -> bytes:
    """Wrap a DEK to one admin's X25519 public key. Only the matching private key can unwrap it."""
    box = SealedBox(PublicKey(admin_public_key))
    return box.encrypt(dek)


def unseal_dek(wrapped_dek: bytes, admin_private_key: bytes) -> bytes:
    """Unwrap a DEK with one admin's X25519 private key. Raises BadTagError on wrong key or wrong container."""
    box = SealedBox(PrivateKey(admin_private_key))
    try:
        return box.decrypt(wrapped_dek)
    except _NaclCryptoError as exc:
        raise BadTagError("failed to unseal data key: wrong key or wrong container") from exc


def encrypt_number(number: str, dek: bytes) -> bytes:
    """Encrypt the Aadhaar number under the DEK. Nonce is generated and embedded by SecretBox."""
    box = SecretBox(dek)
    return box.encrypt(number.encode("utf-8"))


def decrypt_number(sealed_number: bytes, dek: bytes) -> str:
    """Decrypt the Aadhaar number under the DEK. Raises BadTagError on wrong key or tampered ciphertext."""
    box = SecretBox(dek)
    try:
        return box.decrypt(sealed_number).decode("utf-8")
    except _NaclCryptoError as exc:
        raise BadTagError("failed to decrypt number: wrong key or tampered ciphertext") from exc


def signing_payload(wrapped_deks: dict[str, str], sealed_number_b64: str) -> bytes:
    """Canonical bytes signed for a container — field order and separators are fixed.

    Public (not module-private) because app.services.decrypt_service and the
    sub-admin re-wrap migration also need it to (re-)sign/verify a container.
    Covers the *whole* wrapped_deks map, so tampering with any one recipient's
    entry — not just the one being read right now — invalidates the signature.
    """
    return json.dumps(
        {"wrapped_deks": wrapped_deks, "sealed_number_b64": sealed_number_b64},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def encrypt_and_seal(number: str, admin_public_keys: dict[str, bytes], sender_signing_key: bytes) -> Container:
    """
    Full encryption path: generate one DEK, encrypt the number once, wrap that
    same DEK separately for every admin in admin_public_keys, sign the result.
    """
    dek = generate_dek()
    sealed_number = encrypt_number(number, dek)
    wrapped_deks = {admin_id: _b64(seal_dek(dek, pub)) for admin_id, pub in admin_public_keys.items()}
    del dek  # best-effort discard; see README Honest Notes on managed-memory scrubbing limits

    sealed_number_b64 = _b64(sealed_number)
    signature = identity.sign(signing_payload(wrapped_deks, sealed_number_b64), sender_signing_key)

    return {
        "alg": ALG,
        "wrapped_deks": wrapped_deks,
        "sealed_number_b64": sealed_number_b64,
        "signature_b64": _b64(signature),
    }


def decrypt_container(container: Container, admin_id: str, admin_private_key: bytes, sender_verify_key: bytes) -> str:
    """
    Full decryption path: verify the signature over the whole wrapped_deks map
    first (authenticate-then-decrypt), then unseal *this admin's* copy of the
    DEK, then decrypt the number. Raises BadTagError if admin_id has no entry
    in wrapped_deks at all (this admin was never granted access to this record).
    """
    if container["alg"] != ALG:
        raise ValueError(f"unsupported container alg: {container['alg']!r}")

    payload = signing_payload(container["wrapped_deks"], container["sealed_number_b64"])
    identity.verify_or_raise(payload, _ub64(container["signature_b64"]), sender_verify_key)

    wrapped_dek_b64 = container["wrapped_deks"].get(admin_id)
    if wrapped_dek_b64 is None:
        raise BadTagError(f"admin {admin_id!r} has no access to this record")

    dek = unseal_dek(_ub64(wrapped_dek_b64), admin_private_key)
    number = decrypt_number(_ub64(container["sealed_number_b64"]), dek)
    del dek
    return number
