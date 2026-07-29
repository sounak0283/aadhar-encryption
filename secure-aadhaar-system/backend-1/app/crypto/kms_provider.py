"""
kms_provider.py
Production admin identity provider: the private key lives inside AWS KMS
(ECC_NIST_P256, KeyUsage=KEY_AGREEMENT) and never leaves it.

Wrapping a DEK (the public submission path) only needs the admin's cached
public key and a locally generated ephemeral keypair — no AWS call, so
message encryption never depends on KMS availability. Unwrapping a DEK (the
admin decrypt path) calls KMS's ECDH key-agreement operation and gets back
only a derived shared secret; the private key itself is never exported, not
even into this process's memory, not even during an active session.

NOT YET VERIFIED AGAINST A REAL KMS ENDPOINT. AWS's asymmetric ECDH
key-agreement API (`derive_shared_secret`, KeyAgreementAlgorithm="ECDH") is
a newer KMS capability; the exact operation/parameter names and response
shape here are this project's best understanding at write time. Confirm
against current boto3/botocore docs and a real call against your own KMS
key before trusting this in production — see README Open Decisions. Unit
tests here mock the KMS client and verify this project's own logic, not
AWS's actual API contract.
"""
import base64
import struct

import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.exceptions import CryptoError as _NaclCryptoError
from nacl.secret import SecretBox

from app.crypto.exceptions import BadTagError
from app.crypto.password_utils import verify_password
from app.providers.identity_provider import KMS_ALG

ALG = KMS_ALG
_HKDF_INFO = b"secure-aadhaar-kms-dek-wrap-v1"
_LEN_PREFIX = struct.Struct(">H")  # 2-byte big-endian length prefix for the ephemeral DER public key


def _hkdf(shared_secret: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=salt, info=_HKDF_INFO).derive(shared_secret)


def _pack_wrapped_dek(ephemeral_pub_der: bytes, ciphertext: bytes) -> bytes:
    return _LEN_PREFIX.pack(len(ephemeral_pub_der)) + ephemeral_pub_der + ciphertext


def _unpack_wrapped_dek(data: bytes) -> tuple[bytes, bytes]:
    (pub_len,) = _LEN_PREFIX.unpack_from(data)
    offset = _LEN_PREFIX.size
    return data[offset : offset + pub_len], data[offset + pub_len :]


class KmsUnlockedIdentity:
    """
    Unlocked state for the AWS KMS provider. There is no local secret to hold
    onto — "unlocked" only means this session is authorized to keep asking
    KMS to derive shared secrets on the admin's behalf until it expires.
    close() is a no-op: nothing sensitive was ever cached here in the first
    place, unlike the local provider's raw private key in memory.
    """

    def __init__(self, kms_client, key_id: str):
        self._kms = kms_client
        self._key_id = key_id

    def unwrap_dek(self, wrapped_dek_b64: str) -> bytes:
        ephemeral_pub_der, ciphertext = _unpack_wrapped_dek(base64.b64decode(wrapped_dek_b64))

        try:
            response = self._kms.derive_shared_secret(
                KeyId=self._key_id,
                KeyAgreementAlgorithm="ECDH",
                PublicKey=ephemeral_pub_der,
            )
        except ClientError as exc:
            raise BadTagError(f"KMS key agreement failed: wrong key or wrong container ({exc})") from exc

        wrapping_key = _hkdf(response["SharedSecret"], salt=ephemeral_pub_der)
        try:
            return SecretBox(wrapping_key).decrypt(ciphertext)
        except _NaclCryptoError as exc:
            raise BadTagError("failed to unwrap DEK: wrong key or tampered container") from exc

    def close(self) -> None:
        pass


class KmsIdentityProvider:
    """
    Admin identity backed by an AWS KMS asymmetric key. The `password` passed
    to unlock() authenticates the admin to *this backend* (checked against a
    stored Argon2id verifier, app.crypto.password_utils.verify_password) — it
    does not decrypt anything itself. KMS access is governed by the backend's
    own IAM identity (an attached role in production; AWS_PROFILE for local
    testing), resolved automatically by boto3's standard credential chain.
    See README's "unlock chain — AWS KMS provider" section.
    """

    def __init__(self, admin_identity: dict):
        self._key_id = admin_identity["kms_key_arn"]
        self._password_hash = admin_identity["password_hash"]
        self._kms = boto3.client("kms")
        self._public_key_der: bytes | None = None

    def alg(self) -> str:
        return ALG

    def public_key(self) -> bytes:
        if self._public_key_der is None:
            self._public_key_der = self._kms.get_public_key(KeyId=self._key_id)["PublicKey"]
        return self._public_key_der

    def wrap_dek(self, dek: bytes) -> str:
        admin_public_key = serialization.load_der_public_key(self.public_key())
        if not isinstance(admin_public_key, ec.EllipticCurvePublicKey):
            raise ValueError("admin KMS key is not an EC public key")

        ephemeral_private = ec.generate_private_key(ec.SECP256R1())
        ephemeral_pub_der = ephemeral_private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        shared_secret = ephemeral_private.exchange(ec.ECDH(), admin_public_key)
        wrapping_key = _hkdf(shared_secret, salt=ephemeral_pub_der)

        ciphertext = SecretBox(wrapping_key).encrypt(dek)
        return base64.b64encode(_pack_wrapped_dek(ephemeral_pub_der, ciphertext)).decode("ascii")

    def unlock(self, password: str) -> KmsUnlockedIdentity:
        if not verify_password(password, self._password_hash):
            raise BadTagError("wrong password")
        return KmsUnlockedIdentity(self._kms, self._key_id)
