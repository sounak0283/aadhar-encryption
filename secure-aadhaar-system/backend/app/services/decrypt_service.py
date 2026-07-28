"""
decrypt_service.py
Decryption-path orchestration: verify the signature over the whole
wrapped_deks map, unwrap *this admin's* copy of the DEK via their unlocked
identity, decrypt the number. Provider-agnostic — identical whether the
private key is local or AWS KMS-backed, since it only ever calls the
UnlockedIdentity interface, never provider internals. The container's `alg`
field records which provider wrapped it (see SUPPORTED_ALGS).
"""
import base64

from app.crypto import envelope, identity
from app.crypto.exceptions import BadTagError
from app.providers.identity_provider import SUPPORTED_ALGS, UnlockedIdentity


def decrypt_container(container: dict, admin_id: str, unlocked_identity: UnlockedIdentity, sender_verify_key: bytes) -> str:
    if container["alg"] not in SUPPORTED_ALGS:
        raise ValueError(f"unsupported container alg: {container['alg']!r}")

    payload = envelope.signing_payload(container["wrapped_deks"], container["sealed_number_b64"])
    identity.verify_or_raise(payload, base64.b64decode(container["signature_b64"]), sender_verify_key)

    wrapped_dek_b64 = container["wrapped_deks"].get(admin_id)
    if wrapped_dek_b64 is None:
        raise BadTagError(f"admin {admin_id!r} has no access to this record")

    dek = unlocked_identity.unwrap_dek(wrapped_dek_b64)
    return envelope.decrypt_number(base64.b64decode(container["sealed_number_b64"]), dek)
