"""
Encryption-path orchestration for the public submission endpoint. The DEK is
wrapped separately for every currently active admin (master + all
sub-admins) so any of them can later decrypt it, via *each admin's own*
identity provider — local (X25519 SealedBox) and AWS KMS (P-256 ECDH) wrap
differently, so this dispatches per admin rather than assuming one scheme
for everyone. In practice all admins created through the multi-admin flow
use the local provider; a KMS-provider admin can still coexist (its own
entry wraps correctly through its own provider), it just won't have been
created via app.services.admin_management_service, which only builds local
identities.
"""
import base64
from datetime import datetime, timezone

from app.crypto import envelope, identity
from app import db
from app.providers.identity_provider import load_identity_provider
from app.services import admin_identity_service, admins_service


class NoActiveAdminsError(Exception):
    """Raised when there's no admin at all to wrap the DEK for — the number
    would otherwise be encrypted with no one able to ever decrypt it."""


def _mask(number: str) -> str:
    return f"XXXX-XXXX-{number[-4:]}"


async def encrypt_and_store(number: str, submitted_by: str) -> tuple[str, str]:
    admins = await admins_service.list_active()
    if not admins:
        raise NoActiveAdminsError("no active admin exists yet — complete admin registration first")

    sender_signing_key = admin_identity_service.load_sender_signing_key()

    dek = envelope.generate_dek()
    sealed_number = envelope.encrypt_number(number, dek)

    wrapped_deks: dict[str, str] = {}
    alg = None
    for admin in admins:
        provider = load_identity_provider(admin)
        wrapped_deks[str(admin["_id"])] = provider.wrap_dek(dek)
        if alg is None:
            alg = provider.alg()
    del dek  # best-effort discard; see README Honest Notes on managed-memory scrubbing limits

    sealed_number_b64 = base64.b64encode(sealed_number).decode("ascii")
    payload = envelope.signing_payload(wrapped_deks, sealed_number_b64)
    signature_b64 = base64.b64encode(identity.sign(payload, sender_signing_key)).decode("ascii")

    masked_preview = _mask(number)
    doc = {
        "alg": alg,
        "wrapped_deks": wrapped_deks,
        "sealed_number_b64": sealed_number_b64,
        "signature_b64": signature_b64,
        "created_at": datetime.now(timezone.utc),
        "masked_preview": masked_preview,
        "submitted_by": submitted_by,
    }
    result = await db.containers_collection().insert_one(doc)
    return str(result.inserted_id), masked_preview
