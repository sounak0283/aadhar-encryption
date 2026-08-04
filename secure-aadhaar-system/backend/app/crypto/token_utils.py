"""
token_utils.py
Deterministic per-Aadhaar-number lookup tag, analogous to UIDAI's UID Token
(Aadhaar Authentication API Spec 2.5, section 2.2 — "This Token will remain
same for an Aadhaar number for all authentication requests by that
particular entity"). The same Aadhaar number always produces the same tag
for this deployment, so a resubmission resolves to the same reference_id
instead of creating a duplicate container, without the tag ever revealing
or being reversible to the Aadhaar number.

Keyed HMAC, not a bare hash: Aadhaar numbers only have ~10^11 possible
values (11 free digits, the 12th is a checksum), small enough to brute-force
offline against an unkeyed hash. HMAC with a server-only key (TOKEN_HMAC_KEY)
means an attacker would also need that key, which never leaves the server
and is never derived from anything an admin or user provides.
"""
import hashlib
import hmac


def compute_lookup_tag(aadhaar_number: str, token_hmac_key: bytes) -> str:
    return hmac.new(token_hmac_key, aadhaar_number.encode("utf-8"), hashlib.sha256).hexdigest()


REFERENCE_ID_LENGTH = 44  # chars — within the requested 40-50 range


def derive_reference_id(lookup_tag: str) -> str:
    """Public reference ID, derived by truncating the full 256-bit (64 hex
    char) lookup_tag to its first REFERENCE_ID_LENGTH hex characters. Still
    deterministic (same Aadhaar number -> same reference_id) and still only
    computable by someone holding TOKEN_HMAC_KEY — truncation shortens the
    identifier for display/UID-Token-style use, it doesn't weaken the
    de-duplication guarantee, which still keys off the untruncated tag."""
    return lookup_tag[:REFERENCE_ID_LENGTH].upper()
