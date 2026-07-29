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
