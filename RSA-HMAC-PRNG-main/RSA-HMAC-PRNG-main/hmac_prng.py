"""
hmac_prng.py
HMAC-based PRNG utilities. Uses HMAC-SHA256 over SHA256(message) as the seed.
"""
import hmac
import hashlib
from typing import Optional

def hmac_prng(message: bytes, key: bytes, output_len: Optional[int] = None) -> bytes:
    """
    Generate a deterministic, cryptographically secure salt derived from the message and a secret key.

    Steps:
    1. Compute base = SHA256(message)
    2. Compute HMAC(key, base)
    3. If output_len > 32, expand using a simple counter-based expansion (HKDF-like)

    Args:
        message: input message bytes
        key: secret key bytes used by HMAC
        output_len: desired output bytes length (default 32)

    Returns:
        salt bytes of length output_len (default 32)
    """
    base = hashlib.sha256(message).digest()

    def single():
        return hmac.new(key, base, hashlib.sha256).digest()

    if output_len is None or output_len == 32:
        return single()

    # Expand to required length (simple construction for demo; use HKDF for production)
    out = b""
    counter = 1
    while len(out) < output_len:
        data = base + counter.to_bytes(1, "big")
        out += hmac.new(key, data, hashlib.sha256).digest()
        counter += 1
    return out[:output_len]
