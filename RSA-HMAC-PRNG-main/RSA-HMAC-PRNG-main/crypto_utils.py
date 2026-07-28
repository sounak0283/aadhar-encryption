"""
crypto_utils.py
Core functions to sign and verify messages using HMAC-PRNG salt + RSA-PSS.
Loads the HMAC key from .env using python-dotenv.
"""
import json
import base64
import time
import os
from typing import Dict, Any

from Crypto.Signature import pss
from Crypto.Hash import SHA256

from key_utils import load_private_key, load_public_key
from hmac_prng import hmac_prng
from dotenv import load_dotenv

# Load environment variables from .env in project root
load_dotenv()

# Read HMAC key from environment; raise informative error if missing
HMAC_KEY_ENV = os.getenv("HMAC_KEY")
if HMAC_KEY_ENV is None:
    raise EnvironmentError("HMAC_KEY not found in environment variables. Create a .env file with HMAC_KEY=<your_key>.")

# Convert to bytes
HMAC_KEY = HMAC_KEY_ENV.encode("utf-8")

def _b64(x: bytes) -> str:
    return base64.b64encode(x).decode("utf-8")

def _ub64(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def sign_message(message: bytes, private_pem: bytes, salt_len: int = 32) -> Dict[str, Any]:
    """
    Sign a message using HMAC-PRNG-generated salt and RSA-PSS.

    Args:
        message: message bytes to sign
        private_pem: private key in PEM bytes
        salt_len: length of salt to generate (default 32 bytes)

    Returns:
        A JSON-serializable container with scheme metadata, timestamp, salt and signature (base64 encoded).
    """
    priv = load_private_key(private_pem)

    # 1) Generate salt from message and secret key
    salt = hmac_prng(message, HMAC_KEY, output_len=salt_len)

    # 2) Augment message and hash
    augmented = message + salt
    digest = SHA256.new(augmented)

    # 3) Sign digest using RSA-PSS
    signer = pss.new(priv)
    signature = signer.sign(digest)

    container = {
        "scheme": "hmac_prng_rsa_pss_v1",
        "ts": int(time.time()),
        "salt_len": salt_len,
        "salt_b64": _b64(salt),
        "sig_b64": _b64(signature)
    }
    return container

def verify_message(message: bytes, public_pem: bytes, container: Dict[str, Any]) -> bool:
    """
    Verify a container produced by sign_message.

    Returns True if verification succeeds, False otherwise.
    """
    if container.get("scheme") != "hmac_prng_rsa_pss_v1":
        raise ValueError("Unsupported signature scheme")

    pub = load_public_key(public_pem)
    salt = _ub64(container["salt_b64"])
    sig = _ub64(container["sig_b64"])

    augmented = message + salt
    digest = SHA256.new(augmented)

    verifier = pss.new(pub)
    try:
        verifier.verify(digest, sig)
        return True
    except (ValueError, TypeError):
        return False

def container_to_json(container: Dict[str, Any]) -> str:
    return json.dumps(container, separators=(',', ':'), sort_keys=True)

def container_from_json(s: str) -> Dict[str, Any]:
    return json.loads(s)
