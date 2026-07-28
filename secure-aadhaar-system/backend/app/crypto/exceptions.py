"""Custom exceptions for the crypto layer — decouple callers from PyNaCl internals."""


class CryptoError(Exception):
    """Base class for all crypto-layer failures."""


class BadSignatureError(CryptoError):
    """Raised when an Ed25519 signature does not verify."""


class BadTagError(CryptoError):
    """Raised when AEAD authentication fails: wrong key, wrong password, or tampered ciphertext."""
