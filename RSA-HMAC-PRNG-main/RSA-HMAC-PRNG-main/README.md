# HMAC-PRNG Augmented RSA-PSS Signature (Expanded Codebase)

This repository implements a secure digital-signature scheme using:

- HMAC-based PRNG (HMAC-SHA256 derived salt)
- Message augmentation: message || salt
- SHA-256 hashing
- RSA-PSS signing and verification

## Setup

1. Create & activate virtual environment:

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```
