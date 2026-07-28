"""
debug_totp.py
Diagnose a TOTP mismatch during admin login: checks a code against a much
wider time window than the real login endpoint uses, to distinguish "clock
drift" from "wrong secret entirely". Diagnostic only — the real
/api/admin/login endpoint still enforces the normal +/-30s window
(app/crypto/totp_utils.py's verify_totp_code, valid_window=1).

Usage:
    python scripts/debug_totp.py
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pyotp  # noqa: E402

from app.config import get_app_totp_key  # noqa: E402
from app.crypto import totp_utils  # noqa: E402
from app.services import admin_identity_service  # noqa: E402

WINDOW_STEPS = 10  # +/- 10 * 30s = +/- 5 minutes


def main() -> None:
    admin_identity = admin_identity_service.get_admin_identity()
    secret = totp_utils.decrypt_totp_secret(admin_identity["totp_secret_encrypted"], get_app_totp_key())

    code = input("Enter the code currently shown in your authenticator app: ").strip()

    totp = pyotp.TOTP(secret)
    now = time.time()
    print(f"Server UTC time: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(now))}")

    match_offset = None
    for offset in range(-WINDOW_STEPS, WINDOW_STEPS + 1):
        if totp.at(now + offset * 30) == code:
            match_offset = offset
            break

    if match_offset is None:
        print(f"\nNo match within +/-{WINDOW_STEPS * 30} seconds.")
        print("This is not a clock drift issue — the code doesn't correspond to this")
        print("admin's TOTP secret at all. Likely a duplicate/stale entry in your")
        print("authenticator app, or bootstrap was re-run with --force since this")
        print("entry was scanned.")
    elif match_offset == 0:
        print("\nCode matches exactly at the server's current time — no drift issue.")
        print("If login still fails, something else is wrong (check the request is")
        print("actually reaching the server), or try again with a freshly rotated code.")
    else:
        drift_seconds = match_offset * 30
        direction = "ahead of" if drift_seconds > 0 else "behind"
        print(f"\nCode matches, but is {abs(drift_seconds)}s {direction} the server's clock.")
        print("This is a clock sync issue — fix automatic time sync on your phone")
        print("and/or this machine rather than the app itself.")


if __name__ == "__main__":
    main()
