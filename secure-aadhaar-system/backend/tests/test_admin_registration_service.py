"""
Unit tests for the first-admin (master) self-registration flow
(app.services.admin_registration_service), now async and Mongo-backed via
the fake_admins fixture instead of a local file.
"""
import pyotp
import pytest

from app.services import admin_registration_service, admins_service

USERNAME = "master"
PASSWORD = "a-strong-registration-password"


async def test_start_returns_setup_material(fake_admins, app_totp_key):
    token, otpauth_uri, secret, qr_png_b64 = await admin_registration_service.start(USERNAME, PASSWORD)
    assert token
    assert otpauth_uri.startswith("otpauth://totp/")
    assert secret in otpauth_uri
    assert len(qr_png_b64) > 0
    assert await admins_service.any_admin_exists() is False  # not written yet


async def test_start_rejects_short_username(fake_admins, app_totp_key):
    with pytest.raises(admin_registration_service.InvalidUsernameError):
        await admin_registration_service.start("ab", PASSWORD)


async def test_start_rejects_weak_password(fake_admins, app_totp_key):
    with pytest.raises(admin_registration_service.WeakPasswordError):
        await admin_registration_service.start(USERNAME, "short")


async def test_confirm_creates_master_admin(fake_admins, app_totp_key):
    token, _, secret, _ = await admin_registration_service.start(USERNAME, PASSWORD)
    admin_id = await admin_registration_service.confirm(token, pyotp.TOTP(secret).now())

    admin = await admins_service.get_by_id(admin_id)
    assert admin is not None
    assert admin["username"] == USERNAME
    assert admin["role"] == "master"
    assert admin["status"] == "active"
    assert admin["created_by"] is None


async def test_confirmed_admin_actually_unlocks_with_the_registration_password(fake_admins, app_totp_key):
    token, _, secret, _ = await admin_registration_service.start(USERNAME, PASSWORD)
    admin_id = await admin_registration_service.confirm(token, pyotp.TOTP(secret).now())

    from app.providers.identity_provider import load_identity_provider

    admin = await admins_service.get_by_id(admin_id)
    provider = load_identity_provider(admin)
    provider.unlock(PASSWORD)  # must not raise


async def test_confirm_wrong_code_does_not_register(fake_admins, app_totp_key):
    token, _, _secret, _ = await admin_registration_service.start(USERNAME, PASSWORD)
    with pytest.raises(ValueError):
        await admin_registration_service.confirm(token, "000000")
    assert await admins_service.any_admin_exists() is False


async def test_confirm_unknown_token_raises(fake_admins, app_totp_key):
    with pytest.raises(admin_registration_service.RegistrationNotFoundError):
        await admin_registration_service.confirm("nonexistent-token", "123456")


async def test_start_refuses_when_already_registered(fake_admins, app_totp_key):
    token, _, secret, _ = await admin_registration_service.start(USERNAME, PASSWORD)
    await admin_registration_service.confirm(token, pyotp.TOTP(secret).now())

    with pytest.raises(admin_registration_service.AlreadyRegisteredError):
        await admin_registration_service.start("someone-else", "another-password-123")


async def test_confirm_refuses_if_someone_else_registered_first(fake_admins, app_totp_key):
    token, _, secret, _ = await admin_registration_service.start(USERNAME, PASSWORD)

    # Simulate a race: another registration completes while this one is still pending.
    await admins_service.create(
        {
            "username": "someone-else",
            "role": "master",
            "status": "active",
            "key_provider": "local",
            "public_key_b64": "AA==",
            "encrypted_private_key": {
                "kdf": "argon2id",
                "salt_b64": "AA==",
                "time_cost": 1,
                "memory_cost_kib": 8,
                "parallelism": 1,
                "sealed_priv_b64": "AA==",
            },
            "totp_secret_encrypted": "AA==",
            "created_by": None,
        }
    )

    with pytest.raises(admin_registration_service.AlreadyRegisteredError):
        await admin_registration_service.confirm(token, pyotp.TOTP(secret).now())


async def test_pending_registration_expires(fake_admins, app_totp_key):
    import time

    token, _, secret, _ = await admin_registration_service.start(USERNAME, PASSWORD)

    pending = admin_registration_service._pending[token]
    pending.expires_at = time.monotonic() - 1  # force expiry without waiting 10 real minutes

    with pytest.raises(admin_registration_service.RegistrationNotFoundError):
        await admin_registration_service.confirm(token, pyotp.TOTP(secret).now())
