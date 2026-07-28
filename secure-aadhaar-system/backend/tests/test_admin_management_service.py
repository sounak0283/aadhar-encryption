"""
Unit tests for master-gated sub-admin creation and the retroactive DEK
re-wrap (app.services.admin_management_service) — the core of multi-admin
support: a new sub-admin must be able to decrypt records submitted before
they existed, and the re-wrap must be idempotent and signature-correct.
"""
import base64

import pyotp
import pytest

from app.crypto import envelope
from app.providers.identity_provider import load_identity_provider
from app.services import admin_management_service, admins_service

SUB_USERNAME = "sub-one"
SUB_PASSWORD = "a-strong-sub-admin-password"


async def _unlock_master(master_admin):
    provider = load_identity_provider(master_admin["doc"])
    return provider.unlock(master_admin["password"])


async def test_start_returns_setup_material(master_admin, fake_admins):
    token, uri, secret, qr = await admin_management_service.start(master_admin["id"], SUB_USERNAME, SUB_PASSWORD)
    assert token
    assert uri.startswith("otpauth://totp/")
    assert secret in uri
    assert len(qr) > 0
    assert await admins_service.get_by_username(SUB_USERNAME) is None  # not written yet


async def test_start_rejects_taken_username(master_admin, fake_admins):
    with pytest.raises(admin_management_service.UsernameTakenError):
        await admin_management_service.start(master_admin["id"], master_admin["username"], SUB_PASSWORD)


async def test_start_rejects_weak_password(master_admin, fake_admins):
    with pytest.raises(admin_management_service.WeakPasswordError):
        await admin_management_service.start(master_admin["id"], SUB_USERNAME, "short")


async def test_confirm_creates_sub_admin(master_admin, fake_admins):
    unlocked = await _unlock_master(master_admin)
    token, _, secret, _ = await admin_management_service.start(master_admin["id"], SUB_USERNAME, SUB_PASSWORD)

    new_admin_id, granted = await admin_management_service.confirm(
        master_admin["id"], unlocked, token, pyotp.TOTP(secret).now()
    )

    sub = await admins_service.get_by_id(new_admin_id)
    assert sub["username"] == SUB_USERNAME
    assert sub["role"] == "sub"
    assert sub["status"] == "active"
    assert sub["created_by"] == master_admin["id"]
    assert granted == 0  # no containers existed yet


async def test_confirm_wrong_code_fails(master_admin, fake_admins):
    unlocked = await _unlock_master(master_admin)
    token, _, _secret, _ = await admin_management_service.start(master_admin["id"], SUB_USERNAME, SUB_PASSWORD)

    with pytest.raises(ValueError):
        await admin_management_service.confirm(master_admin["id"], unlocked, token, "000000")
    assert await admins_service.get_by_username(SUB_USERNAME) is None


async def test_confirm_unknown_token_fails(master_admin, fake_admins):
    unlocked = await _unlock_master(master_admin)
    with pytest.raises(admin_management_service.RegistrationNotFoundError):
        await admin_management_service.confirm(master_admin["id"], unlocked, "nonexistent", "123456")


async def test_confirm_rejects_token_belonging_to_a_different_master(master_admin, fake_admins):
    """A pending sub-admin registration started by one master can't be confirmed
    using a different master's id, even with the right code."""
    unlocked = await _unlock_master(master_admin)
    token, _, secret, _ = await admin_management_service.start(master_admin["id"], SUB_USERNAME, SUB_PASSWORD)

    with pytest.raises(admin_management_service.RegistrationNotFoundError):
        await admin_management_service.confirm("some-other-master-id", unlocked, token, pyotp.TOTP(secret).now())


async def test_retroactive_access_granted_for_existing_container(master_admin, fake_admins, fake_containers, sender_identity):
    """The whole point of this feature: a container submitted *before* the
    sub-admin existed must be decryptable by them *after* they're created."""
    number = "123456789012"
    container = envelope.encrypt_and_seal(number, {master_admin["id"]: master_admin["public_key"]}, sender_identity["signing_key"])
    await fake_containers.insert_one({**container, "masked_preview": "XXXX-XXXX-9012"})

    unlocked = await _unlock_master(master_admin)
    token, _, secret, _ = await admin_management_service.start(master_admin["id"], SUB_USERNAME, SUB_PASSWORD)
    new_admin_id, granted = await admin_management_service.confirm(
        master_admin["id"], unlocked, token, pyotp.TOTP(secret).now()
    )
    assert granted == 1

    # The sub-admin must now be able to decrypt that pre-existing record on their own.
    updated_doc = next(iter(fake_containers._docs.values()))
    sub = await admins_service.get_by_id(new_admin_id)
    sub_provider = load_identity_provider(sub)
    sub_unlocked = sub_provider.unlock(SUB_PASSWORD)

    from app.services import decrypt_service

    recovered = decrypt_service.decrypt_container(updated_doc, new_admin_id, sub_unlocked, sender_identity["verify_key"])
    assert recovered == number

    # The master must *still* be able to decrypt it too — granting access to
    # someone else must not revoke or corrupt the master's own entry.
    master_recovered = decrypt_service.decrypt_container(updated_doc, master_admin["id"], unlocked, sender_identity["verify_key"])
    assert master_recovered == number


async def test_retroactive_grant_is_idempotent(master_admin, fake_admins, fake_containers, sender_identity):
    """Re-running the re-wrap (e.g. because a previous run partially failed)
    must not double-wrap or corrupt already-migrated containers."""
    number = "123456789012"
    container = envelope.encrypt_and_seal(number, {master_admin["id"]: master_admin["public_key"]}, sender_identity["signing_key"])
    await fake_containers.insert_one({**container, "masked_preview": "XXXX-XXXX-9012"})

    unlocked = await _unlock_master(master_admin)
    token, _, secret, _ = await admin_management_service.start(master_admin["id"], SUB_USERNAME, SUB_PASSWORD)
    new_admin_id, granted = await admin_management_service.confirm(
        master_admin["id"], unlocked, token, pyotp.TOTP(secret).now()
    )
    assert granted == 1

    # Simulate re-running just the re-wrap step again directly.
    sub = await admins_service.get_by_id(new_admin_id)
    public_key = base64.b64decode(sub["public_key_b64"])
    second_run_granted = await admin_management_service._grant_retroactive_access(
        master_admin["id"], unlocked, new_admin_id, public_key
    )
    assert second_run_granted == 0  # nothing left to do, already granted

    doc = next(iter(fake_containers._docs.values()))
    assert len(doc["wrapped_deks"]) == 2  # master + the one sub-admin, not duplicated


async def test_new_submissions_after_sub_admin_created_are_wrapped_for_both(master_admin, fake_admins, fake_containers, sender_identity):
    from app.services import submission_service

    unlocked = await _unlock_master(master_admin)
    token, _, secret, _ = await admin_management_service.start(master_admin["id"], SUB_USERNAME, SUB_PASSWORD)
    new_admin_id, _ = await admin_management_service.confirm(master_admin["id"], unlocked, token, pyotp.TOTP(secret).now())

    reference_id, _ = await submission_service.encrypt_and_store("123456789012", submitted_by="test-submitter-id")
    from bson import ObjectId

    doc = fake_containers._docs[ObjectId(reference_id)]
    assert set(doc["wrapped_deks"].keys()) == {master_admin["id"], new_admin_id}
