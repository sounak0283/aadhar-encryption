"""Unit tests for regular-user accounts (app.services.users_service)."""
import pytest

from app.services import users_service


async def test_create_and_get_by_username(fake_users):
    user_id = await users_service.create("alice", "hashed-password")
    user = await users_service.get_by_username("alice")
    assert user is not None
    assert str(user["_id"]) == user_id
    assert user["status"] == "active"


async def test_get_by_id(fake_users):
    user_id = await users_service.create("bob", "hashed-password")
    user = await users_service.get_by_id(user_id)
    assert user is not None
    assert user["username"] == "bob"


async def test_get_by_id_invalid_returns_none(fake_users):
    assert await users_service.get_by_id("not-a-valid-objectid") is None


async def test_get_by_username_unknown_returns_none(fake_users):
    assert await users_service.get_by_username("nobody") is None


async def test_create_rejects_duplicate_username(fake_users):
    await users_service.create("carol", "hash1")
    with pytest.raises(users_service.UsernameTakenError):
        await users_service.create("carol", "hash2")


async def test_create_assigns_unique_reference_no(fake_users):
    await users_service.create("dave", "hashed-password")
    user = await users_service.get_by_username("dave")
    assert user["unique_reference_no"]
    assert len(user["unique_reference_no"]) == 8


async def test_different_users_get_different_reference_numbers(fake_users):
    await users_service.create("erin", "hash1")
    await users_service.create("frank", "hash2")
    erin = await users_service.get_by_username("erin")
    frank = await users_service.get_by_username("frank")
    assert erin["unique_reference_no"] != frank["unique_reference_no"]
