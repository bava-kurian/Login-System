# backend/app/tests/test_security_user.py
# ------------------------------------------------------------
# Tests for password hashing + user service
# ------------------------------------------------------------

import pytest
from app.db.session import SessionLocal
from app.services import user_service
from app.core import security


@pytest.fixture(scope="function")
def db():
    """
    Fresh DB session for each test.
    Rolls back after test.
    """
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


# ------------------------
# Tests for hashing
# ------------------------

def test_password_hashing_and_verification():
    password = "supersecret"
    hashed = security.hash_password(password)

    assert hashed != password  # must not store plain text
    assert security.verify_password(hashed, password) is True
    assert security.verify_password(hashed, "wrongpass") is False


# ------------------------
# Tests for user_service
# ------------------------

def test_create_user_and_fetch(db):
    user = user_service.create_user(db, "alice@example.com", "mypassword", "Alice")

    assert user.id is not None
    assert user.email == "alice@example.com"

    fetched = user_service.get_user_by_email(db, "alice@example.com")
    assert fetched.id == user.id


def test_set_password(db):
    user = user_service.create_user(db, "bob@example.com", "oldpass")

    old_hash = user.hashed_password
    updated = user_service.set_password(db, user, "newpass")

    assert updated.hashed_password != old_hash
    assert security.verify_password(updated.hashed_password, "newpass") is True


def test_check_lockout(db):
    user = user_service.create_user(db, "charlie@example.com", "charpass")

    assert user_service.check_lockout(user) is False  # active by default

    user.is_active = False
    db.commit()

    assert user_service.check_lockout(user) is True  # locked when inactive
