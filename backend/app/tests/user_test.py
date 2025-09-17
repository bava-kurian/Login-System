# backend/app/tests/test_security_user.py
# ------------------------------------------------------------
# Tests for password hashing and user helper functions
# using the actual DB setup from session.py
# ------------------------------------------------------------

import pytest
from app.db.session import SessionLocal
from app.db import models
from app.services import user_service
from app.core import security


@pytest.fixture(scope="function")
def db():
    """
    Creates a fresh database session for each test.
    Rolls back after each test to avoid side effects.
    """
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


# ------------------------
# Tests for security.py
# ------------------------

def test_password_hash_and_verify():
    """Ensure password hashing and verification works."""
    password = "supersecret"
    hashed = security.hash_password(password)

    assert hashed != password
    assert security.verify_password(hashed, password) is True
    assert security.verify_password(hashed, "wrongpass") is False


# ------------------------
# Tests for user_service.py
# ------------------------

def test_create_user_and_fetch(db):
    """Create a user and fetch by email."""
    user = user_service.create_user(db, email="servertest@example.com", password="mypassword", full_name="Server User")

    assert user.id is not None
    assert user.email == "servertest@example.com"

    fetched = user_service.get_user_by_email(db, "servertest@example.com")
    assert fetched.id == user.id


def test_set_password(db):
    """Update a user’s password and verify the change."""
    user = user_service.create_user(db, email="pwchange@example.com", password="oldpass")

    old_hash = user.hashed_password
    updated = user_service.set_password(db, user, "newpass")

    assert updated.hashed_password != old_hash
    assert security.verify_password(updated.hashed_password, "newpass") is True


def test_check_lockout(db):
    """Check lockout status for active/inactive users."""
    user = user_service.create_user(db, email="locktest@example.com", password="lockpass")

    assert user_service.check_lockout(user) is False  # active by default

    user.is_active = False
    db.commit()

    assert user_service.check_lockout(user) is True  # locked when inactive
