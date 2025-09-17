# backend/app/services/user_service.py
# ------------------------------------------------------------
# User-related DB helper functions
# ------------------------------------------------------------

from sqlalchemy.orm import Session
from app.db import models
from app.core.security import hash_password, verify_password


def create_user(db: Session, email: str, password: str, full_name: str = None) -> models.User:
    """
    Create and store a new user in the database.
    Password is securely hashed.
    """
    normalized_email = email.strip().lower()
    user = models.User(
        email=normalized_email,
        hashed_password=hash_password(password),
        full_name=full_name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_user_by_email(db: Session, email: str) -> models.User | None:
    """
    Retrieve a user by email.
    """
    normalized_email = email.strip().lower()
    return db.query(models.User).filter(models.User.email == normalized_email).first()


def set_password(db: Session, user: models.User, new_password: str) -> models.User:
    """
    Update a user's password (re-hash).
    """
    user.hashed_password = hash_password(new_password)
    db.commit()
    db.refresh(user)
    return user


def check_lockout(user: models.User) -> bool:
    """
    Check if a user is locked out (inactive).
    Returns True if locked, False if active.
    """
    return not user.is_active
