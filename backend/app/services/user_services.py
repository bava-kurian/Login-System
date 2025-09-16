# backend/app/services/user_service.py
from sqlalchemy.orm import Session
from app.db.models import User
from app.core.security import hash_password, verify_password
from datetime import datetime, timedelta


MAX_FAILED_ATTEMPTS = 5
LOCKOUT_TIME = timedelta(minutes=15)

def create_user(db: Session, email: str, password: str) -> User:
    """
    Create a new user with a hashed password.
    """
    user = User(
        email=email,
        hashed_password=hash_password(password),
        failed_attempts=0,
        locked_until=None
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def get_user_by_email(db: Session, email: str) -> User | None:
    """
    Retrieve a user by email.
    """
    return db.query(User).filter(User.email == email).first()

def set_password(db: Session, user: User, new_password: str) -> None:
    """
    Update a user's password.
    """
    user.hashed_password = hash_password(new_password)
    db.commit()

def check_lockout(user: User) -> bool:
    """
    Check if a user is currently locked out.
    """
    if user.locked_until and datetime.utcnow() < user.locked_until:
        return True
    return False

def verify_user_password(db: Session, user: User, password: str) -> bool:
    """
    Verify user password with lockout logic.
    """
    if check_lockout(user):
        return False

    if verify_password(user.hashed_password, password):
        user.failed_attempts = 0
        db.commit()
        return True
    else:
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.utcnow() + LOCKOUT_TIME
        db.commit()
        return False
