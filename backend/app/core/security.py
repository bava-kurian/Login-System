# backend/app/core/security.py
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Argon2 password hasher instance
pwd_hasher = PasswordHasher()

def hash_password(password: str) -> str:
    """
    Hash a plain password using Argon2.
    """
    return pwd_hasher.hash(password)

def verify_password(hashed_password: str, plain_password: str) -> bool:
    """
    Verify a password against its hash.
    Returns True if valid, False if not.
    """
    try:
        return pwd_hasher.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False
