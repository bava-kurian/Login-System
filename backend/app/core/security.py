
# ------------------------------------------------------------
# Password hashing utilities (Argon2)
# ------------------------------------------------------------

from passlib.context import CryptContext

# Configure Argon2
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    """
    Hash a plain password using Argon2.
    """
    return pwd_context.hash(password)


def verify_password(hashed: str, password: str) -> bool:
    """
    Verify a plain password against a stored hash.
    """
    return pwd_context.verify(password, hashed)
