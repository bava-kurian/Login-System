# tests/test_security.py
from app.core.security import hash_password, verify_password

def test_password_hashing_and_verification():
    password = "supersecret"
    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(hashed, password) is True
    assert verify_password(hashed, "wrongpassword") is False

