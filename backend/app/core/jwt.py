# backend/app/core/jwt.py
# ------------------------------------------------------------
# JWT utilities: access + refresh token creation
# ------------------------------------------------------------
from  jose import jwt
from datetime import datetime, timedelta, timezone
import os
import secrets
from app.config import settings 
import hashlib

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7


def create_access_token(payload: dict, expires_delta: timedelta | None = None) -> str:
    """
    Create a short-lived access token (JWT).
    """
    to_encode = payload.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token():
    """Generate a secure refresh token and return (token, token_hash, issued_at, expires_at)."""
    token = secrets.token_urlsafe(64)  # raw token string
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(days=30)

    return token, token_hash, issued_at, expires_at
