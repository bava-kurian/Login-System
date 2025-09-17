# backend/app/tests/test_jwt.py
import pytest
from datetime import datetime, timedelta, timezone

from app.core import jwt as jwt_utils
from app.db.models import RefreshToken, User
from app.db.session import SessionLocal


def test_access_token_creation():
    payload = {"sub": "test@example.com"}
    token = jwt_utils.create_access_token(payload, expires_delta=timedelta(minutes=5))

    assert token is not None

    decoded = jwt_utils.jwt.decode(
        token,
        jwt_utils.settings.SECRET_KEY,
        algorithms=["HS256"]
    )
    assert decoded["sub"] == "test@example.com"
    assert "exp" in decoded


def test_refresh_token_rotation():
    db = SessionLocal()

    # clean up if user already exists
    db.query(User).filter_by(email="rotate@example.com").delete()
    db.commit()

    # create dummy user
    user = User(email="rotate@example.com", hashed_password="hashed")
    db.add(user)
    db.commit()
    db.refresh(user)

    # issue refresh token
    token, token_hash, issued_at, expires_at = jwt_utils.create_refresh_token()
    db_token = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        issued_at=issued_at,
        expires_at=expires_at,
        revoked=False,
    )
    db.add(db_token)
    db.commit()
    db.refresh(db_token)

    assert db_token.revoked is False
    assert db_token.expires_at > datetime.now(timezone.utc).replace(tzinfo=None)

    # simulate rotation
    new_token, new_token_hash, new_issued, new_expires = jwt_utils.create_refresh_token()
    db_token.revoked = True
    db.add(db_token)

    new_db_token = RefreshToken(
        user_id=user.id,
        token_hash=new_token_hash,
        issued_at=new_issued,
        expires_at=new_expires,
        revoked=False,
    )
    db.add(new_db_token)
    db.commit()
    db.refresh(new_db_token)

    assert db_token.revoked is True
    assert new_db_token.revoked is False
    assert new_db_token.expires_at > datetime.now(timezone.utc).replace(tzinfo=None)

    db.close()
