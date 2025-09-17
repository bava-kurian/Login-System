# backend/app/services/token_service.py
# ------------------------------------------------------------
# Refresh token DB storage + rotation
# ------------------------------------------------------------
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from app.db.models import RefreshToken
from app.core.security import hash_password, verify_password
from app.core.jwt import REFRESH_TOKEN_EXPIRE_DAYS, create_refresh_token


def issue_refresh_token(db: Session, user_id: int) -> str:
    """
    Create and store a new refresh token for a user.
    Returns the plaintext token (to give to client).
    """
    token_plain = create_refresh_token()
    token_hash = hash_password(token_plain)

    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    refresh = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
        revoked=False,
    )
    db.add(refresh)
    db.commit()
    db.refresh(refresh)
    return token_plain


def verify_and_rotate_refresh_token(db: Session, user_id: int, token_plain: str) -> str | None:
    """
    Verify given refresh token, revoke it, and issue a new one.
    Returns new plaintext refresh token if valid, else None.
    """
    old_token = (
        db.query(RefreshToken)
        .filter(RefreshToken.user_id == user_id, RefreshToken.revoked == False)
        .order_by(RefreshToken.created_at.desc())
        .first()
    )
    if not old_token:
        return None

    if old_token.expires_at < datetime.now(timezone.utc):
        return None

    if not verify_password(old_token.token_hash, token_plain):
        return None

    # Revoke old
    old_token.revoked = True
    db.commit()

    # Issue new
    return issue_refresh_token(db, user_id)
