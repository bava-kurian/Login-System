# backend/app/services/token_service.py
# ------------------------------------------------------------
# Refresh token DB storage + rotation
# ------------------------------------------------------------
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from app.db.models import RefreshToken
from app.core.jwt import create_refresh_token
import hashlib


def issue_refresh_token(db: Session, user_id: int) -> str:
    """
    Create and store a new refresh token for a user.
    Returns the plaintext token (to give to client).
    """
    token_plain, token_hash, issued_at, expires_at = create_refresh_token()

    refresh = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        issued_at=issued_at.replace(tzinfo=None),
        expires_at=expires_at.replace(tzinfo=None),
        revoked=False,
    )
    db.add(refresh)
    db.commit()
    db.refresh(refresh)
    return token_plain


def verify_and_rotate_refresh_token(db: Session, user_id: int, token_plain: str) -> str | None:
    """
    Verify the provided refresh token for the given user, revoke it, and issue a new one.
    Returns new plaintext refresh token if valid, else None.
    """
    provided_hash = hashlib.sha256(token_plain.encode()).hexdigest()

    token_row = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.user_id == user_id,
            RefreshToken.token_hash == provided_hash,
            RefreshToken.revoked == False,
        )
        .order_by(RefreshToken.created_at.desc())
        .first()
    )
    if not token_row:
        return None

    # Normalize aware/naive comparison (DB likely stores naive)
    now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    if token_row.expires_at <= now_naive:
        return None

    # Revoke old and issue new
    token_row.revoked = True
    db.commit()
    return issue_refresh_token(db, user_id)
