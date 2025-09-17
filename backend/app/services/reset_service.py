"""
Password reset token issuance and consumption.
"""
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
import secrets
import hashlib
from app.db.models import ResetToken, User
from app.services.user_service import set_password


RESET_TOKEN_EXPIRE_MINUTES = 30


def _now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def issue_reset_token(db: Session, user: User) -> str:
    """
    Create a single-use password reset token for the given user.
    Stores only the SHA-256 hash. Returns the plaintext token.
    """
    token_plain = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token_plain.encode()).hexdigest()
    issued = _now_naive()
    expires = issued + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)

    reset = ResetToken(
        user_id=user.id,
        token_hash=token_hash,
        used=False,
        created_at=issued,
        expires_at=expires,
    )
    db.add(reset)
    db.commit()
    db.refresh(reset)
    return token_plain


def consume_reset_token(db: Session, token_plain: str, new_password: str) -> bool:
    """
    Verify the token hash, ensure not expired and not used, set new password, and mark token used.
    Returns True if successful else False.
    """
    token_hash = hashlib.sha256(token_plain.encode()).hexdigest()

    row = (
        db.query(ResetToken)
        .filter(ResetToken.token_hash == token_hash)
        .order_by(ResetToken.created_at.desc())
        .first()
    )
    if not row:
        return False

    if row.used:
        return False

    if row.expires_at <= _now_naive():
        return False

    user = db.query(User).filter(User.id == row.user_id).first()
    if not user:
        return False

    # Update password and mark token used
    set_password(db, user, new_password)
    row.used = True
    db.commit()
    return True


