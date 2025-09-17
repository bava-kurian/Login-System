import pytest
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.services.user_service import create_user
from app.services.reset_service import issue_reset_token, consume_reset_token, RESET_TOKEN_EXPIRE_MINUTES
from app.db.models import User, ResetToken
from datetime import timedelta


def test_reset_token_single_use_and_expiry():
    db: Session = SessionLocal()

    # create user
    db.query(User).filter(User.email == "reset@test.com").delete()
    db.commit()
    user = create_user(db, "reset@test.com", "Secret123!")

    # issue token
    token = issue_reset_token(db, user)

    # consume once OK
    ok1 = consume_reset_token(db, token, "NewPass123!")
    assert ok1 is True

    # second time should fail (single-use)
    ok2 = consume_reset_token(db, token, "Another123!")
    assert ok2 is False

    # simulate expiry by manually setting expires_at back in time
    rt = db.query(ResetToken).order_by(ResetToken.created_at.desc()).first()
    rt.used = False
    rt.expires_at = rt.created_at - timedelta(minutes=1)
    db.commit()

    ok3 = consume_reset_token(db, token, "Another123!")
    assert ok3 is False

    db.close()


