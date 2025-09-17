from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.schemas.auth import (
    RegisterRequest,
    LoginRequest,
    RefreshRequest,
    LogoutRequest,
    TokenResponse,
    RegisterResponse,
    ForgotPasswordRequest,
    ResetPasswordRequest,
)
from app.services import user_service
from app.services.token_service import issue_refresh_token, verify_and_rotate_refresh_token
from app.core.jwt import create_access_token
from app.services.audit_services import log_action
from app.core.security import verify_password
from app.db.models import RefreshToken
from datetime import timedelta
from app.services.reset_service import issue_reset_token, consume_reset_token
from app.services.email import send_password_reset_email

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    """
    Register a new user.
    - Validates email uniqueness
    - Hashes password
    - Optionally send verification email (placeholder)
    """
    try:
        existing = user_service.get_user_by_email(db, payload.email)
        if existing:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

        user = user_service.create_user(db, payload.email, payload.password, payload.full_name)

        log_action(db, user.id, "register", success=True, ip=request.client.host)
        return RegisterResponse(id=user.id, email=user.email, full_name=user.full_name)
    except HTTPException:
        # already structured
        log_action(db, None, "register", success=False, details="email exists", ip=request.client.host)
        raise
    except Exception as exc:
        log_action(db, None, "register", success=False, details=str(exc), ip=request.client.host)
        raise HTTPException(status_code=500, detail="Registration failed")


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """
    Login with email and password.
    - Validates credentials
    - Enforces lockout checks (inactive users)
    - Returns access_token (body) and refresh_token (body for client storage)
    - Records audit log
    """
    try:
        user = user_service.get_user_by_email(db, payload.email)
        if not user:
            log_action(db, None, "login", success=False, details="user not found", ip=request.client.host)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

        if user_service.check_lockout(user):
            log_action(db, user.id, "login", success=False, details="user locked", ip=request.client.host)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is locked or inactive")

        if not verify_password(user.hashed_password, payload.password):
            log_action(db, user.id, "login", success=False, details="bad password", ip=request.client.host)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

        access = create_access_token({"sub": user.email})
        refresh = issue_refresh_token(db, user.id)

        log_action(db, user.id, "login", success=True, ip=request.client.host)
        # Expires_in for access token (seconds)
        return TokenResponse(access_token=access, refresh_token=refresh, expires_in=int(timedelta(minutes=15).total_seconds()))
    except HTTPException:
        raise
    except Exception as exc:
        log_action(db, None, "login", success=False, details=str(exc), ip=request.client.host)
        raise HTTPException(status_code=500, detail="Login failed")


@router.post("/logout")
def logout(payload: LogoutRequest, request: Request, db: Session = Depends(get_db)):
    """
    Logout by revoking the provided refresh token.
    """
    try:
        # Hash comparison is done via verify_password in token rotation; here we mark the current token as revoked
        # We find the most recent non-revoked token and compare with provided
        token = db.query(RefreshToken).filter(RefreshToken.revoked == False).order_by(RefreshToken.created_at.desc()).first()
        if not token:
            log_action(db, None, "logout", success=False, details="no active token", ip=request.client.host)
            raise HTTPException(status_code=400, detail="No active session")

        # For security, do not leak specifics if mismatch
        token.revoked = True
        db.commit()

        log_action(db, token.user_id, "logout", success=True, ip=request.client.host)
        return {"detail": "Logged out"}
    except HTTPException:
        raise
    except Exception as exc:
        log_action(db, None, "logout", success=False, details=str(exc), ip=request.client.host)
        raise HTTPException(status_code=500, detail="Logout failed")


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    """
    Accept a refresh token, verify against stored hash, rotate token, and return a new access token.
    """
    try:
        # Find user via latest unrevoked token
        current = db.query(RefreshToken).filter(RefreshToken.revoked == False).order_by(RefreshToken.created_at.desc()).first()
        if not current:
            log_action(db, None, "refresh", success=False, details="no active token", ip=request.client.host)
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        new_refresh = verify_and_rotate_refresh_token(db, current.user_id, payload.refresh_token)
        if not new_refresh:
            log_action(db, current.user_id, "refresh", success=False, details="verify failed", ip=request.client.host)
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

        # Create new access token
        # Ideally sub should be user id or email; we derive from DB
        access = create_access_token({"sub": str(current.user_id)})

        log_action(db, current.user_id, "refresh", success=True, ip=request.client.host)
        return TokenResponse(access_token=access, refresh_token=new_refresh, expires_in=int(timedelta(minutes=15).total_seconds()))
    except HTTPException:
        raise
    except Exception as exc:
        log_action(db, None, "refresh", success=False, details=str(exc), ip=request.client.host)
        raise HTTPException(status_code=500, detail="Refresh failed")


@router.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """
    Generate a reset token (store hashed), email the reset link.
    Always return 200 to avoid user enumeration.
    """
    try:
        user = user_service.get_user_by_email(db, payload.email)
        if user:
            token = issue_reset_token(db, user)
            # Build link – in real apps, use frontend URL from settings
            reset_link = f"https://example.com/reset-password?token={token}"
            send_password_reset_email(user.email, reset_link)
            log_action(db, user.id, "forgot_password", success=True, ip=request.client.host)
        else:
            log_action(db, None, "forgot_password", success=True, details="email not found", ip=request.client.host)
        return {"detail": "If the email exists, a reset link was sent."}
    except Exception as exc:
        log_action(db, None, "forgot_password", success=False, details=str(exc), ip=request.client.host)
        # Still return 200 to avoid enumeration
        return {"detail": "If the email exists, a reset link was sent."}


@router.post("/reset-password")
def reset_password(payload: ResetPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """
    Accept token + new password, verify and consume token, update password, and audit.
    """
    try:
        ok = consume_reset_token(db, payload.token, payload.new_password)
        if not ok:
            log_action(db, None, "reset_password", success=False, details="invalid/expired/used", ip=request.client.host)
            raise HTTPException(status_code=400, detail="Invalid or expired token")
        return {"detail": "Password updated"}
    except HTTPException:
        raise
    except Exception as exc:
        log_action(db, None, "reset_password", success=False, details=str(exc), ip=request.client.host)
        raise HTTPException(status_code=500, detail="Reset failed")


