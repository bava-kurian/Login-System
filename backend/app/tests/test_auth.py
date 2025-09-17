import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import User, AuditLog


@pytest.fixture
def test_user(db_session: Session):
    """Pre-create a test user for login tests."""
    user = User(email="existing@example.com", hashed_password="$argon2id$v=19$m=65536,t=3,p=4$Z5l/pKTK+sVHPLj4Yj7LXg$A5Mjde9kC+v1QCKKLtNE86hf0E92HYkp0UyCQRAxqHI", full_name="Existing User")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_register_success(client: TestClient, db_session: Session):
    payload = {"email": "newuser@example.com", "password": "newpassword", "full_name": "New User"}
    resp = client.post("/auth/register", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == payload["email"]

    user = db_session.query(User).filter_by(email=payload["email"]).first()
    assert user is not None

    log = db_session.query(AuditLog).filter_by(action="REGISTER").first()
    assert log is not None and log.success is True


def test_register_duplicate(client: TestClient, test_user: User):
    payload = {"email": "existing@example.com", "password": "another", "full_name": "Dup User"}
    resp = client.post("/auth/register", json=payload)
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Email already registered"


def test_login_success(client: TestClient, test_user: User, monkeypatch):
    # Monkeypatch verify_user_password to bypass real hashing
    from app.services import user_service
    monkeypatch.setattr(user_service, "verify_user_password", lambda db, u, pwd: True)

    resp = client.post("/auth/login", json={"email": test_user.email, "password": "any"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data and "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_login_invalid_password(client: TestClient, test_user: User, monkeypatch):
    from app.services import user_service
    monkeypatch.setattr(user_service, "verify_user_password", lambda db, u, pwd: False)

    resp = client.post("/auth/login", json={"email": test_user.email, "password": "wrong"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid credentials"


def test_refresh_success(client: TestClient, test_user: User, monkeypatch):
    # Monkeypatch to simulate valid rotation
    from app.services import token_service
    def fake_verify_and_rotate(db, token):
        return test_user, "new_refresh_token"
    monkeypatch.setattr(token_service, "verify_and_rotate_refresh_token", fake_verify_and_rotate)

    resp = client.post("/auth/refresh", json={"refresh_token": "old_token"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data and "refresh_token" in data
    assert data["refresh_token"] == "new_refresh_token"


def test_refresh_invalid(client: TestClient, monkeypatch):
    from app.services import token_service
    monkeypatch.setattr(token_service, "verify_and_rotate_refresh_token", lambda db, t: None)

    resp = client.post("/auth/refresh", json={"refresh_token": "bad"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid or expired refresh token"


def test_logout_success(client: TestClient, monkeypatch):
    from app.services import token_service
    monkeypatch.setattr(token_service, "revoke_refresh_token", lambda db, t: True)

    resp = client.post("/auth/logout", json={"refresh_token": "valid"})
    assert resp.status_code == 204


def test_logout_invalid(client: TestClient, monkeypatch):
    from app.services import token_service
    monkeypatch.setattr(token_service, "revoke_refresh_token", lambda db, t: False)

    resp = client.post("/auth/logout", json={"refresh_token": "bad"})
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid token or already revoked"
