from .session import SessionLocal
from.models import User
from app.core.security import hash_password

def seed_admin():
    db = SessionLocal()
    admin = db.query(User).filter_by(email="admin@example.com").first()
    if not admin:
        admin = User(
            email="admin@example.com",
            hashed_password=hash_password("admin123"),
            full_name="Admin User",
            is_active=True
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)
        print("✅ Admin user created:", admin.email)
    else:
        print("⚡ Admin already exists")

if __name__ == "__main__":
    seed_admin()
