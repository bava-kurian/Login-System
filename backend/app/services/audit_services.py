from sqlalchemy.orm import Session
from app.db.models import AuditLog

def log_action(db: Session, user_id: int | None, action: str, success: bool = True, details: str | None = None, ip: str | None = None):
    log = AuditLog(user_id=user_id, action=action, ip_address=ip, success=success, details=details)
    db.add(log)
    db.commit()
