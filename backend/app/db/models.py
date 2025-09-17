from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime, timedelta

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    tokens = relationship("RefreshToken", back_populates="user")
    reset_tokens = relationship("ResetToken", back_populates="user")
    logs = relationship("AuditLog", back_populates="user")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    token_hash = Column(String(512), nullable=False, unique=True)  # store only hashed token
    revoked = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="tokens")


class ResetToken(Base):
    __tablename__ = "reset_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    token_hash = Column(String(512), nullable=False, unique=True)  # hashed token only
    used = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="reset_tokens")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    action = Column(Text, nullable=False)
    ip_address = Column(String(45))
    success = Column(Boolean, default=True)   
    details = Column(Text, nullable=True)     

    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="logs")

