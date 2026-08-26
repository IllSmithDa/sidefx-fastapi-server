# app/models.py
from sqlalchemy import (
    Column,
    Integer,
    String,
    UniqueConstraint,
    DateTime,
    Text,
    Boolean,
    ForeignKey,
    func,
)
from sqlalchemy.orm import relationship, Mapped, mapped_column
from app.db import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("username", name="uq_users_username"),
        UniqueConstraint("email_hash", name="uq_users_email_hash"),
    )

    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False, index=True)
    email_hash = Column(String(64), nullable=False, index=True)    
    email_enc = Column(String(512), nullable=True)  # <-- MUST exist
    # Password-auth users store a hash here. OAuth-only users (for example,
    # accounts created through Google) intentionally have no GermFx password.
    password_hash = Column(String(255), nullable=True)
    is_email_verified = Column(Boolean, nullable=False, server_default="false")
    email_verification_sent_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    symptom_logs = relationship(
        "SymptomLog", back_populates="user", cascade="all, delete-orphan"
    )
        # ✨ ADD THIS:
    user_medications = relationship(
        "UserMedication", back_populates="user", cascade="all, delete-orphan"
    )
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    is_active = Column(Boolean, nullable=False, server_default="true")
    # account_status can be "active", "deactivated", "suspended"
    account_status = Column(String(20), nullable=False, server_default="active")
    deactivated_at = Column(DateTime(timezone=True), nullable=True)
    suspended_at = Column(DateTime(timezone=True), nullable=True)
    suspension_reason = Column(Text, nullable=True)
    role = Column(String(20), nullable=False, server_default="user", index=True)
    settings = relationship(
        "UserSettings",
        back_populates="user",
        cascade="all, delete-orphan",
        uselist=False,
    )
    subscription = relationship(
        "UserSubscription",
        back_populates="user",
        cascade="all, delete-orphan",
        uselist=False,
    )
    usage_counters = relationship(
        "UserUsageCounter",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    feedback = relationship(
        "UserFeedback",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    oauth_identities = relationship(
        "UserOAuthIdentity",
        back_populates="user",
        cascade="all, delete-orphan",
    )

class UserOAuthIdentity(Base):
    __tablename__ = "user_oauth_identities"
    __table_args__ = (
        UniqueConstraint(
            "provider",
            "provider_subject",
            name="uq_oauth_provider_subject",
        ),
        UniqueConstraint(
            "user_id",
            "provider",
            name="uq_user_oauth_provider",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    provider = Column(String(20), nullable=False)
    provider_subject = Column(String(255), nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    user = relationship(
        "User",
        back_populates="oauth_identities",
    )
