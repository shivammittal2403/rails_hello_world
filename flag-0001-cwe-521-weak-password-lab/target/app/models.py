"""SQLAlchemy ORM models — complete NexaDesk identity data model."""
from __future__ import annotations

import secrets
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
)
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(255))
    permissions = relationship("Permission", secondary="role_permissions", back_populates="roles")
    users = relationship("User", secondary="user_roles", back_populates="roles")


class Permission(Base):
    __tablename__ = "permissions"
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)  # e.g. tickets.read
    description = Column(String(255))
    roles = relationship("Role", secondary="role_permissions", back_populates="permissions")


class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_id = Column(ForeignKey("roles.id"), primary_key=True)
    permission_id = Column(ForeignKey("permissions.id"), primary_key=True)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)   # Argon2id PHC string
    given_name = Column(String(120))
    family_name = Column(String(120))
    department = Column(String(120))
    status = Column(String(32), default="pending_activation")  # active|pending_activation|disabled|must_reset_password
    is_admin = Column(Boolean, default=False)
    is_training_account = Column(Boolean, default=False)  # synthetic lab account marker (not a credential hint)
    invitation_token = Column(String(64), index=True)     # for activation flow
    failed_login_count = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True))
    password_changed_at = Column(DateTime(timezone=True), default=utcnow)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    last_login_at = Column(DateTime(timezone=True))

    roles = relationship("Role", secondary="user_roles", backref="members", lazy="joined")
    profile = relationship("EmployeeProfile", back_populates="user", uselist=False)
    history = relationship("PasswordHistory", back_populates="user", cascade="all, delete-orphan")

    def full_name(self) -> str:
        return f"{self.given_name or ''} {self.family_name or ''}".strip() or self.username


class UserRole(Base):
    __tablename__ = "user_roles"
    user_id = Column(ForeignKey("users.id"), primary_key=True)
    role_id = Column(ForeignKey("roles.id"), primary_key=True)


class SessionRecord(Base):
    """Server-side sessions (token stored only as SHA-256 digest)."""
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True)
    token_digest = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True))
    ip = Column(String(64))
    user_agent = Column(String(255))
    user = relationship("User")


class PasswordHistory(Base):
    __tablename__ = "password_history"
    id = Column(Integer, primary_key=True)
    user_id = Column(ForeignKey("users.id"), nullable=False)
    password_hash = Column(String(255), nullable=False)
    policy_mode = Column(String(16))
    created_at = Column(DateTime(timezone=True), default=utcnow)
    user = relationship("User", back_populates="history")


class PasswordPolicyConfig(Base):
    """Persisted policy configuration row; runtime enforcement reads this in admin UI."""
    __tablename__ = "password_policy"
    id = Column(Integer, primary_key=True)
    mode = Column(String(16), nullable=False)      # vulnerable|patched
    min_length = Column(Integer, nullable=False)
    max_length = Column(Integer, nullable=False)
    blocklist_enabled = Column(Boolean, default=False)
    contextual_checks_enabled = Column(Boolean, default=False)
    composition_rules = Column(Boolean, default=False)
    forced_rotation_days = Column(Integer, default=0)
    updated_by = Column(String(64))
    updated_at = Column(DateTime(timezone=True), default=utcnow)
    notes = Column(Text)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(ForeignKey("users.id"), nullable=False)
    token_digest = Column(String(64), unique=True, nullable=False)
    purpose = Column(String(16), default="activation")  # activation|reset|admin_reset_required
    used = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    user = relationship("User")


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True)
    identifier = Column(String(255))   # what was typed as username (kept for forensics)
    success = Column(Boolean, default=False)
    ip = Column(String(64))
    user_agent = Column(String(255))
    correlation_id = Column(String(64))
    created_at = Column(DateTime(timezone=True), default=utcnow)


class AuthenticationEvent(Base):
    __tablename__ = "authentication_events"
    id = Column(Integer, primary_key=True)
    event_id = Column(String(64), unique=True, default=lambda: secrets.token_hex(12))
    event_type = Column(String(64), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    username_ref = Column(String(64))
    service = Column(String(64), default="identity-service")
    severity = Column(String(16), default="info")
    outcome = Column(String(64))
    policy_mode = Column(String(16))
    details = Column(JSON, default=dict)   # NEVER contains plaintext passwords
    correlation_id = Column(String(64))
    created_at = Column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    actor_user_id = Column(Integer, ForeignKey("users.id"))
    actor_username = Column(String(64))
    action = Column(String(96), nullable=False)
    target = Column(String(160))
    details = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class EmployeeProfile(Base):
    __tablename__ = "employee_profiles"
    id = Column(Integer, primary_key=True)
    user_id = Column(ForeignKey("users.id"), unique=True, nullable=False)
    title = Column(String(120))
    office_location = Column(String(120))
    manager_username = Column(String(64))
    employee_code = Column(String(32))    # synthetic badge code
    hire_date = Column(String(16))
    user = relationship("User", back_populates="profile")


class SupportTicket(Base):
    __tablename__ = "support_tickets"
    id = Column(Integer, primary_key=True)
    ticket_number = Column(String(24), unique=True)
    subject = Column(String(255))
    body = Column(Text)
    priority = Column(String(16), default="normal")
    status = Column(String(24), default="open")
    requester_username = Column(String(64))
    assignee_username = Column(String(64))
    created_at = Column(DateTime(timezone=True), default=utcnow)


class TrainingDocument(Base):
    __tablename__ = "training_documents"
    id = Column(Integer, primary_key=True)
    doc_code = Column(String(32), unique=True)
    title = Column(String(255))
    classification = Column(String(32), default="internal")  # internal|restricted|training-only
    owner_role = Column(String(64), default="Standard Employee")
    content = Column(Text)   # synthetic training content; restricted ones hold stage evidence
    requires_auth = Column(Boolean, default=True)


class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    id = Column(Integer, primary_key=True)
    alert_id = Column(String(64), unique=True, default=lambda: "AL-" + secrets.token_hex(6))
    rule_id = Column(String(96))
    title = Column(String(255))
    severity = Column(String(16))
    event_ids = Column(JSON, default=list)
    correlation_ids = Column(JSON, default=list)
    summary = Column(Text)
    status = Column(String(24), default="open")   # open|acknowledged|closed
    created_at = Column(DateTime(timezone=True), default=utcnow)


class ChallengeProgress(Base):
    __tablename__ = "challenge_progress"
    id = Column(Integer, primary_key=True)
    session_key = Column(String(64), index=True)   # per-student progress key (cookie)
    stage = Column(String(48), nullable=False)
    score = Column(Integer, default=0)
    verified = Column(Boolean, default=False)
    server_evidence = Column(JSON, default=dict)   # SERVER-validated facts only
    completed_at = Column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("session_key", "stage", name="uq_stage_once"),)


class ChallengeEvidence(Base):
    __tablename__ = "challenge_evidence"
    id = Column(Integer, primary_key=True)
    session_key = Column(String(64), index=True)
    stage = Column(String(48))
    kind = Column(String(48))          # weak_acceptance_proof | auth_success | ...
    payload = Column(JSON, default=dict)
    sha256 = Column(String(64))
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Flag(Base):
    __tablename__ = "flags"
    id = Column(Integer, primary_key=True)
    flag_id = Column(String(32), unique=True, default="FLAG-0001")
    token = Column(String(128), nullable=False)     # random on init/reset; never hardcoded
    unlocked = Column(Boolean, default=False)
    unlocked_at = Column(DateTime(timezone=True))
    unlock_conditions_met = Column(JSON, default=list)
