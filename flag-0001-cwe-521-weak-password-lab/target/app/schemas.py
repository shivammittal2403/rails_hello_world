"""Pydantic schemas (API/DB DTOs). No schema ever exposes password_hash."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---- identity -----------------------------------------------------------------
class UserPublic(ORMModel):
    username: str
    email: EmailStr
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    department: Optional[str] = None
    status: str
    is_admin: bool
    roles: list[str] = []
    last_login_at: Optional[datetime] = None


class UserAdminRow(ORMModel):
    username: str
    email: EmailStr
    full_name: str
    department: Optional[str] = None
    status: str
    is_training_account: bool
    failed_login_count: int
    last_login_at: Optional[datetime] = None
    password_changed_at: Optional[datetime] = None
    roles: list[str] = []


class RegisterRequest(BaseModel):
    given_name: str = Field(min_length=1, max_length=80)
    family_name: str = Field(min_length=1, max_length=80)
    email: EmailStr
    requested_username: Optional[str] = None
    department: str = "Operations"


class ActivationRequest(BaseModel):
    invitation_token: str
    username: str
    password: str  # accepted by WEAK server-side policy in vulnerable mode (CWE-521)


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class PasswordResetStartRequest(BaseModel):
    identifier: str  # username or email


class PasswordResetConfirmRequest(BaseModel):
    token: str
    new_password: str


# ---- security ------------------------------------------------------------------
class PolicyDescriptor(BaseModel):
    mode: str
    policy_name: str
    min_length: int
    max_length: int
    rules: list[str]
    blocklist_enabled: bool
    contextual_checks_enabled: bool


class LoginAttemptPublic(ORMModel):
    identifier: str
    success: bool
    created_at: datetime


class AuthenticationEventPublic(ORMModel):
    event_id: str
    event_type: str
    username_ref: Optional[str]
    severity: str
    outcome: Optional[str]
    policy_mode: Optional[str]
    correlation_id: Optional[str]
    created_at: datetime
    details: dict = {}


class SecurityAlertPublic(ORMModel):
    alert_id: str
    rule_id: Optional[str]
    title: str
    severity: str
    summary: Optional[str]
    status: str
    event_ids: list = []
    created_at: datetime


# ---- business ------------------------------------------------------------------
class TicketPublic(ORMModel):
    ticket_number: str
    subject: str
    priority: str
    status: str
    requester_username: str
    assignee_username: Optional[str]
    created_at: datetime


class DocumentMeta(ORMModel):
    doc_code: str
    title: str
    classification: str
    owner_role: str


class DocumentFull(DocumentMeta):
    content: str


# ---- challenge -------------------------------------------------------------------
class StageStatus(BaseModel):
    stage: str
    title: str
    points: int
    verified: bool
    completed_at: Optional[datetime] = None


class ProgressResponse(BaseModel):
    score: int
    max_score: int
    bonus: int
    stages: list[StageStatus]
    flag_available: bool
    flag: Optional[str] = None
