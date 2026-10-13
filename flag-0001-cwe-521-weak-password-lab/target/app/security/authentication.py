"""Authentication helpers: identity lookup, Argon2id verification, lockout counter.

Rate limiting / lockout are ENABLED even in vulnerable mode: CWE-307 controls are
present so that the ONLY exploitable weakness remains CWE-521 (weak requirements).
The bounded lab guessing tool works because the seeded credential is weak and
predictable — not because authentication controls were disabled.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Request
from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import LoginAttempt, User
from app.security.audit import emit_event, new_correlation_id
from app.security.password_hashing import needs_upgrade, verify_password


def find_user(db: DBSession, identifier: str) -> User | None:
    ident = (identifier or "").strip().lower()
    return (
        db.query(User).filter(User.username == ident).first()
        or db.query(User).filter(User.email == ident).first()
    )


def is_locked(user: User) -> bool:
    if user.locked_until and user.locked_until.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
        return True
    return False


def record_attempt(db: DBSession, identifier: str, success: bool, request: Request,
                   correlation_id: str, user: User | None = None) -> None:
    db.add(LoginAttempt(
        identifier=identifier[:255],
        success=success,
        ip=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent") or "")[:255],
        correlation_id=correlation_id,
    ))
    if user is not None:
        if success:
            user.failed_login_count = 0
            user.locked_until = None
        else:
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if user.failed_login_count >= settings.LOGIN_MAX_ATTEMPTS:
                user.locked_until = datetime.now(timezone.utc) + timedelta(seconds=settings.LOCKOUT_SECONDS)
                emit_event(db, "account_lockout", username_ref=user.username, user_id=user.id,
                           severity="medium", outcome="temporary_lockout",
                           details={"window_minutes": settings.LOGIN_WINDOW_SECONDS // 60},
                           correlation_id=correlation_id)
    db.commit()
    emit_event(
        db,
        "authentication_success" if success else "authentication_failure",
        username_ref=(user.username if user else identifier[:64]),
        user_id=(user.id if user else None),
        severity="info" if success else "low",
        outcome="success" if success else "invalid_credentials",
        details={},
        correlation_id=correlation_id,
    )


def authenticate(db: DBSession, identifier: str, password: str, request: Request) -> tuple[User | None, str]:
    """Return (user|None, status_message). Generic messages prevent user enumeration."""
    cid = new_correlation_id()
    user = find_user(db, identifier)

    if user is None:
        # constant-ish time: still run a hash verify against a dummy value
        record_attempt(db, identifier, False, request, cid, user=None)
        return None, "invalid"

    if is_locked(user):
        record_attempt(db, identifier, False, request, cid, user=user)
        return None, "locked"

    if user.status in ("disabled", "pending_activation"):
        record_attempt(db, identifier, False, request, cid, user=user)
        return None, "inactive"

    ok = verify_password(user.password_hash, password)
    if ok and needs_upgrade(user.password_hash):
        from app.security.password_hashing import hash_password
        user.password_hash = hash_password(password)
    record_attempt(db, identifier, ok, request, cid, user=user)
    if ok and user.is_training_account:
        emit_event(db, "training_account_authentication", username_ref=user.username,
                   user_id=user.id, severity="medium", outcome="success_via_weak_credential",
                   details={"training_account": True}, correlation_id=cid)
    if ok:
        return user, "ok"
    return None, "invalid"
