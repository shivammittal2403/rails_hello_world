"""Server-side session management.

Session tokens are random 32-byte values; only their SHA-256 digest is stored.
Cookie flags: HttpOnly, SameSite=Lax, Path=/ . Session expiry enforced server-side.
(Redis is used for the live login-attempt counter when available; DB remains the
source of truth for sessions so the app also works without Redis.)
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Request, Response
from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import SessionRecord, User


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: DBSession, user: User, request: Request, response: Response) -> str:
    token = secrets.token_urlsafe(32)
    rec = SessionRecord(
        token_digest=_digest(token),
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=settings.SESSION_MAX_AGE_SECONDS),
        ip=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent") or "")[:255],
    )
    db.add(rec)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        path="/",
        max_age=settings.SESSION_MAX_AGE_SECONDS,
    )
    return token


def get_current_user(db: DBSession, request: Request) -> User | None:
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not token:
        return None
    rec = db.query(SessionRecord).filter(
        SessionRecord.token_digest == _digest(token),
        SessionRecord.revoked_at.is_(None),
    ).first()
    if not rec:
        return None
    if rec.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return None
    return rec.user


def logout(db: DBSession, request: Request, response: Response) -> None:
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if token:
        rec = db.query(SessionRecord).filter(SessionRecord.token_digest == _digest(token)).first()
        if rec and rec.revoked_at is None:
            rec.revoked_at = datetime.now(timezone.utc)
            db.commit()
    response.delete_cookie(settings.SESSION_COOKIE_NAME, path="/")
