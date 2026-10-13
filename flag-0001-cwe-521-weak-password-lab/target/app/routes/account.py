"""Account self-service: profile, password change, activity."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.models import LoginAttempt, PasswordHistory, User
from app.schemas import UserPublic
from app.security.audit import emit_event, new_correlation_id
from app.security.authorization import require_login
from app.security.password_hashing import hash_password, verify_password
from app.security.password_policy import evaluate_password, public_policy_descriptor
from app.services.templates import templates

router = APIRouter()


@router.get("/account")
async def account_page(request: Request, db: DBSession = Depends(get_db)):
    from app.security.sessions import get_current_user
    user = get_current_user(db, request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    recent = (db.query(LoginAttempt).filter(LoginAttempt.identifier.in_(
        [user.username, user.email])).order_by(LoginAttempt.id.desc()).limit(15).all())
    return templates.TemplateResponse(request, "account.html",
                                      {"user": user, "recent": recent,
                                       "policy": public_policy_descriptor()})


@router.post("/account/password/change")
async def password_change(request: Request, db: DBSession = Depends(get_db),
                          current_password: str = Form(...), new_password: str = Form(...)):
    from app.security.sessions import get_current_user
    user = get_current_user(db, request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    cid = new_correlation_id()
    if not verify_password(user.password_hash, current_password):
        return templates.TemplateResponse(request, "account.html",
                                          {"user": user, "recent": [],
                                           "error": "Current password is incorrect.",
                                           "policy": public_policy_descriptor()}, status_code=401)
    ctx = {"username": user.username, "email": user.email, "given_name": user.given_name,
           "family_name": user.family_name, "org_name": "Nexaline Systems",
           "department": user.department}
    result = evaluate_password(new_password, ctx)     # SERVER-SIDE policy check
    if not result.accepted:
        emit_event(db, "password_policy_violation", username_ref=user.username, user_id=user.id,
                   severity="low", outcome="weak_password_rejected",
                   details={"flow": "change", "reasons": result.reasons}, correlation_id=cid)
        return templates.TemplateResponse(request, "account.html",
                                          {"user": user, "recent": [],
                                           "error": " | ".join(result.reasons),
                                           "policy": public_policy_descriptor()}, status_code=400)
    user.password_hash = hash_password(new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    db.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash,
                           policy_mode="change"))
    db.commit()
    emit_event(db, "password_change_completed", username_ref=user.username, user_id=user.id,
               outcome="password_set", details={"flow": "change"}, correlation_id=cid)
    _note_weak_acceptance(request, db, new_password)
    return RedirectResponse(url="/account?changed=1", status_code=303)


# ------------------------- JSON twins -------------------------------------------
@router.get("/api/v1/account/me")
async def me(user: User = Depends(require_login)):
    return UserPublic(username=user.username, email=user.email,
                      given_name=user.given_name, family_name=user.family_name,
                      department=user.department, status=user.status,
                      is_admin=user.is_admin, roles=[r.name for r in user.roles],
                      last_login_at=user.last_login_at)


@router.post("/api/v1/account/password/change")
async def password_change_api(request: Request, db: DBSession = Depends(get_db)):
    from app.security.sessions import get_current_user
    user = get_current_user(db, request)
    if user is None:
        return JSONResponse({"ok": False, "detail": "authentication required"}, status_code=401)
    body = await request.json()
    cid = new_correlation_id()
    if not verify_password(user.password_hash, str(body.get("current_password", ""))):
        return JSONResponse({"ok": False, "detail": "current password incorrect"}, status_code=401)
    new_password = str(body.get("new_password", ""))
    ctx = {"username": user.username, "email": user.email, "given_name": user.given_name,
           "family_name": user.family_name, "org_name": "Nexaline Systems",
           "department": user.department}
    result = evaluate_password(new_password, ctx)
    if not result.accepted:
        emit_event(db, "password_policy_violation", username_ref=user.username, user_id=user.id,
                   severity="low", outcome="weak_password_rejected",
                   details={"flow": "change", "reasons": result.reasons}, correlation_id=cid)
        return JSONResponse({"ok": False, "detail": "policy rejected",
                             "reasons": result.reasons}, status_code=422)
    user.password_hash = hash_password(new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    db.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash, policy_mode="change"))
    db.commit()
    emit_event(db, "password_change_completed", username_ref=user.username, user_id=user.id,
               outcome="password_set", details={"flow": "change"}, correlation_id=cid)
    _note_weak_acceptance(request, db, new_password)
    return {"ok": True}


def _note_weak_acceptance(request: Request, db: DBSession, password: str) -> None:
    from app.config import settings
    from app.security import patched_policy
    from app.routes.challenge import record_weak_acceptance_for_request
    fails_patched = len(password) < patched_policy.MIN_LENGTH
    in_blocklist = patched_policy._normalize(password) in patched_policy._BLOCKLIST
    if settings.is_vulnerable() and (fails_patched or in_blocklist):
        record_weak_acceptance_for_request(request, db, len(password), in_blocklist)
