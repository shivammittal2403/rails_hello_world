"""Password reset + change flows. Server-side policy enforced on every new value."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.models import PasswordHistory, PasswordResetToken, User
from app.security.audit import emit_event, new_correlation_id
from app.security.authentication import find_user
from app.security.password_hashing import hash_password, verify_password
from app.security.password_policy import evaluate_password, public_policy_descriptor
from app.services.templates import templates

router = APIRouter()

RESET_TTL_MINUTES = 30


def _digest(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


@router.post("/password/reset")
async def reset_start(request: Request, db: DBSession = Depends(get_db),
                      identifier: str = Form(...)):
    user = find_user(db, identifier)
    token = None
    if user and user.status == "active":
        token = "RST-" + secrets.token_hex(12)
        db.add(PasswordResetToken(
            user_id=user.id, token_digest=_digest(token), purpose="reset",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=RESET_TTL_MINUTES),
        ))
        db.commit()
        emit_event(db, "password_reset_requested", username_ref=user.username,
                   user_id=user.id, outcome="token_issued", details={})
    # Uniform response — do not leak account existence
    ctx = {"identifier": identifier}
    if token:  # synthetic lab: display instead of e-mailing
        ctx["simulated_token"] = token
    return templates.TemplateResponse(request, "reset_request.html", ctx)


@router.get("/password/reset/confirm")
async def reset_confirm_form(request: Request, token: str = "", db: DBSession = Depends(get_db)):
    rt = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_digest == _digest(token),
        PasswordResetToken.used.is_(False)).first() if token else None
    valid = bool(rt and rt.expires_at.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc))
    return templates.TemplateResponse(request, "reset_confirm.html",
                                      {"token": token, "valid": valid,
                                       "policy": public_policy_descriptor()})


@router.post("/password/reset/confirm")
async def reset_confirm(request: Request, db: DBSession = Depends(get_db),
                        token: str = Form(...), new_password: str = Form(...)):
    cid = new_correlation_id()
    rt = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_digest == _digest(token),
        PasswordResetToken.used.is_(False)).first()
    if not rt or rt.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return templates.TemplateResponse(request, "reset_confirm.html",
                                          {"token": token, "valid": False,
                                           "error": "Reset link invalid or expired.",
                                           "policy": public_policy_descriptor()}, status_code=400)
    user = rt.user
    ctx = {"username": user.username, "email": user.email, "given_name": user.given_name,
           "family_name": user.family_name, "org_name": "Nexaline Systems",
           "department": user.department}
    result = evaluate_password(new_password, ctx)
    if not result.accepted:
        emit_event(db, "password_policy_violation", username_ref=user.username,
                   user_id=user.id, severity="low", outcome="weak_password_rejected",
                   details={"flow": "reset", "reasons": result.reasons}, correlation_id=cid)
        return templates.TemplateResponse(request, "reset_confirm.html",
                                          {"token": token, "valid": True,
                                           "error": " | ".join(result.reasons),
                                           "policy": public_policy_descriptor()}, status_code=400)
    rt.used = True
    user.password_hash = hash_password(new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    user.failed_login_count = 0
    user.locked_until = None
    db.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash,
                           policy_mode="reset"))
    db.commit()
    emit_event(db, "password_reset_completed", username_ref=user.username, user_id=user.id,
               outcome="password_set", details={"flow": "reset"}, correlation_id=cid)
    _note_weak_acceptance(request, db, new_password)
    return templates.TemplateResponse(request, "reset_done.html", {})


# ----------------------- JSON API twins -----------------------------------------
@router.post("/api/v1/password/reset/start")
async def reset_start_api(request: Request, db: DBSession = Depends(get_db)):
    body = await request.json()
    user = find_user(db, str(body.get("identifier", "")))
    if user and user.status == "active":
        token = "RST-" + secrets.token_hex(12)
        db.add(PasswordResetToken(user_id=user.id, token_digest=_digest(token), purpose="reset",
                                  expires_at=datetime.now(timezone.utc) + timedelta(minutes=RESET_TTL_MINUTES)))
        db.commit()
        emit_event(db, "password_reset_requested", username_ref=user.username, user_id=user.id,
                   outcome="token_issued", details={})
        return {"ok": True, "simulated_token": token,
                "note": "Synthetic lab: token returned instead of e-mailed."}
    return {"ok": True, "detail": "if the account exists a reset link was issued"}


@router.post("/api/v1/password/reset/confirm")
async def reset_confirm_api(request: Request, db: DBSession = Depends(get_db)):
    body = await request.json()
    token = str(body.get("token", ""))
    new_password = str(body.get("new_password", ""))
    cid = new_correlation_id()
    rt = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_digest == _digest(token),
        PasswordResetToken.used.is_(False)).first()
    if not rt or rt.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return JSONResponse({"ok": False, "detail": "invalid token"}, status_code=400)
    user = rt.user
    ctx = {"username": user.username, "email": user.email, "given_name": user.given_name,
           "family_name": user.family_name, "org_name": "Nexaline Systems",
           "department": user.department}
    result = evaluate_password(new_password, ctx)
    if not result.accepted:
        emit_event(db, "password_policy_violation", username_ref=user.username, user_id=user.id,
                   severity="low", outcome="weak_password_rejected",
                   details={"flow": "reset", "reasons": result.reasons}, correlation_id=cid)
        return JSONResponse({"ok": False, "detail": "policy rejected",
                             "reasons": result.reasons}, status_code=422)
    rt.used = True
    user.password_hash = hash_password(new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    user.failed_login_count = 0; user.locked_until = None
    db.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash, policy_mode="reset"))
    db.commit()
    emit_event(db, "password_reset_completed", username_ref=user.username, user_id=user.id,
               outcome="password_set", details={"flow": "reset"}, correlation_id=cid)
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
