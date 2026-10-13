"""Registration and invited-account activation.

Flow: employee onboarding request -> admin/seed issues invitation token ->
activate page sets username + password -> SERVER-side policy validates the
password (this is where CWE-521 lives: in vulnerable mode weak values pass).
Client-side hints exist but are advisory only; enforcement is server-side.
"""
from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.database import get_db
from app.models import PasswordHistory, PasswordResetToken, User, UserRole, Role
from app.security.audit import emit_event, new_correlation_id
from app.security.password_hashing import hash_password
from app.security.password_policy import evaluate_password, public_policy_descriptor
from app.services.templates import templates

router = APIRouter()

LAB_DOMAIN = "nexaline.example"


def _username_from(email: str, requested: str | None) -> str:
    if requested:
        return re.sub(r"[^a-z0-9._-]", "", requested.lower())[:40]
    local = email.split("@")[0]
    return re.sub(r"[^a-z0-9._-]", "", local.lower())[:40]


@router.post("/register")
async def register(request: Request, db: DBSession = Depends(get_db),
                   given_name: str = Form(...), family_name: str = Form(...),
                   email: str = Form(...), department: str = Form("Operations")):
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse(request, "register.html",
                                          {"error": "An account with this email already exists."},
                                          status_code=409)
    username = _username_from(email, None)
    while db.query(User).filter(User.username == username).first():
        username = username + str(secrets.randbelow(90) + 10)
    inv = "INV-" + secrets.token_hex(8)
    user = User(username=username, email=email, given_name=given_name,
                family_name=family_name, department=department,
                status="pending_activation", invitation_token=inv,
                password_hash=hash_password("placeholder-" + secrets.token_hex(8)))
    db.add(user)
    db.commit()
    role = db.query(Role).filter_by(name="Standard Employee").first()
    if role:
        db.add(UserRole(user_id=user.id, role_id=role.id))
        db.commit()
    emit_event(db, "account_created", username_ref=username, user_id=user.id,
               outcome="pending_activation", details={"via": "registration"})
    # Synthetic lab environment: no real mail transport — the activation link is
    # displayed once in the response ("sent to mailbox" simulation banner).
    return templates.TemplateResponse(
        request, "register_success.html",
        {"username": username, "invitation_token": inv,
         "simulated_mail": True},
    )


@router.get("/activate")
async def activate_form(request: Request, token: str = "", db: DBSession = Depends(get_db)):
    user = db.query(User).filter(User.invitation_token == token).first() if token else None
    return templates.TemplateResponse(request, "activate.html",
                                      {"token": token, "user": user,
                                       "policy": public_policy_descriptor()})


@router.post("/activate")
async def activate_submit(request: Request, db: DBSession = Depends(get_db),
                          invitation_token: str = Form(...), username: str = Form(...),
                          password: str = Form(...)):
    user = db.query(User).filter(User.invitation_token == invitation_token).first()
    cid = new_correlation_id()
    if user is None or user.status != "pending_activation":
        return templates.TemplateResponse(request, "activate.html",
                                          {"token": invitation_token, "user": None,
                                           "error": "Invitation is invalid or already used.",
                                           "policy": public_policy_descriptor()}, status_code=400)
    uname = re.sub(r"[^a-z0-9._-]", "", username.lower())[:40]
    if not uname or db.query(User).filter(User.username == uname).first():
        return templates.TemplateResponse(request, "activate.html",
                                          {"token": invitation_token, "user": user,
                                           "error": "Username unavailable.",
                                           "policy": public_policy_descriptor()}, status_code=400)
    ctx = {"username": uname, "email": user.email, "given_name": user.given_name,
           "family_name": user.family_name, "org_name": "Nexaline Systems",
           "department": user.department}
    result = evaluate_password(password, ctx)          # SERVER-SIDE enforcement
    if not result.accepted:
        emit_event(db, "password_policy_violation", username_ref=uname, user_id=user.id,
                   severity="low", outcome="weak_password_rejected",
                   details={"flow": "activation", "reasons": result.reasons},
                   correlation_id=cid)
        return templates.TemplateResponse(request, "activate.html",
                                          {"token": invitation_token, "user": user,
                                           "error": " | ".join(result.reasons),
                                           "policy": public_policy_descriptor()}, status_code=400)
    # Accepted. NOTE: storage is always Argon2id regardless of policy mode.
    user.username = uname
    user.password_hash = hash_password(password)
    user.status = "active"
    user.password_changed_at = datetime.now(timezone.utc)
    user.invitation_token = None
    db.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash,
                           policy_mode="activation"))
    db.commit()
    emit_event(db, "account_activated", username_ref=uname, user_id=user.id,
               outcome="activation_complete", details={"flow": "activation"},
               correlation_id=cid)
    _note_weak_acceptance(request, db, password)
    emit_event(db, "password_policy_evaluation", username_ref=uname, user_id=user.id,
               severity="info", outcome="accepted",
               details={"flow": "activation", "length_class": len(password) >= 15 and "strong" or "short"},
               correlation_id=cid)
    return templates.TemplateResponse(request, "activate_success.html", {"username": uname})


# ------------------------- JSON API twins (used by attacker tools/tests) --------
@router.post("/api/v1/register")
async def register_api(request: Request, db: DBSession = Depends(get_db)):
    body = await request.json()
    email = str(body.get("email", ""))
    if db.query(User).filter(User.email == email).first():
        return JSONResponse({"ok": False, "detail": "email exists"}, status_code=409)
    username = _username_from(email, body.get("requested_username"))
    inv = "INV-" + secrets.token_hex(8)
    user = User(username=username, email=email,
                given_name=str(body.get("given_name", "New")),
                family_name=str(body.get("family_name", "Employee")),
                department=str(body.get("department", "Operations")),
                status="pending_activation", invitation_token=inv,
                password_hash=hash_password("placeholder-" + secrets.token_hex(8)))
    db.add(user); db.commit()
    role = db.query(Role).filter_by(name="Standard Employee").first()
    if role:
        db.add(UserRole(user_id=user.id, role_id=role.id)); db.commit()
    emit_event(db, "account_created", username_ref=username, user_id=user.id,
               outcome="pending_activation", details={"via": "registration-api"})
    return {"ok": True, "username": username, "invitation_token": inv,
            "note": "Synthetic lab: activation token returned directly instead of e-mail."}


@router.post("/api/v1/activate")
async def activate_api(request: Request, db: DBSession = Depends(get_db)):
    body = await request.json()
    user = db.query(User).filter(User.invitation_token == str(body.get("invitation_token", ""))).first()
    cid = new_correlation_id()
    if user is None or user.status != "pending_activation":
        return JSONResponse({"ok": False, "detail": "invalid invitation"}, status_code=400)
    username = str(body.get("username", "")).lower()
    password = str(body.get("password", ""))
    ctx = {"username": username, "email": user.email, "given_name": user.given_name,
           "family_name": user.family_name, "org_name": "Nexaline Systems",
           "department": user.department}
    result = evaluate_password(password, ctx)
    if not result.accepted:
        emit_event(db, "password_policy_violation", username_ref=username, user_id=user.id,
                   severity="low", outcome="weak_password_rejected",
                   details={"flow": "activation", "reasons": result.reasons}, correlation_id=cid)
        return JSONResponse({"ok": False, "detail": "policy rejected",
                             "reasons": result.reasons}, status_code=422)
    user.username = username or user.username
    user.password_hash = hash_password(password)
    user.status = "active"
    user.password_changed_at = datetime.now(timezone.utc)
    user.invitation_token = None
    db.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash,
                           policy_mode="activation"))
    db.commit()
    emit_event(db, "account_activated", username_ref=user.username, user_id=user.id,
               outcome="activation_complete", details={"flow": "activation"}, correlation_id=cid)
    _note_weak_acceptance(request, db, password)
    return {"ok": True, "username": user.username}


def _note_weak_acceptance(request: Request, db: DBSession, password: str) -> None:
    """If the ACTIVE (vulnerable) policy just accepted a value that the PATCHED
    policy would reject, record a server-side pending marker so stage 04 can be
    claimed truthfully. Plaintext is never stored — only length + blocklist flag."""
    from app.security import patched_policy
    from app.routes.challenge import record_weak_acceptance_for_request
    ctx = {}
    fails_patched = len(password) < patched_policy.MIN_LENGTH
    in_blocklist = patched_policy._normalize(password) in patched_policy._BLOCKLIST
    if settings.is_vulnerable() and (fails_patched or in_blocklist):
        record_weak_acceptance_for_request(request, db, len(password), in_blocklist)
