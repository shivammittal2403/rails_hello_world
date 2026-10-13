"""Administrator routes: user directory, account status controls, policy view,
security events, access review. All actions audited; all require Administrator."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.models import (
    AuditLog, AuthenticationEvent, PasswordPolicyConfig, SecurityAlert, User, UserRole, Role,
)
from app.schemas import AuthenticationEventPublic, SecurityAlertPublic, UserAdminRow
from app.security.audit import emit_event
from app.security.authorization import require_admin, require_login
from app.security.password_policy import public_policy_descriptor
from app.services.templates import templates

router = APIRouter()


def _audit(db: DBSession, actor: User, action: str, target: str, details: dict):
    db.add(AuditLog(actor_user_id=actor.id, actor_username=actor.username,
                    action=action, target=target, details=details))
    db.commit()
    emit_event(db, "admin_action", username_ref=actor.username, user_id=actor.id,
               severity="medium", outcome=action, details={"target": target})


@router.get("/admin")
async def admin_page(request: Request, db: DBSession = Depends(get_db)):
    from app.security.sessions import get_current_user
    user = get_current_user(db, request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    if not any(r.name == "Administrator" for r in user.roles):
        return templates.TemplateResponse(request, "forbidden.html", {"user": user}, status_code=403)
    users = db.query(User).order_by(User.username).all()
    rows = [UserAdminRow(
        username=u.username, email=u.email, full_name=u.full_name(), department=u.department,
        status=u.status, is_training_account=bool(u.is_training_account),
        failed_login_count=u.failed_login_count or 0, last_login_at=u.last_login_at,
        password_changed_at=u.password_changed_at,
        roles=[r.name for r in u.roles]).model_dump() for u in users]
    events = db.query(AuthenticationEvent).order_by(AuthenticationEvent.id.desc()).limit(50).all()
    alerts = db.query(SecurityAlert).order_by(SecurityAlert.id.desc()).limit(25).all()
    cfg = db.query(PasswordPolicyConfig).first()
    return templates.TemplateResponse(request, "admin.html", {
        "user": user, "users": rows,
        "events": [AuthenticationEventPublic.model_validate(e).model_dump() for e in events],
        "alerts": [SecurityAlertPublic.model_validate(a).model_dump() for a in alerts],
        "policy": public_policy_descriptor(),
        "policy_cfg": cfg.__dict__ if cfg else {},
    })


@router.get("/api/v1/admin/users")
async def admin_users(user: User = Depends(require_admin), db: DBSession = Depends(get_db)):
    out = []
    for u in db.query(User).order_by(User.username).all():
        # NOTE: password_hash intentionally never serialized (test_password_hash_api asserts)
        out.append({
            "username": u.username, "email": u.email, "full_name": u.full_name(),
            "department": u.department, "status": u.status,
            "is_training_account": bool(u.is_training_account),
            "failed_login_count": u.failed_login_count or 0,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "password_changed_at": u.password_changed_at.isoformat() if u.password_changed_at else None,
            "roles": [r.name for r in u.roles],
        })
    return out


@router.post("/api/v1/admin/users/{username}/unlock")
async def unlock(username: str, request: Request, db: DBSession = Depends(get_db),
                 actor: User = Depends(require_admin)):
    u = db.query(User).filter(User.username == username).first()
    if not u:
        return JSONResponse({"ok": False, "detail": "not found"}, status_code=404)
    u.locked_until = None
    u.failed_login_count = 0
    db.commit()
    _audit(db, actor, "account_unlock", username, {})
    return {"ok": True}


@router.post("/api/v1/admin/users/{username}/require-reset")
async def require_reset(username: str, db: DBSession = Depends(get_db),
                        actor: User = Depends(require_admin)):
    """Remediation mechanism for previously weak seeded accounts: force the owner
    through the legitimate reset flow instead of silently rewriting hashes."""
    u = db.query(User).filter(User.username == username).first()
    if not u:
        return JSONResponse({"ok": False, "detail": "not found"}, status_code=404)
    u.status = "must_reset_password"
    db.commit()
    _audit(db, actor, "force_password_reset", username, {"reason": "CWE-521 remediation"})
    emit_event(db, "identity_hardening", username_ref=username, user_id=u.id,
               severity="info", outcome="reset_required_set",
               details={"mechanism": "admin_force_reset"})
    return {"ok": True}


@router.post("/api/v1/admin/users/{username}/disable")
async def disable(username: str, db: DBSession = Depends(get_db),
                  actor: User = Depends(require_admin)):
    u = db.query(User).filter(User.username == username).first()
    if not u:
        return JSONResponse({"ok": False, "detail": "not found"}, status_code=404)
    u.status = "disabled"
    db.commit()
    _audit(db, actor, "account_disable", username, {})
    return {"ok": True}


@router.get("/api/v1/admin/events")
async def admin_events(since_id: int = 0, limit: int = 200,
                       user: User = Depends(require_login),
                       db: DBSession = Depends(get_db)):
    from app.security.authorization import user_permissions
    perms = user_permissions(user)
    if "*" not in perms and "events.read" not in perms:
        return JSONResponse({"ok": False, "detail": "missing permission events.read"}, status_code=403)
    rows = (db.query(AuthenticationEvent)
            .filter(AuthenticationEvent.id > since_id)
            .order_by(AuthenticationEvent.id.asc()).limit(min(limit, 500)).all())
    return [AuthenticationEventPublic.model_validate(e).model_dump() for e in rows]


@router.get("/api/v1/admin/alerts")
async def admin_alerts(user: User = Depends(require_login), db: DBSession = Depends(get_db)):
    from app.security.authorization import user_permissions
    perms = user_permissions(user)
    if "*" not in perms and "alerts.read" not in perms:
        return JSONResponse({"ok": False, "detail": "missing permission alerts.read"}, status_code=403)
    rows = db.query(SecurityAlert).order_by(SecurityAlert.id.desc()).limit(100).all()
    return [SecurityAlertPublic.model_validate(a).model_dump() for a in rows]


@router.get("/api/v1/admin/access-review")
async def access_review(user: User = Depends(require_admin), db: DBSession = Depends(get_db)):
    review = []
    for u in db.query(User).order_by(User.username).all():
        review.append({
            "username": u.username,
            "roles": sorted(r.name for r in u.roles),
            "status": u.status,
            "dormant": bool(u.last_login_at is None),
            "training": bool(u.is_training_account),
        })
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "entries": review}
