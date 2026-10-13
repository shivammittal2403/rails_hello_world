"""NexaDesk Enterprise Identity Portal — FastAPI application entrypoint.

Realistic enterprise behavior; the single intentional primary defect is the
server-side weak password requirements (CWE-521) selected by PASSWORD_POLICY_MODE.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.database import Base, SessionLocal, engine, get_db
from app.models import User
from app.routes import account, admin, challenge, dashboard, login, password_reset, register
from app.security.password_policy import public_policy_descriptor
from app.services.seeding import seed_all
from app.services.templates import templates
from app.middleware.recon import recon_observer

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Multi-worker containers may race on first seed; tolerate unique clashes.
        try:
            seed_all(db)
        except IntegrityError:
            db.rollback()
        from app.challenge.flag_manager import ensure_flag
        try:
            ensure_flag(db)      # random flag generated at init / after reset
        except IntegrityError:
            db.rollback()
    finally:
        db.close()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    docs_url=None, redoc_url=None,   # enterprise posture: no interactive schema pages
    lifespan=lifespan,
)

app.add_middleware(recon_observer)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "app", "static")), name="static")

app.include_router(login.router)
app.include_router(register.router)
app.include_router(password_reset.router)
app.include_router(account.router)
app.include_router(dashboard.router)
app.include_router(admin.router)
app.include_router(challenge.router)


# ----------------------------- page routes ---------------------------------------
@app.get("/", include_in_schema=False)
def index(request: Request, db: DBSession = Depends(get_db)):
    from app.security.sessions import get_current_user
    if get_current_user(db, request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return RedirectResponse(url="/login", status_code=303)


@app.get("/login", include_in_schema=False)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html",
                                      {"error": None, "identifier": ""})


@app.get("/register", include_in_schema=False)
def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html", {"error": None})


@app.get("/training", include_in_schema=False)
def training_page(request: Request):
    """Training dashboard: challenges, objectives, progress, hints. Shows NO answers."""
    return templates.TemplateResponse(request, "training.html",
                                      {"stages": challenge.STAGES,
                                       "challenge_id": settings.LAB_CHALLENGE_ID})


@app.get("/security", include_in_schema=False)
def security_dashboard(request: Request, db: DBSession = Depends(get_db)):
    from app.security.sessions import get_current_user
    user = get_current_user(db, request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request, "security.html", {"user": user})


@app.get("/healthz")
def healthz(db: DBSession = Depends(get_db)):
    from sqlalchemy import text
    db.execute(text("SELECT 1"))
    return {"status": "ok", "mode": settings.PASSWORD_POLICY_MODE,
            "version": settings.APP_VERSION}


# --------------------------- public identity API ----------------------------------
@app.get("/api/v1/info")
def info():
    """Application fingerprint endpoint (intentionally discoverable for recon stage)."""
    return {
        "product": settings.APP_NAME,
        "organization": settings.ORG_NAME,
        "version": settings.APP_VERSION,
        "identity_flows": ["login", "registration", "invited_activation",
                           "password_change", "password_reset"],
        "session": "http-only cookie",
        "environment": "authorized training range (synthetic data only)",
    }


@app.get("/api/v1/policy")
def policy():
    """Active server-side password policy descriptor (advertised requirements)."""
    return public_policy_descriptor()


@app.post("/api/v1/policy/evaluate")
async def policy_evaluate(request: Request, db: DBSession = Depends(get_db)):
    """Dry-run evaluation helper used by registration UI and the authorized lab
    policy tester. Returns verdict + reasons ONLY; never stores anything, never
    reveals valid credentials. Rate-limited like other auth-adjacent endpoints."""
    body = await request.json()
    candidate = str(body.get("candidate", ""))
    ctx = {k: str(v) for k, v in (body.get("context") or {}).items()}
    result = _evaluate(candidate, ctx)
    from app.security.audit import emit_event
    emit_event(db, "password_policy_evaluation", severity="info",
               outcome="accepted" if result.accepted else "rejected",
               details={"reason_count": len(result.reasons)})
    return result.to_dict()


def _evaluate(pw, ctx):
    from app.security.password_policy import evaluate_password
    return evaluate_password(pw, ctx)


@app.get("/api/v1/roles")
def roles_public():
    """Public role catalog (enterprise self-description; not sensitive)."""
    from app.security.authorization import ROLE_PERMISSIONS
    return [{"role": r, "permissions": sorted(p)} for r, p in ROLE_PERMISSIONS.items()]


from fastapi.exceptions import HTTPException as FastAPIHTTPException


@app.exception_handler(404)
async def not_found(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"ok": False, "detail": "not found"}, status_code=404)
    return templates.TemplateResponse(request, "404.html", {"request": request}, status_code=404)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
