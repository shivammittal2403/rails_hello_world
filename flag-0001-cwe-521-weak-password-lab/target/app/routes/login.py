"""Login routes: page + API. Generic failure messages, lockout-aware, event-emitting."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.schemas import UserPublic
from app.security.authentication import authenticate
from app.security.sessions import create_session, get_current_user, logout
from app.services.templates import templates

router = APIRouter()


@router.post("/login")
async def login(request: Request, db: DBSession = Depends(get_db),
                identifier: str = Form(...), password: str = Form(...)):
    user, status_msg = authenticate(db, identifier, password, request)
    if user is None:
        msg = {
            "invalid": "Sign-in failed. Verify your credentials or use account assistance.",
            "locked": "This account is temporarily locked after repeated failures. Try again later.",
            "inactive": "This account is not active. Complete activation or contact the service desk.",
        }[status_msg]
        return templates.TemplateResponse(request, "login.html",
                                          {"error": msg, "identifier": identifier}, status_code=401)
    resp = RedirectResponse(url="/dashboard", status_code=303)
    create_session(db, user, request, resp)
    return resp


@router.post("/api/v1/login")
async def login_api(request: Request, db: DBSession = Depends(get_db)):
    body = await request.json()
    identifier = str(body.get("identifier", ""))
    password = str(body.get("password", ""))
    user, status_msg = authenticate(db, identifier, password, request)
    if user is None:
        code = 423 if status_msg == "locked" else 401
        detail = {"locked": "account temporarily locked",
                  "inactive": "account inactive",
                  "invalid": "invalid credentials"}[status_msg]
        return JSONResponse({"ok": False, "detail": detail}, status_code=code)
    resp = JSONResponse({"ok": True, "user": UserPublic(
        username=user.username, email=user.email, given_name=user.given_name,
        family_name=user.family_name, department=user.department, status=user.status,
        is_admin=user.is_admin, roles=[r.name for r in user.roles],
        last_login_at=user.last_login_at).model_dump()})
    create_session(db, user, request, resp)
    return resp


@router.get("/logout")
@router.post("/logout")
@router.post("/api/v1/logout")
async def logout_route(request: Request, db: DBSession = Depends(get_db)):
    resp = RedirectResponse(url="/login", status_code=303)
    logout(db, request, resp)
    return resp
