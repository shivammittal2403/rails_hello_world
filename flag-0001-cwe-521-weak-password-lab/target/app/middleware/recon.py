"""Recon observation middleware.

Records server-side evidence that a participant interacted with the isolated
target's discovery surface (GET /api/v1/info, GET /api/v1/policy, HEAD /). This
is what makes stage-01 validation *real*: the fact is created by the application
observing its own traffic, not by a browser claim. Also emits identity_route_probe
events when identity endpoints are probed, and document_access_denied events for
RBAC blocks (useful to SOC/forensics)."""
from __future__ import annotations

import threading

from fastapi import Request

from app.database import SessionLocal
from app.models import User
from app.security.audit import emit_event
from app.security.sessions import get_current_user

RECON_PATHS = {"/api/v1/info", "/api/v1/policy", "/"}
IDENTITY_PATHS = {
    "/login": "login", "/register": "register", "/activate": "activation",
    "/password/reset": "password_reset", "/account": "account",
    "/api/v1/login": "login", "/api/v1/register": "register",
    "/api/v1/activate": "activation", "/api/v1/password/reset/start": "password_reset",
}

_seen_lock = threading.Lock()
_seen_paths: set[str] = set()


async def recon_observer(request: Request, call_next):
    path = request.url.path
    method = request.method.upper()

    # De-dup per-process so background noise doesn't spam events
    key = f"{method}:{path}"
    first_hit = False
    with _seen_lock:
        if key not in _seen_paths:
            _seen_paths.add(key)
            first_hit = True

    if first_hit:
        db = SessionLocal()
        try:
            if method == "GET" and path in RECON_PATHS and path != "/":
                emit_event(db, "recon_observed", severity="info",
                           outcome="application_fingerprint_requested",
                           details={"path": path})
            elif method in ("GET", "HEAD") and path in IDENTITY_PATHS:
                emit_event(db, "identity_route_probe", severity="info",
                           outcome="identity_endpoint_observed",
                           details={"path": path, "route_class": IDENTITY_PATHS[path]})
        finally:
            db.close()

    response = await call_next(request)

    # Record RBAC denials as forensic events (403 on documents endpoint)
    if response.status_code == 403 and path.startswith("/api/v1/documents"):
        db = SessionLocal()
        try:
            user = get_current_user(db, request)
            emit_event(db, "document_access_denied",
                       username_ref=(user.username if user else None),
                       user_id=(user.id if user else None),
                       severity="low", outcome="rbac_denied",
                       details={"path": path})
        finally:
            db.close()

    # Security headers (defensive posture; not the challenge focus)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response
