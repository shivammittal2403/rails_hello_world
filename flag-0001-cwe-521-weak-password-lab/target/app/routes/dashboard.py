"""Employee dashboard: tickets, documents (RBAC-enforced), profile, activity."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session as DBSession

from app.challenge.flag_manager import ensure_flag  # noqa: F401 (import side-effect safety)
from app.database import get_db
from app.models import SupportTicket, TrainingDocument, User
from app.schemas import DocumentFull, DocumentMeta, TicketPublic
from app.security.authorization import require_login, user_permissions
from app.services.templates import templates

router = APIRouter()

CLASSIFICATION_PERMISSION = {
    "internal": "docs.internal.read",
    "restricted": "docs.restricted.read",
    "training-only": "docs.training_only.read",
}


@router.get("/dashboard")
async def dashboard(request: Request, db: DBSession = Depends(get_db)):
    from app.security.sessions import get_current_user
    user = get_current_user(db, request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    perms = user_permissions(user)
    tickets = db.query(SupportTicket).order_by(SupportTicket.id.desc()).limit(20).all()
    docs = []
    for d in db.query(TrainingDocument).all():
        need = CLASSIFICATION_PERMISSION.get(d.classification, "docs.internal.read")
        if "*" in perms or need in perms:
            docs.append(d)
    return templates.TemplateResponse(request, "dashboard.html",
                                      {"user": user, "perms": sorted(perms),
                                       "tickets": tickets, "documents": docs})


@router.get("/api/v1/tickets")
async def tickets_api(user: User = Depends(require_login), db: DBSession = Depends(get_db)):
    rows = db.query(SupportTicket).order_by(SupportTicket.id.desc()).limit(50).all()
    return [TicketPublic.model_validate(r).model_dump() for r in rows]


@router.get("/api/v1/documents")
async def documents_list(user: User = Depends(require_login), db: DBSession = Depends(get_db)):
    perms = user_permissions(user)
    out = []
    for d in db.query(TrainingDocument).all():
        need = CLASSIFICATION_PERMISSION.get(d.classification, "docs.internal.read")
        if "*" in perms or need in perms:
            out.append(DocumentMeta.model_validate(d).model_dump())
    return out


@router.get("/api/v1/documents/{doc_code}")
async def document_detail(doc_code: str, request: Request,
                          user: User = Depends(require_login),
                          db: DBSession = Depends(get_db)):
    """RBAC enforced SERVER-SIDE. Unauthorized classification -> 403 (no content leak)."""
    perms = user_permissions(user)
    d = db.query(TrainingDocument).filter(TrainingDocument.doc_code == doc_code).first()
    if d is None:
        return JSONResponse({"ok": False, "detail": "not found"}, status_code=404)
    need = CLASSIFICATION_PERMISSION.get(d.classification, "docs.internal.read")
    if not ("*" in perms or need in perms):
        return JSONResponse({"ok": False, "detail": f"missing permission {need}"}, status_code=403)
    payload = DocumentFull.model_validate(d).model_dump()
    # Stage-06 server-side observation: reading the incident brief through the
    # compromised synthetic identity is recorded automatically.
    if doc_code == "TRN-CWE521-READTHIS" and user.is_training_account:
        from app.challenge.progress import get_or_create_session_key, record_server_fact
        sk = get_or_create_session_key(request)
        record_server_fact(db, sk, "06-impact", "fact_impact", {
            "accessed_training_data_as_synthetic_user": True,
            "account": user.username, "doc_code": doc_code,
            "evidence_note": "IMPACT-NXD-521-OK",
        })
    return payload
