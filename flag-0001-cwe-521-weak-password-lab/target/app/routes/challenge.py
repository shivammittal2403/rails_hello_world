"""FLAG-0001 challenge REST API.

Design rules enforced here:
 * The server validates every stage claim against real facts it recorded itself.
 * Browser progress values are never trusted (claims must match server evidence).
 * The flag token is only ever returned after ALL unlock conditions pass; it is
   never embedded in templates, JS bundles, or public endpoints before that.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session as DBSession

from app.challenge.flag_manager import ensure_flag, evaluate_unlock, release_flag_if_earned
from app.challenge.progress import (
    complete_stage, get_or_create_session_key, has_fact, progress_summary, record_server_fact,
)
from app.challenge.stages import STAGES, TOTAL_POINTS
from app.challenge.verifier import run_verifier
from app.config import settings
from app.database import get_db
from app.services import forensics

router = APIRouter()


@router.get("/api/v1/challenge/config")
async def challenge_config():
    """Public challenge metadata — deliberately contains NO answers/credentials."""
    return {
        "challenge_id": settings.LAB_CHALLENGE_ID,
        "cwe": settings.LAB_CWE,
        "title": "Weak Password Requirements — Login & Identity Range",
        "total_points": TOTAL_POINTS,
        "stages": [{"stage": s["stage"], "title": s["title"], "points": s["points"]} for s in STAGES],
        "difficulty_modes": ["beginner", "intermediate", "advanced"],
        "flag_format": "FLAG{cwe_521_<random-token>}  (generated at lab init)",
    }


@router.get("/api/v1/challenge/progress")
async def challenge_progress(request: Request, db: DBSession = Depends(get_db)):
    sk = get_or_create_session_key(request)
    summary = progress_summary(db, sk)
    flag = release_flag_if_earned(db, sk)
    summary["flag_available"] = flag is not None
    summary["flag"] = flag  # None until server verifies all conditions
    return summary


@router.post("/api/v1/challenge/observe/{kind}")
async def observe(kind: str, request: Request, db: DBSession = Depends(get_db)):
    """Server-side fact recorder used by legitimate flows AND the authorized lab
    tooling. Facts describe what the SERVER actually did/served — clients cannot
    forge an acceptance fact because this endpoint re-checks real state first."""
    sk = get_or_create_session_key(request)
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    if kind == "fact_recon":
        # Requires that the participant really fetched discovery endpoints. The
        # recon middleware records hits; we verify at least one info/policy fetch.
        from app.models import AuthenticationEvent
        hit = (db.query(AuthenticationEvent)
               .filter(AuthenticationEvent.event_type == "recon_observed").first())
        if hit is None:
            return JSONResponse({"ok": False, "detail": "no target interaction observed yet"},
                                status_code=412)
        record_server_fact(db, sk, "01-recon", "fact_recon",
                           {"observed_at": hit.created_at.isoformat(), "source": "server-middleware"})
        awarded, ev = run_verifier(db, sk, "01-recon")
        return {"ok": True, "awarded": awarded, "evidence": ev}

    if kind == "fact_identity_routes":
        found = set(body.get("routes_found", []))
        required = {"login", "register", "activation", "password_reset"}
        if not required.issubset(found):
            return JSONResponse({"ok": False, "detail": "incomplete route set"}, status_code=422)
        record_server_fact(db, sk, "02-identity-discovery", "fact_identity_routes",
                           {"routes_found": sorted(found)})
        awarded, ev = run_verifier(db, sk, "02-identity-discovery")
        return {"ok": True, "awarded": awarded, "evidence": ev}

    if kind == "fact_policy_analysis":
        record_server_fact(db, sk, "03-password-policy", "fact_policy_analysis", {
            "identified_min_length": int(body.get("identified_min_length", -1)),
            "blocklist_enabled": bool(body.get("blocklist_enabled", True)),
            "contextual_checks_enabled": bool(body.get("contextual_checks_enabled", True)),
            "assessment": str(body.get("assessment", "")),
        })
        awarded, ev = run_verifier(db, sk, "03-password-policy")
        return {"ok": True, "awarded": awarded, "reason": ev.get("reason") if not awarded else None,
                "evidence": ev}

    if kind == "fact_weak_acceptance":
        # Only accepted when the server ITSELF just accepted a weak password in a
        # legitimate flow for THIS lab session (the activation/change routes call
        # record_weak_acceptance directly). Client claims alone are insufficient.
        pending_path = os.path.join(settings.EVIDENCE_DIR, f"pending:{sk}")
        if not os.path.exists(pending_path):
            return JSONResponse({"ok": False,
                                 "detail": "no server-recorded acceptance for this lab session; "
                                           "complete a legitimate account-management flow first"},
                                status_code=412)
        with open(pending_path) as fh:
            meta = fh.read().strip()
        os.remove(pending_path)
        length = int(meta.split(":")[0])
        matches_blocklist = meta.endswith(":bl1")
        sha = record_server_fact(db, sk, "04-weak-password-validation", "fact_weak_acceptance", {
            "accepted_by_legitimate_flow": True,
            "candidate_metadata": {"length": length},
            "matches_lab_blocklist": matches_blocklist,
        })
        awarded, ev = run_verifier(db, sk, "04-weak-password-validation")
        return {"ok": True, "awarded": awarded, "evidence_sha256": sha, "reason": ev.get("reason") if not awarded else None}

    if kind == "fact_controlled_auth":
        username = str(body.get("account", ""))
        budget = int(body.get("attempt_budget", 12))
        used = int(body.get("attempts_used", 999))
        from app.models import LoginAttempt
        ok = (db.query(LoginAttempt)
              .filter(LoginAttempt.identifier == username.lower(),
                      LoginAttempt.success.is_(True)).first())
        if ok is None:
            return JSONResponse({"ok": False, "detail": "server has no successful auth for that account"},
                                status_code=412)
        if used > budget:
            return JSONResponse({"ok": False, "detail": "budget exceeded"}, status_code=422)
        record_server_fact(db, sk, "05-controlled-authentication", "fact_controlled_auth", {
            "account": username.lower(), "attempt_budget": budget, "attempts_used": used,
            "success_correlation_id": ok.correlation_id,
        })
        awarded, ev = run_verifier(db, sk, "05-controlled-authentication")
        return {"ok": True, "awarded": awarded, "reason": ev.get("reason") if not awarded else None}

    if kind == "fact_detection_review":
        matched = body.get("matched_alert_ids", [])
        record_server_fact(db, sk, "07-detection", "fact_detection_review",
                           {"matched_alert_ids": matched})
        awarded, ev = run_verifier(db, sk, "07-detection")
        return {"ok": True, "awarded": awarded, "reason": ev.get("reason") if not awarded else None}

    if kind == "fact_forensic_export":
        export = forensics.export_timeline(db, sk)
        record_server_fact(db, sk, "08-forensics", "fact_forensic_export",
                           {"manifest_sha256": export["manifest_sha256"],
                            "event_count": export["event_count"]})
        awarded, ev = run_verifier(db, sk, "08-forensics")
        return {"ok": True, "awarded": awarded, "export": export["paths"], "evidence": ev}

    if kind == "fact_remediation":
        record_server_fact(db, sk, "09-remediation", "fact_remediation", {
            "plan_submitted": True,
            "patched_mode_active": not settings.is_vulnerable(),
            "notes": str(body.get("notes", ""))[:2000],
        })
        awarded, ev = run_verifier(db, sk, "09-remediation")
        return {"ok": True, "awarded": awarded}

    if kind == "fact_patch_verify":
        record_server_fact(db, sk, "10-verification", "fact_patch_verify", {
            "weak_rejected": bool(body.get("weak_rejected")),
            "strong_accepted": bool(body.get("strong_accepted")),
            "legit_login_ok": bool(body.get("legit_login_ok")),
        })
        awarded, ev = run_verifier(db, sk, "10-verification")
        return {"ok": True, "awarded": awarded, "reason": ev.get("reason") if not awarded else None}

    return JSONResponse({"ok": False, "detail": "unknown fact kind"}, status_code=404)


@router.get("/api/v1/challenge/unlock-status")
async def unlock_status(request: Request, db: DBSession = Depends(get_db)):
    """Progress transparency WITHOUT leaking the flag or credentials."""
    sk = get_or_create_session_key(request)
    ok, missing = evaluate_unlock(db, sk)
    return {"ready": ok, "missing_conditions": missing}


@router.get("/api/v1/challenge/forensics/export")
async def forensic_export(request: Request, db: DBSession = Depends(get_db)):
    sk = get_or_create_session_key(request)
    export = forensics.export_timeline(db, sk)
    record_server_fact(db, sk, "08-forensics", "fact_forensic_export",
                       {"manifest_sha256": export["manifest_sha256"],
                        "event_count": export["event_count"]})
    run_verifier(db, sk, "08-forensics")
    return export


def record_weak_acceptance_for_request(request: Request, db: DBSession, length: int,
                                       matches_blocklist: bool) -> None:
    """Called by legitimate account-management flows immediately AFTER the server
    accepted a demonstrably weak password. Writes a short-lived pending marker
    bound to the lab session key so stage 04 can only be claimed truthfully."""
    sk = get_or_create_session_key(request)
    os.makedirs(settings.EVIDENCE_DIR, exist_ok=True)
    path = os.path.join(settings.EVIDENCE_DIR, f"pending:{sk}")
    with open(path, "w") as fh:
        fh.write(f"{length}:{'bl1' if matches_blocklist else 'bl0'}")
