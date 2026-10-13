"""Server-side challenge state. Progress is keyed by an opaque lab cookie; every
stage transition is VALIDATED BY THE SERVER against real application facts
(events, DB rows, HTTP outcomes). Browser-submitted progress values are never
trusted. Repeated submissions cannot award duplicate points (unique constraint).
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone

from fastapi import Request, Response
from sqlalchemy.orm import Session as DBSession

from app.challenge.stages import STAGES, TOTAL_POINTS, stage_by_key
from app.models import ChallengeEvidence, ChallengeProgress

LAB_COOKIE = "nexadesk_lab"


def get_or_create_session_key(request: Request, response: Response | None = None) -> str:
    key = request.cookies.get(LAB_COOKIE)
    if not key:
        key = "lab-" + secrets.token_hex(10)
        if response is not None:
            response.set_cookie(LAB_COOKIE, key, httponly=True, samesite="lax", path="/", max_age=86400 * 30)
    return key


def record_server_fact(db: DBSession, session_key: str, stage: str, kind: str, payload: dict) -> str:
    """Persist a server-validated fact about what actually happened."""
    blob = json.dumps(payload, sort_keys=True, default=str).encode()
    ev = ChallengeEvidence(
        session_key=session_key, stage=stage, kind=kind,
        payload=payload, sha256=hashlib.sha256(blob).hexdigest(),
    )
    db.add(ev)
    db.commit()
    return ev.sha256


def has_fact(db: DBSession, session_key: str, kind: str) -> ChallengeEvidence | None:
    return (
        db.query(ChallengeEvidence)
        .filter(ChallengeEvidence.session_key == session_key,
                ChallengeEvidence.kind == kind)
        .order_by(ChallengeEvidence.id.desc())
        .first()
    )


def complete_stage(db: DBSession, session_key: str, stage_key: str, evidence: dict) -> bool:
    """Award a stage once, server-side. Returns True if newly awarded."""
    meta = stage_by_key(stage_key)
    if meta is None:
        return False
    existing = (
        db.query(ChallengeProgress)
        .filter(ChallengeProgress.session_key == session_key,
                ChallengeProgress.stage == stage_key)
        .first()
    )
    if existing and existing.verified:
        return False  # no duplicate awards
    now = datetime.now(timezone.utc)
    if existing:
        existing.verified = True
        existing.score = meta["points"]
        existing.completed_at = now
        existing.server_evidence = evidence
    else:
        db.add(ChallengeProgress(
            session_key=session_key, stage=stage_key, score=meta["points"],
            verified=True, server_evidence=evidence, completed_at=now,
        ))
    db.commit()
    return True


def progress_summary(db: DBSession, session_key: str) -> dict:
    rows = (
        db.query(ChallengeProgress)
        .filter(ChallengeProgress.session_key == session_key,
                ChallengeProgress.verified.is_(True))
        .all()
    )
    done = {r.stage: r for r in rows}
    stages_out = []
    score = 0
    for s in STAGES:
        row = done.get(s["stage"])
        if row:
            score += row.score
        stages_out.append({
            "stage": s["stage"], "title": s["title"], "points": s["points"],
            "verified": bool(row),
            "completed_at": row.completed_at if row else None,
        })
    bonus = sum(int(r.server_evidence.get("bonus", 0)) for r in rows if isinstance(r.server_evidence, dict))
    return {
        "score": score, "max_score": TOTAL_POINTS, "bonus": min(bonus, 300),
        "stages": stages_out,
        "completed_stages": sorted(done.keys()),
    }
