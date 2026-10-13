"""FLAG-0001 flag lifecycle.

The flag value `FLAG{cwe_521_<random_token>}` is generated at initialization or
reset (never hardcoded, never shipped in frontend JS, never published in student
docs). It is released ONLY when the server verifies all unlock conditions:

  C1  Student interacted with the intended isolated target      (recon fact)
  C2  Weak password acceptance behavior identified              (policy analysis fact)
  C3  A weak password accepted by a legitimate account flow     (activation/change fact)
  C4  Controlled synthetic authentication objective completed   (auth fact)
  C5  Required evidence recorded                                (evidence rows exist)
"""
from __future__ import annotations

import secrets
from datetime import datetime, timezone

from sqlalchemy.orm import Session as DBSession

from app.challenge.progress import has_fact, progress_summary
from app.config import settings
from app.models import ChallengeEvidence, Flag

REQUIRED_FACTS = [
    "fact_recon",                 # C1
    "fact_identity_routes",       # C1/C2
    "fact_policy_analysis",       # C2
    "fact_weak_acceptance",       # C3
    "fact_controlled_auth",       # C4
    "fact_impact",                # C4 impact proof
    "fact_detection_review",      # C5 SOC review performed
    "fact_forensic_export",       # C5 evidence export
]


def ensure_flag(db: DBSession) -> Flag:
    """Create the random flag on first use / after reset."""
    flag = db.query(Flag).filter(Flag.flag_id == settings.LAB_CHALLENGE_ID).first()
    if flag is None:
        flag = Flag(
            flag_id=settings.LAB_CHALLENGE_ID,
            token=f"FLAG{{cwe_521_{secrets.token_urlsafe(18)}}}",
            unlocked=False,
        )
        db.add(flag)
        db.commit()
    return flag


def evaluate_unlock(db: DBSession, session_key: str) -> tuple[bool, list[str]]:
    """Server-side check of every unlock condition for this lab participant."""
    missing = []
    for kind in REQUIRED_FACTS:
        if has_fact(db, session_key, kind) is None:
            missing.append(kind)
    summary = progress_summary(db, session_key)
    # also require stages 01-06 to be server-awarded
    done = set(summary["completed_stages"])
    for stage in ("01-recon", "02-identity-discovery", "03-password-policy",
                  "04-weak-password-validation", "05-controlled-authentication", "06-impact"):
        if stage not in done:
            missing.append(f"stage:{stage}")
    return (len(missing) == 0), missing


def release_flag_if_earned(db: DBSession, session_key: str) -> str | None:
    flag = ensure_flag(db)
    ok, missing = evaluate_unlock(db, session_key)
    if ok and not flag.unlocked:
        flag.unlocked = True
        flag.unlocked_at = datetime.now(timezone.utc)
        flag.unlock_conditions_met = ["server-verified:all"]
        db.commit()
    if flag.unlocked:
        return flag.token
    return None


def evidence_count(db: DBSession, session_key: str) -> int:
    return (
        db.query(ChallengeEvidence)
        .filter(ChallengeEvidence.session_key == session_key)
        .count()
    )
