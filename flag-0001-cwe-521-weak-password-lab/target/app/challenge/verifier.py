"""Stage verifiers. Each verifier cross-checks a claimed completion against REAL
server-side facts (DB rows, recorded events, actual HTTP outcomes captured by the
application itself). Client-submitted values are treated as claims only."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session as DBSession

from app.challenge.progress import complete_stage, has_fact, record_server_fact
from app.config import settings
from app.models import AuthenticationEvent, LoginAttempt, User


def verify_recon(db: DBSession, session_key: str) -> tuple[bool, dict]:
    """Awarded when the participant fetched /api/v1/info AND /api/v1/policy from
    the isolated target — the application records these hits server-side."""
    fact = has_fact(db, session_key, "fact_recon")
    if fact is None:
        return False, {"reason": "target interaction not yet observed"}
    return complete_stage(db, session_key, "01-recon", fact.payload), fact.payload


def verify_identity_discovery(db: DBSession, session_key: str) -> tuple[bool, dict]:
    fact = has_fact(db, session_key, "fact_identity_routes")
    if fact is None:
        return False, {"reason": "identity endpoints not enumerated"}
    payload = fact.payload or {}
    required = {"login", "register", "activation", "password_reset"}
    found = set(payload.get("routes_found", []))
    if not required.issubset(found):
        return False, {"reason": f"missing routes: {sorted(required - found)}"}
    return complete_stage(db, session_key, "02-identity-discovery", payload), payload


def verify_policy_analysis(db: DBSession, session_key: str) -> tuple[bool, dict]:
    """Participant must submit an analysis that correctly identifies the defective
    minimum length and absence of blocklist/contextual checks in the LIVE policy."""
    fact = has_fact(db, session_key, "fact_policy_analysis")
    if fact is None:
        return False, {"reason": "no policy analysis submitted"}
    p = fact.payload or {}
    from app.security.password_policy import get_policy
    live = get_policy().descriptor()
    ok = (
        p.get("identified_min_length") == live["min_length"]
        and p.get("blocklist_enabled") == live["blocklist_enabled"]
        and p.get("contextual_checks_enabled") == live["contextual_checks_enabled"]
        and p.get("assessment") == "insufficient"  # student conclusion vs NIST SP 800-63B
    )
    if not ok:
        return False, {"reason": "analysis does not match live server policy"}
    return complete_stage(db, session_key, "03-password-policy", p), p


def verify_weak_acceptance(db: DBSession, session_key: str) -> tuple[bool, dict]:
    """Requires a WEAK password (would fail patched policy) actually ACCEPTED by a
    legitimate account-management flow. The server re-evaluates the recorded
    candidate metadata against the patched ruleset to prove weakness objectively;
    plaintext candidates are never stored."""
    fact = has_fact(db, session_key, "fact_weak_acceptance")
    if fact is None:
        return False, {"reason": "no weak acceptance proof recorded"}
    p = fact.payload or {}
    if not p.get("accepted_by_legitimate_flow"):
        return False, {"reason": "acceptance not tied to a legitimate flow"}
    # objective weakness test: value fails the PATCHED policy
    from app.security import patched_policy
    probe = p.get("candidate_metadata", {})
    length_ok = probe.get("length", 99) < patched_policy.MIN_LENGTH
    known_weak = p.get("matches_lab_blocklist", False)
    if not (length_ok or known_weak):
        return False, {"reason": "accepted password was not demonstrably weak"}
    return complete_stage(db, session_key, "04-weak-password-validation", p), p


def verify_controlled_auth(db: DBSession, session_key: str) -> tuple[bool, dict]:
    """Server-side proof: within THIS lab's bounded budget, a successful login
    occurred for the designated synthetic training account with attempts<=budget
    and no lockout triggered on that account by the participant."""
    fact = has_fact(db, session_key, "fact_controlled_auth")
    if fact is None:
        return False, {"reason": "controlled authentication not completed"}
    p = fact.payload or {}
    username = p.get("account")
    budget = int(p.get("attempt_budget", 12))
    used = int(p.get("attempts_used", 99))
    if used > budget:
        return False, {"reason": "attempt budget exceeded"}
    user = db.query(User).filter(User.username == username, User.is_training_account.is_(True)).first()
    if user is None:
        return False, {"reason": "not a synthetic training account"}
    success = (
        db.query(LoginAttempt)
        .filter(LoginAttempt.identifier == username, LoginAttempt.success.is_(True))
        .first()
    )
    if success is None:
        return False, {"reason": "no successful authentication recorded server-side"}
    return complete_stage(db, session_key, "05-controlled-authentication", p), p


def verify_impact(db: DBSession, session_key: str) -> tuple[bool, dict]:
    fact = has_fact(db, session_key, "fact_impact")
    if fact is None:
        return False, {"reason": "impact not demonstrated"}
    p = fact.payload or {}
    if not p.get("accessed_training_data_as_synthetic_user"):
        return False, {"reason": "training data not accessed via the compromised identity"}
    return complete_stage(db, session_key, "06-impact", p), p


def verify_detection(db: DBSession, session_key: str) -> tuple[bool, dict]:
    """Participant reviewed SOC alerts correlated to their own attack events."""
    fact = has_fact(db, session_key, "fact_detection_review")
    if fact is None:
        return False, {"reason": "SOC review not recorded"}
    p = fact.payload or {}
    matched_alerts = p.get("matched_alert_ids", [])
    if not matched_alerts:
        return False, {"reason": "no alerts correlated to the incident"}
    return complete_stage(db, session_key, "07-detection", p), p


def verify_forensics(db: DBSession, session_key: str) -> tuple[bool, dict]:
    fact = has_fact(db, session_key, "fact_forensic_export")
    if fact is None:
        return False, {"reason": "forensic export not generated"}
    p = fact.payload or {}
    if not p.get("manifest_sha256"):
        return False, {"reason": "export lacks integrity manifest"}
    return complete_stage(db, session_key, "08-forensics", p), p


def verify_remediation(db: DBSession, session_key: str) -> tuple[bool, dict]:
    """Remediation = environment switched to patched mode (admin action recorded)
    OR remediation plan artifact registered through the admin workflow."""
    fact = has_fact(db, session_key, "fact_remediation")
    if fact is None:
        return False, {"reason": "remediation not registered"}
    p = fact.payload or {}
    return complete_stage(db, session_key, "09-remediation", p), p


def verify_patch_verification(db: DBSession, session_key: str) -> tuple[bool, dict]:
    """Requires the SAME weak candidate to be REJECTED by the live patched policy,
    plus regression evidence that a strong passphrase is accepted and login works."""
    fact = has_fact(db, session_key, "fact_patch_verify")
    if fact is None:
        return False, {"reason": "patch verification not recorded"}
    p = fact.payload or {}
    if settings.is_vulnerable():
        return False, {"reason": "environment still in vulnerable mode — run patched compose"}
    if not (p.get("weak_rejected") and p.get("strong_accepted") and p.get("legit_login_ok")):
        return False, {"reason": "verification matrix incomplete"}
    return complete_stage(db, session_key, "10-verification", p), p


VERIFIERS = {
    "01-recon": verify_recon,
    "02-identity-discovery": verify_identity_discovery,
    "03-password-policy": verify_policy_analysis,
    "04-weak-password-validation": verify_weak_acceptance,
    "05-controlled-authentication": verify_controlled_auth,
    "06-impact": verify_impact,
    "07-detection": verify_detection,
    "08-forensics": verify_forensics,
    "09-remediation": verify_remediation,
    "10-verification": verify_patch_verification,
}


def run_verifier(db: DBSession, session_key: str, stage_key: str) -> tuple[bool, dict]:
    fn = VERIFIERS.get(stage_key)
    if fn is None:
        return False, {"reason": "unknown stage"}
    return fn(db, session_key)
