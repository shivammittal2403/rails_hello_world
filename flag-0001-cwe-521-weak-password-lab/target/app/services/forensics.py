"""Forensic timeline reconstruction — built from stored events, NOT a hardcoded
narrative. Produces timeline.json / timeline.csv / timeline.md + evidence-manifest
with SHA-256 integrity hashes and redacted evidence records."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from datetime import datetime, timezone

from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import AuthenticationEvent, ChallengeEvidence, SecurityAlert

# Map event types to the lab's canonical T0..T10 investigation phases
PHASE_MAP = {
    "recon_observed": ("T0", "Initial application discovery"),
    "identity_route_probe": ("T1", "Identity route inspection"),
    "password_policy_evaluation": ("T2", "Password policy analysis"),
    "password_policy_violation": ("T2", "Password policy analysis"),
    "account_activated": ("T3", "Weak password accepted in legitimate flow"),
    "authentication_failure": ("T4", "Account authentication attempt"),
    "authentication_success": ("T5", "Successful synthetic account authentication"),
    "document_access_denied": ("T6", "Access control enforcement"),
    "admin_action": ("T6", "Administrative activity"),
    "policy_change_attempt": ("T9", "Policy remediation attempt"),
    "identity_hardening": ("T9", "Policy remediation"),
    "evidence_collected": ("T8", "Evidence collection"),
}


def _phase_for(ev: AuthenticationEvent) -> tuple[str, str]:
    if ev.event_type == "authentication_success" and ev.username_ref and \
            (ev.details or {}).get("training_account"):
        return ("T5", "Successful synthetic account authentication")
    if ev.event_type == "document_access_denied":
        return ("T6", "Access control enforcement")
    return PHASE_MAP.get(ev.event_type, ("TX", "Auxiliary activity"))


def build_timeline(db: DBSession, session_key: str | None = None) -> list[dict]:
    rows = db.query(AuthenticationEvent).order_by(AuthenticationEvent.id.asc()).all()
    out = []
    for ev in rows:
        phase, label = _phase_for(ev)
        out.append({
            "phase": phase,
            "phase_label": label,
            "timestamp": ev.created_at.isoformat() if ev.created_at else None,
            "event_id": ev.event_id,
            "source": ev.service,
            "event_type": ev.event_type,
            "username_ref": ev.username_ref,
            "severity": ev.severity,
            "outcome": ev.outcome,
            "policy_mode": ev.policy_mode,
            "correlation_id": ev.correlation_id,
            "details_redacted": _redact(ev.details or {}),
        })
    if session_key:
        for ce in db.query(ChallengeEvidence).filter(
                ChallengeEvidence.session_key == session_key).all():
            out.append({
                "phase": f"S:{ce.stage}",
                "phase_label": "Challenge stage fact recorded",
                "timestamp": ce.created_at.isoformat() if ce.created_at else None,
                "event_id": f"cev-{ce.id}",
                "source": "challenge-service",
                "event_type": ce.kind,
                "username_ref": None,
                "severity": "info",
                "outcome": "recorded",
                "policy_mode": settings.PASSWORD_POLICY_MODE,
                "correlation_id": None,
                "details_redacted": {"sha256": ce.sha256},
            })
    out.sort(key=lambda r: (r["timestamp"] or ""))
    return out


def _redact(details: dict) -> dict:
    """Defense-in-depth: drop anything secret-shaped even though emit_event already
    sanitizes; plaintext passwords/tokens must never appear in exports."""
    safe = {}
    for k, v in details.items():
        lk = k.lower()
        if any(b in lk for b in ("password", "token", "secret", "hash")):
            safe[k] = "<redacted>"
        else:
            safe[k] = v
    return safe


def export_timeline(db: DBSession, session_key: str) -> dict:
    timeline = build_timeline(db, session_key)
    alerts = db.query(SecurityAlert).order_by(SecurityAlert.id.asc()).all()
    evidence_rows = db.query(ChallengeEvidence).filter(
        ChallengeEvidence.session_key == session_key).all()

    out_dir = os.path.join(settings.EVIDENCE_DIR, "forensics")
    os.makedirs(out_dir, exist_ok=True)

    files = {}

    def write(name: str, content: str) -> str:
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        files[name] = hashlib.sha256(content.encode()).hexdigest()
        return path

    paths = {}
    tj = json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(),
                     "lab_session": session_key,
                     "note": "Reconstructed from stored events; synthetic data.",
                     "events": timeline}, indent=2)
    paths["timeline.json"] = write("timeline.json", tj)

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["phase", "timestamp", "event_id", "source", "event_type",
                "username_ref", "severity", "outcome", "policy_mode", "correlation_id"])
    for r in timeline:
        w.writerow([r["phase"], r["timestamp"], r["event_id"], r["source"],
                    r["event_type"], r["username_ref"], r["severity"], r["outcome"],
                    r["policy_mode"], r["correlation_id"]])
    paths["timeline.csv"] = write("timeline.csv", buf.getvalue())

    md = ["# FLAG-0001 Forensic Timeline (synthetic)", "",
          "| Phase | Timestamp | Event | Actor | Outcome |", "|---|---|---|---|---|"]
    for r in timeline:
        md.append(f"| {r['phase']} | {r['timestamp']} | {r['event_type']} | "
                  f"{r['username_ref'] or '-'} | {r['outcome'] or '-'} |")
    md += ["", "## Correlated alerts", ""]
    for a in alerts:
        md.append(f"- **{a.alert_id}** [{a.severity}] {a.title} "
                  f"(rules={a.rule_id}; events={len(a.event_ids or [])})")
    paths["timeline.md"] = write("timeline.md", "\n".join(md) + "\n")

    manifest = {
        "lab_session": session_key,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "sha256",
        "files": files,
        "evidence_records": [
            {"id": e.id, "stage": e.stage, "kind": e.kind, "sha256": e.sha256}
            for e in evidence_rows],
        "alert_ids": [a.alert_id for a in alerts],
    }
    mj = json.dumps(manifest, indent=2)
    paths["evidence-manifest.json"] = write("evidence-manifest.json", mj)

    return {
        "ok": True,
        "event_count": len(timeline),
        "manifest_sha256": hashlib.sha256(mj.encode()).hexdigest(),
        "paths": paths,
        "dir": out_dir,
    }
