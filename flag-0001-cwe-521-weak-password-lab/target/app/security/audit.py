"""Structured security event emission (JSONL to disk + DB + Redis pub/sub).

NEVER includes plaintext passwords or session tokens. Event schema follows the
lab specification:

{timestamp, event_id, service, event_type, user_id, policy_mode, severity,
 correlation_id, outcome, details}
"""
from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone

from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import AuthenticationEvent

_EVENT_LOG_PATH = os.environ.get("EVENT_LOG_PATH", "/data/events/security_events.jsonl")


def new_correlation_id() -> str:
    return "corr-" + secrets.token_hex(8)


def _emit_log_line(payload: dict) -> None:
    """Append JSONL; degrade gracefully if shared volume not mounted."""
    try:
        os.makedirs(os.path.dirname(_EVENT_LOG_PATH), exist_ok=True)
        with open(_EVENT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, separators=(",", ":")) + "\n")
    except OSError:
        pass  # file sink optional; DB sink still authoritative


def _publish_redis(payload: dict) -> None:
    if not settings.REDIS_URL:
        return
    try:
        import redis
        r = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
        r.publish("nexadesk:events", json.dumps(payload))
    except Exception:
        pass  # observer also polls the DB — Redis is best-effort fast path


def emit_event(
    db: DBSession | None,
    event_type: str,
    *,
    username_ref: str | None = None,
    user_id: int | None = None,
    severity: str = "info",
    outcome: str | None = None,
    details: dict | None = None,
    correlation_id: str | None = None,
) -> dict:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_id": "evt-" + secrets.token_hex(10),
        "service": "identity-service",
        "event_type": event_type,
        "user_id": user_id,
        "policy_mode": settings.PASSWORD_POLICY_MODE,
        "severity": severity,
        "correlation_id": correlation_id or new_correlation_id(),
        "outcome": outcome,
        "details": details or {},
    }
    # sanitize defensively — no secret material may ever reach a log
    for forbidden in ("password", "token", "secret", "hash"):
        if any(forbidden in k.lower() for k in payload["details"]):
            payload["details"] = {
                k: "<redacted>" for k in payload["details"]
            }
            break
    _emit_log_line(payload)
    _publish_redis(payload)
    if db is not None:
        rec = AuthenticationEvent(
            event_id=payload["event_id"],
            event_type=event_type,
            user_id=user_id,
            username_ref=username_ref,
            severity=severity,
            outcome=outcome,
            policy_mode=payload["policy_mode"],
            details=payload["details"],
            correlation_id=payload["correlation_id"],
        )
        db.add(rec)
        db.commit()
    return payload
