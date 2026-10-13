"""Password policy engine.

Two genuinely different SERVER-SIDE policies are selectable at runtime via
PASSWORD_POLICY_MODE. The active policy object is returned by get_policy().

The vulnerable policy is the intentional CWE-521 defect of this cyber range.
The patched policy follows NIST SP 800-63B Rev4 §5.1.1.2 single-factor guidance.
"""
from __future__ import annotations

from app.config import settings
from app.security import vulnerable_policy, patched_policy


class PolicyResult:
    def __init__(self, accepted: bool, reasons: list[str], warnings: list[str] | None = None):
        self.accepted = accepted
        self.reasons = reasons            # rejection reasons (empty when accepted)
        self.warnings = warnings or []   # non-blocking advisories

    def to_dict(self) -> dict:
        return {
            "accepted": self.accepted,
            "reasons": self.reasons,
            "warnings": self.warnings,
        }


def get_policy():
    """Return the ACTIVE server-side policy module (vulnerable or patched)."""
    if settings.is_vulnerable():
        return vulnerable_policy
    return patched_policy


def evaluate_password(password: str, context: dict | None = None) -> PolicyResult:
    """Evaluate a candidate password against the ACTIVE server-side policy.

    `context` carries identity attributes for contextual weakness checks:
    username, email, given_name, family_name, org_name, department.
    """
    policy = get_policy()
    return policy.evaluate(password, context or {})


def public_policy_descriptor() -> dict:
    """Non-secret description of the current policy shown in the UI/API.

    Deliberately does NOT reveal any valid credential. In vulnerable mode it
    truthfully advertises the defective minimum (this IS the realistic flaw:
    the organization believes its requirements are adequate).
    """
    policy = get_policy()
    return policy.descriptor()
