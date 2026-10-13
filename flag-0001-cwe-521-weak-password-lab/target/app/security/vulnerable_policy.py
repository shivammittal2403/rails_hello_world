"""VULNERABLE password policy — the intentional CWE-521 defect.

Legacy 2000s-era internal IT standard ("Nexaline STD-SEC-004 rev. 2016"):
  * minimum length 4 characters
  * requires only letters and digits somewhere in the string
  * NO blocklist / breached-password checking
  * NO contextual (username/company/department) checking
  * repetition and sequences permitted
  * composition rules + forced 90-day rotation (obsolete practice, kept here
    because it looks like "security" while providing almost no real strength)

This file's runtime enforcement matches its advertised configuration exactly;
the defect is inadequate REQUIREMENTS, not hidden behavior.
"""
from __future__ import annotations

MIN_LENGTH = 4
MAX_LENGTH = 32          # legacy form truncation risk documented in PATCH_COMPARISON.md

# Legacy composition rule (deliberately weak): must contain >=1 letter AND >=1 digit.
_LETTERS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_DIGITS = set("0123456789")


def descriptor() -> dict:
    return {
        "mode": "vulnerable",
        "policy_name": "Nexaline STD-SEC-004 (legacy)",
        "min_length": MIN_LENGTH,
        "max_length": MAX_LENGTH,
        "rules": [
            "Minimum length: 4 characters",
            "Must contain at least one letter and one digit",
            "Password must be changed every 90 days",
        ],
        "blocklist_enabled": False,
        "contextual_checks_enabled": False,
        "cwe_note": "Requirements are insufficient per NIST SP 800-63B / OWASP ASVS V2.1 (CWE-521).",
    }


def evaluate(password: str, context: dict) -> "object":
    from app.security.password_policy import PolicyResult

    reasons: list[str] = []
    warnings: list[str] = []

    if password is None or len(password) == 0:
        reasons.append("Password is required.")
        return PolicyResult(False, reasons, warnings)

    if len(password) < MIN_LENGTH:
        reasons.append(f"Password must be at least {MIN_LENGTH} characters long.")

    has_letter = any(c in _LETTERS for c in password)
    has_digit = any(c in _DIGITS for c in password)
    if not (has_letter and has_digit):
        reasons.append("Password must contain at least one letter and one number.")

    # NOTE: No blocklist check. No sequence/repetition check. No contextual check.
    # 'password', '123456', 'nexaline2024', '<username>1' are all ACCEPTED here.
    return PolicyResult(len(reasons) == 0, reasons, warnings)
