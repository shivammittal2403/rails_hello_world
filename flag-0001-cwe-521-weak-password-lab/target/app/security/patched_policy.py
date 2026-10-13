"""PATCHED password policy — NIST SP 800-63B Revision 4 §5.1.1.2 aligned.

Requirements implemented SERVER-SIDE (never only in JavaScript):
  * minimum 15 characters for single-factor authentication
    (Rev4 §5.1.1.2: min 15; if the verifier supports longer, up to >=64 allowed)
  * maximum length 128 (>= 64 required by NIST; no truncation)
  * spaces and printable Unicode accepted; no arbitrary composition rules
  * local synthetic blocklist of commonly used / expected / compromised values
  * contextual rejection: username, email local-part, names, org, department,
    and company-derived or predictable sequence/repetition variants
  * paste/autofill friendly (the form does not disable them)
  * no forced periodic rotation (only on evidence of compromise)
  * meaningful, specific rejection feedback

Multi-factor note: NIST Rev4 allows min 8 chars when a SPA uses an out-of-band
 authenticator; this lab's portal is single-factor, so 15 applies. See docs.
"""
from __future__ import annotations

import re
import unicodedata

MIN_LENGTH = 15
MAX_LENGTH = 128

# Synthetic blocklist — laboratory values only, NOT derived from real breach data.
_BLOCKLIST_RAW = """
password passw0rd p@ssword password1 welcome1 welcome2024 qwerty qwerty123
abc123 abcd1234 123456 1234567 12345678 123456789 1234567890 111111111111111
00000000 letmein secret changeme temp123 test123 admin admin123 administrator
iloveyou monkey dragon sunshine princess football baseball superman batman
trustno1 whatever starwars passw0rd123 winter2024 summer2024 spring2024
fall2024 nexaline nexaline2024 nexaline123 company1 companycompany
correcthorsetesestapletes
"""

_BLOCKLIST = {w for w in _BLOCKLIST_RAW.split() if w}

_SEQ_CHARS = [
    "0123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


def descriptor() -> dict:
    return {
        "mode": "patched",
        "policy_name": "Nexaline STD-SEC-004 rev. 2026 (NIST SP 800-63B R4)",
        "min_length": MIN_LENGTH,
        "max_length": MAX_LENGTH,
        "rules": [
            f"Minimum length: {MIN_LENGTH} characters (single-factor per NIST SP 800-63B R4)",
            f"Maximum length: {MAX_LENGTH} characters (no truncation)",
            "Spaces and Unicode accepted; paste and autofill allowed",
            "Commonly used, expected, and compromised passwords rejected (blocklist)",
            "Context-derived passwords rejected (username, name, company, department)",
            "No composition rules; no forced periodic rotation",
        ],
        "blocklist_enabled": True,
        "contextual_checks_enabled": True,
    }


def _normalize(s: str) -> str:
    s = unicodedata.normalize("NFKC", s or "")
    return s.lower().strip()


def _common_substitutions(variant: str) -> set[str]:
    table = {"a": "@4", "e": "3", "i": "1!l", "o": "0", "s": "5$", "t": "7+"}
    outs = {variant}
    for ch, subs in table.items():
        new = set()
        for v in outs:
            if ch in v:
                for sub in subs:
                    new.add(v.replace(ch, sub))
        outs |= new
    return outs


def _contains_sequence(pw: str, min_len: int = 5) -> bool:
    low = pw.lower()
    for i in range(len(low) - min_len + 1):
        chunk = low[i:i + min_len]
        for seq in _SEQ_CHARS:
            if chunk in seq:
                return True
            if chunk in seq[::-1]:
                return True
    # repeated single char run
    if re.search(r"(.)\1{%d,}" % (min_len - 1), pw):
        return True
    return False


def evaluate(password: str, context: dict):
    from app.security.password_policy import PolicyResult

    reasons: list[str] = []
    warnings: list[str] = []

    if not password:
        return PolicyResult(False, ["Password is required."], warnings)

    # No truncation: long passphrases are supported up to MAX_LENGTH.
    if len(password) < MIN_LENGTH:
        reasons.append(
            f"Too short: NIST SP 800-63B R4 requires at least {MIN_LENGTH} "
            f"characters for single-factor sign-in. Use a memorable passphrase."
        )
    if len(password) > MAX_LENGTH:
        reasons.append(f"Too long: maximum supported length is {MAX_LENGTH} characters.")

    norm = _normalize(password)
    stripped = re.sub(r"[^a-z0-9]", "", norm)

    # Blocklist (direct + light substitution variants)
    if norm in _BLOCKLIST or stripped in _BLOCKLIST:
        reasons.append("This password appears on our commonly-used/compromised password blocklist.")
    else:
        for token in _common_substitutions(norm):
            if token in _BLOCKLIST:
                reasons.append("This password is a known variant of a commonly-used password.")
                break

    # Contextual checks
    ctx_tokens = set()
    for key in ("username", "email", "given_name", "family_name", "org_name",
                "department", "company"):
        val = _normalize(str(context.get(key, "")))
        if not val:
            continue
        parts = re.split(r"[^a-z0-9]+", val)
        for p in parts:
            if len(p) >= 3:
                ctx_tokens.add(p)
        if "@" in val:
            ctx_tokens.add(val.split("@")[0])
    # also check against any username-like value embedded with digits suffix
    for tok in sorted(ctx_tokens, key=len, reverse=True):
        if len(tok) >= 4 and tok in stripped:
            reasons.append(
                "Passwords must not contain parts of your username, name, or organization identifiers."
            )
            break

    # Predictable sequences / repetition (only meaningful once basic length passes)
    if not reasons and _contains_sequence(password):
        reasons.append("Predictable character sequences or repeated runs are not allowed.")

    if not reasons:
        warnings.append(
            "Consider a unique passphrase managed in your enterprise password manager."
        )

    return PolicyResult(len(reasons) == 0, reasons, warnings)
