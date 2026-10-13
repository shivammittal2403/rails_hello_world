"""FLAG-0001 stage catalog — single source of truth for the scoring system."""
from __future__ import annotations

STAGES: list[dict] = [
    {"stage": "01-recon",                 "title": "Reconnaissance and application discovery",   "points": 100},
    {"stage": "02-identity-discovery",    "title": "Identity endpoint discovery",                "points": 100},
    {"stage": "03-password-policy",       "title": "Password policy inspection",                 "points": 200},
    {"stage": "04-weak-password-validation", "title": "Weak password acceptance proof",          "points": 250},
    {"stage": "05-controlled-authentication", "title": "Controlled authentication",              "points": 200},
    {"stage": "06-impact",                "title": "Synthetic account access and impact",        "points": 150},
    {"stage": "07-detection",             "title": "SOC event detection",                        "points": 150},
    {"stage": "08-forensics",             "title": "Forensic evidence reconstruction",           "points": 100},
    {"stage": "09-remediation",           "title": "Secure password policy implementation",      "points": 150},
    {"stage": "10-verification",          "title": "Patch and regression verification",          "points": 100},
]

TOTAL_POINTS = sum(s["points"] for s in STAGES)  # 1500

BONUS_MAX = 300  # red-team report +100, original detection rule +100, remediation report +100


def stage_by_key(key: str) -> dict | None:
    return next((s for s in STAGES if s["stage"] == key), None)
