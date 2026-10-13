"""NexaDesk Enterprise Identity Portal - configuration.

Modes:
  PASSWORD_POLICY_MODE=vulnerable  -> CWE-521 defective server-side policy (default lab target)
  PASSWORD_POLICY_MODE=patched     -> NIST SP 800-63B Rev4-aligned policy (docker-compose.patched.yml)
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


@dataclass
class Settings:
    APP_NAME: str = "NexaDesk Enterprise Identity Portal"
    APP_VERSION: str = "1.4.2"
    ORG_NAME: str = "Nexaline Systems (synthetic training org)"

    DATABASE_URL: str = field(
        default_factory=lambda: os.environ.get(
            "DATABASE_URL", "sqlite:///./nexadesk.db"
        )
    )
    REDIS_URL: str = field(default_factory=lambda: os.environ.get("REDIS_URL", ""))

    SECRET_KEY: str = field(
        default_factory=lambda: os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    )
    FLAG_PEPPER: str = field(
        default_factory=lambda: os.environ.get("FLAG_PEPPER") or secrets.token_hex(32)
    )

    PASSWORD_POLICY_MODE: str = field(
        default_factory=lambda: os.environ.get("PASSWORD_POLICY_MODE", "vulnerable")
    )

    SESSION_COOKIE_NAME: str = "nexadesk_session"
    SESSION_MAX_AGE_SECONDS: int = 60 * 60 * 8  # 8h workday session

    # Rate limiting / lockout (CWE-307 controls are ENABLED even in vulnerable mode;
    # the primary weakness is exclusively CWE-521 weak password requirements).
    LOGIN_MAX_ATTEMPTS: int = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "8"))
    LOGIN_WINDOW_SECONDS: int = int(os.environ.get("LOGIN_WINDOW_SECONDS", "300"))
    LOCKOUT_SECONDS: int = int(os.environ.get("LOCKOUT_SECONDS", "300"))

    LAB_CHALLENGE_ID: str = "FLAG-0001"
    LAB_CWE: str = "CWE-521"

    EVIDENCE_DIR: str = field(
        default_factory=lambda: os.environ.get("EVIDENCE_DIR", "./evidence")
    )

    def is_vulnerable(self) -> bool:
        return self.PASSWORD_POLICY_MODE.lower().strip() == "vulnerable"


settings = Settings()
