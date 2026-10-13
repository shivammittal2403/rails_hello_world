"""Argon2id password hashing.

IMPORTANT: Password storage remains secure in BOTH vulnerable and patched modes.
CWE-521 is about weak *requirements* (acceptance), never about plaintext storage.
Plaintext passwords are never written to logs, events, or responses.
"""
from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError, needs_rehash

# OWASP Password Storage Cheat Sheet parameters (Argon2id)
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,   # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    """Return an Argon2id PHC string for the given plaintext password."""
    if isinstance(password, bytes):  # defensive; we always pass str
        password = password.decode("utf-8", errors="strict")
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


def needs_upgrade(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except Exception:
        return False
