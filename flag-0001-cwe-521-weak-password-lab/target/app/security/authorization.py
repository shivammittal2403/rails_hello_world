"""Role-based authorization dependencies (server-side; CWE-602 avoided)."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.models import User
from app.security.sessions import get_current_user

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "Standard Employee": {"tickets.read", "tickets.create", "docs.internal.read", "profile.self.write"},
    "Finance Staff": {"tickets.read", "tickets.create", "docs.internal.read", "profile.self.write"},
    "Human Resources": {"tickets.read", "tickets.create", "docs.internal.read", "docs.restricted.read",
                        "profile.self.write", "directory.read"},
    "Security Analyst": {"tickets.read", "docs.internal.read", "docs.restricted.read",
                         "events.read", "alerts.read", "profile.self.write", "directory.read"},
    "IT Support": {"tickets.read", "tickets.create", "tickets.triage", "docs.internal.read",
                   "profile.self.write", "directory.read"},
    "External Auditor": {"docs.training_only.read", "events.read"},
    "Administrator": {"*"},
}


def user_permissions(user: User) -> set[str]:
    perms: set[str] = set()
    for role in user.roles:
        perms |= ROLE_PERMISSIONS.get(role.name, set())
    return perms


def require_login(request: Request, db: DBSession = Depends(get_db)) -> User:
    user = get_current_user(db, request)
    if user is None:
        # API clients get 401; browsers are redirected by the page routes themselves.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Authentication required")
    return user


def require_permission(permission: str):
    def dep(user: User = Depends(require_login)) -> User:
        perms = user_permissions(user)
        if "*" in perms or permission in perms:
            return user
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Missing permission: {permission}")
    return dep


require_admin = require_permission("admin.manage")  # only Administrator has '*'
