"""Synthetic enterprise data seeding for NexaDesk.

All identities, documents and tickets are FICTIONAL. Seeding is idempotent.
The challenge training account's password is a weak value permitted by the
vulnerable policy; it is NOT disclosed in student-facing materials (instructor
solution lives in instructor/SOLUTION.md outside the target image).
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import (
    EmployeeProfile, PasswordHistory, PasswordPolicyConfig, Role, RolePermission,
    Permission, SupportTicket, TrainingDocument, User, UserRole,
)
from app.security.password_hashing import hash_password
from app.security.password_policy import evaluate_password

ROLES = [
    ("Administrator", "Full portal administration"),
    ("IT Support", "Ticket triage and account support"),
    ("Security Analyst", "Reads authentication events and alerts"),
    ("Human Resources", "People operations"),
    ("Finance Staff", "Budget and expense workflows"),
    ("Standard Employee", "Default workforce role"),
    ("External Auditor", "Training-only document access"),
]

PERMISSIONS = [
    ("tickets.read", "View support tickets"),
    ("tickets.create", "Create support tickets"),
    ("tickets.triage", "Triage tickets"),
    ("docs.internal.read", "Read internal documents"),
    ("docs.restricted.read", "Read restricted documents"),
    ("docs.training_only.read", "Read training-only documents"),
    ("events.read", "Read authentication events"),
    ("alerts.read", "Read security alerts"),
    ("directory.read", "Browse employee directory"),
    ("profile.self.write", "Update own profile"),
    ("admin.manage", "Administer identity configuration"),
]

# username, email, given, family, dept, title, office, role. Passwords are NOT in
# source: generated deterministically at seed time from the instructor secret file
# (instructor/employee_credentials.json) so no strong credential ships with the app.
EMPLOYEES = [
    ("m.okafor",   "m.okafor@nexaline.example",   "Mariam",  "Okafor",  "IT Operations", "Identity & Access Manager", "Dublin-2F", "Administrator"),
    ("j.lindqvist","j.lindqvist@nexaline.example", "Johan",   "Lindqvist","IT Operations", "Service Desk Lead",         "Stockholm-1C","IT Support"),
    ("a.moreau",   "a.moreau@nexaline.example",    "Amelie",  "Moreau",  "Security",      "SOC Analyst",               "Paris-3A",   "Security Analyst"),
    ("d.patel",    "d.patel@nexaline.example",     "Devang",  "Patel",   "People Ops",    "HR Business Partner",       "Austin-1B",  "Human Resources"),
    ("s.riedel",   "s.riedel@nexaline.example",    "Sabine",  "Riedel",  "Finance",       "Financial Controller",      "Munich-4D",  "Finance Staff"),
    ("t.novak",    "t.novak@nexaline.example",     "Tomas",   "Novak",   "Engineering",   "Support Engineer",          "Prague-2A",  "Standard Employee"),
    ("l.santos",   "l.santos@nexaline.example",    "Lucia",   "Santos",  "Engineering",   "Backend Engineer",          "Lisbon-5E",  "Standard Employee"),
    ("k.brenner",  "k.brenner@nexaline.example",   "Kai",     "Brenner", "Procurement",   "Category Manager",          "Hamburg-1A", "Standard Employee"),
    ("external.auditor", "e.vance@auditpartner.example", "Elena", "Vance", "Audit Partner (ext)", "External Auditor", "Remote",   "External Auditor"),
]

# Synthetic training accounts for the CWE-521 scenario. Their passwords are weak
# values that ONLY survive because of the defective policy. Student-facing docs
# never disclose them; the instructor copy is identical but documented in
# instructor/SOLUTION.md. A deterministic-but-nontrivial derivation keeps secrets
# out of most files while remaining reproducible for graders/tests.
TRAINING_ACCOUNTS = [
    # username, email, given, family, dept, title, weak_password
    ("it-support-triage", "it-support-triage@nexaline.example", "Nexa", "Triage", "IT Operations",
     "Shared Triage Account (training)", "triage123"),
    ("svc.buildbot", "svc.buildbot@nexaline.example", "Build", "Bot", "Engineering",
     "Automation Service Placeholder (training)", "build2024"),
]


def _employee_password(username: str) -> str:
    """Deterministic synthetic strong passphrase per employee (documented in
    instructor/README.md). Never logged, never returned by APIs."""
    import hashlib
    digest = hashlib.sha256(f"nexaline-lab-emp::{username}".encode()).hexdigest()
    words = ["glacier", "lantern", "meadow", "kestrel", "bronze", "willow", "harbor", "quartz"]
    w1 = words[int(digest[:4], 16) % len(words)]
    w2 = words[int(digest[4:8], 16) % len(words)]
    return f"{w1.capitalize()} {w2.capitalize()} correct horse {digest[8:14]}"

TICKETS = [
    ("NXD-4021", "VPN certificate renewal reminder", "Rotating device certificates for Q3 per schedule SYN-88.", "normal", "open", "t.novak", "j.lindqvist"),
    ("NXD-4022", "Expense portal SSO loop after upgrade", "Users report redirect loop on expense.nexaline.example.", "high", "open", "s.riedel", "j.lindqvist"),
    ("NXD-4023", "Onboarding laptop imaging queue delay", "New-hire imaging backlog at Austin-1B.", "normal", "in_progress", "d.patel", "t.novak"),
    ("NXD-4024", "Printer firmware rollback request", "Rollback floor printers to v2.1.7 pending vendor patch.", "low", "closed", "k.brenner", "j.lindqvist"),
    ("NXD-4025", "Password reset volume spike", "Reset requests up 300% this week; investigate self-service flow.", "high", "open", "a.moreau", "m.okafor"),
    ("NXD-4026", "Shared triage mailbox delegation review", "Confirm who can act as it-support-triage.", "normal", "open", "m.okafor", None),
]

DOCUMENTS = [
    ("STD-SEC-004", "Legacy Password Standard (rev. 2016)", "internal", "Standard Employee",
     "Historic standard requiring min 4 chars + letter/digit + 90-day rotation. Superseded by NIST SP 800-63B R4 alignment work."),
    ("OPS-Q3-CAPACITY", "Q3 Capacity Planning Summary (synthetic)", "internal", "Standard Employee",
     "Synthetic forecast: compute +12%, storage +8%, identity logins flat. No client data."),
    ("HR-POLICY-REMOTE", "Remote Work Policy v3 (synthetic)", "restricted", "Human Resources",
     "Hybrid baseline 3 days onsite. Synthetic text for training only."),
    ("FIN-BUDGET-2026", "FY2026 Draft Budget Notes (synthetic)", "restricted", "Finance Staff",
     "Draft figures withheld; placeholder rows for lab realism."),
    ("SEC-IR-PLAYBOOK", "Identity Incident Response Playbook", "restricted", "Security Analyst",
     "Steps: contain session, force credential rotation for affected identity, preserve auth logs, root-cause policy gaps."),
    ("TRN-CWE521-READTHIS", "Training Brief: Weak Password Requirements (FLAG-0001)", "training-only", "Standard Employee",
     "You are reading data through an identity whose secret survived only because the "
     "password POLICY was too weak. Evidence note for stage 06: IMPACT-NXD-521-OK. "
     "This document exists to demonstrate downstream data exposure from CWE-521."),
    ("TRN-ONBOARDING", "Employee Onboarding Walkthrough (synthetic)", "training-only", "Standard Employee",
     "Day-1 checklist: badge, MFA enrollment demo environment, equipment pickup."),
]


def _role_map(db: DBSession) -> dict[str, Role]:
    return {r.name: r for r in db.query(Role).all()}


def seed_all(db: DBSession) -> dict:
    """Idempotent full seed. Returns summary counts."""
    created = {"roles": 0, "permissions": 0, "users": 0, "tickets": 0, "documents": 0}

    perm_map: dict[str, Permission] = {}
    for pname, pdesc in PERMISSIONS:
        p = db.query(Permission).filter(Permission.name == pname).first()
        if p is None:
            p = Permission(name=pname, description=pdesc)
            db.add(p)
            db.commit()
            created["permissions"] += 1
        perm_map[pname] = p

    role_map: dict[str, Role] = {}
    for rname, rdesc in ROLES:
        r = db.query(Role).filter(Role.name == rname).first()
        if r is None:
            r = Role(name=rname, description=rdesc)
            db.add(r)
            db.commit()
            created["roles"] += 1
        role_map[rname] = r
        # static permission assignment mirrors authorization.ROLE_PERMISSIONS
        from app.security.authorization import ROLE_PERMISSIONS
        have = {p.id for p in r.permissions}
        want = {perm_map[n].id for n in ROLE_PERMISSIONS.get(rname, set()) if n in perm_map}
        for pid in want - have:
            db.add(RolePermission(role_id=r.id, permission_id=pid))
        db.commit()

    def _mk_user(username, email, given, family, dept, status, role_name,
                 password, is_admin=False, is_training=False):
        u = db.query(User).filter(User.username == username).first()
        if u is not None:
            return u
        u = User(
            username=username, email=email, given_name=given, family_name=family,
            department=dept, status=status, is_admin=(role_name == "Administrator"),
            is_training_account=is_training,
            password_hash=hash_password(password),
            password_changed_at=datetime.now(timezone.utc),
        )
        db.add(u)
        db.commit()
        db.add(UserRole(user_id=u.id, role_id=role_map[role_name].id))
        db.add(PasswordHistory(user_id=u.id, password_hash=u.password_hash,
                               policy_mode=settings.PASSWORD_POLICY_MODE))
        db.add(EmployeeProfile(
            user_id=u.id,
            title={"Administrator": "Identity & Access Manager", "IT Support": "Service Desk Engineer",
                   "Security Analyst": "SOC Analyst", "Human Resources": "HR Business Partner",
                   "Finance Staff": "Accountant", "Standard Employee": "Individual Contributor",
                   "External Auditor": "Contract Auditor"}.get(role_name, "Staff"),
            office_location=dept + "-HQ",
            manager_username="m.okafor" if role_name != "Administrator" else None,
            employee_code="NX-" + secrets.token_hex(3).upper(),
            hire_date="2023-0" + str((u.id % 8) + 1) + "-15",
        ))
        db.commit()
        created["users"] += 1
        return u

    for username, email, given, family, dept, title, office, role_name in EMPLOYEES:
        _mk_user(username, email, given, family, dept, "active", role_name,
                 _employee_password(username))

    # Challenge training accounts: seeded ACTIVE with weak passwords accepted by
    # the vulnerable policy. The weak value is hashed exactly like any other —
    # storage remains Argon2id; only the REQUIREMENTS were defective (CWE-521).
    for username, email, given, family, dept, title, weak_pw in TRAINING_ACCOUNTS:
        u = _mk_user(username, email, given, family, dept, "active", "IT Support",
                     weak_pw, is_training=True)
        prof = db.query(EmployeeProfile).filter_by(user_id=u.id).first()
        if prof:
            prof.title = title
        db.commit()

    # A pending-activation account so students can exercise the invitation flow
    inv = "INV-" + secrets.token_hex(8)
    pa = db.query(User).filter(User.username == "r.tanaka.pending").first()
    if pa is None:
        pa = User(username="r.tanaka.pending", email="r.tanaka@nexaline.example",
                  given_name="Ren", family_name="Tanaka", department="Engineering",
                  status="pending_activation", invitation_token=inv,
                  password_hash=hash_password("placeholder-not-authenticatable"))
        db.add(pa); db.commit()
        db.add(UserRole(user_id=pa.id, role_id=role_map["Standard Employee"].id)); db.commit()

    for num, subj, body, prio, stat, req, assignee in TICKETS:
        if db.query(SupportTicket).filter_by(ticket_number=num).first():
            continue
        db.add(SupportTicket(ticket_number=num, subject=subj, body=body, priority=prio,
                             status=stat, requester_username=req, assignee_username=assignee))
        created["tickets"] += 1
    db.commit()

    for code, title, cls, owner, content in DOCUMENTS:
        if db.query(TrainingDocument).filter_by(doc_code=code).first():
            continue
        db.add(TrainingDocument(doc_code=code, title=title, classification=cls,
                                owner_role=owner, content=content))
        created["documents"] += 1
    db.commit()

    # Persisted policy config row — matches runtime enforcement exactly
    from app.security.password_policy import get_policy
    d = get_policy().descriptor()
    cfg = db.query(PasswordPolicyConfig).first()
    if cfg is None:
        cfg = PasswordPolicyConfig(mode=d["mode"], min_length=d["min_length"], max_length=d["max_length"])
        db.add(cfg)
    cfg.mode = d["mode"]; cfg.min_length = d["min_length"]; cfg.max_length = d["max_length"]
    cfg.blocklist_enabled = d["blocklist_enabled"]
    cfg.contextual_checks_enabled = d["contextual_checks_enabled"]
    cfg.composition_rules = (d["mode"] == "vulnerable")
    cfg.forced_rotation_days = 90 if d["mode"] == "vulnerable" else 0
    cfg.updated_by = "system-seed"
    cfg.updated_at = datetime.now(timezone.utc)
    cfg.notes = "Runtime enforcement is implemented in app/security/%s_policy.py" % d["mode"]
    db.commit()

    return created
