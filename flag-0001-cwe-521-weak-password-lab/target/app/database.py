"""Database engine/session management. PostgreSQL in Docker; SQLite fallback for
local development and automated tests (same ORM code paths)."""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

url = settings.DATABASE_URL
connect_args = {}
if url.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
