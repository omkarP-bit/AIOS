"""Database engine and session management."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from aios.config import get_settings
from aios.db.models import Base

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _normalise_url(url: str) -> str:
    """Strip the SQLAlchemy driver prefix from a plain libpq URL."""
    for prefix in ("postgresql+psycopg2://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg2://" + url[len(prefix) :]
    return url


def build_engine(url: str | None = None, **kwargs: Any) -> Engine:
    settings = get_settings()
    dsn = _normalise_url(url or settings.database_url)
    if "sqlite" in dsn:
        return create_engine(dsn, future=True, **kwargs)
    options: dict[str, Any] = {
        "pool_pre_ping": True,
        "pool_size": 5,
        "max_overflow": 10,
        "pool_recycle": 1800,
        "future": True,
    }
    options.update(kwargs)
    return create_engine(dsn, **options)


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = build_engine()
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)
    return _session_factory


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on any exception."""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def create_all(engine: Engine | None = None) -> None:
    Base.metadata.create_all(engine or get_engine())


def drop_all(engine: Engine | None = None) -> None:
    Base.metadata.drop_all(engine or get_engine())


def healthcheck(engine: Engine | None = None) -> dict[str, Any]:
    """Cheap liveness probe. Returns the server version, never credentials."""
    eng = engine or get_engine()
    try:
        with eng.connect() as conn:
            version = conn.execute(text("select version()")).scalar_one()
        return {"ok": True, "server": str(version).split(",")[0]}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def schema_ready(engine: Engine | None = None) -> bool:
    """True when the tables exist.

    Distinct from :func:`healthcheck`, which only proves the server answers.
    A reachable server with an empty database passes the first and fails the
    second, and conflating them is how you end up reporting a durable audit
    trail while every insert is throwing.
    """
    eng = engine or get_engine()
    try:
        with eng.connect() as conn:
            return bool(
                conn.execute(
                    text("select to_regclass('public.actions') is not null")
                ).scalar()
            )
    except Exception:
        return False


def ledger_status(engine: Engine | None = None) -> dict[str, Any]:
    """One call for everything a caller needs to decide where to write.

    Returns ``ready`` only when the server answers *and* the schema is
    present; the API uses it to pick a backend rather than discovering the
    problem one failed insert at a time.
    """
    eng = engine or get_engine()
    reachable = healthcheck(eng)
    if not reachable.get("ok"):
        return {"backend": "memory", "durable": False, "reason": reachable.get("error")}
    if not schema_ready(eng):
        return {
            "backend": "memory",
            "durable": False,
            "reason": "schema not initialised; run `aios db init`",
        }
    return {"backend": "postgres", "durable": True, "reason": None}


def init_db(url: str | None = None) -> dict[str, Any]:
    """Create the schema if needed. Safe to call repeatedly."""
    eng = build_engine(url) if url else get_engine()
    create_all(eng)
    return healthcheck(eng)


def reset_engine() -> None:
    """Test hook — drop the cached engine, session factory, and settings.

    Settings are cleared too, because the engine is built from them and a
    cached Settings object would quietly keep serving the previous database
    URL after the environment changed.
    """
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None
    get_settings.cache_clear()


__all__ = [
    "build_engine",
    "create_all",
    "drop_all",
    "get_engine",
    "get_session_factory",
    "healthcheck",
    "init_db",
    "ledger_status",
    "reset_engine",
    "schema_ready",
    "session_scope",
]
