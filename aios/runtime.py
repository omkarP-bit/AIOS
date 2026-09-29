"""Composition root.

One place that knows how to wire a gateway, a capability manager, and a
ledger together. The API and the CLI both build their engine here, and that
is the point: they were wired separately and immediately drifted, with the
CLI's agent path silently writing its audit trail to memory while the API's
wrote to PostgreSQL. Two call sites, two answers to "is this logged?".
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy.orm import sessionmaker

from aios.config import Settings
from aios.db.ledger import PostgresLedger
from aios.db.session import build_engine, ledger_status
from aios.gateway import OSGateway
from aios.security import CapabilityManager, SecurityEngine

log = logging.getLogger("aios.runtime")


@contextmanager
def security_engine(
    settings: Settings,
    gateway: OSGateway | None = None,
    *,
    capabilities: CapabilityManager | None = None,
) -> Iterator[SecurityEngine]:
    """Yield a SecurityEngine wired to the best available ledger.

    PostgreSQL when the server answers *and* the schema exists; otherwise
    in-memory. The fallback is logged rather than silent, because it means
    the audit trail dies with the process — a caller that cannot tell the
    difference will believe it has a durable record when it does not.

    Use as a context manager so the database session is committed and closed
    exactly once, whatever the caller does inside.
    """
    gw = gateway or OSGateway(
        proc_root=settings.proc_root,
        sys_root=settings.sys_root,
        max_read_bytes=settings.max_read_bytes,
        max_dir_entries=settings.max_dir_entries,
    )
    manager = capabilities or CapabilityManager()

    # Built from the settings actually passed in, not the global cached ones.
    # An earlier version took a `settings` argument and then quietly consulted
    # get_settings() for the ledger decision, so a caller that configured an
    # unreachable database got a durable-looking engine pointed somewhere else.
    db_engine = build_engine(settings.database_url)
    status = ledger_status(db_engine)

    if status["durable"]:
        factory = sessionmaker(bind=db_engine, expire_on_commit=False, future=True)
        session = factory()
        try:
            ledger = PostgresLedger(session)
            yield SecurityEngine(
                gw,
                capability_manager=manager,
                ledger=ledger,
                security_event_recorder=ledger.record_security_event,
            )
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        return

    log.warning(
        "using in-memory ledger (%s); the audit trail will not survive a restart",
        status["reason"],
    )
    yield SecurityEngine(gw, capability_manager=manager)


__all__ = ["security_engine"]
