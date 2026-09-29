"""PostgreSQL ledger integration tests.

These run against a real database on purpose. The questions they answer —
does the foreign key hold, does a denial reach ``security_events``, is the
lifecycle actually append-only — are questions a mocked session cannot answer,
and every one of them has already been wrong at least once during this build.

Skipped, not failed, when no database is reachable, so ``pytest`` stays useful
on a machine without one.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from aios.db.ledger import PostgresLedger
from aios.db.models import (
    Action,
    ActionEvent,
    AuditLog,
    Base,
    Capability_,
    SecurityEvent,
    Session_,
)
from aios.db.session import build_engine, create_all
from aios.gateway import OSGateway
from aios.models import ActionState
from aios.security import (
    Capability,
    CapabilityManager,
    Decision,
    SecurityEngine,
    make_ai_request,
)

TEST_DB_URL = os.environ.get(
    "AIOS_TEST_DATABASE_URL", "postgresql+psycopg2://aios:aios@localhost/aios_test"
)


def ordered_subsequence(actual: list[str], milestones: list[str]) -> bool:
    """True if `milestones` appear in `actual` in that order, extras allowed."""
    it = iter(actual)
    return all(any(row == m for row in it) for m in milestones)


@pytest.fixture(scope="module")
def engine():
    """A real engine, or a skip.

    Own database rather than the dev one so dropping the schema on teardown
    cannot destroy anything the developer was working on.
    """
    try:
        eng = build_engine(TEST_DB_URL)
        with eng.connect() as conn:
            conn.exec_driver_sql("select 1")
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"PostgreSQL not available: {type(exc).__name__}: {exc}")
    create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture
def session(engine) -> Iterator[Session]:
    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with factory() as s:
        yield s
        s.rollback()
        for table in reversed(Base.metadata.sorted_tables):
            s.execute(table.delete())
        s.commit()


@pytest.fixture
def ledger(session: Session) -> PostgresLedger:
    return PostgresLedger(session)


@pytest.fixture
def gateway(proc_root: Path, sys_root: Path) -> OSGateway:
    return OSGateway(proc_root=proc_root, sys_root=sys_root)


# ---------------------------------------------------------------- allow path


def test_allowed_action_is_persisted_end_to_end(
    gateway: OSGateway, session: Session
) -> None:
    ledger = PostgresLedger(session)
    engine = SecurityEngine(gateway, ledger=ledger)
    verdict = engine.process(make_ai_request("process.list", {"limit": 2}))

    assert verdict.decision is Decision.ALLOW
    assert verdict.state is ActionState.COMPLETED
    assert ledger.failures == 0

    session.commit()
    row = session.get(Action, verdict.action_id)
    assert row is not None
    assert row.state == "COMPLETED"
    assert row.decision == "ALLOW"
    assert row.completed_at is not None
    assert row.duration_ms is not None

    events = session.execute(
        select(ActionEvent)
        .where(ActionEvent.action_id == verdict.action_id)
        .order_by(ActionEvent.event_id)
    ).scalars().all()
    # A step may be logged more than once in the same state — the capability
    # and policy gates each write a row while the action is still VALIDATED —
    # so the persisted sequence is the state machine's milestones *in order*,
    # not a chain of legal edges. The edges are enforced by assert_transition
    # at the point of transition and covered in the engine tests.
    assert ordered_subsequence(
        [e.state for e in events],
        ["VALIDATED", "AUTHORIZED", "EXECUTED", "OBSERVED", "COMPLETED"],
    )
    assert events[-1].state == "COMPLETED"


def test_action_row_survives_an_unknown_session_id(
    gateway: OSGateway, session: Session
) -> None:
    """Regression: actions.session_id is a foreign key, and nothing used to
    create the row it points at, so a first-run action lost its whole audit
    trail to a foreign-key violation."""
    ledger = PostgresLedger(session, strict=True)
    engine = SecurityEngine(gateway, ledger=ledger)
    verdict = engine.process(
        make_ai_request("system.cpu", session_id="never-registered-session")
    )
    session.commit()

    assert verdict.decision is Decision.ALLOW
    assert ledger.failures == 0
    assert session.get(Session_, "never-registered-session") is not None
    assert session.get(Action, verdict.action_id) is not None


def test_repeated_persisted_states_are_kept(
    gateway: OSGateway, session: Session
) -> None:
    """The ledger is append-only, so a state that appears twice must not
    collapse — otherwise 'authorized then denied' looks like 'denied'."""
    ledger = PostgresLedger(session)
    engine = SecurityEngine(gateway, ledger=ledger)
    verdict = engine.process(make_ai_request("process.inspect", {"pid": 1}))
    session.commit()

    events = session.execute(
        select(ActionEvent)
        .where(ActionEvent.action_id == verdict.action_id)
        .order_by(ActionEvent.event_id)
    ).scalars().all()
    # Three rows, and the repeat is the point: the capability gate was
    # reached while VALIDATED and refused, then DENIED closed it out. A ledger
    # that collapsed repeats would make this look like a bare refusal.
    assert [e.state for e in events] == ["VALIDATED", "VALIDATED", "DENIED"]
    assert [e.decision for e in events] == ["ALLOW", "DENY", "DENY"]


# ---------------------------------------------------------------- deny path


def test_denied_action_lands_in_denied_state_with_a_reason(
    gateway: OSGateway, session: Session
) -> None:
    ledger = PostgresLedger(session)
    engine = SecurityEngine(gateway, ledger=ledger)
    verdict = engine.process(make_ai_request("process.inspect", {"pid": 1}))
    session.commit()

    assert verdict.decision is Decision.DENY
    row = session.get(Action, verdict.action_id)
    assert row.state == "DENIED"
    assert row.decision == "DENY"
    assert row.denial_reason == "capability_missing"
    assert row.completed_at is not None


def test_denial_is_forwarded_to_security_events(
    gateway: OSGateway, session: Session
) -> None:
    """The detection-rate measurement is computed from this table, so a
    denial that fails to write here is a denial the system cannot prove it
    caught."""
    ledger = PostgresLedger(session)
    engine = SecurityEngine(
        gateway, ledger=ledger, security_event_recorder=ledger.record_security_event
    )
    verdict = engine.process(make_ai_request("process.inspect", {"pid": 1}))
    session.commit()

    events = session.execute(
        select(SecurityEvent).where(SecurityEvent.action_id == verdict.action_id)
    ).scalars().all()
    assert len(events) == 1
    assert events[0].category == "capability_violation"
    assert events[0].severity == "MEDIUM"
    assert events[0].details["denial_reason"] == "capability_missing"
    assert ledger.security_event_counts()["capability_violation"] >= 1


def test_gateway_refusal_is_recorded_after_authorization(
    gateway: OSGateway, session: Session
) -> None:
    manager = CapabilityManager(
        default_grants=[Capability(action="filesystem.stat", scope=("/**",))]
    )
    ledger = PostgresLedger(session)
    engine = SecurityEngine(gateway, capability_manager=manager, ledger=ledger)
    verdict = engine.process(make_ai_request("filesystem.stat", {"path": "/etc/shadow"}))
    session.commit()

    events = session.execute(
        select(ActionEvent)
        .where(ActionEvent.action_id == verdict.action_id)
        .order_by(ActionEvent.event_id)
    ).scalars().all()
    states = [e.state for e in events]
    assert "AUTHORIZED" in states, "the action really was authorized first"
    assert states[-1] == "DENIED"
    row = session.get(Action, verdict.action_id)
    assert row.denial_reason == "gateway_refused"


# ---------------------------------------------------------------- reads


def test_get_action_reconstructs_the_whole_lifecycle(
    gateway: OSGateway, session: Session
) -> None:
    ledger = PostgresLedger(session)
    engine = SecurityEngine(gateway, ledger=ledger)
    verdict = engine.process(make_ai_request("process.list", {"limit": 1}))
    session.commit()

    record = ledger.get_action(verdict.action_id)
    assert record is not None
    assert record["action_type"] == "process.list"
    assert record["state"] == "COMPLETED"
    assert [e["state"] for e in record["events"]][0] == "VALIDATED"
    assert record["events"][-1]["state"] == "COMPLETED"


def test_list_and_count_reflect_persisted_rows(
    gateway: OSGateway, session: Session
) -> None:
    ledger = PostgresLedger(session)
    engine = SecurityEngine(gateway, ledger=ledger)
    engine.process(make_ai_request("process.list"))
    engine.process(make_ai_request("process.inspect", {"pid": 1}))
    session.commit()

    assert ledger.count_by_decision() == {"ALLOW": 1, "DENY": 1}
    assert len(ledger.list_actions()) == 2
    assert len(ledger.list_actions(state="DENIED")) == 1
    assert len(ledger.list_actions(agent_id="local-agent")) == 2


# ---------------------------------------------------------------- capabilities


def test_capability_grant_and_revoke_are_audited(session: Session) -> None:
    ledger = PostgresLedger(session)
    ledger.sync_capability("agent-a", Capability(action="process.list"))
    session.commit()

    caps = ledger.list_capabilities("agent-a")
    assert len(caps) == 1
    assert caps[0]["active"] is True

    ledger.sync_revocation("agent-a", "process.list", principal="operator")
    session.commit()

    caps = ledger.list_capabilities("agent-a")
    assert caps[0]["active"] is False
    assert caps[0]["revoked_by"] == "operator"

    ops = [a.operation for a in session.execute(select(AuditLog)).scalars()]
    assert "capability.grant" in ops
    assert "capability.revoke" in ops


def test_regrant_updates_in_place(session: Session) -> None:
    ledger = PostgresLedger(session)
    ledger.sync_capability("agent-b", Capability(action="filesystem.read", scope=("/a/*",)))
    session.commit()
    ledger.sync_capability("agent-b", Capability(action="filesystem.read", scope=("/b/*",)))
    session.commit()

    rows = session.execute(
        select(Capability_).where(
            Capability_.agent_id == "agent-b", Capability_.action == "filesystem.read"
        )
    ).scalars().all()
    assert len(rows) == 1, "unique constraint should upsert, not duplicate"
    assert rows[0].scope == ["/b/*"]


def test_upsert_requires_postgres(session: Session) -> None:
    """sync_capability uses ON CONFLICT, so it is genuinely PostgreSQL-only.

    Asserted rather than left implicit: the models import cleanly against
    SQLite, and it would be easy to assume a test run there covers this file.
    """
    assert session.bind is not None
    assert session.bind.dialect.name == "postgresql"


def test_healthcheck_reports_without_leaking_credentials() -> None:
    from aios.db.session import healthcheck

    eng = create_engine(TEST_DB_URL)
    result = healthcheck(eng)
    assert result["ok"] is True
    assert result["server"].startswith("PostgreSQL")
    # The healthcheck is exposed by the API; it must not echo the DSN.
    assert "aios:aios" not in result["server"]
