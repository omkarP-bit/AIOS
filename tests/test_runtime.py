"""Composition-root and CLI agent-path tests.

The bug these exist for: the CLI and the API each built their own
SecurityEngine, and the CLI's silently used an in-memory ledger while the
API's used PostgreSQL. Both reported success. Nothing in the test suite
noticed, because the engine was correct in both cases — only the durability
of the audit trail differed.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from aios.cli.main import app as cli_app
from aios.db.ledger import PostgresLedger
from aios.gateway import OSGateway
from aios.models import ActionState, DataOrigin
from aios.runtime import security_engine
from aios.security import InMemoryLedger
from aios.security.engine import LedgerRecord

runner = CliRunner()


@pytest.fixture
def settings(tmp_path: Path):
    from aios.config import Settings

    return Settings(
        proc_root=Path("/proc"),
        sys_root=Path("/sys"),
        database_url="postgresql+psycopg2://aios:nosuchuser@127.0.0.1:1/none",
    )


def test_unreachable_database_falls_back_to_memory(
    settings, proc_root: Path, sys_root: Path
) -> None:
    """Fail to memory rather than to a broken Postgres session."""
    gateway = OSGateway(proc_root=proc_root, sys_root=sys_root)
    with security_engine(settings, gateway) as engine:
        assert isinstance(engine.ledger, InMemoryLedger)
        assert engine.ledger_errors == 0


def test_fallback_engine_still_makes_decisions(
    settings, proc_root: Path, sys_root: Path
) -> None:
    from aios.security import make_ai_request

    gateway = OSGateway(proc_root=proc_root, sys_root=sys_root)
    with security_engine(settings, gateway) as engine:
        assert engine.process(make_ai_request("process.list")).decision.value == "ALLOW"
        denied = engine.process(make_ai_request("process.inspect", {"pid": 1}))
        assert denied.decision.value == "DENY"


def test_api_and_cli_share_one_wiring() -> None:
    """Both call sites build the engine through aios.runtime, not their own.

    Asserted structurally rather than by behaviour because the original bug
    was invisible to behaviour: both engines were correct, they just disagreed
    about where the audit trail went.
    """
    import aios.api as api_module
    import aios.cli.main as cli_module

    for module in (api_module, cli_module):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "from aios.runtime import security_engine" in source, module.__name__
        # A call site that re-wired the engine itself is the thing to catch.
        assert "SecurityEngine(" not in source, module.__name__


# ---------------------------------------------------------------- CLI


def test_cli_act_runs_an_allowed_action(proc_root: Path, sys_root: Path, monkeypatch) -> None:
    import aios.cli.main as cli

    monkeypatch.setattr(cli, "_gateway", lambda: OSGateway(proc_root, sys_root))
    monkeypatch.setattr(cli, "_settings", lambda: _offline_settings())
    result = runner.invoke(
        cli_app,
        ["act"],
        input='{"type":"process.list","params":{"limit":1}}',
    )
    assert result.exit_code == 0, result.output
    assert "ALLOW" in result.output
    assert "COMPLETED" in result.output


def test_cli_act_denies_an_ungranted_action(
    proc_root: Path, sys_root: Path, monkeypatch
) -> None:
    """Exit code non-zero, so a script cannot mistake a denial for success."""
    import aios.cli.main as cli

    monkeypatch.setattr(cli, "_gateway", lambda: OSGateway(proc_root, sys_root))
    monkeypatch.setattr(cli, "_settings", lambda: _offline_settings())
    result = runner.invoke(
        cli_app, ["act"], input='{"type":"process.inspect","params":{"pid":1}}'
    )
    assert result.exit_code == 1
    assert "DENY" in result.output
    assert "capability_missing" in result.output


def test_cli_act_dry_run_does_not_execute(
    proc_root: Path, sys_root: Path, monkeypatch
) -> None:
    import aios.cli.main as cli

    monkeypatch.setattr(cli, "_gateway", lambda: OSGateway(proc_root, sys_root))
    monkeypatch.setattr(cli, "_settings", lambda: _offline_settings())
    result = runner.invoke(
        cli_app,
        ["act", "--dry-run"],
        input='{"type":"system.cpu"}',
    )
    assert result.exit_code == 0
    assert "AUTHORIZED" in result.output
    assert "not executed" in result.output


def test_cli_act_rejects_a_forbidden_action(
    proc_root: Path, sys_root: Path, monkeypatch
) -> None:
    import aios.cli.main as cli

    monkeypatch.setattr(cli, "_gateway", lambda: OSGateway(proc_root, sys_root))
    monkeypatch.setattr(cli, "_settings", lambda: _offline_settings())
    result = runner.invoke(
        cli_app, ["act"], input='{"type":"process.kill","params":{"pid":1}}'
    )
    assert result.exit_code == 1
    assert "forbidden" in result.output


def test_cli_db_status_reports_degraded_rather_than_claiming_durability(
    monkeypatch,
) -> None:
    monkeypatch.setenv("AIOS_DATABASE_URL", "postgresql+psycopg2://x@127.0.0.1:1/none")
    from aios.db import session as db_session

    db_session.reset_engine()
    try:
        result = runner.invoke(cli_app, ["db", "status"])
        assert result.exit_code == 0
        assert "degraded" in result.output
        assert "aios db init" in result.output
    finally:
        db_session.reset_engine()


def _offline_settings():
    from aios.config import Settings

    return Settings(database_url="postgresql+psycopg2://x@127.0.0.1:1/none")


# ---------------------------------------------------------------- ledger contract


def test_every_ledger_implementation_satisfies_the_protocol() -> None:
    """Structural check that PostgresLedger still implements what the engine
    calls, without needing a database to do it."""
    for name in ("record", "record_security_event", "list_actions", "get_action"):
        assert callable(getattr(PostgresLedger, name, None)), name


def test_in_memory_ledger_keeps_state_order() -> None:
    from aios.security import Decision, RiskClass

    ledger = InMemoryLedger()
    for state in (ActionState.VALIDATED, ActionState.AUTHORIZED, ActionState.COMPLETED):
        ledger.record(
            LedgerRecord(
                action_id="a",
                session_id="s",
                agent_id="g",
                action="system.cpu",
                state=state,
                risk=RiskClass.LOW,
                decision=Decision.ALLOW,
                reason="",
            )
        )
    assert ledger.states("a") == [
        ActionState.VALIDATED,
        ActionState.AUTHORIZED,
        ActionState.COMPLETED,
    ]


def test_ai_origin_is_never_trusted() -> None:
    """Sanity check on the provenance model the whole design rests on."""
    from aios.models import ActionRequest, ActionType

    request = ActionRequest(
        action_id="origins-01",
        agent_id="local-agent",
        session_id="s",
        type=ActionType.SYSTEM_CPU,
        params={},
        origin=DataOrigin.AI,
    )
    assert request.trust_domain.value == "T3"
    assert request.trust_domain is not DataOrigin.AI
