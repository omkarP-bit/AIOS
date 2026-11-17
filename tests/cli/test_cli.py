"""Command-level tests: exit codes, JSON cleanliness, and injection safety.

Commands are driven through Typer's CliRunner with a fake core client, so the
tests exercise argument parsing, rendering, and exit mapping without a socket
or a model.
"""

from __future__ import annotations

import json
import re

import pytest
from conftest import AUDIT, HEALTH, PROCESSES, SCHEMA, FakeClient
from typer.testing import CliRunner

from aios.cli.commands import app
from aios.cli.config import Config
from aios.cli.state import build_state, get_state, set_state

ANSI = re.compile(r"\x1b|\x07|\r")


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def use(fake, *, json_output: bool = False, verbose: bool = False) -> None:
    state = build_state(
        Config(),
        client=fake,
        json_output=json_output,
        no_color=True,
        verbose=verbose,
    )
    set_state(state)


def test_version(runner) -> None:
    use(object())
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "aios 0.7.0" in result.output


def test_version_json(runner) -> None:
    use(object(), json_output=True)
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert json.loads(result.output)["aios"] == "0.7.0"


def test_status_json_is_machine_readable(runner, fake_client) -> None:
    use(fake_client, json_output=True)
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert set(payload) == {"status", "cpu", "memory", "processes", "network", "health"}
    assert not ANSI.search(result.output)
    assert "\x1b" not in result.output


def test_audit_json_counts(runner, fake_client) -> None:
    use(fake_client, json_output=True)
    result = runner.invoke(app, ["audit", "--limit", "5"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["count"] == len(AUDIT)
    assert payload["entries"][0]["action_id"] == "act-allow"


def test_process_render_neutralizes_hostile_names(runner) -> None:
    hostile = {
        "processes": [
            {
                "pid": 666,
                "name": "evil\x1b[31mred\x07\u202ename",
                "state": "S",
                "cpu_percent": 1.0,
                "rss_bytes": 1024,
            }
        ]
    }
    from conftest import FakeClient

    use(FakeClient(processes=hostile))
    result = runner.invoke(app, ["processes"])
    assert result.exit_code == 0
    assert "\x1b" not in result.output
    assert "\x07" not in result.output
    assert "\u202e" not in result.output


def test_audit_render_neutralizes_control_characters(runner) -> None:
    from conftest import FakeClient

    entries = [
        {
            "action_id": "act-\x1b]0;pwned\x07",
            "action": "filesystem.read\rspoof",
            "risk": "MEDIUM",
            "decision": "DENY",
            "state": "DENIED",
            "denial_reason": "capability_missing",
            "at": "2026-11-15T10:01:00Z",
        }
    ]
    use(FakeClient(audit=entries))
    result = runner.invoke(app, ["audit"])
    assert result.exit_code == 0
    assert "\x1b" not in result.output
    assert "\x07" not in result.output
    assert "pwned" not in result.output


def test_unavailable_core_exits_4(runner) -> None:
    from aios.cli.errors import ServiceUnavailable

    class Broken:
        def _fail(self, *_args, **_kwargs):
            raise ServiceUnavailable("Cannot reach the AIOS core at http://127.0.0.1:8000.")

        status = _fail
        cpu = _fail
        memory = _fail
        processes = _fail
        network = _fail
        health = _fail

    use(Broken())
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 4
    assert "Cannot reach the AIOS core" in result.output


def test_unexpected_exception_does_not_show_traceback(runner) -> None:
    class Exploding:
        def health(self):
            raise RuntimeError("boom")

        def status(self):
            raise RuntimeError("boom")

        def cpu(self, *_args, **_kwargs):
            raise RuntimeError("boom")

        def memory(self):
            raise RuntimeError("boom")

        def processes(self, **_kwargs):
            raise RuntimeError("boom")

        def network(self, **_kwargs):
            raise RuntimeError("boom")

    use(Exploding())
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 1
    assert "Traceback" not in result.output
    assert "unexpected error" in result.output


def test_denied_ask_exits_3(runner, fake_client, provider) -> None:
    provider.responses = [
        json.dumps(
            {
                "action": "filesystem.read",
                "params": {"path": "/etc/shadow"},
                "intent": "read a secret",
            }
        )
    ]
    fake_client.verdict = {
        "decision": "DENY",
        "action": "filesystem.read",
        "risk": "MEDIUM",
        "denial_reason": "forbidden_action",
        "target": "/etc/shadow",
    }
    use(fake_client)
    result = runner.invoke(app, ["ask", "read /etc/shadow"])
    assert result.exit_code == 3
    assert "DENY" in result.output
    assert "policy denied filesystem.read on /etc/shadow" in result.output
    assert "nothing was run" in result.output


def test_chat_mode_shows_only_the_answer(fake_client, provider, capsys) -> None:
    import aios.cli.assistant as assistant_module
    from aios.cli.state import get_state

    provider.responses = [
        json.dumps({"action": "system.status", "params": {}}),
        json.dumps({"answer": "Everything looks healthy."}),
    ]
    fake_client.verdict = {
        "decision": "ALLOW",
        "action": "system.status",
        "risk": "LOW",
        "data": {"status": "ok"},
        "source": "procfs:/proc",
        "trust_domain": "T2",
    }
    use(fake_client)
    result = assistant_module.Assistant(get_state()).run(
        "status", execute_allowed=True, show_actions=False
    )
    output = capsys.readouterr().out
    assert result.answer == "Everything looks healthy."
    assert "PROPOSED BY AI" not in output
    assert "Result" not in output
    assert "Thinking / Plan" not in output


def test_confirm_not_approved_does_not_execute(runner, fake_client, provider, monkeypatch) -> None:
    import aios.cli.assistant as assistant_module

    provider.responses = [
        json.dumps(
            {
                "action": "filesystem.read",
                "params": {"path": "/tmp/note.txt"},
                "intent": "read a note",
            }
        )
    ]
    fake_client.verdict = {
        "decision": "CONFIRM",
        "action": "filesystem.read",
        "risk": "MEDIUM",
        "denial_reason": "confirmation_required",
        "target": "/tmp/note.txt",
        "requires_confirmation": True,
    }
    monkeypatch.setattr(assistant_module.Confirm, "ask", staticmethod(lambda *a, **k: False))
    use(fake_client)
    state = assistant_module.Assistant
    from aios.cli.state import get_state

    result = state(get_state()).run("read /tmp/note.txt", interactive=True, execute_allowed=True)
    assert result.confirmed is False
    assert all(call[0] != "confirm" for call in fake_client.calls)


def test_confirm_approved_executes_once(fake_client, provider, monkeypatch, capsys) -> None:
    import aios.cli.assistant as assistant_module
    from aios.cli.state import get_state

    provider.responses = [
        json.dumps(
            {
                "action": "filesystem.read",
                "params": {"path": "/tmp/note.txt"},
                "intent": "read a note",
            }
        ),
        json.dumps({"answer": "The file says hello."}),
    ]
    fake_client.verdict = {
        "decision": "CONFIRM",
        "action": "filesystem.read",
        "risk": "MEDIUM",
        "denial_reason": "confirmation_required",
        "target": "/tmp/note.txt",
        "requires_confirmation": True,
    }
    fake_client.confirm_verdict = {
        "decision": "ALLOW",
        "action": "filesystem.read",
        "risk": "MEDIUM",
        "target": "/tmp/note.txt",
        "data": {"path": "/tmp/note.txt", "content": "hello"},
        "trust_domain": "T3",
        "data_trust": "T4",
        "source": "external",
    }
    monkeypatch.setattr(assistant_module.Confirm, "ask", staticmethod(lambda *a, **k: True))
    use(fake_client)
    result = assistant_module.Assistant(get_state()).run(
        "read /tmp/note.txt", interactive=True, execute_allowed=True
    )
    assert result.confirmed is True
    assert [call[0] for call in fake_client.calls].count("confirm") == 1
    assert result.answer == "The file says hello."
    # The request ran as the operator (T3), but the bytes are untrusted (T4).
    rendered = capsys.readouterr().out
    assert "T4 UNTRUSTED" in rendered
    assert "trust T3" not in rendered


def test_ask_json_has_no_ansi(runner, fake_client, provider) -> None:
    provider.responses = [
        json.dumps({"action": "none", "reason": "nothing to do", "answer": "All good."})
    ]
    use(fake_client, json_output=True)
    result = runner.invoke(app, ["ask", "how are you?"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["answer"] == "All good."
    assert "\x1b" not in result.output


def test_model_failure_is_friendly(runner, fake_client, monkeypatch) -> None:
    from aios.ai.providers import ProviderError

    monkeypatch.setattr(
        "aios.cli.assistant.build_provider",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ProviderError("no model")),
    )
    use(fake_client)
    result = runner.invoke(app, ["ask", "hello"])
    assert result.exit_code == 1
    assert "local model" in result.output
    assert "Traceback" not in result.output


def test_provider_error_names_the_configured_provider(runner, fake_client, monkeypatch) -> None:
    from aios.ai.providers import ProviderError

    class Failing:
        name = "groq"
        model = "test-model"
        external = True

        def complete(self, _system, _user):
            raise ProviderError("groq rejected the request (401): Invalid API Key")

    monkeypatch.setenv("AIOS_MODEL_PROVIDER", "groq")
    monkeypatch.setenv("AIOS_ALLOW_EXTERNAL_MODEL", "true")
    monkeypatch.setenv("AIOS_GROQ_API_KEY", "secret")
    monkeypatch.setattr("aios.cli.assistant.build_provider", lambda *_args, **_kwargs: Failing())
    use(fake_client)
    result = runner.invoke(app, ["ask", "hello"])
    assert result.exit_code == 1
    assert "Groq could not answer" in result.output
    assert "Invalid API Key" in result.output
    assert "Ollama" not in result.output


def test_provider_mentioning_control_chars_is_escaped(runner, fake_client, provider) -> None:
    provider.responses = [
        json.dumps(
            {
                "action": "none",
                "reason": "done",
                "answer": "hi\x1b[2Jthere\x07 friend",
            }
        )
    ]
    use(fake_client)
    result = runner.invoke(app, ["ask", "hello"])
    assert result.exit_code == 0
    assert "\x1b" not in result.output


def test_model_command_shows_the_config_without_the_key(runner, monkeypatch) -> None:
    monkeypatch.setenv("AIOS_MODEL_PROVIDER", "groq")
    monkeypatch.setenv("AIOS_ALLOW_EXTERNAL_MODEL", "true")
    monkeypatch.setenv("AIOS_GROQ_API_KEY", "super-secret-key")
    monkeypatch.setenv("AIOS_GROQ_MODEL", "test-model")
    use(object())
    result = runner.invoke(app, ["model"])
    assert result.exit_code == 0
    assert "groq" in result.output
    assert "test-model" in result.output
    assert "external" in result.output
    assert "super-secret-key" not in result.output


def test_model_command_explains_a_missing_opt_in(runner, monkeypatch) -> None:
    monkeypatch.setenv("AIOS_MODEL_PROVIDER", "groq")
    monkeypatch.setenv("AIOS_ALLOW_EXTERNAL_MODEL", "false")
    monkeypatch.setenv("AIOS_GROQ_API_KEY", "secret")
    use(object())
    result = runner.invoke(app, ["model"])
    assert result.exit_code == 0
    assert "AIOS_ALLOW_EXTERNAL_MODEL" in result.output


def test_model_command_json(runner, monkeypatch) -> None:
    monkeypatch.setenv("AIOS_MODEL_PROVIDER", "groq")
    monkeypatch.setenv("AIOS_ALLOW_EXTERNAL_MODEL", "true")
    monkeypatch.setenv("AIOS_GROQ_API_KEY", "secret")
    use(object(), json_output=True)
    result = runner.invoke(app, ["model"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["provider"] == "groq"
    assert payload["ready"] is True
    assert "secret" not in result.output


def test_health_services_are_shown(runner, fake_client) -> None:
    use(fake_client)
    result = runner.invoke(app, ["security"])
    assert result.exit_code == 0
    for service in HEALTH["services"]:
        assert service.upper() in result.output


def test_process_limit_is_passed_through(runner, fake_client) -> None:
    seen = {}

    class Recorder(type(fake_client)):
        def processes(self, *, limit=50, sort_by="cpu", name_filter=None):
            seen.update({"limit": limit, "sort_by": sort_by})
            return PROCESSES

    use(Recorder())
    result = runner.invoke(app, ["processes", "--limit", "7", "--sort", "mem"])
    assert result.exit_code == 0
    assert seen == {"limit": 7, "sort_by": "mem"}


PLAN_SCHEMA = {
    **SCHEMA,
    "allowed_actions": [*SCHEMA["allowed_actions"], "process.signal"],
    "params_schema": {
        **SCHEMA["params_schema"],
        "process.signal": {
            "properties": {"pid": {"type": "integer"}, "signal": {"type": "string"}}
        },
    },
    "plan_actions": ["process.signal"],
}

PLAN_PAYLOAD = {
    "plan_id": "plan-core",
    "plan_hash": "sha256:core",
    "kind": "process.signal",
    "target": "4242",
    "steps": [
        {
            "step_id": "step-1",
            "action": "process.signal",
            "target": "4242",
            "params": {"pid": 4242, "signal": "TERM", "uid": 1000, "name": "sleep"},
        }
    ],
}

APPLY_VERDICT = {
    "decision": "ALLOW",
    "executed": True,
    "action": "process.signal",
    "target": "4242",
    "state": "COMPLETED",
    "risk": "HIGH",
    "data": {"status": "signal_sent", "signal": "TERM"},
    "source": "executor:process.signal",
    "trust_domain": "T1",
}


def test_assistant_plan_is_shown_then_applied_only_after_approval(provider, monkeypatch, capsys):
    import aios.cli.assistant as assistant_module

    fake = FakeClient(
        schema=PLAN_SCHEMA,
        plan_payload=PLAN_PAYLOAD,
        apply_verdict=APPLY_VERDICT,
    )
    provider.responses = [
        json.dumps(
            {
                "action": "process.signal",
                "params": {"pid": 4242, "signal": "TERM"},
                "intent": "stop a stray process",
            }
        ),
        json.dumps({"answer": "The process was signalled."}),
    ]
    monkeypatch.setattr(assistant_module.Confirm, "ask", staticmethod(lambda *a, **k: True))
    use(fake)
    result = assistant_module.Assistant(get_state()).run(
        "stop pid 4242", interactive=True, execute_allowed=True
    )
    assert result.confirmed is True
    assert result.approval_plan is not None
    assert any(name == "build_plan" for name, _ in fake.calls)
    applied = [payload for name, payload in fake.calls if name == "apply_plan"]
    assert applied == [("plan-core", "sha256:core", "step-1", "process.signal")]
    assert "APPROVAL PLAN" in capsys.readouterr().out


def test_assistant_plan_is_not_applied_when_not_interactive(provider, monkeypatch):
    import aios.cli.assistant as assistant_module

    fake = FakeClient(schema=PLAN_SCHEMA, plan_payload=PLAN_PAYLOAD)
    provider.responses = [
        json.dumps(
            {
                "action": "process.signal",
                "params": {"pid": 4242, "signal": "TERM"},
            }
        )
    ]
    asked = False

    def refuse(*_args, **_kwargs):
        nonlocal asked
        asked = True
        return True

    monkeypatch.setattr(assistant_module.Confirm, "ask", staticmethod(refuse))
    use(fake)
    result = assistant_module.Assistant(get_state()).run(
        "stop pid 4242", interactive=False, execute_allowed=True
    )
    assert asked is False
    assert not any(name == "apply_plan" for name, _ in fake.calls)
    assert "did not run" in (result.answer or "")
    assert "sha256:core" in (result.answer or "")


def test_assistant_zombie_plan_refusal_is_truthful(provider, monkeypatch):
    import aios.cli.assistant as assistant_module
    from aios.cli.errors import CliError

    class ZombieClient(FakeClient):
        def build_plan(self, action, params, *, intent=None):
            raise CliError(
                "a zombie is already dead; its parent must reap it",
                next_step="Do not signal it.",
            )

    fake = ZombieClient(schema=PLAN_SCHEMA)
    provider.responses = [
        json.dumps(
            {"action": "process.signal", "params": {"pid": 4242, "signal": "KILL"}}
        )
    ]
    monkeypatch.setattr(assistant_module.Confirm, "ask", staticmethod(lambda *a, **k: True))
    use(fake)
    result = assistant_module.Assistant(get_state()).run(
        "kill the zombie", interactive=True, execute_allowed=True
    )
    assert result.denied is True
    assert "cannot be killed" in (result.answer or "")
    assert "parent" in (result.answer or "")
    assert not any(name == "apply_plan" for name, _ in fake.calls)


def test_plan_command_prints_the_core_hash(runner, fake_client) -> None:
    use(fake_client)
    result = runner.invoke(app, ["plan", "process.signal", "--pid", "42"])
    assert result.exit_code == 0
    assert "sha256:test" in result.output
    assert "Nothing has run" in result.output


def test_plan_command_json_is_machine_readable(runner, fake_client) -> None:
    use(fake_client, json_output=True)
    result = runner.invoke(app, ["plan", "process.signal", "--pid", "42"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["plan_id"] == "plan-test"
    assert payload["steps"][0]["action"] == "process.signal"


def test_apply_command_sends_the_exact_hash(runner, fake_client) -> None:
    fake_client.apply_verdict = APPLY_VERDICT
    use(fake_client)
    result = runner.invoke(
        app,
        ["apply", "plan-test", "--plan-hash", "sha256:test", "--step-id", "step-1"],
    )
    assert result.exit_code == 0
    assert ("apply_plan", ("plan-test", "sha256:test", "step-1", None)) in fake_client.calls
