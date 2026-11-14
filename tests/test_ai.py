"""AI runtime tests: providers, parsing, context, and the CLI ask path."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from aios.ai import (
    GroqProvider,
    OllamaProvider,
    Planner,
    ProposalError,
    ProviderError,
    build_provider,
    build_snapshot,
    parse_proposal,
    provider_status,
    render_snapshot,
)
from aios.config import Settings
from aios.gateway import OSGateway

runner = CliRunner()


def _settings(**overrides) -> Settings:
    base = {
        "proc_root": Path("/proc"),
        "sys_root": Path("/sys"),
        "database_url": "sqlite://",
    }
    base.update(overrides)
    return Settings(**base)


# ---------------------------------------------------------------- providers


def test_groq_is_disabled_without_explicit_opt_in() -> None:
    settings = _settings(groq_api_key="key")
    with pytest.raises(ProviderError, match="external model use is disabled"):
        build_provider(settings)


def test_groq_requires_a_key() -> None:
    settings = _settings(allow_external_model=True, groq_api_key="")
    with pytest.raises(ProviderError, match="AIOS_GROQ_API_KEY"):
        build_provider(settings)


def test_groq_provider_is_selected_when_opted_in() -> None:
    settings = _settings(allow_external_model=True, groq_api_key="key")
    provider = build_provider(settings)
    assert isinstance(provider, GroqProvider)
    assert provider.external is True


def test_ollama_provider_is_selected() -> None:
    settings = _settings(model_provider="ollama")
    provider = build_provider(settings)
    assert isinstance(provider, OllamaProvider)
    assert provider.external is False


def test_unknown_provider_is_refused() -> None:
    with pytest.raises(ProviderError, match="unknown model provider"):
        build_provider(_settings(model_provider="dreams"))


def test_provider_status_never_contains_the_key() -> None:
    settings = _settings(allow_external_model=True, groq_api_key="super-secret")
    status = provider_status(settings)
    assert "super-secret" not in json.dumps(status)
    assert status["configured"] is True


def test_groq_completion_parses_content(monkeypatch) -> None:
    def fake_post(*_a, **_k):
        return httpx.Response(
            200,
            request=httpx.Request("POST", "https://api.groq.com"),
            json={"choices": [{"message": {"content": '{"action":"none"}'}}]},
        )

    monkeypatch.setattr("aios.ai.providers.httpx.post", fake_post)
    provider = GroqProvider(api_key="k", model="m")
    assert provider.complete("s", "u") == '{"action":"none"}'


@pytest.mark.parametrize(
    "exc", [httpx.ConnectError("down"), httpx.ReadTimeout("slow"), httpx.HTTPStatusError]
)
def test_groq_errors_are_provider_errors(monkeypatch, exc: Exception) -> None:
    def boom(*_a, **_k):
        raise exc

    monkeypatch.setattr("aios.ai.providers.httpx.post", boom)
    with pytest.raises(ProviderError):
        GroqProvider(api_key="k", model="m").complete("s", "u")


def test_ollama_completion_parses_content(monkeypatch) -> None:
    def fake_post(*_a, **_k):
        return httpx.Response(
            200,
            request=httpx.Request("POST", "http://127.0.0.1:11434"),
            json={"message": {"content": '{"action":"none"}'}},
        )

    monkeypatch.setattr("aios.ai.providers.httpx.post", fake_post)
    assert OllamaProvider(model="m").complete("s", "u") == '{"action":"none"}'


# ---------------------------------------------------------------- parsing


def test_parse_proposal_builds_a_closed_request() -> None:
    request = parse_proposal(
        '{"action":"process.list","params":{"limit":3},"intent":"look"}'
    )
    assert request is not None
    assert request.action_name == "process.list"
    assert request.params == {"limit": 3}
    assert request.origin.value == "ai"
    assert request.trust_domain.value == "T3"


def test_parse_proposal_accepts_a_markdown_fence() -> None:
    request = parse_proposal('```json\n{"action":"system.cpu"}\n```')
    assert request is not None
    assert request.action_name == "system.cpu"


def test_parse_proposal_none_means_no_action() -> None:
    assert parse_proposal('{"action":"none","reason":"nothing to do"}') is None


@pytest.mark.parametrize(
    "raw",
    [
        "I will run rm -rf /",
        '{"action":"shell.exec","params":{}}',
        '{"action":"not.real"}',
        '{"action":"process.list","params":{"limit":"many"}}',
        '{"action":"process.list","params":{"extra":1}}',
        '{"params":{}}',
        "[]",
    ],
)
def test_parse_proposal_rejects_hostile_or_invalid_output(raw: str) -> None:
    with pytest.raises(ProposalError):
        parse_proposal(raw)


# ---------------------------------------------------------------- planner


class FakeProvider:
    name = "fake"
    model = "fake-1"
    external = False

    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.calls = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        return self.answer


def test_planner_logs_a_hash_not_the_prompt() -> None:
    provider = FakeProvider('{"action":"system.memory"}')
    plan = Planner(provider).propose("how is memory?", "{}")
    assert plan.request is not None
    assert plan.request.action_name == "system.memory"
    assert len(plan.prompt_hash) == 64
    assert "how is memory?" not in plan.prompt_hash
    assert provider.calls


def test_planner_surfaces_decline_reason() -> None:
    plan = Planner(FakeProvider('{"action":"none","reason":"no action needed"}')).propose(
        "hello", "{}"
    )
    assert plan.request is None
    assert plan.reason == "no action needed"


# ---------------------------------------------------------------- context


def test_snapshot_is_aggregate_and_never_file_content(
    proc_root: Path, sys_root: Path
) -> None:
    gateway = OSGateway(proc_root=proc_root, sys_root=sys_root)
    snapshot = build_snapshot(gateway, process_limit=3)
    rendered = render_snapshot(snapshot)
    assert snapshot["host"]["hostname"] == "aios-fixture"
    assert len(snapshot["top_processes"]) <= 3
    assert "notice" in snapshot
    assert "untested-data" not in rendered  # no arbitrary fixture file bytes
    assert "filename" not in snapshot
    assert "/etc/shadow" not in rendered


# ---------------------------------------------------------------- CLI


def _cli_settings() -> Settings:
    return Settings(database_url="sqlite://")


def _install_fake_provider(monkeypatch, answer: str) -> FakeProvider:
    import aios.ai as ai

    provider = FakeProvider(answer)
    monkeypatch.setattr(ai, "build_provider", lambda _settings: provider)
    return provider


def test_cli_ask_authorizes_without_executing(
    proc_root: Path, sys_root: Path, monkeypatch
) -> None:
    import aios.cli.main as cli

    monkeypatch.setattr(cli, "_gateway", lambda: OSGateway(proc_root, sys_root))
    monkeypatch.setattr(cli, "_settings", _cli_settings)
    _install_fake_provider(monkeypatch, '{"action":"system.cpu"}')

    result = runner.invoke(cli.app, ["ask", "check cpu"])
    assert result.exit_code == 0, result.output
    assert "AUTHORIZED" in result.output
    assert "not executed" in result.output


def test_cli_ask_executes_when_explicitly_allowed(
    proc_root: Path, sys_root: Path, monkeypatch
) -> None:
    import aios.cli.main as cli

    monkeypatch.setattr(cli, "_gateway", lambda: OSGateway(proc_root, sys_root))
    monkeypatch.setattr(cli, "_settings", _cli_settings)
    _install_fake_provider(monkeypatch, '{"action":"process.list","params":{"limit":2}}')

    result = runner.invoke(cli.app, ["ask", "--execute", "list processes"])
    assert result.exit_code == 0, result.output
    assert "COMPLETED" in result.output


def test_cli_ask_denies_a_forbidden_model_answer(
    proc_root: Path, sys_root: Path, monkeypatch
) -> None:
    import aios.cli.main as cli

    monkeypatch.setattr(cli, "_gateway", lambda: OSGateway(proc_root, sys_root))
    monkeypatch.setattr(cli, "_settings", _cli_settings)
    _install_fake_provider(monkeypatch, '{"action":"process.kill","params":{"pid":1}}')

    result = runner.invoke(cli.app, ["ask", "kill everything"])
    assert result.exit_code == 1
    assert "forbidden" in result.output


def test_cli_provider_status_does_not_print_the_key(monkeypatch) -> None:
    import aios.cli.main as cli

    monkeypatch.setattr(
        cli,
        "_settings",
        lambda: Settings(
            database_url="sqlite://",
            allow_external_model=True,
            groq_api_key="super-secret",
        ),
    )
    result = runner.invoke(cli.app, ["provider"])
    assert result.exit_code == 0
    assert "groq" in result.output
    assert "super-secret" not in result.output
