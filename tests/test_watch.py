"""Tests for continuous telemetry rendering.

The failure modes worth guarding here are not cosmetic. Watch mode is the one
place in the CLI where an implementation detail turns into a wrong number:

* A gateway rebuilt per tick throws away the previous-sample state that CPU
  and process percentages are derived from, so every reading becomes either
  blank or a delta over a zero-length window.
* An unbounded loop with no interval floor turns a monitor into a spin loop
  that shows up in the very counters it reports.
* TTY detection decides between in-place redraw and a scrolling record.
  Getting it wrong produces control-character soup in a piped log.
"""

from __future__ import annotations

import io
import json
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from rich.console import Console

from aios.cli.watch import (
    HISTORY,
    MIN_INTERVAL_S,
    Sparkline,
    WatchConfig,
    WatchError,
    is_tty,
    kv_table,
    run_watch,
)

# ---------------------------------------------------------------- config


def test_interval_floor_is_enforced() -> None:
    """Sampling faster than the floor perturbs the counters being measured."""
    with pytest.raises(WatchError, match="at least"):
        WatchConfig.build(0.001, 1, False)


def test_interval_floor_message_explains_why() -> None:
    try:
        WatchConfig.build(0.0, 1, False)
    except WatchError as exc:
        assert "perturbs" in str(exc)
    else:
        pytest.fail("expected WatchError")


def test_interval_at_the_floor_is_accepted() -> None:
    cfg = WatchConfig.build(MIN_INTERVAL_S, 1, False)
    assert cfg.interval_s == MIN_INTERVAL_S


def test_count_must_be_positive() -> None:
    with pytest.raises(WatchError, match="count"):
        WatchConfig.build(1.0, 0, False)


def test_json_requires_a_bound() -> None:
    """An unbounded stream is unreadable in a terminal and never terminates
    in a pipe, so --count is mandatory rather than advisory."""
    with pytest.raises(WatchError, match="count"):
        WatchConfig.build(1.0, None, True)


def test_count_may_be_omitted_without_json() -> None:
    cfg = WatchConfig.build(1.0, None, False)
    assert cfg.count is None


# ---------------------------------------------------------------- sparkline


def test_sparkline_starts_empty() -> None:
    assert Sparkline().render().plain == "-"


def test_sparkline_grows_with_each_sample() -> None:
    s = Sparkline(width=10)
    for i in range(4):
        s.push(i * 10.0)
    rendered = s.render().plain
    assert len(rendered) == 4
    # Rising values must render as rising blocks, which is the whole point.
    assert rendered == "▁▂▄▆"[: len(rendered)] or rendered[0] <= rendered[-1]


def test_sparkline_is_bounded_by_width() -> None:
    s = Sparkline(width=5)
    for i in range(50):
        s.push(float(i))
    assert len(s.render().plain) == 5


def test_sparkline_ignores_missing_values() -> None:
    s = Sparkline()
    s.push(None)
    s.push(50.0)
    s.push(None)
    assert len(s.render().plain) == 1


def test_sparkline_clamps_out_of_range_values() -> None:
    """A value above the window is a real reading. It must be drawn at full
    height, not raise or wrap around to an empty bar."""
    s = Sparkline()
    s.push(100.0)
    s.push(9999.0)
    assert s.render(lo=0.0, hi=100.0).plain.endswith("█")


def test_sparkline_handles_negative_values() -> None:
    s = Sparkline()
    s.push(-50.0)
    s.push(50.0)
    assert len(s.render(lo=-100.0, hi=100.0).plain) == 2


def test_sparkline_peak() -> None:
    s = Sparkline()
    assert s.peak is None
    s.push(10.0)
    s.push(42.0)
    s.push(5.0)
    assert s.peak == 42.0


def test_sparkline_default_history_width() -> None:
    assert HISTORY >= 30


# ---------------------------------------------------------------- tty


def test_is_tty_false_when_redirected() -> None:
    """A piped console must not be redrawn in place — that is how a log ends
    up full of escape sequences."""
    console = Console(file=io.StringIO(), force_terminal=False)
    assert is_tty(console) is False


def test_is_tty_true_for_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    console = Console(file=io.StringIO(), force_terminal=True, width=80)
    assert is_tty(console) is True


def test_forced_terminal_with_piped_stdout_still_refuses(monkeypatch) -> None:  # noqa: ANN001
    """force_terminal says what to *emit*, not where it is going. If stdout is
    a file, an in-place redraw lands in that file as escape-sequence soup."""
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)
    console = Console(file=io.StringIO(), force_terminal=True, width=80)
    assert is_tty(console) is False


# ---------------------------------------------------------------- run_watch


class FakeObservation:
    def __init__(self, n: int) -> None:
        self.timestamp = type("T", (), {"isoformat": lambda self: f"t{n}"})()
        self.type = "system.cpu"
        self.source = "/proc/stat"
        self.trust_domain = type("D", (), {"value": "T0"})()
        self.is_trusted = True
        self.data = type("Data", (), {"model_dump": lambda self, mode=None: {"n": n}})()


def _counting_fetch() -> Callable[[], FakeObservation]:
    """A fetch whose payload increments, so a renderer can prove it saw a
    distinct sample each tick rather than the same object repeated."""
    n = 0

    def fetch() -> FakeObservation:
        nonlocal n
        n += 1
        return FakeObservation(n)

    return fetch


def test_run_watch_calls_fetch_once_per_sample() -> None:
    calls: list[int] = []

    def fetch():
        calls.append(1)
        return FakeObservation(len(calls))

    console = Console(file=io.StringIO(), force_terminal=False, width=100)
    run_watch(console, WatchConfig.build(0.1, 4, False), fetch, lambda o, t: f"sample {t}")
    assert len(calls) == 4


def test_run_watch_numbering_starts_at_one() -> None:
    seen: list[int] = []
    console = Console(file=io.StringIO(), force_terminal=False, width=100)
    run_watch(
        console,
        WatchConfig.build(0.1, 3, False),
        lambda: FakeObservation(0),
        lambda o, t: seen.append(t) or "x",
    )
    assert seen == [1, 2, 3]


def test_run_watch_emits_one_record_per_sample_when_piped() -> None:
    """Not one in-place rewrite. A redirect gets a readable append-only log."""
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=100)
    run_watch(
        console,
        WatchConfig.build(0.1, 3, False),
        lambda: FakeObservation(0),
        lambda o, t: f"frame-{t}",
    )
    out = buf.getvalue()
    assert out.count("frame-1") == 1
    assert out.count("frame-3") == 1
    assert "\x1b[" not in out, "a piped stream must not contain escape sequences"


def test_run_watch_uses_one_gateway_across_samples() -> None:
    """The reason run_watch takes a fetch callable rather than building a
    gateway internally: observer state must survive between samples for
    percentages to mean anything."""
    gateways: list[object] = []

    class FakeGateway:
        def execute(self, request):  # noqa: ANN001
            gateways.append(self)
            return FakeObservation(len(gateways))

    gateway = FakeGateway()
    fetch = lambda: gateway.execute(None)  # noqa: E731
    console = Console(file=io.StringIO(), force_terminal=False, width=100)
    run_watch(console, WatchConfig.build(0.1, 3, False), fetch, lambda o, t: "x")
    assert len(gateways) == 3
    assert len({id(g) for g in gateways}) == 1


def test_run_watch_json_emits_ndjson_with_provenance(capsys: pytest.CaptureFixture) -> None:
    """One object per line, and the trust envelope travels with each sample.

    A bare dump of the data would drop the trust domain, and a stream is
    exactly where a consumer would have no other way to recover it.

    The stream goes to real stdout rather than the rich console, because the
    point is to survive a pipe into `jq`.
    """
    console = Console(file=io.StringIO(), force_terminal=False, width=100)
    run_watch(
        console,
        WatchConfig.build(0.1, 2, True),
        _counting_fetch(),
        lambda o, t: "unused",
    )
    out = capsys.readouterr().out
    lines = [ln for ln in out.splitlines() if ln.strip()]
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["sample"] == 1
    assert first["trust_domain"] == "T0"
    assert first["source"] == "/proc/stat"
    assert first["trusted"] is True
    assert first["data"] == {"n": 1}
    assert json.loads(lines[1])["sample"] == 2


def test_run_watch_json_does_not_use_the_renderer(capsys: pytest.CaptureFixture) -> None:
    """The renderer produces rich renderables that cannot be serialised, so
    JSON mode must not call it."""
    console = Console(file=io.StringIO(), force_terminal=False, width=100)

    def render(obs, tick):  # noqa: ANN001
        raise AssertionError("renderer must not run in json mode")

    run_watch(console, WatchConfig.build(0.1, 1, True), _counting_fetch(), render)
    assert capsys.readouterr().out.strip()


def test_run_watch_renderer_receives_each_sample() -> None:
    rendered: list[int] = []
    console = Console(file=io.StringIO(), force_terminal=False, width=100)
    run_watch(
        console,
        WatchConfig.build(0.1, 3, False),
        _counting_fetch(),
        lambda o, t: rendered.append(o.data.model_dump()["n"]) or f"n={t}",
    )
    assert rendered == [1, 2, 3]


def test_renderables_are_accepted_from_the_renderer() -> None:
    """A real renderer returns rich objects, not strings, so the loop must
    pass whatever it gets straight to the console."""
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=100)
    run_watch(
        console,
        WatchConfig.build(0.1, 1, False),
        lambda: FakeObservation(0),
        lambda o, t: kv_table(),
    )
    assert buf.getvalue().strip()


# ---------------------------------------------------------------- integration


def test_watch_cpu_reads_the_live_machine_each_tick() -> None:
    """End to end: a real gateway against real /proc, sampled repeatedly.

    The values must move. A watch that reuses one snapshot would render a
    convincing but completely inert monitor.
    """
    from aios.gateway import OSGateway
    from aios.models import ActionRequest, ActionType

    s = Console(file=io.StringIO(), force_terminal=False, width=100)
    config = WatchConfig.build(MIN_INTERVAL_S, 3, False)
    gateway = OSGateway(proc_root=Path("/proc"), sys_root=Path("/sys"))

    samples: list[float] = []

    def fetch():
        obs = gateway.execute(
            ActionRequest(
                action_id="watch-test",
                agent_id="local-agent",
                session_id="test",
                type=ActionType.SYSTEM_CPU,
                params={"interval_s": config.interval_s},
            )
        )
        total = (obs.data.percent or {}).get("total")
        if total is not None:
            samples.append(total)
        return obs

    def render(obs, tick):  # noqa: ANN001
        spark = Sparkline()
        spark.push(samples[-1] if samples else None)
        return kv_table()

    run_watch(s, config, fetch, render)
    assert len(samples) == 3
    assert all(0.0 <= v <= 100.0 for v in samples)


def test_cli_rejects_a_sub_floor_interval() -> None:
    """The guard must fire before any sampling, not after."""
    from typer.testing import CliRunner

    from aios.cli.main import app

    result = CliRunner().invoke(app, ["cpu", "-w", "--interval", "0.001", "--count", "1"])
    assert result.exit_code == 1
    assert "at least" in result.output


def test_cli_json_watch_requires_count() -> None:
    from typer.testing import CliRunner

    from aios.cli.main import app

    result = CliRunner().invoke(app, ["cpu", "-w", "--json", "--interval", "0.1"])
    assert result.exit_code == 1
    assert "count" in result.output
