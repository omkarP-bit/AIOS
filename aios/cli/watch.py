"""Continuous telemetry rendering for the CLI.

The one-shot commands answer "what is true right now". Watch mode answers
"what is true *over time*", which needs three things the one-shot path cannot
give you:

1. **A persistent gateway.** ``CpuObserver`` and ``ProcessObserver`` derive
   percentages from the *previous* call. A fresh gateway per sample would
   throw that state away and every reading would either be blank or computed
   over a zero-length window, which is worse than reporting nothing.
2. **A real interval.** Sampling as fast as the reads complete turns a
   monitoring tool into a spin loop that measurably perturbs the machine it is
   supposed to be watching.
3. **In-place redraw.** Streaming whole tables to a scrolling terminal makes
   the history unreadable, so a TTY gets a redrawing region and a pipe gets
   one snapshot per line.

Read-only throughout: this only calls the same whitelisted observation
handlers the one-shot commands call, and it writes nothing to the audit
ledger. Watching a machine is not an authorised action against it.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

# Below this, the sampling loop costs more in scheduler churn than the extra
# resolution is worth, and on a busy host it shows up in the numbers it
# reports. 100 ms is roughly the floor for a useful live view.
MIN_INTERVAL_S = 0.1

# How many samples of history the sparklines retain.
HISTORY = 120


class WatchError(Exception):
    """Raised for a bad watch configuration, reported before any sampling."""


@dataclass
class WatchConfig:
    """Validated watch settings."""

    interval_s: float
    count: int | None = None
    json_out: bool = False

    @classmethod
    def build(
        cls,
        interval_s: float,
        count: int | None,
        json_out: bool,
        allowed_min: float = MIN_INTERVAL_S,
    ) -> WatchConfig:
        if interval_s < allowed_min:
            raise WatchError(
                f"interval must be at least {allowed_min}s "
                f"(got {interval_s}s). Sampling faster than this perturbs the "
                f"very counters being measured."
            )
        if count is not None and count < 1:
            raise WatchError(f"count must be at least 1 (got {count})")
        if json_out and count is None:
            # An unbounded JSON stream printed to a terminal is unreadable, and
            # to a pipe it never terminates. Either way it needs a bound.
            raise WatchError("--json requires --count, so the stream has an end")
        return cls(interval_s=interval_s, count=count, json_out=json_out)


def is_tty(console: Console) -> bool:
    """Whether a live redraw will be visible.

    Checks the console rather than stdout directly so a redirected stream is
    detected the same way rich detects it.
    """
    return console.is_terminal and sys.stdout.isatty()


class Sparkline:
    """A rolling one-line history of a numeric series.

    A bar shows the current value. A sparkline shows whether the machine is
    trending up, spiking periodically, or pinned flat — which is the thing
    you actually open a monitor to find out, and which a single bar cannot
    show.
    """

    BLOCKS = "▁▂▃▄▅▆▇█"

    def __init__(self, width: int = HISTORY) -> None:
        self.width = width
        self._values: list[float] = []

    def push(self, value: float | None) -> None:
        if value is None:
            return
        self._values.append(float(value))
        if len(self._values) > self.width:
            del self._values[: len(self._values) - self.width]

    @property
    def peak(self) -> float | None:
        """Highest value currently held, or None if nothing has been pushed.

        Used to pick a scaling window, so that a series whose natural range is
        well above 0-100 is not drawn as a permanently full block.
        """
        return max(self._values) if self._values else None

    def render(self, lo: float = 0.0, hi: float = 100.0) -> Text:
        if not self._values:
            return Text("-", style="dim")
        span = hi - lo
        if span <= 0:
            span = 1.0
        chars: list[str] = []
        for v in self._values:
            # Clamp before scaling: a value outside the window is still a real
            # reading, it just cannot be drawn in the space available.
            frac = (min(max(v, lo), hi) - lo) / span
            idx = int(round(frac * (len(self.BLOCKS) - 1)))
            chars.append(self.BLOCKS[idx])
        style = "dim" if len(self._values) < self.width else "cyan"
        return Text("".join(chars), style=style)


def run_watch(
    console: Console,
    cfg: WatchConfig,
    fetch: Callable[[], Any],
    render: Callable[[Any, int], Any],
    *,
    header: str = "",
) -> None:
    """Sample ``fetch`` on an interval, redrawing in place on a TTY.

    ``fetch`` must return the observation for this sample. ``render`` receives
    that observation and the 1-based sample number, and returns something
    rich can display. ``fetch`` is called with a *single* long-lived gateway,
    which is what makes CPU and process percentages real deltas rather than
    noise.
    """
    if cfg.json_out:
        _run_watch_ndjson(cfg, fetch)
        return

    tick = 0
    started = time.monotonic()

    def snapshot() -> Any:
        nonlocal tick
        tick += 1
        return render(fetch(), tick)

    if not is_tty(console):
        # Piped or redirected. Refreshing in place would produce either one
        # overwritten line or a control-character soup, so emit a plain
        # record per sample instead and let the consumer decide what to keep.
        while True:
            console.print(snapshot())
            if cfg.count is not None and tick >= cfg.count:
                return
            time.sleep(cfg.interval_s)

    try:
        with Live(
            console=console,
            refresh_per_second=max(1, int(1 / cfg.interval_s)),
            screen=False,
            transient=False,
        ) as live:
            while True:
                elapsed = time.monotonic() - started
                if header:
                    live.console.print(Text(header, style="bold"), end="")
                live.update(snapshot(), refresh=True)
                if cfg.count is not None and tick >= cfg.count:
                    live.console.print(
                        Text(
                            f"  {tick} samples over {elapsed:.1f}s "
                            f"({elapsed / tick:.2f}s each) — ctrl-c to stop",
                            style="dim",
                        )
                    )
                    return
                time.sleep(cfg.interval_s)
    except KeyboardInterrupt:
        # rich restores the cursor and clears the region on the way out; the
        # only thing left to do is say where we got to.
        console.print(
            Text(
                f"\nstopped after {tick} samples over {time.monotonic() - started:.1f}s",
                style="dim",
            )
        )


def _run_watch_ndjson(cfg: WatchConfig, fetch: Callable[[], Any]) -> None:
    """One JSON object per line, flushed, so ``| jq`` or ``tail -f`` works."""
    tick = 0
    while True:
        tick += 1
        obs = fetch()
        payload = {
            "sample": tick,
            "timestamp": obs.timestamp.isoformat(),
            "type": obs.type,
            "source": obs.source,
            "trust_domain": obs.trust_domain.value,
            "trusted": obs.is_trusted,
            "data": (
                obs.data.model_dump(mode="json")
                if hasattr(obs.data, "model_dump")
                else obs.data
            ),
        }
        sys.stdout.write(json.dumps(payload, default=str) + "\n")
        sys.stdout.flush()
        if cfg.count is not None and tick >= cfg.count:
            return
        time.sleep(cfg.interval_s)


def kv_table(title: str | None = None) -> Table:
    t = Table(title=title, show_header=False)
    t.add_column("field", style="cyan", no_wrap=True)
    t.add_column("value")
    return t
