"""Optional eBPF observation.

This module never executes a probe. It detects whether the tooling exists,
parses JSON lines produced by the bundled bpftrace script, and reports status.
Running a probe requires privileges that the control plane does not hold.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROBE_PATH = Path(__file__).with_name("aios_trace.bt")


@dataclass(frozen=True)
class EbpfEvent:
    kind: str
    pid: int
    comm: str
    detail: str
    timestamp_ns: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "pid": self.pid,
            "comm": self.comm,
            "detail": self.detail,
            "timestamp_ns": self.timestamp_ns,
        }


def bpftrace_path() -> str | None:
    return shutil.which("bpftrace")


def probe_status(probe_path: str | Path | None = None) -> dict[str, Any]:
    """Report availability without attempting to run anything."""
    path = Path(probe_path) if probe_path else PROBE_PATH
    tool = bpftrace_path()
    reasons: list[str] = []
    if tool is None:
        reasons.append("bpftrace not installed")
    if not path.exists():
        reasons.append(f"probe script missing: {path}")
    return {
        "available": not reasons,
        "tool": tool,
        "probe": str(path),
        "reason": "; ".join(reasons) or None,
        "requires_root": True,
        # Shown for the operator to run deliberately; never executed here.
        "command": f"sudo {tool or 'bpftrace'} {path}" if tool else None,
    }


def parse_event(line: str) -> EbpfEvent | None:
    """Parse one JSON line. Unknown or malformed lines are skipped."""
    line = line.strip()
    if not line:
        return None
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    try:
        return EbpfEvent(
            kind=str(payload["kind"])[:64],
            pid=int(payload["pid"]),
            comm=str(payload.get("comm", ""))[:64],
            detail=str(payload.get("detail", ""))[:512],
            timestamp_ns=int(payload["timestamp_ns"]) if "timestamp_ns" in payload else None,
        )
    except (KeyError, TypeError, ValueError):
        return None


def parse_events(text: str) -> list[EbpfEvent]:
    events: list[EbpfEvent] = []
    for line in text.splitlines():
        event = parse_event(line)
        if event is not None:
            events.append(event)
    return events


def read_events(path: str | Path) -> list[EbpfEvent]:
    return parse_events(Path(path).read_text(encoding="utf-8"))


__all__ = [
    "PROBE_PATH",
    "EbpfEvent",
    "bpftrace_path",
    "parse_event",
    "parse_events",
    "probe_status",
    "read_events",
]
