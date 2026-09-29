"""CPU observer — ``/proc/stat``, `/sys/devices/system/cpu`.

CPU utilisation needs two samples separated by an interval; the first call
establishes the baseline and reports ``None`` for percentages rather than
inventing a number.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from aios.observers.paths import read_text, resolve_under


@dataclass(frozen=True)
class CpuTimes:
    user: int
    nice: int
    system: int
    idle: int
    iowait: int
    irq: int
    softirq: int
    steal: int

    @property
    def total(self) -> int:
        return (
            self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
        )

    @property
    def busy(self) -> int:
        return self.total - self.idle - self.iowait

    def diff(self, other: CpuTimes) -> CpuTimes:
        return CpuTimes(
            user=other.user - self.user,
            nice=other.nice - self.nice,
            system=other.system - self.system,
            idle=other.idle - self.idle,
            iowait=other.iowait - self.iowait,
            irq=other.irq - self.irq,
            softirq=other.softirq - self.softirq,
            steal=other.steal - self.steal,
        )

    def percent(self, other: CpuTimes) -> dict[str, float]:
        """Utilisation between this sample and ``other``, in percent."""
        delta = self.diff(other)
        total = delta.total
        if total <= 0:
            return {
                "total": 0.0,
                "user": 0.0,
                "nice": 0.0,
                "system": 0.0,
                "iowait": 0.0,
                "irq": 0.0,
                "softirq": 0.0,
                "steal": 0.0,
                "idle": 0.0,
            }
        pct = 100.0 / total
        return {
            "total": round(delta.busy * pct, 2),
            "user": round(delta.user * pct, 2),
            "nice": round(delta.nice * pct, 2),
            "system": round(delta.system * pct, 2),
            "iowait": round(delta.iowait * pct, 2),
            "irq": round(delta.irq * pct, 2),
            "softirq": round(delta.softirq * pct, 2),
            "steal": round(delta.steal * pct, 2),
            "idle": round(delta.idle * pct, 2),
        }


class CpuCore(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    percent: float | None = Field(default=None, description="Requires two samples")


class CpuFrequency(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cpu: str
    khz: int | None = None
    scaling_governor: str | None = None

    @property
    def mhz(self) -> float | None:
        return None if self.khz is None else self.khz / 1000.0

    @property
    def ghz(self) -> float | None:
        """kHz to GHz is a division by 1e6, not by 1e3.

        Dividing by 1000 gives MHz. Labelling that result "GHz" reports a
        4.4 GHz CPU as running at 4400 GHz, which is the bug this property
        exists to make impossible.
        """
        return None if self.khz is None else self.khz / 1_000_000.0

    @property
    def human(self) -> str:
        """A frequency in whichever unit keeps the number readable.

        A modern CPU sits between roughly 800 MHz and 5 GHz, so MHz stays
        within a readable 3-4 digit range while GHz would render almost
        everything as "0.8" or "1.2" and lose all its precision.
        """
        if self.khz is None:
            return "-"
        mhz = self.khz / 1000.0
        if mhz >= 1000:
            return f"{mhz / 1000.0:.2f} GHz"
        return f"{mhz:.0f} MHz"


class CpuInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    logical_cores: int
    load_average_1m: float | None = None
    load_average_5m: float | None = None
    load_average_15m: float | None = None
    percent: dict[str, float] | None = Field(
        default=None, description="Requires two samples separated by an interval"
    )
    per_core: list[CpuCore] = Field(default_factory=list)
    frequencies: list[CpuFrequency] = Field(default_factory=list)


def _parse_cpu_line(line: str) -> tuple[str, CpuTimes] | None:
    """Parse ``cpu0  100 0 100 700 0 0 0 0 0 0`` style lines."""
    parts = line.split()
    if len(parts) < 5:
        return None
    label = parts[0]
    try:
        values = [int(p) for p in parts[1:9]]
    except ValueError:
        return None
    padded = values + [0] * (8 - len(values))
    return label, CpuTimes(*padded[:8])


def parse_stat(text: str) -> tuple[CpuTimes, list[tuple[str, CpuTimes]]]:
    """Return the aggregate ``cpu`` sample plus per-core samples."""
    aggregate: CpuTimes | None = None
    cores: list[tuple[str, CpuTimes]] = []
    for line in text.splitlines():
        if not line.startswith("cpu"):
            continue
        parsed = _parse_cpu_line(line)
        if parsed is None:
            continue
        label, times = parsed
        if label == "cpu":
            aggregate = times
        elif label.startswith("cpu"):
            cores.append((label, times))
    if aggregate is None:
        raise ValueError("no aggregate 'cpu' line in stat output")
    return aggregate, cores


class CpuObserver:
    """Reads CPU utilisation from a procfs root."""

    def __init__(self, proc_root: Path, sys_root: Path | None = None) -> None:
        self.proc_root = Path(proc_root)
        self.sys_root = Path(sys_root) if sys_root else self.proc_root.parent / "sys"
        self._prev: CpuTimes | None = None
        self._prev_cores: dict[str, CpuTimes] = {}

    def read_stat(self) -> tuple[CpuTimes, list[tuple[str, CpuTimes]]]:
        text = read_text(resolve_under(self.proc_root, "stat"))
        return parse_stat(text)

    def _read_loadavg(self) -> tuple[float | None, float | None, float | None]:
        try:
            parts = read_text(resolve_under(self.proc_root, "loadavg"), 4096).split()
        except OSError:
            return None, None, None
        floats: list[float | None] = []
        for part in parts[:3]:
            try:
                floats.append(float(part))
            except ValueError:
                floats.append(None)
        while len(floats) < 3:
            floats.append(None)
        return floats[0], floats[1], floats[2]

    def _read_frequencies(self) -> list[CpuFrequency]:
        base = resolve_under(self.sys_root, "devices/system/cpu")
        out: list[CpuFrequency] = []
        try:
            entries = sorted(p.name for p in base.iterdir() if p.name.startswith("cpu"))
        except OSError:
            return out
        for entry in entries:
            if not entry[3:].isdigit():
                continue
            khz: int | None = None
            cur = base / entry / "cpufreq" / "scaling_cur_freq"
            if cur.exists():
                try:
                    khz = int(read_text(cur, 64).strip())
                except (OSError, ValueError):
                    khz = None
            governor: str | None = None
            gov = base / entry / "cpufreq" / "scaling_governor"
            if gov.exists():
                try:
                    governor = read_text(gov, 256).strip()
                except OSError:
                    governor = None
            if khz is not None or governor is not None:
                out.append(CpuFrequency(cpu=entry, khz=khz, scaling_governor=governor))
        return out

    def collect(self, interval_s: float = 0.25) -> CpuInfo:
        """Take a reading. Percentages require a prior sample.

        With no prior sample, sleeps ``interval_s`` to establish one.
        """
        aggregate, cores = self.read_stat()
        previous, previous_cores = self._prev, self._prev_cores

        if previous is None:
            # No baseline yet: use this sample as the baseline, wait, and take
            # a second one so the very first call can still report a real
            # delta instead of a fabricated percentage.
            time.sleep(interval_s)
            baseline, baseline_cores = aggregate, dict(cores)
            aggregate, cores = self.read_stat()
            previous = baseline
            previous_cores = baseline_cores

        percent = previous.percent(aggregate) if previous else None
        per_core: list[CpuCore] = []
        for name, times in cores:
            prior = previous_cores.get(name) if previous_cores else None
            pct = prior.percent(times)["total"] if prior else None
            per_core.append(CpuCore(name=name, percent=pct))

        self._prev = aggregate
        self._prev_cores = dict(cores)

        load1, load5, load15 = self._read_loadavg()
        return CpuInfo(
            logical_cores=len(cores) or 1,
            load_average_1m=load1,
            load_average_5m=load5,
            load_average_15m=load15,
            percent=percent,
            per_core=per_core,
            frequencies=self._read_frequencies(),
        )

    def prime(self) -> None:
        """Record a baseline without sleeping or reporting percentages."""
        aggregate, cores = self.read_stat()
        self._prev = aggregate
        self._prev_cores = dict(cores)


def read_cpu(proc_root: Path, sys_root: Path | None = None, interval_s: float = 0.25) -> CpuInfo:
    return CpuObserver(proc_root, sys_root).collect(interval_s=interval_s)
