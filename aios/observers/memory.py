"""Memory observer — ``/proc/meminfo``.

Percentages are computed against ``MemTotal`` and are deliberately derived
here rather than read from a vendor field, so the number the AI explains is
the number this code produced.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from aios.observers.paths import read_text, resolve_under

# meminfo fields are in kibibytes unless the name ends in _bytes.
_REQUIRED = ("MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "SwapTotal", "SwapFree")

_OPTIONAL = (
    "Dirty",
    "Shmem",
    "Slab",
    "SReclaimable",
    "SUnreclaim",
    "Active",
    "Inactive",
    "Active(anon)",
    "Inactive(anon)",
    "Active(file)",
    "Inactive(file)",
    "Unevictable",
    "Mlocked",
    "SwapCached",
    "VmallocTotal",
    "VmallocUsed",
    "VmallocChunk",
    "AnonPages",
    "Mapped",
    "PageTables",
    "KernelStack",
    "CommitLimit",
    "Committed_AS",
    "HugePages_Total",
    "HugePages_Free",
    "Hugepagesize",
)


class MemoryInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_kb: int
    free_kb: int
    available_kb: int
    buffers_kb: int
    cached_kb: int
    swap_total_kb: int
    swap_free_kb: int
    used_kb: int
    used_percent: float
    available_percent: float
    swap_used_kb: int
    swap_used_percent: float
    fields_kb: dict[str, int] = Field(default_factory=dict)
    hugepages_total: int | None = None
    hugepages_free: int | None = None
    hugepage_size_kb: int | None = None


def parse_meminfo(text: str) -> dict[str, int]:
    """Parse ``Key:   1234 kB`` lines into a kibibyte-keyed dict."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, rest = line.partition(":")
        parts = rest.split()
        if not parts:
            continue
        try:
            value = int(parts[0])
        except ValueError:
            continue
        # Any unit that is not "kB" is converted so downstream maths is uniform.
        unit = parts[1] if len(parts) > 1 else "kB"
        if unit == "kB":
            out[key] = value
        elif unit == "mB" or unit == "MB":
            out[key] = value * 1024
        else:
            out[key] = value
    return out


def _meminfo_model(fields: dict[str, int]) -> MemoryInfo:
    missing = [k for k in _REQUIRED if k not in fields]
    if missing:
        raise ValueError(f"meminfo missing required fields: {missing}")

    total = fields["MemTotal"]
    free = fields["MemFree"]
    available = fields["MemAvailable"]
    swap_total = fields["SwapTotal"]
    swap_free = fields["SwapFree"]

    used = total - available
    used_pct = round(100.0 * used / total, 2) if total else 0.0
    avail_pct = round(100.0 * available / total, 2) if total else 0.0
    swap_used = swap_total - swap_free
    swap_pct = round(100.0 * swap_used / swap_total, 2) if swap_total else 0.0

    extra = {k: fields[k] for k in _OPTIONAL if k in fields}

    return MemoryInfo(
        total_kb=total,
        free_kb=free,
        available_kb=available,
        buffers_kb=fields["Buffers"],
        cached_kb=fields["Cached"],
        swap_total_kb=swap_total,
        swap_free_kb=swap_free,
        used_kb=used,
        used_percent=used_pct,
        available_percent=avail_pct,
        swap_used_kb=swap_used,
        swap_used_percent=swap_pct,
        fields_kb=extra,
        hugepages_total=fields.get("HugePages_Total"),
        hugepages_free=fields.get("HugePages_Free"),
        hugepage_size_kb=fields.get("Hugepagesize"),
    )


def read_memory(proc_root: Path) -> MemoryInfo:
    text = read_text(resolve_under(Path(proc_root), "meminfo"))
    return _meminfo_model(parse_meminfo(text))
