"""Heuristics for recognising injection-shaped text in untrusted data.

This is a detection aid, never an authorization input. A payload that matches
nothing here is still untrusted; a payload that matches everything is still
only data. The engine, not this module, decides what may run.
"""

from __future__ import annotations

import re
from typing import Any

_PATTERNS: dict[str, re.Pattern[str]] = {
    "instruction_override": re.compile(
        r"(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+"
        r"(instructions|rules|prompts)",
        re.IGNORECASE,
    ),
    "role_override": re.compile(
        r"(you\s+are\s+now|act\s+as|new\s+(system\s+)?prompt|developer\s+mode)",
        re.IGNORECASE,
    ),
    "secret_access": re.compile(
        r"(/etc/(shadow|passwd|sudoers)|id_rsa|\.ssh/|api[_-]?key|secret|token)",
        re.IGNORECASE,
    ),
    "shell_syntax": re.compile(
        r"(rm\s+-rf|;\s*(sh|bash|zsh)\b|\$\(|`[^`]+`|\|\s*(sh|bash)\b|curl\s+http)",
        re.IGNORECASE,
    ),
    "exfiltration": re.compile(
        r"(exfiltrat|send\s+(this|the)\s+(data|file|content)\s+to|base64\s+-d|nc\s+-e)",
        re.IGNORECASE,
    ),
    "protocol_spoof": re.compile(
        r'"(action|type)"\s*:\s*"(process\.(kill|terminate)|shell\.exec|command\.run)"',
        re.IGNORECASE,
    ),
}


def scan_untrusted(text: str) -> list[str]:
    """Return the categories of injection-shaped text, without rewriting it."""
    return sorted(category for category, pattern in _PATTERNS.items() if pattern.search(text))


def scan_payload(value: Any) -> list[str]:
    """Scan a value that may contain nested strings or lists."""
    if isinstance(value, str):
        return scan_untrusted(value)
    if isinstance(value, dict):
        return sorted({flag for item in value.values() for flag in scan_payload(item)})
    if isinstance(value, list | tuple | set):
        return sorted({flag for item in value for flag in scan_payload(item)})
    return []


def annotation(value: Any) -> dict[str, Any]:
    """A compact, non-destructive detection note for a context payload."""
    flags = scan_payload(value)
    return {"suspicious": bool(flags), "categories": flags}


__all__ = ["annotation", "scan_payload", "scan_untrusted"]
