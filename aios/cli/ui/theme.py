"""Colors and styles for the AIOS terminal UI."""

from __future__ import annotations

from rich.text import Text
from rich.theme import Theme

from aios.cli.ui.sanitize import sanitize_inline

RISK_COLORS = {
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold red",
}

TRUST_COLORS = {
    "T0": "blue",
    "T1": "cyan",
    "T2": "green",
    "T3": "yellow",
    "T4": "magenta",
    "UNTRUSTED": "bold white on red",
}

DECISION_COLORS = {"ALLOW": "green", "CONFIRM": "yellow", "DENY": "bold red"}

STATE_COLORS = {
    "PROPOSED": "dim",
    "VALIDATED": "cyan",
    "AUTHORIZED": "green",
    "EXECUTED": "green",
    "OBSERVED": "blue",
    "COMPLETED": "bold green",
    "DENIED": "bold red",
    "CONFIRM": "yellow",
}

STATUS_COLORS = {
    "ok": "green",
    "degraded": "yellow",
    "unavailable": "bold red",
    "down": "bold red",
    "unknown": "dim",
}

AIOS_THEME = Theme(
    {
        "aios.panel": "cyan",
        "aios.dim": "dim",
        "aios.ok": "green",
        "aios.warn": "yellow",
        "aios.bad": "bold red",
        "aios.title": "bold",
        "aios.risk.low": "green",
        "aios.risk.medium": "yellow",
        "aios.risk.high": "red",
        "aios.risk.critical": "bold red",
        "aios.trust.t0": "blue",
        "aios.trust.t1": "cyan",
        "aios.trust.t2": "green",
        "aios.trust.t3": "yellow",
        "aios.trust.t4": "magenta",
        "aios.trust.untrusted": "bold white on red",
    }
)


def risk_style(risk: object) -> str:
    return RISK_COLORS.get(str(risk or "").upper(), "dim")


def trust_style(domain: object) -> str:
    return TRUST_COLORS.get(str(domain or "UNTRUSTED").upper(), "bold white on red")


def decision_style(decision: object) -> str:
    return DECISION_COLORS.get(str(decision or "").upper(), "dim")


def state_style(state: object) -> str:
    return STATE_COLORS.get(str(state or "").upper(), "dim")


def status_style(status: object) -> str:
    return STATUS_COLORS.get(str(status or "unknown").lower(), "dim")


def badge(label: object, style: str = "aios.title") -> Text:
    """A colored, space-padded label built as a Text object."""
    text = sanitize_inline(label, max_length=32) or "-"
    return Text(f" {text} ", style=style)


def risk_badge(risk: object) -> Text:
    label = str(risk or "UNKNOWN").upper()
    return badge(label, risk_style(label))


def trust_badge(domain: object) -> Text:
    label = str(domain or "UNTRUSTED").upper()
    if label in {"T4", "UNTRUSTED"}:
        label = f"{label} UNTRUSTED"
    return badge(label, trust_style(domain))


def decision_badge(decision: object) -> Text:
    label = str(decision or "UNKNOWN").upper()
    return badge(label, decision_style(label))


def state_badge(state: object) -> Text:
    label = str(state or "UNKNOWN").upper()
    return badge(label, state_style(label))


def status_badge(status: object) -> Text:
    label = str(status or "unknown").lower()
    return badge(label, status_style(label))


__all__ = [
    "AIOS_THEME",
    "badge",
    "decision_badge",
    "decision_style",
    "risk_badge",
    "risk_style",
    "state_badge",
    "state_style",
    "status_badge",
    "status_style",
    "trust_badge",
    "trust_style",
]
