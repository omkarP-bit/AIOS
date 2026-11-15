"""Sanitize untrusted text before it reaches the terminal.

Everything from the system or the model is hostile: process names, command
lines, filenames, file content, and model prose. The sanitizer is deliberately
lossy. It is applied at render time, never used as an authorization decision.
"""

from __future__ import annotations

import re
import unicodedata

TRUNCATION = " [truncated]"

# CSI, OSC, DCS/PM/APC, and two-byte escapes. The OSC branch also consumes an
# unterminated sequence so a truncated payload cannot smuggle a bell or CR.
_ANSI = re.compile(
    r"""
    \x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?   # OSC
  | \x1b[P^_][^\x1b]*(?:\x1b\\)?         # DCS / PM / APC
  | \x1b\[[0-?]*[ -/]*[@-~]              # CSI
  | \x1b[@-Z\\-_]                        # Fe escape
    """,
    re.VERBOSE,
)

# Bidi overrides and zero-width characters can reorder or hide text.
_INVISIBLE = dict.fromkeys(
    map(
        ord,
        "\u061c\u200b\u200c\u200d\u200e\u200f"
        "\u202a\u202b\u202c\u202d\u202e"
        "\u2066\u2067\u2068\u2069\ufeff",
    ),
    None,
)

# C0 controls except tab/newline, DEL, and C1 controls.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def sanitize(value: object, *, max_length: int | None = None, multiline: bool = False) -> str:
    """Return inert text safe to place in a terminal.

    ANSI sequences, control characters, and bidi overrides are removed. Carriage
    returns become newlines so ``\\r`` cannot overwrite earlier output. Inline
    mode folds newlines and tabs into spaces. Long results end with
    ``[truncated]``.
    """
    text = "" if value is None else str(value)
    text = _ANSI.sub("", text)
    text = text.translate(_INVISIBLE)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL.sub("", text)
    if multiline:
        text = text.replace("\x0b", "\n").replace("\x0c", "\n")
    else:
        text = text.replace("\n", " ").replace("\t", " ")
    text = unicodedata.normalize("NFC", text)
    if max_length is not None and max_length >= 0 and len(text) > max_length:
        if max_length <= len(TRUNCATION):
            return TRUNCATION[:max_length]
        keep = max(0, max_length - len(TRUNCATION))
        text = text[:keep].rstrip() + TRUNCATION
    return text


def sanitize_inline(value: object, *, max_length: int = 256) -> str:
    """Sanitize one table cell or label."""
    return sanitize(value, max_length=max_length)


def sanitize_block(value: object, *, max_length: int = 20_000) -> str:
    """Sanitize a multi-line block such as model prose or file content."""
    return sanitize(value, max_length=max_length, multiline=True)


__all__ = ["TRUNCATION", "sanitize", "sanitize_block", "sanitize_inline"]
