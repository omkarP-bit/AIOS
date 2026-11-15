from __future__ import annotations

from aios.cli.ui.sanitize import TRUNCATION, sanitize, sanitize_block, sanitize_inline


def test_strips_csi_and_keeps_text() -> None:
    assert sanitize("\x1b[31mred\x1b[0m") == "red"
    assert sanitize("before\x1b[2J\x1b[Hroot# ") == "beforeroot# "


def test_strips_osc_and_bell() -> None:
    assert sanitize("\x1b]0;owned\x07ok") == "ok"
    assert sanitize("ring\x07ring") == "ringring"
    assert sanitize("\x1b]8;;https://example.invalid\x1b\\link\x1b]8;;\x1b\\") == "link"


def test_carriage_return_cannot_overwrite_inline() -> None:
    assert sanitize_inline("safe\rmalicious") == "safe malicious"


def test_carriage_return_cannot_overwrite_block() -> None:
    assert sanitize_block("safe\rmalicious") == "safe\nmalicious"
    assert "\r" not in sanitize_block("a\r\nb")


def test_control_and_c1_characters_are_removed() -> None:
    assert sanitize("a\x00b\x08c\x7fd\x9be") == "abcde"


def test_rich_markup_is_data_not_markup() -> None:
    # The sanitizer does not interpret markup. Renderers must use Text objects.
    assert sanitize("[bold red]x[/]") == "[bold red]x[/]"


def test_long_values_are_truncated_with_marker() -> None:
    result = sanitize("x" * 500, max_length=40)
    assert result.endswith(TRUNCATION)
    assert len(result) <= 40


def test_tiny_limit_stays_within_budget() -> None:
    result = sanitize("x" * 50, max_length=5)
    assert len(result) == 5
    assert result == TRUNCATION[:5]


def test_bidi_and_zero_width_overrides_are_removed() -> None:
    hostile = "safe\u202egnp.exe\u202c"
    assert sanitize(hostile) == "safegnp.exe"
    assert sanitize("a\u200bb\u2066c\u2069") == "abc"


def test_unicode_is_normalized() -> None:
    assert sanitize("Cafe\u0301") == "Caf\u00e9"


def test_multiline_keeps_newlines_and_inline_folds_them() -> None:
    assert sanitize_block("one\ntwo") == "one\ntwo"
    assert sanitize_inline("one\ntwo") == "one two"


def test_none_and_empty() -> None:
    assert sanitize(None) == ""
    assert sanitize("") == ""
