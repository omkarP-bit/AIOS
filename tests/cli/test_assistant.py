"""Trust of returned data, not of the request that asked for it.

A confirmed read runs under the operator's trust (T3) but returns bytes from an
untrusted source (T4). The UI must show the data's trust, never the request's.
"""

from __future__ import annotations

from aios.cli.assistant import data_trust


def test_data_trust_prefers_the_observation() -> None:
    verdict = {"trust_domain": "T3", "data_trust": "T4"}
    assert data_trust(verdict) == "T4"


def test_data_trust_falls_back_for_older_cores() -> None:
    assert data_trust({"trust_domain": "T3"}) == "T3"


def test_data_trust_is_absent_without_a_verdict_field() -> None:
    assert data_trust({}) is None
