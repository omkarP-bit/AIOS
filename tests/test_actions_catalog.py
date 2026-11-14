"""Action catalog tests — the invariants that keep the protocol honest.

The catalog is the single place that says what an action *is*. These tests
assert that it cannot describe something the rest of the system forbids.
"""

from __future__ import annotations

import pytest

from aios.actions.catalog import (
    CATALOG,
    EXECUTOR_ACTIONS,
    FORBIDDEN_ACTIONS,
    PLAN_ACTIONS,
    ApprovalClass,
    Effect,
    assert_catalog_safe,
    descriptor_for,
    effect_for,
    is_read_only,
    requires_plan,
)
from aios.models import make_request
from aios.models.actions import FORBIDDEN_ACTION_NAMES, PARAMS_MAP, ActionError
from aios.security.capabilities import RiskClass, ScopeDimension, risk_for, scope_dimension_for


def test_catalog_and_protocol_cover_the_same_actions() -> None:
    assert set(CATALOG) == set(PARAMS_MAP)


def test_catalog_and_protocol_agree_on_the_forbidden_set() -> None:
    assert FORBIDDEN_ACTIONS == FORBIDDEN_ACTION_NAMES


def test_no_action_is_both_catalogued_and_forbidden() -> None:
    assert not (set(CATALOG) & FORBIDDEN_ACTIONS)


def test_plan_actions_are_exactly_the_planner_ones() -> None:
    assert set(PLAN_ACTIONS) == {"filesystem.quarantine", "filesystem.restore"}
    assert all(descriptor_for(name).approval is ApprovalClass.PLAN for name in PLAN_ACTIONS)


def test_executor_actions_are_a_subset_of_plan_actions() -> None:
    assert EXECUTOR_ACTIONS <= PLAN_ACTIONS


def test_catalog_safety_checks_pass() -> None:
    assert_catalog_safe()


def test_every_action_declares_a_canonical_owasp_tag() -> None:
    for name, descriptor in CATALOG.items():
        assert descriptor.owasp, f"{name} has no OWASP tags"
        assert all(tag.startswith("OWASP-") for tag in descriptor.owasp), name


def test_catalog_risk_matches_the_capability_table() -> None:
    for name, descriptor in CATALOG.items():
        assert risk_for(name) is RiskClass(descriptor.risk), name


def test_catalog_scope_matches_the_capability_table() -> None:
    expected = {
        "none": ScopeDimension.NONE,
        "path": ScopeDimension.PATH,
        "pid": ScopeDimension.PID,
    }
    for name, descriptor in CATALOG.items():
        assert scope_dimension_for(name) is expected[descriptor.scope], name


@pytest.mark.parametrize("name", sorted(CATALOG))
def test_read_only_flag_matches_effect(name: str) -> None:
    descriptor = descriptor_for(name)
    assert descriptor is not None
    if descriptor.effect is Effect.OBSERVE:
        assert is_read_only(name)
    else:
        assert not is_read_only(name)


@pytest.mark.parametrize("name", sorted(PLAN_ACTIONS))
def test_plan_actions_are_not_read_only(name: str) -> None:
    assert requires_plan(name)
    assert not is_read_only(name)
    assert effect_for(name) in (Effect.STAGE, Effect.REVERSIBLE)


def test_reversible_actions_declare_a_catalogued_inverse() -> None:
    for name, descriptor in CATALOG.items():
        if descriptor.effect in (Effect.STAGE, Effect.REVERSIBLE):
            assert descriptor.inverse in CATALOG, name
            assert descriptor.inverse != name, name


def test_quarantine_and_restore_are_inverses() -> None:
    assert descriptor_for("filesystem.quarantine").inverse == "filesystem.restore"
    assert descriptor_for("filesystem.restore").inverse == "filesystem.quarantine"


def test_unknown_action_is_not_described_or_allowed() -> None:
    assert descriptor_for("filesystem.purge") is None
    assert effect_for("filesystem.purge") is Effect.FORBIDDEN
    assert not is_read_only("filesystem.purge")


def test_forbidden_actions_cannot_be_constructed() -> None:
    for name in sorted(FORBIDDEN_ACTIONS):
        with pytest.raises(ActionError):
            make_request(name)
