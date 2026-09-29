"""Tests for action lifecycle state machine."""

from __future__ import annotations

import pytest

from aios.models.lifecycle import (
    TERMINAL_STATES,
    ActionState,
    IllegalTransition,
    assert_transition,
    can_transition,
)


def test_happy_path_lifecycle() -> None:
    path = [
        ActionState.PROPOSED,
        ActionState.VALIDATED,
        ActionState.AUTHORIZED,
        ActionState.EXECUTED,
        ActionState.OBSERVED,
        ActionState.COMPLETED,
    ]
    for current, target in zip(path, path[1:], strict=False):
        assert can_transition(current, target), f"{current} -> {target} should be legal"


def test_denial_path() -> None:
    assert can_transition(ActionState.PROPOSED, ActionState.VALIDATED)
    assert can_transition(ActionState.VALIDATED, ActionState.DENIED)


def test_authorized_cannot_go_back_to_validated() -> None:
    assert not can_transition(ActionState.AUTHORIZED, ActionState.VALIDATED)


def test_executed_cannot_become_denied() -> None:
    """Once the gateway ran it, a DENY rewrite would falsify the ledger."""
    assert not can_transition(ActionState.EXECUTED, ActionState.DENIED)


def test_completed_is_terminal() -> None:
    assert ActionState.COMPLETED in TERMINAL_STATES
    for state in ActionState:
        assert not can_transition(ActionState.COMPLETED, state)


def test_observed_may_violate_then_stop() -> None:
    assert can_transition(ActionState.OBSERVED, ActionState.VIOLATION)
    assert ActionState.VIOLATION in TERMINAL_STATES


def test_invalid_transition_raises() -> None:
    with pytest.raises(IllegalTransition):
        assert_transition(ActionState.PROPOSED, ActionState.EXECUTED)


def test_every_state_is_reachable_from_proposed_or_terminal() -> None:
    """No orphan states: everything is either reachable or terminal."""
    seen = {ActionState.PROPOSED}
    frontier = [ActionState.PROPOSED]
    from aios.models.lifecycle import TRANSITIONS

    while frontier:
        current = frontier.pop()
        for target in TRANSITIONS[current]:
            if target not in seen:
                seen.add(target)
                frontier.append(target)
    assert seen == set(ActionState)
