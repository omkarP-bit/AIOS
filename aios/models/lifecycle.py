"""Action lifecycle states and the transitions allowed between them.

A lifecycle is a state machine rather than a set of free-form status strings,
so an illegal transition (e.g. EXECUTED -> PROPOSED) raises instead of
silently rewriting history in the ledger.
"""

from __future__ import annotations

from enum import Enum


class ActionState(str, Enum):
    PROPOSED = "PROPOSED"
    VALIDATED = "VALIDATED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTED = "EXECUTED"
    OBSERVED = "OBSERVED"
    COMPLETED = "COMPLETED"
    DENIED = "DENIED"
    FAILED = "FAILED"
    VIOLATION = "VIOLATION"


#: Legal forward transitions. Terminal states have no outgoing edges.
TRANSITIONS: dict[ActionState, frozenset[ActionState]] = {
    ActionState.PROPOSED: frozenset(
        {ActionState.VALIDATED, ActionState.DENIED, ActionState.FAILED}
    ),
    ActionState.VALIDATED: frozenset(
        {ActionState.AUTHORIZED, ActionState.DENIED, ActionState.FAILED}
    ),
    ActionState.AUTHORIZED: frozenset(
        {ActionState.EXECUTED, ActionState.DENIED, ActionState.FAILED}
    ),
    ActionState.EXECUTED: frozenset({ActionState.OBSERVED, ActionState.FAILED}),
    ActionState.OBSERVED: frozenset({ActionState.COMPLETED, ActionState.VIOLATION}),
    ActionState.COMPLETED: frozenset(),
    ActionState.DENIED: frozenset(),
    ActionState.FAILED: frozenset(),
    ActionState.VIOLATION: frozenset(),
}

TERMINAL_STATES = frozenset(
    s for s, nxt in TRANSITIONS.items() if not nxt
)


class IllegalTransition(RuntimeError):
    def __init__(self, current: ActionState, target: ActionState) -> None:
        super().__init__(f"illegal action lifecycle transition: {current.value} -> {target.value}")
        self.current = current
        self.target = target


def can_transition(current: ActionState, target: ActionState) -> bool:
    return target in TRANSITIONS.get(current, frozenset())


def assert_transition(current: ActionState, target: ActionState) -> None:
    if not can_transition(current, target):
        raise IllegalTransition(current, target)
