"""The closed action shape the planner is allowed to produce.

This is deliberately a plain data object, not an authorization. It is posted
to the Go core, which owns validation, capability checks, policy, and
execution. Nothing here can approve anything.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


def new_action_id(prefix: str = "ai") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


@dataclass(frozen=True)
class ActionRequest:
    action_id: str
    agent_id: str
    session_id: str
    type: str
    params: dict[str, Any] = field(default_factory=dict)
    intent: str | None = None
    origin: str = "ai"

    @property
    def action_name(self) -> str:
        return self.type

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "action_id": self.action_id,
            "type": self.type,
            "params": self.params,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "origin": self.origin,
        }
        if self.intent is not None:
            payload["intent"] = self.intent
        return payload


__all__ = ["ActionRequest", "new_action_id"]
