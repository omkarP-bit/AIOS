"""The action catalog fetched from the Go core.

The core is the source of truth for which actions exist. The planner only
uses this metadata to build its prompt and to reject obvious nonsense before
posting; the core still validates every field and makes every decision.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


class CatalogError(ValueError):
    """The core returned a schema the planner cannot use."""


@dataclass(frozen=True)
class Catalog:
    protocol_version: str
    allowed: tuple[str, ...]
    forbidden: tuple[str, ...]
    params: Mapping[str, tuple[str, ...]]
    plan_actions: tuple[str, ...] = ()

    @classmethod
    def from_schema(cls, payload: Mapping[str, Any]) -> Catalog:
        allowed = payload.get("allowed_actions")
        forbidden = payload.get("forbidden_actions")
        schemas = payload.get("params_schema")
        if not isinstance(allowed, list) or not isinstance(forbidden, list):
            raise CatalogError("schema is missing allowed_actions or forbidden_actions")
        if not isinstance(schemas, dict):
            raise CatalogError("schema is missing params_schema")
        params: dict[str, tuple[str, ...]] = {}
        for action in allowed:
            if not isinstance(action, str):
                raise CatalogError("allowed_actions must contain strings")
            entry = schemas.get(action, {})
            properties = entry.get("properties", {}) if isinstance(entry, dict) else {}
            if not isinstance(properties, dict):
                raise CatalogError(f"schema for {action} is malformed")
            params[action] = tuple(sorted(properties))
        raw_plan_actions = payload.get("plan_actions", [])
        if not isinstance(raw_plan_actions, list) or not all(
            isinstance(action, str) for action in raw_plan_actions
        ):
            raise CatalogError("plan_actions must be a list of strings")
        return cls(
            protocol_version=str(payload.get("protocol_version", "")),
            allowed=tuple(allowed),
            forbidden=tuple(forbidden),
            params=params,
            plan_actions=tuple(raw_plan_actions),
        )

    def allows(self, action: str) -> bool:
        return action in self.params

    def needs_plan(self, action: str) -> bool:
        return action in self.plan_actions

    def summary(self) -> str:
        return "\n".join(
            f"- {action}: {list(self.params[action])}" for action in sorted(self.params)
        )


__all__ = ["Catalog", "CatalogError"]
