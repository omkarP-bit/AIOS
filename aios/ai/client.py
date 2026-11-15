"""HTTP client for the Go control core.

The Python side has no policy engine, no executor, and no filesystem writes.
It can read aggregate observations for prompt context, validate a proposal,
ask the core for a dry-run decision, and post a proposal for execution. The
core decides what any of that means.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from aios.ai.catalog import Catalog
from aios.ai.env import load_dotenv
from aios.ai.protocol import ActionRequest

_OBSERVATION_ROUTES = {
    "system.status": "/system/status",
    "system.cpu": "/system/cpu",
    "system.memory": "/system/memory",
    "system.hostname": "/system/hostname",
    "process.list": "/processes",
    "network.connections": "/network/connections",
}


class ControlError(RuntimeError):
    """The core could not be reached or returned an unusable response."""


class ControlClient:
    def __init__(
        self,
        base_url: str | None = None,
        *,
        timeout_s: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        load_dotenv()
        self.base_url = (
            base_url or os.environ.get("AIOS_API_URL") or "http://127.0.0.1:8000"
        ).rstrip("/")
        self.timeout_s = timeout_s
        self._transport = transport
        self._catalog: Catalog | None = None

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=self.timeout_s, transport=self._transport)

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        try:
            with self._client() as client:
                response = client.get(f"{self.base_url}{path}", params=params)
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ControlError(f"GET {path} failed: {type(exc).__name__}") from exc
        if response.status_code >= 400:
            detail = payload.get("detail") if isinstance(payload, dict) else None
            raise ControlError(detail or f"GET {path} returned {response.status_code}")
        return payload

    def schema(self, *, refresh: bool = False) -> Catalog:
        if self._catalog is None or refresh:
            self._catalog = Catalog.from_schema(self._get("/actions/schema"))
        return self._catalog

    def observe(self, action: str, params: dict[str, Any] | None = None) -> Any:
        """Read one aggregate observation through the operator route."""
        if action == "process.inspect":
            pid = (params or {}).get("pid")
            if not isinstance(pid, int):
                raise ControlError("process.inspect requires an integer pid")
            return self._get(f"/processes/{pid}")["data"]
        route = _OBSERVATION_ROUTES.get(action)
        if route is None:
            raise ControlError(f"{action} is not an operator observation route")
        return self._get(route, params or {})["data"]

    def validate(self, request: ActionRequest) -> dict[str, Any]:
        return self._post("/actions/validate", request.to_payload())

    def execute(
        self, request: ActionRequest, *, dry_run: bool = False
    ) -> tuple[int, dict[str, Any]]:
        payload = request.to_payload()
        payload["dry_run"] = dry_run
        return self._post_status("/actions/execute", payload)

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        status, body = self._post_status(path, payload)
        if status >= 400:
            raise ControlError(body.get("detail") or f"POST {path} returned {status}")
        return body

    def _post_status(self, path: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        try:
            with self._client() as client:
                response = client.post(f"{self.base_url}{path}", json=payload)
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ControlError(f"POST {path} failed: {type(exc).__name__}") from exc
        if not isinstance(body, dict):
            raise ControlError(f"POST {path} returned a non-object response")
        return response.status_code, body


__all__ = ["ControlClient", "ControlError"]
