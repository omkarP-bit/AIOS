"""Thin HTTP client for the Go control core.

This module never imports the gateway, never reads ``/proc``, and never runs a
subprocess. It sends requests, validates the shape of the response, and maps
transport problems to friendly CLI errors.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from aios.ai.catalog import Catalog
from aios.ai.protocol import ActionRequest
from aios.cli.errors import (
    CliError,
    ServiceUnavailable,
    api_timeout,
    api_unreachable,
    stale_core,
    unexpected_response,
)

_OBSERVATION_ROUTES = {
    "system.status": "/system/status",
    "system.cpu": "/system/cpu",
    "system.memory": "/system/memory",
    "system.hostname": "/system/hostname",
    "process.list": "/processes",
    "network.connections": "/network/connections",
}

_PROCESS_SORTS = {"cpu": "cpu", "mem": "memory", "memory": "memory", "pid": "pid", "name": "name"}


class CoreClient:
    """One configured connection to the AIOS core."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout_s: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self._transport = transport
        self._catalog: Catalog | None = None

    # -- transport -----------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        verdict_statuses: bool = False,
    ) -> tuple[int, dict[str, Any]]:
        try:
            with httpx.Client(timeout=self.timeout_s, transport=self._transport) as client:
                response = client.request(
                    method, f"{self.base_url}{path}", params=params, json=json_body
                )
        except httpx.TimeoutException as exc:
            raise api_timeout(self.base_url, self.timeout_s) from exc
        except httpx.HTTPError as exc:
            raise api_unreachable(self.base_url, exc) from exc

        try:
            body = response.json()
        except ValueError as exc:
            if response.status_code == 404:
                raise stale_core(path) from exc
            raise unexpected_response(path) from exc
        if not isinstance(body, dict):
            raise unexpected_response(path)
        if response.status_code >= 500:
            detail = body.get("detail") or body.get("error") or "internal error"
            raise ServiceUnavailable(
                f"The AIOS core failed while handling {path}: {detail}",
                next_step="Check the core logs, then retry.",
            )
        if response.status_code >= 400 and not (verdict_statuses and response.status_code == 403):
            detail = body.get("detail") or body.get("error") or f"HTTP {response.status_code}"
            if body.get("error") == "refused" and body.get("detail"):
                detail = str(body["detail"])
            raise CliError(
                f"The AIOS core rejected {path}: {detail}",
                next_step="Check the request values, then retry.",
            )
        return response.status_code, body

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("GET", path, params=params)[1]

    def _post(
        self, path: str, payload: dict[str, Any], *, verdict_statuses: bool = False
    ) -> tuple[int, dict[str, Any]]:
        return self._request("POST", path, json_body=payload, verdict_statuses=verdict_statuses)

    # -- observations --------------------------------------------------

    def observe(self, action: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Read one aggregate observation. This mirrors the AI context client."""
        if action == "process.inspect":
            pid = (params or {}).get("pid")
            if not isinstance(pid, int):
                raise CliError("process.inspect needs an integer pid", next_step="Pass --pid N.")
            body = self._get(f"/processes/{pid}")
            return _data(body, f"/processes/{pid}")
        route = _OBSERVATION_ROUTES.get(action)
        if route is None:
            raise CliError(f"{action} is not an operator observation route")
        return _data(self._get(route, params or {}), route)

    def status(self) -> dict[str, Any]:
        return self.observe("system.status")

    def cpu(self, interval_s: float = 0.25) -> dict[str, Any]:
        return self.observe("system.cpu", {"interval_s": interval_s})

    def memory(self, *, include_fields: bool = False) -> dict[str, Any]:
        return self.observe("system.memory", {"include_fields": include_fields})

    def processes(
        self,
        *,
        limit: int = 50,
        sort_by: str = "cpu",
        name_filter: str | None = None,
    ) -> dict[str, Any]:
        api_sort = _PROCESS_SORTS.get(sort_by)
        if api_sort is None:
            raise CliError(f"unknown sort {sort_by!r}", next_step="Use cpu, mem, pid, or name.")
        params: dict[str, Any] = {"limit": limit, "sort_by": api_sort}
        if name_filter:
            params["name_filter"] = name_filter
        return self.observe("process.list", params)

    def network(self, *, limit: int = 200, listening_only: bool = False) -> dict[str, Any]:
        return self.observe(
            "network.connections",
            {"limit": limit, "listening_only": listening_only, "attribute_pids": True},
        )

    # -- operator views ------------------------------------------------

    def health(self) -> dict[str, Any]:
        body = self._get("/health")
        if not isinstance(body.get("services"), dict):
            raise unexpected_response("/health")
        return body

    def audit(self, *, limit: int = 100, denied: bool = False) -> list[dict[str, Any]]:
        body = self._get("/audit", {"limit": limit, "denied": "true" if denied else "false"})
        entries = body.get("entries")
        if not isinstance(entries, list):
            raise unexpected_response("/audit")
        return [entry for entry in entries if isinstance(entry, dict)]

    def security_summary(self) -> dict[str, Any]:
        body = self._get("/security/summary")
        if not isinstance(body.get("counts"), dict) or not isinstance(body.get("services"), dict):
            raise unexpected_response("/security/summary")
        return body

    # -- actions -------------------------------------------------------

    def schema(self, *, refresh: bool = False) -> Catalog:
        if self._catalog is None or refresh:
            try:
                self._catalog = Catalog.from_schema(self._get("/actions/schema"))
            except (ValueError, TypeError) as exc:
                raise unexpected_response("/actions/schema") from exc
        return self._catalog

    def validate(self, request: ActionRequest) -> dict[str, Any]:
        body = self._post("/actions/validate", request.to_payload())[1]
        if not isinstance(body.get("valid"), bool):
            raise unexpected_response("/actions/validate")
        return body

    def propose(self, request: ActionRequest) -> tuple[int, dict[str, Any]]:
        status, body = self._post("/actions/propose", request.to_payload(), verdict_statuses=True)
        _require_decision(body, "/actions/propose")
        return status, body

    def confirm(self, request: ActionRequest) -> tuple[int, dict[str, Any]]:
        status, body = self._post("/actions/confirm", request.to_payload(), verdict_statuses=True)
        _require_decision(body, "/actions/confirm")
        return status, body

    def execute(
        self, request: ActionRequest, *, dry_run: bool = False
    ) -> tuple[int, dict[str, Any]]:
        payload = request.to_payload()
        payload["dry_run"] = dry_run
        status, body = self._post("/actions/execute", payload, verdict_statuses=True)
        _require_decision(body, "/actions/execute")
        return status, body


def _data(body: dict[str, Any], path: str) -> dict[str, Any]:
    data = body.get("data")
    if not isinstance(data, dict):
        raise unexpected_response(path)
    return data


def _require_decision(body: dict[str, Any], path: str) -> None:
    decision = body.get("decision")
    if decision not in {"ALLOW", "CONFIRM", "DENY"}:
        raise unexpected_response(path)


def client_from_config(config: Any) -> CoreClient:
    return CoreClient(config.api_url, timeout_s=config.timeout_s)


def history_dir(path: Path) -> Path:
    return path.parent


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)


__all__ = [
    "CoreClient",
    "client_from_config",
    "ensure_parent",
    "history_dir",
]
