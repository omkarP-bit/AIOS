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
    DeniedError,
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
    "process.diagnose": "/processes/diagnose",
    "network.connections": "/network/connections",
    "network.status": "/network/status",
    "filesystem.usage": "/filesystem/usage",
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

    def diagnose(
        self,
        *,
        limit: int = 200,
        include_orphans: bool = True,
        top_n: int = 5,
    ) -> dict[str, Any]:
        return self.observe(
            "process.diagnose",
            {"limit": limit, "include_orphans": include_orphans, "top_n": top_n},
        )

    def network_status(self) -> dict[str, Any]:
        return self.observe(
            "network.status",
            {"include_wireless": True, "include_link_speed": True},
        )

    def disk(self) -> dict[str, Any]:
        return self.observe("filesystem.usage", {"include_pseudo": False})

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

    def build_plan(
        self,
        action: str,
        params: dict[str, Any],
        *,
        intent: str | None = None,
    ) -> dict[str, Any]:
        """Ask the core to build an exact, hash-bound plan.

        The caller supplies only the intent (pid/signal or connection). The
        core captures target identity and assigns plan and step ids; this
        client never computes a hash.
        """
        payload: dict[str, Any] = {"type": action, "params": params}
        if intent:
            payload["intent"] = intent
        body = self._post("/actions/plan", payload)[1]
        for key in ("plan_id", "plan_hash"):
            if not isinstance(body.get(key), str) or not body[key]:
                raise unexpected_response("/actions/plan")
        steps = body.get("steps")
        if not isinstance(steps, list) or not steps or not isinstance(steps[0], dict):
            raise unexpected_response("/actions/plan")
        return body

    def apply_plan(
        self,
        plan_id: str,
        plan_hash: str,
        step_id: str,
        *,
        action: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        payload: dict[str, Any] = {
            "plan_id": plan_id,
            "plan_hash": plan_hash,
            "step_id": step_id,
        }
        if action:
            payload["type"] = action
        status, body = self._post("/actions/apply", payload, verdict_statuses=True)
        _require_decision(body, "/actions/apply")
        return status, body

    # -- deterministic filesystem cleanup ------------------------------

    def filesystem_find(
        self,
        root: str,
        *,
        min_age_days: int = 0,
        min_size_bytes: int = 0,
        extensions: list[str] | None = None,
        max_results: int = 500,
    ) -> dict[str, Any]:
        """Run a read-only scan driven only by deterministic criteria."""
        payload: dict[str, Any] = {
            "root": root,
            "min_age_days": min_age_days,
            "min_size_bytes": min_size_bytes,
            "max_results": max_results,
        }
        if extensions:
            payload["extensions"] = extensions
        _status, body = self._post("/filesystem/find", payload, verdict_statuses=True)
        verdict = _cleanup_verdict(body, "/filesystem/find")
        return {"verdict": verdict, "scan": _object(body.get("scan"), "/filesystem/find")}

    def propose_cleanup(
        self,
        root: str,
        *,
        min_age_days: int = 0,
        min_size_bytes: int = 0,
        extensions: list[str] | None = None,
        max_results: int = 500,
    ) -> dict[str, Any]:
        """Ask the core to build an engine-owned cleanup plan from a scan."""
        payload: dict[str, Any] = {
            "root": root,
            "min_age_days": min_age_days,
            "min_size_bytes": min_size_bytes,
            "max_results": max_results,
        }
        if extensions:
            payload["extensions"] = extensions
        body = self._post("/plans", payload)[1]
        for key in ("plan_id", "plan_hash", "plan", "status"):
            if key not in body:
                raise unexpected_response("/plans")
        if not isinstance(body["plan"], dict):
            raise unexpected_response("/plans")
        _cleanup_verdict(body.get("verdict") or {}, "/plans")
        return body

    def get_plan(self, plan_id: str) -> dict[str, Any]:
        body = self._get(f"/plans/{plan_id}")
        if not isinstance(body.get("plan"), dict):
            raise unexpected_response(f"/plans/{plan_id}")
        return body

    def list_plans(self) -> list[dict[str, Any]]:
        body = self._get("/plans")
        plans = body.get("plans")
        if not isinstance(plans, list) or not all(isinstance(p, dict) for p in plans):
            raise unexpected_response("/plans")
        return plans

    def approve_cleanup(
        self, plan_id: str, plan_hash: str, operator: str = "operator-cli"
    ) -> dict[str, Any]:
        """Bind the typed exact hash to the stored plan. No paths are sent."""
        payload = {"plan_hash": plan_hash, "operator": operator}
        body = self._post(f"/plans/{plan_id}/approve", payload)[1]
        if not isinstance(body.get("plan"), dict):
            raise unexpected_response(f"/plans/{plan_id}/approve")
        return body

    def trash_cleanup(self, plan_id: str) -> dict[str, Any]:
        """Execute an approved plan. The request contains only the plan id."""
        _status, body = self._post(f"/plans/{plan_id}/trash", {}, verdict_statuses=True)
        verdict = _cleanup_verdict(body, f"/plans/{plan_id}/trash")
        return {"verdict": verdict, "plan": _object(body.get("plan"), "/plans/{id}/trash")}

    def restore_action(self, action_id: str) -> dict[str, Any]:
        """Restore every entry of one trash action, located by audit id."""
        _status, body = self._post(f"/restore/{action_id}", {}, verdict_statuses=True)
        verdicts = body.get("verdicts")
        if not isinstance(verdicts, list) or not verdicts:
            raise unexpected_response(f"/restore/{action_id}")
        for verdict in verdicts:
            if not isinstance(verdict, dict):
                raise unexpected_response(f"/restore/{action_id}")
            raise_for_verdict(verdict, f"/restore/{action_id}")
        return {"action_id": action_id, "verdicts": verdicts}


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise unexpected_response(path)
    return value


def _cleanup_verdict(body: dict[str, Any], path: str) -> dict[str, Any]:
    verdict = _object(body.get("verdict"), path)
    raise_for_verdict(verdict, path)
    return verdict


_UNAVAILABLE_REASONS = {
    "policy_unavailable",
    "audit_unavailable",
    "backend_unavailable",
}


def raise_for_verdict(verdict: dict[str, Any], path: str) -> None:
    decision = verdict.get("decision")
    if decision not in {"ALLOW", "CONFIRM", "DENY"}:
        raise unexpected_response(path)
    if decision != "DENY":
        return
    reason = str(verdict.get("denial_reason") or "")
    if reason in _UNAVAILABLE_REASONS:
        raise ServiceUnavailable(
            "AIOS is failing closed because a security service is unavailable.",
            next_step="Check `aios status` and the core logs, then retry.",
        )
    raise DeniedError(
        "The AIOS security policy denied this cleanup request.",
        next_step="Run `aios security` to see why, then adjust the request.",
        detail=reason or None,
    )


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
    "raise_for_verdict",
    "ensure_parent",
    "history_dir",
]
