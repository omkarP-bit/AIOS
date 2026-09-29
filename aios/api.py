"""FastAPI control API.

Two deliberately separate surfaces, and the difference matters:

**Operator observation** — ``GET /system/*``, ``/processes*``,
``/network/connections``. These call ``OSGateway`` directly. They are the
local human's view of the machine, they are read-only, and they do not
consume capabilities. That is fine because the caller is the operator, not
the model.

**Agent action** — ``POST /actions/validate`` and ``POST /actions/execute``.
These go through the ``SecurityEngine``: protocol validation, scope
consistency, capability check, policy, then execution, with every step
written to the ledger. An agent may not reach the gateway any other way.

The split is the whole point. If the read routes also went through the
capability check, the operator could not look at their own machine without a
grant; if the agent could reach them, a grant would not mean anything. The
agent path is the one that is fenced.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from aios.config import Settings, get_settings
from aios.db.session import ledger_status
from aios.gateway import (
    ActionNotPermitted,
    OSGateway,
    PreconditionFailed,
)
from aios.models import (
    FORBIDDEN_ACTION_NAMES,
    PARAMS_MAP,
    ActionRequest,
    ActionState,
    ActionType,
    DataOrigin,
)
from aios.observers.process import ProcessNotFound
from aios.runtime import security_engine
from aios.security import Decision, SecurityEngine

API_TITLE = "AIOS Control API"
API_VERSION = "0.4.0"


def get_gateway(request: Request) -> OSGateway:
    """Gateway instance bound to the app's configured roots.

    Stored on app.state rather than built per request, so the CPU observer
    keeps its previous sample and utilisation is actually a delta.
    """
    gateway = getattr(request.app.state, "gateway", None)
    if gateway is None:
        settings: Settings = request.app.state.settings
        gateway = OSGateway(
            proc_root=settings.proc_root,
            sys_root=settings.sys_root,
            max_read_bytes=settings.max_read_bytes,
            max_dir_entries=settings.max_dir_entries,
        )
        request.app.state.gateway = gateway
    return gateway


GatewayDep = Annotated[OSGateway, Depends(get_gateway)]


def get_security_engine(request: Request) -> Iterator[SecurityEngine]:
    """A security engine bound to this request's ledger session.

    Wiring lives in :mod:`aios.runtime` so the CLI's agent path and this one
    cannot drift — which they did, until the CLI's actions were going to an
    in-memory ledger while the API's went to PostgreSQL.
    """
    with security_engine(
        request.app.state.settings, get_gateway(request)
    ) as engine:
        yield engine


EngineDep = Annotated[SecurityEngine, Depends(get_security_engine)]


class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    error: str
    detail: str | None = None


class ValidateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    valid: bool
    action_id: str | None = None
    type: str | None = None
    validated_params: dict[str, Any] | None = None
    trust_domain: str | None = None
    #: A rejected proposal terminates at DENIED, matching the lifecycle.
    state: str = ActionState.VALIDATED.value
    error: str | None = None
    detail: str | None = None


class ActionSchemaResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol_version: str
    allowed_actions: list[str]
    forbidden_actions: list[str]
    params_schema: dict[str, Any]


class ExecuteRequest(BaseModel):
    """An agent's proposal, plus who is making it.

    ``agent_id`` and ``origin`` are inputs to the decision, not decoration:
    the capability check is per-agent, and ``origin`` decides the trust
    domain that governs path-shaped actions. Both are therefore validated
    against closed sets rather than passed through as free strings.
    """

    model_config = ConfigDict(extra="forbid")

    action_id: str
    type: str
    params: dict[str, Any] = {}
    agent_id: str = "local-agent"
    session_id: str = "api"
    origin: str = "ai"
    requested_scope: dict[str, Any] = {}
    intent: str | None = None
    #: Check and log, but do not run. Always safe to pass.
    dry_run: bool = False


class ExecuteResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str
    action: str
    state: str
    decision: str
    risk: str
    reason: str
    denial_reason: str | None = None
    agent_id: str
    trust_domain: str
    capability: str | None = None
    source: str | None = None
    duration_ms: float | None = None
    executed: bool = False
    data: dict[str, Any] | None = None


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(
        title=API_TITLE,
        version=API_VERSION,
        description=(
            "Read-only control plane. Execution requires the security engine; "
            "this API cannot be used to run a privileged action."
        ),
    )
    app.state.settings = settings
    app.state.gateway = None
    # Resolved once at startup rather than per request, and only counts as
    # durable if the schema actually exists. Discovering it later would mean
    # reporting a durable audit trail while every insert is throwing.
    status = ledger_status()
    app.state.ledger_backend = status["backend"]
    app.state.ledger_reason = status["reason"]

    def run(gateway: OSGateway, request: ActionRequest):
        """Execute and shape the response, translating gateway errors to 4xx."""
        try:
            observation, duration_ms = gateway.execute_timed(request)
        except (ActionNotPermitted, PreconditionFailed, ProcessNotFound) as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "action_id": request.action_id,
            "state": ActionState.EXECUTED.value,
            "success": True,
            "source": observation.source,
            "trust_domain": observation.trust_domain.value,
            "timestamp": observation.timestamp,
            "duration_ms": round(duration_ms, 3),
            "data": observation.data,
        }

    @app.exception_handler(ValueError)
    async def _value_error(_request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "detail": str(exc)},
        )

    # ------------------------------------------------------------ meta

    @app.get("/health", tags=["meta"])
    def health() -> dict[str, Any]:
        backend = app.state.ledger_backend
        return {
            "status": "ok",
            "version": API_VERSION,
            "proc_root": str(settings.proc_root),
            "gateway_actions": len(OSGateway(settings.proc_root).supported_actions),
            # Surfaced because an in-memory ledger means the audit trail is
            # lost when the process exits. A degraded mode an operator cannot
            # see is not a degraded mode they can act on.
            "ledger": backend,
            "ledger_durable": backend == "postgres",
            "ledger_detail": app.state.ledger_reason,
        }

    @app.get("/actions/schema", response_model=ActionSchemaResponse, tags=["meta"])
    def action_schema() -> ActionSchemaResponse:
        return ActionSchemaResponse(
            protocol_version=API_VERSION,
            allowed_actions=sorted(PARAMS_MAP),
            forbidden_actions=sorted(FORBIDDEN_ACTION_NAMES),
            params_schema={
                name: model.model_json_schema()
                for name, model in sorted(PARAMS_MAP.items())
            },
        )

    # ------------------------------------------------------------ system

    @app.get("/system/status", tags=["system"])
    def system_status(gateway: GatewayDep) -> dict[str, Any]:
        return run(
            gateway,
            ActionRequest(
                action_id="api-system-status",
                agent_id="api-client",
                session_id="api",
                type=ActionType.SYSTEM_STATUS,
            ),
        )

    @app.get("/system/cpu", tags=["system"])
    def system_cpu(
        gateway: GatewayDep,
        interval_s: Annotated[float, Query(ge=0.0, le=5.0)] = 0.25,
    ) -> dict[str, Any]:
        return run(
            gateway,
            ActionRequest(
                action_id="api-system-cpu",
                agent_id="api-client",
                session_id="api",
                type=ActionType.SYSTEM_CPU,
                params={"interval_s": interval_s},
            ),
        )

    @app.get("/system/memory", tags=["system"])
    def system_memory(
        gateway: GatewayDep, include_fields: bool = False
    ) -> dict[str, Any]:
        return run(
            gateway,
            ActionRequest(
                action_id="api-system-memory",
                agent_id="api-client",
                session_id="api",
                type=ActionType.SYSTEM_MEMORY,
                params={"include_fields": include_fields},
            ),
        )

    @app.get("/system/hostname", tags=["system"])
    def system_hostname(gateway: GatewayDep) -> dict[str, Any]:
        return run(
            gateway,
            ActionRequest(
                action_id="api-system-hostname",
                agent_id="api-client",
                session_id="api",
                type=ActionType.SYSTEM_HOSTNAME,
            ),
        )

    # ------------------------------------------------------------ processes

    @app.get("/processes", tags=["process"])
    def list_processes(
        gateway: GatewayDep,
        limit: Annotated[int, Query(ge=1, le=1000)] = 50,
        sort_by: str = Query("cpu", pattern="^(cpu|memory|pid|name)$"),
        name_filter: Annotated[str | None, Query(max_length=64)] = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit, "sort_by": sort_by}
        if name_filter:
            params["name_filter"] = name_filter
        return run(
            gateway,
            ActionRequest(
                action_id="api-process-list",
                agent_id="api-client",
                session_id="api",
                type=ActionType.PROCESS_LIST,
                params=params,
            ),
        )

    @app.get("/processes/{pid}", tags=["process"])
    def inspect_process(
        gateway: GatewayDep,
        pid: Annotated[int, Path(ge=1, le=4_194_303)],
    ) -> dict[str, Any]:
        return run(
            gateway,
            ActionRequest(
                action_id=f"api-process-inspect-{pid}",
                agent_id="api-client",
                session_id="api",
                type=ActionType.PROCESS_INSPECT,
                params={"pid": pid},
            ),
        )

    # ------------------------------------------------------------ network

    @app.get("/network/connections", tags=["network"])
    def network_connections(
        gateway: GatewayDep,
        limit: Annotated[int, Query(ge=1, le=2000)] = 200,
        listening_only: bool = False,
        attribute_pids: bool = True,
    ) -> dict[str, Any]:
        return run(
            gateway,
            ActionRequest(
                action_id="api-network-connections",
                agent_id="api-client",
                session_id="api",
                type=ActionType.NETWORK_CONNECTIONS,
                params={
                    "limit": limit,
                    "listening_only": listening_only,
                    "attribute_pids": attribute_pids,
                },
            ),
        )

    # ------------------------------------------------------------ actions

    @app.post("/actions/validate", response_model=ValidateResponse, tags=["actions"])
    def validate_action(payload: dict[str, Any]) -> ValidateResponse:
        """Parse and validate an AI proposal. Never executes anything.

        This is the endpoint the AI path calls before authorization: if it
        returns valid=false, the proposal is rejected and no further work is
        done. Parsing is strict — unknown types, unknown params, and forbidden
        action names all fail here.
        """
        raw_type = payload.get("type")
        if isinstance(raw_type, str) and raw_type in FORBIDDEN_ACTION_NAMES:
            return ValidateResponse(
                valid=False,
                state=ActionState.DENIED.value,
                error="forbidden_action",
                detail=f"{raw_type} is not permitted by the AIOS action protocol",
            )
        if isinstance(raw_type, str) and raw_type not in PARAMS_MAP:
            return ValidateResponse(
                valid=False,
                state=ActionState.DENIED.value,
                error="unknown_action",
                detail=f"unknown action type: {raw_type!r}",
            )
        try:
            request = ActionRequest.model_validate(payload)
        except Exception as exc:
            return ValidateResponse(
                valid=False,
                state=ActionState.DENIED.value,
                error="invalid_action",
                detail=str(exc)[:1000],
            )
        return ValidateResponse(
            valid=True,
            action_id=request.action_id,
            type=request.action_name,
            validated_params=request.typed_params.model_dump(),
            trust_domain=request.trust_domain.value,
        )

    @app.post("/actions/execute", response_model=ExecuteResponse, tags=["actions"])
    def execute_action(payload: ExecuteRequest, engine: EngineDep):
        """The only path from an agent proposal to the OS.

        Nothing here interprets the action. The engine validates the
        protocol, checks the capability, asks policy, and only then calls the
        gateway; this handler's whole job is to turn the verdict into a
        response. A denial is a well-formed answer, not an error, so the
        verdict body is returned in both cases and the status code only
        distinguishes them for convenience.
        """
        try:
            origin = DataOrigin(payload.origin)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"unknown origin {payload.origin!r}; expected one of "
                + ", ".join(o.value for o in DataOrigin),
            ) from None
        try:
            request = ActionRequest(
                action_id=payload.action_id,
                agent_id=payload.agent_id,
                session_id=payload.session_id,
                type=ActionType(payload.type),
                params=payload.params,
                origin=origin,
                requested_scope=payload.requested_scope,
                intent=payload.intent,
            )
        except ValueError as exc:
            # Malformed proposals are rejected at the edge rather than being
            # handed to the engine as a half-built request.
            raise HTTPException(status_code=400, detail=str(exc)[:1000]) from exc

        verdict = engine.authorize(request) if payload.dry_run else engine.process(request)
        body = ExecuteResponse(
            action_id=verdict.action_id,
            action=verdict.action,
            state=verdict.state.value,
            decision=verdict.decision.value,
            risk=verdict.risk.value,
            reason=verdict.reason[:1000],
            denial_reason=verdict.denial_reason.value if verdict.denial_reason else None,
            agent_id=request.agent_id,
            trust_domain=request.trust_domain.value,
            capability=verdict.capability.matched_capability if verdict.capability else None,
            source=verdict.observation.source if verdict.observation else None,
            duration_ms=round(verdict.duration_ms, 3) if verdict.duration_ms else None,
            executed=verdict.observation is not None,
            data=(
                verdict.observation.data.model_dump()
                if verdict.observation and hasattr(verdict.observation.data, "model_dump")
                else verdict.observation.data
                if verdict.observation
                else None
            ),
        )
        if verdict.decision is Decision.DENY:
            return JSONResponse(
                status_code=403,
                content=body.model_dump(),
                headers={"X-AIOS-Reason": body.denial_reason or "denied"},
            )
        return body

    return app


app = create_app()
