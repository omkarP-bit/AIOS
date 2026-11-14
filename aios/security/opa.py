"""OPA policy client. Any failure is a DENY, never an ALLOW."""

from __future__ import annotations

import time
from typing import Any

import httpx

from aios.models.actions import ActionRequest
from aios.security.capabilities import RiskClass
from aios.security.engine import Decision, PolicyDecision
from aios.security.policy_input import build_policy_input


class OpaPolicyEngine:
    def __init__(
        self,
        url: str,
        timeout_s: float = 2.0,
        decision_path: str = "aios/authz/decision",
    ) -> None:
        self.url = url.rstrip("/")
        self.timeout_s = timeout_s
        self.decision_path = decision_path.strip("/")

    def evaluate(
        self,
        request: ActionRequest,
        risk: RiskClass,
        capability: Any | None = None,
        *,
        plan: Any | None = None,
        approval: Any | None = None,
    ) -> PolicyDecision:
        started = time.perf_counter()
        document = build_policy_input(
            request, risk, capability, plan=plan, approval=approval
        )
        try:
            response = httpx.post(
                f"{self.url}/v1/data/{self.decision_path}",
                json={"input": document},
                timeout=self.timeout_s,
            )
            response.raise_for_status()
            payload = response.json()
            result = payload.get("result")
            if not isinstance(result, dict):
                raise ValueError("policy response has no result object")
            decision = Decision(str(result.get("decision", "")))
            if decision not in (Decision.ALLOW, Decision.DENY, Decision.CONFIRM):
                raise ValueError("policy response has an unknown decision")
            return PolicyDecision(
                decision=decision,
                reason=str(result.get("reason", ""))[:1000],
                risk=risk,
                source="opa",
                policy_id=result.get("policy_id"),
                input_doc=document,
                latency_ms=(time.perf_counter() - started) * 1000.0,
            )
        except Exception as exc:
            return PolicyDecision(
                decision=Decision.DENY,
                reason=f"OPA unavailable: {type(exc).__name__}",
                risk=risk,
                source="opa:unavailable",
                input_doc=document,
                latency_ms=(time.perf_counter() - started) * 1000.0,
            )

    def health(self) -> dict[str, Any]:
        try:
            response = httpx.get(f"{self.url}/health", timeout=self.timeout_s)
            response.raise_for_status()
            return {"ok": True, "status": response.text[:200]}
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


__all__ = ["OpaPolicyEngine"]
