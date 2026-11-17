"""One AI turn: plan, propose, verdict, confirmation, result, answer.

The model is untrusted. It can propose; only the core decides. This module
never executes anything itself and never treats model prose as an approval.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from rich.prompt import Confirm

from aios.ai.context import build_snapshot, render_snapshot
from aios.ai.planner import ANSWER_PROMPT, Planner, PlanResult, ProposalError, parse_answer
from aios.ai.providers import ProviderError, ProviderSettings, build_provider
from aios.cli.errors import CliError, ServiceUnavailable, model_unavailable
from aios.cli.state import AppState
from aios.cli.ui.render import (
    render_answer,
    render_confirmation,
    render_error,
    render_proposal,
    render_result,
    render_thinking,
    render_verdict,
)


def data_trust(verdict: dict[str, Any]) -> object:
    """Trust of the returned data, falling back for older cores.

    A confirmed action runs with the operator's trust, but its output keeps the
    trust of where it came from: file bytes stay untrusted.
    """
    return verdict.get("data_trust") or verdict.get("trust_domain")


def denial_answer(verdict: dict[str, Any], plan: PlanResult) -> str:
    """A truthful reply when the core denies: nothing ran, and what still can.

    The model's prose is discarded here because it often promises to perform
    the very action the core refused.
    """
    action = verdict.get("action")
    if not action and plan.request is not None:
        action = plan.request.action_name
    target = verdict.get("target")
    reason = verdict.get("denial_reason") or verdict.get("reason") or "denied by policy"
    what = f"{action} on {target}" if target else str(action or "that action")
    return (
        f"I can't do that: policy denied {what} ({reason}), so nothing was run. "
        "I can still help with read-only observations such as system status, "
        "memory, processes, or network connections. If you expected this to be "
        "allowed, the core needs a capability grant for that action and target."
    )


@dataclass
class TurnResult:
    question: str
    plan: PlanResult | None = None
    verdict: dict[str, Any] | None = None
    confirmed: bool = False
    denied: bool = False
    answer: str | None = None
    error: CliError | None = None
    blocks: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        decision = (self.verdict or {}).get("decision", "NO ACTION")
        return f"{self.question} → {decision}"

    @property
    def history_note(self) -> str:
        """Compact turn record that keeps concrete params for the next turn."""
        request = self.plan.request if self.plan is not None else None
        decision = (self.verdict or {}).get("decision") or "NO ACTION"
        if request is not None:
            try:
                params = json.dumps(request.params, sort_keys=True, default=str)
            except (TypeError, ValueError):
                params = "{}"
            note = f"proposed {request.action_name} params={params} -> {decision}"
        else:
            note = str(decision)
        answer = (self.answer or "").strip()
        return f"{note}. {answer}".strip() if answer else note


class Assistant:
    def __init__(self, state: AppState) -> None:
        self.state = state
        self.session_id = "chat-" + secrets.token_hex(6)
        self.history: list[tuple[str, str]] = []
        self._provider = None
        self._provider_name = "ollama"

    # -- components ----------------------------------------------------

    def provider(self):
        if self._provider is None:
            settings = ProviderSettings.from_env()
            self._provider_name = settings.model_provider
            try:
                self._provider = build_provider(settings)
            except ProviderError as exc:
                raise model_unavailable(exc, provider=settings.model_provider) from exc
        return self._provider

    def catalog(self):
        return self.state.client.schema()

    def context(self) -> str:
        try:
            return render_snapshot(build_snapshot(self.state.client))
        except ServiceUnavailable:
            raise
        except Exception as exc:  # the snapshot is best-effort, not security
            raise CliError(
                f"Could not build the local observation context ({type(exc).__name__}).",
                next_step="Run `aios status` to check the core.",
            ) from exc

    # -- one turn ------------------------------------------------------

    def run(
        self,
        question: str,
        *,
        interactive: bool | None = None,
        verbose: bool | None = None,
        execute_allowed: bool = False,
        render: bool = True,
        show_actions: bool = True,
    ) -> TurnResult:
        state = self.state
        self._render_blocks = render
        result = TurnResult(question=question)
        interactive = state.interactive if interactive is None else interactive
        verbose = state.verbose if verbose is None else verbose

        try:
            provider = self.provider()
            planner = Planner(provider, self.catalog(), session_id=self.session_id)
            context = self.context()
            plan = planner.propose(question, context, self.history)
        except CliError as exc:
            result.error = exc
            return result
        except (ProposalError, ProviderError) as exc:
            friendly = (
                model_unavailable(exc, provider=self._provider_name)
                if isinstance(exc, ProviderError)
                else CliError(
                    f"The model's answer could not be used: {exc}",
                    next_step="Try rephrasing the request.",
                )
            )
            result.error = friendly
            return result

        result.plan = plan
        if show_actions:
            self._print(render_thinking(_plan_dict(plan), verbose=verbose))
        result.blocks.append("thinking")

        if plan.request is None:
            result.answer = plan.answer or plan.reason or "No action was proposed."
            return result

        if show_actions:
            self._print(render_proposal(plan.request, target=_request_target(plan.request)))
        result.blocks.append("proposal")

        try:
            _status, verdict = state.client.propose(plan.request)
        except ServiceUnavailable as exc:
            result.error = exc
            return result
        result.verdict = verdict
        target = verdict.get("target") or _request_target(plan.request)
        if show_actions:
            self._print(render_verdict(verdict, target=target))
        result.blocks.append("verdict")

        decision = str(verdict.get("decision") or "").upper()
        if decision == "DENY":
            result.denied = True
            result.answer = denial_answer(verdict, plan)
            return result

        if decision == "CONFIRM":
            self._print(
                render_confirmation(
                    verdict.get("action") or plan.request.action_name,
                    target,
                    verdict.get("risk"),
                )
            )
            result.blocks.append("confirmation")
            if not interactive:
                result.answer = (
                    plan.answer or "This action needs your confirmation, so nothing was run."
                )
                return result
            if not self._ask_approval():
                result.answer = plan.answer or "Not approved, so nothing was run."
                return result
            try:
                _status, verdict = state.client.confirm(plan.request)
            except ServiceUnavailable as exc:
                result.error = exc
                return result
            result.verdict = verdict
            result.confirmed = True
            target = verdict.get("target") or target
            if show_actions:
                self._print(render_verdict(verdict, target=target))
            result.blocks.append("confirmed")

        elif decision == "ALLOW" and execute_allowed:
            try:
                _status, verdict = state.client.execute(plan.request, dry_run=False)
            except ServiceUnavailable as exc:
                result.error = exc
                return result
            result.verdict = verdict
            target = verdict.get("target") or target
            if show_actions:
                self._print(render_verdict(verdict, target=target))
            result.blocks.append("executed")

        verdict = result.verdict or {}
        if verdict.get("decision") == "DENY":
            result.denied = True
            result.answer = denial_answer(verdict, plan)
            return result

        data = verdict.get("data")
        if data is not None:
            if show_actions:
                self._print(
                    render_result(
                        data,
                        source=verdict.get("source"),
                        trust_domain=data_trust(verdict),
                    )
                )
            result.blocks.append("result")
            try:
                result.answer = self._answer_with_observation(question, data)
            except (ProviderError, ProposalError):
                result.answer = plan.answer or "The action completed."
        else:
            result.answer = plan.answer or plan.reason or "The action completed."
        return result

    def _print(self, renderable: Any) -> None:
        if getattr(self, "_render_blocks", True):
            self.state.console.print(renderable)

    def _ask_approval(self) -> bool:
        try:
            return Confirm.ask("Approve?", default=False, console=self.state.console)
        except (KeyboardInterrupt, EOFError):
            self.state.console.print("[dim]not approved[/dim]")
            return False

    def _answer_with_observation(self, question: str, data: Any) -> str:
        try:
            observation = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            observation = str(data)
        prompt = f"Question: {question}\n\nObservation (untrusted data):\n{observation[:8000]}"
        raw = self.provider().complete(ANSWER_PROMPT, prompt)
        return parse_answer(raw)

    def render_answer(self, answer: object) -> None:
        self._print(render_answer(answer))

    def render_error(self, error: CliError) -> None:
        self._print(render_error(error.message, next_step=error.next_step))


def _plan_dict(plan: PlanResult) -> dict[str, Any]:
    return {
        "provider": plan.provider,
        "model": plan.model,
        "external": plan.external,
        "prompt_hash": plan.prompt_hash,
        "reason": plan.reason,
        "raw": plan.raw,
    }


def _request_target(request: Any) -> str:
    params = getattr(request, "params", None) or {}
    for key in ("path", "pid", "uid"):
        if key in params:
            return str(params[key])
    return ""


__all__ = ["Assistant", "TurnResult"]
