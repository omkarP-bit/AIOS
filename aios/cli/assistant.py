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
    render_cleanup_plan,
    render_confirmation,
    render_error,
    render_plan,
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
    """A truthful reply when the core denies: nothing ran, and what is needed.

    The model's prose is discarded here because it often promises to perform
    the very action the core refused. The guidance names the real gate: an
    exact capability grant, or an operator-approved mutation plan.
    """
    action = verdict.get("action")
    if not action and plan.request is not None:
        action = plan.request.action_name
    target = verdict.get("target")
    code = str(verdict.get("denial_reason") or "")
    reason = code or verdict.get("reason") or "denied by policy"
    what = f"{action} on {target}" if target else str(action or "that action")
    denied = f"I can't do that: policy denied {what} ({reason}), so nothing was run."

    if code == "forbidden_action":
        guidance = "That action is permanently forbidden and cannot be granted."
    elif code in {
        "approval_missing",
        "approval_invalid",
        "approval_expired",
        "approval_plan_mismatch",
        "plan_contains_forbidden_step",
    }:
        guidance = (
            "Mutations need an operator-approved plan and its exact plan hash; "
            "the AI cannot approve one. See `aios-core cleanup --help`."
        )
    elif action == "filesystem.cleanup_scan":
        guidance = (
            "Capabilities are deny-by-default and scoped to an exact action and "
            "path. The operator flow `aios-core cleanup scan PATH --plan-out "
            "plan.json` grants the scan for that path and writes an approvable "
            "plan; moving or restoring files still needs that plan approved."
        )
    elif action in {"filesystem.quarantine", "filesystem.restore"}:
        guidance = (
            "Mutations need an operator-approved plan and its exact plan hash; "
            "the AI cannot approve one. See `aios-core cleanup --help`."
        )
    else:
        guidance = (
            "Capabilities are deny-by-default: the core needs a grant for this "
            "exact action and target. Ask the operator to grant it, or use the "
            "operator CLI."
        )
    return f"{denied} {guidance}"


def proposal_failure(exc: CliError, action: str) -> CliError:
    """Make an invalid-proposal reply name the missing input.

    The core is right to reject a pathless filesystem request: a scan must be
    bound to an exact root. The generic "check the request values" hint does
    not tell the operator what to do next, so say it plainly.
    """
    if action.startswith("filesystem.") and "path must not be empty" in exc.message:
        return CliError(
            "That request needs an explicit directory, and none was given, "
            "so nothing was scanned or removed.",
            next_step=(
                "Name a directory, for example: aios ask 'find files in "
                "~/Downloads not modified in 29 days'. The operator cleanup "
                "flow is: aios-core cleanup scan PATH --min-age-days 29 "
                "--plan-out plan.json"
            ),
        )
    return exc


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
    approval_plan: dict[str, Any] | None = None

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
                f"Could not build the local observation context: {exc}",
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

        if self.catalog().needs_plan(plan.request.action_name):
            return self._plan_action_turn(
                question,
                plan,
                result,
                interactive=interactive,
                show_actions=show_actions,
            )

        try:
            _status, verdict = state.client.propose(plan.request)
        except ServiceUnavailable as exc:
            result.error = exc
            return result
        except CliError as exc:
            result.error = proposal_failure(exc, plan.request.action_name)
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

    def _cleanup_plan_turn(
        self,
        question: str,
        plan: PlanResult,
        result: TurnResult,
        *,
        show_actions: bool,
    ) -> TurnResult:
        """Return a cleanup plan for separate approval; never trash from chat.

        Only deterministic criteria are forwarded. A missing directory fails
        closed with a request to name one -- chat never falls back to `/`.
        """
        request = plan.request
        if request is None:
            result.answer = "No action was proposed."
            return result
        criteria = _cleanup_criteria(request.params)
        if criteria is None:
            result.answer = (
                "Name a directory to scan, for example 'files in ~/Downloads "
                "not modified in 30 days'. I will show a plan; nothing is moved "
                "until you approve it separately with `aios clean`."
            )
            return result
        try:
            planned = self.state.client.propose_cleanup(
                criteria["root"],
                min_age_days=criteria.get("min_age_days", 0),
                min_size_bytes=criteria.get("min_size_bytes", 0),
                extensions=criteria.get("extensions", []),
                max_results=criteria.get("max_results", 500),
            )
        except CliError as exc:
            result.denied = True
            result.answer = exc.message
            return result
        result.approval_plan = planned
        plan_data = planned.get("plan") or {}
        if show_actions:
            self._print(render_cleanup_plan(plan_data))
        result.blocks.append("plan")
        result.answer = (
            f"I prepared cleanup plan {planned.get('plan_id')} "
            f"(hash {planned.get('plan_hash')}) for {plan_data.get('file_count', 0)} files. "
            "Nothing was moved. Review it, then approve separately with "
            f"`aios clean {criteria['root']} --approve`."
        )
        return result

    def _plan_action_turn(
        self,
        question: str,
        plan: PlanResult,
        result: TurnResult,
        *,
        interactive: bool,
        show_actions: bool,
    ) -> TurnResult:
        """Build, show, and only then apply an exact plan for a mutation.

        The model proposes; the core builds the hash-bound plan; the operator
        sees every step and approves that hash. A non-interactive turn stops
        after the plan and never applies it.
        """
        request = plan.request
        if request is None:
            result.answer = "No action was proposed."
            return result

        # A trash proposal is never applied from chat. The core derives the
        # target list from a deterministic scan and returns a cleanup plan for
        # a separate, explicit operator approval. The model cannot supply paths
        # or approve the plan itself.
        if request.action_name in {"filesystem.trash", "filesystem.quarantine"}:
            return self._cleanup_plan_turn(question, plan, result, show_actions=show_actions)

        params = _plan_intent_params(request.action_name, request.params)
        try:
            planned = self.state.client.build_plan(
                request.action_name, params, intent=request.intent
            )
        except CliError as exc:
            result.denied = True
            result.answer = _plan_failure(request.action_name, params, exc.message)
            return result

        result.approval_plan = planned
        if show_actions:
            self._print(render_plan(planned))
        result.blocks.append("plan")

        plan_id = str(planned.get("plan_id"))
        plan_hash = str(planned.get("plan_hash"))
        steps = planned.get("steps") or []
        step_id = str(steps[0].get("step_id")) if steps and isinstance(steps[0], dict) else ""

        if not interactive:
            result.answer = (
                f"I prepared plan {plan_id} (hash {plan_hash}), but did not run it. "
                "A mutation needs the operator's explicit approval of that exact hash. "
                f"Review it, then run `aios apply {plan_id} --plan-hash {plan_hash} "
                f"--step-id {step_id}`."
            )
            return result

        if not self._ask_plan_approval():
            result.answer = "Not approved, so nothing was run."
            return result

        try:
            _status, verdict = self.state.client.apply_plan(
                plan_id, plan_hash, step_id, action=request.action_name
            )
        except CliError as exc:
            result.error = exc
            return result
        result.verdict = verdict
        result.confirmed = True
        target = verdict.get("target") or planned.get("target")
        if show_actions:
            self._print(render_verdict(verdict, target=str(target or "")))
        result.blocks.append("approved")

        if str(verdict.get("decision") or "").upper() == "DENY":
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
                result.answer = plan.answer or "The approved plan completed."
        else:
            result.answer = plan.answer or "The approved plan completed."
        return result

    def _ask_plan_approval(self) -> bool:
        try:
            return Confirm.ask(
                "Approve this exact plan hash and run it?",
                default=False,
                console=self.state.console,
            )
        except (KeyboardInterrupt, EOFError):
            self.state.console.print("[dim]not approved[/dim]")
            return False

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
    for key in ("path", "pid", "uid", "connection"):
        if key in params:
            return str(params[key])
    return ""


def _plan_intent_params(action: str, params: dict[str, Any]) -> dict[str, Any]:
    """Keep only the operator intent. Plan and step ids belong to the core."""
    keys = {
        "process.signal": ("pid", "signal"),
        "network.prefer": ("connection",),
    }.get(action, ())
    return {key: params[key] for key in keys if key in params}


def _cleanup_criteria(params: dict[str, Any]) -> dict[str, Any] | None:
    """Forward only deterministic selection criteria from a proposal.

    File names, contents, and arbitrary metadata are never criteria. A missing
    directory returns None: chat never substitutes `/` or a home directory.
    """
    root = params.get("root") or params.get("path") or params.get("directory")
    if not isinstance(root, str) or not root.strip():
        return None
    criteria: dict[str, Any] = {"root": root.strip()}
    for key in ("min_age_days", "min_size_bytes", "max_results"):
        value = params.get(key)
        if isinstance(value, int | float) and not isinstance(value, bool):
            criteria[key] = int(value)
    extensions = params.get("extensions")
    if isinstance(extensions, list):
        criteria["extensions"] = [e for e in extensions if isinstance(e, str)]
    return criteria


def _plan_failure(action: str, params: dict[str, Any], message: str) -> str:
    target = params.get("pid") or params.get("connection") or "the requested target"
    lowered = message.lower()
    if "zombie" in lowered:
        guidance = (
            "A zombie is already dead and cannot be killed. Its parent process must "
            "call wait() or be restarted, and a service manager or init must reap it "
            "if the parent is gone."
        )
    elif "not reachable" in lowered or "networkmanager" in lowered:
        guidance = (
            "Network switching needs the core running on the host with access to the "
            "system D-Bus. The container core cannot change host networking."
        )
    elif "owned by uid" in lowered or "not_permitted" in lowered:
        guidance = "The core may only signal processes owned by its own user."
    else:
        guidance = "Nothing was run. Re-check the target, then try again."
    return f"I cannot build an approvable plan for {action} on {target}: {message} {guidance}"


__all__ = ["Assistant", "TurnResult"]
