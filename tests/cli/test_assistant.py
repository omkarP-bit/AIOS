"""Trust of returned data, not of the request that asked for it.

A confirmed read runs under the operator's trust (T3) but returns bytes from an
untrusted source (T4). The UI must show the data's trust, never the request's.
"""

from __future__ import annotations

from aios.ai.planner import PlanResult
from aios.ai.protocol import ActionRequest
from aios.cli.assistant import TurnResult, data_trust, denial_answer


def _plan(request: ActionRequest | None = None) -> PlanResult:
    return PlanResult(
        request=request,
        raw="{}",
        provider="groq",
        model="test-model",
        external=True,
        prompt_hash="hash",
    )


def test_data_trust_prefers_the_observation() -> None:
    verdict = {"trust_domain": "T3", "data_trust": "T4"}
    assert data_trust(verdict) == "T4"


def test_data_trust_falls_back_for_older_cores() -> None:
    assert data_trust({"trust_domain": "T3"}) == "T3"


def test_data_trust_is_absent_without_a_verdict_field() -> None:
    assert data_trust({}) is None


def test_denial_answer_is_truthful_and_helpful() -> None:
    verdict = {
        "decision": "DENY",
        "action": "filesystem.cleanup_scan",
        "target": "/",
        "denial_reason": "capability_missing",
    }
    answer = denial_answer(verdict, _plan())
    assert "policy denied filesystem.cleanup_scan on /" in answer
    assert "capability_missing" in answer
    assert "nothing was run" in answer
    assert "deny-by-default" in answer
    assert "aios-core cleanup scan" in answer
    assert "I'll scan" not in answer


def test_denial_answer_explains_the_plan_gate_for_mutations() -> None:
    verdict = {
        "decision": "DENY",
        "action": "filesystem.quarantine",
        "target": "/home/u/.cache/old",
        "denial_reason": "approval_missing",
    }
    answer = denial_answer(verdict, _plan())
    assert "operator-approved plan" in answer
    assert "plan hash" in answer


def test_denial_answer_marks_forbidden_actions_as_permanent() -> None:
    verdict = {
        "decision": "DENY",
        "action": "filesystem.write",
        "target": "/etc/passwd",
        "denial_reason": "forbidden_action",
    }
    answer = denial_answer(verdict, _plan())
    assert "permanently forbidden" in answer
    assert "cannot be granted" in answer


def test_history_note_keeps_the_concrete_target() -> None:
    request = ActionRequest(
        action_id="act-1",
        agent_id="agent",
        session_id="session",
        type="filesystem.cleanup_scan",
        params={"path": "/", "min_age_days": 7},
    )
    result = TurnResult(
        question="okay scan it",
        plan=_plan(request),
        verdict={"decision": "DENY"},
    )
    note = result.history_note
    assert "proposed filesystem.cleanup_scan" in note
    assert '"path": "/"' in note
    assert "-> DENY" in note
