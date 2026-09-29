"""Action Protocol tests — the wire format the AI must produce."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aios.models import PARAMS_MAP, ActionRequest, ActionType, DataOrigin, make_request
from aios.models.actions import FORBIDDEN_ACTION_NAMES, ActionError


def test_valid_request_round_trips() -> None:
    req = make_request("process.list", params={"limit": 10, "sort_by": "memory"})
    assert req.action_name == "process.list"
    assert req.typed_params.limit == 10
    assert req.typed_params.sort_by == "memory"


def test_unknown_action_type_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ActionRequest(
            action_id="abcdefgh",
            agent_id="local-agent",
            session_id="s1",
            type="process.kill_everything",
        )


def test_make_request_rejects_unknown_and_forbidden() -> None:
    with pytest.raises(ActionError, match="forbidden"):
        make_request("process.terminate")
    with pytest.raises(ActionError, match="unknown"):
        make_request("system.reformat")


@pytest.mark.parametrize("forbidden", sorted(FORBIDDEN_ACTION_NAMES))
def test_every_forbidden_action_is_rejected(forbidden: str) -> None:
    """Not a sample: the whole denylist, so nothing slips in by omission."""
    with pytest.raises(ActionError):
        make_request(forbidden)


def test_no_forbidden_action_appears_in_the_protocol() -> None:
    assert not (set(FORBIDDEN_ACTION_NAMES) & set(PARAMS_MAP))


def test_no_command_or_shell_field_exists() -> None:
    """The wire format cannot express an arbitrary command."""
    fields = set(ActionRequest.model_fields)
    for banned in ("command", "cmd", "shell", "args", "argv", "script", "exec"):
        assert banned not in fields, f"{banned} must not be a request field"
    for name, model in PARAMS_MAP.items():
        for banned in ("command", "cmd", "shell", "argv", "script"):
            assert banned not in model.model_fields, f"{banned} leaked into {name}"


def test_extra_top_level_field_rejected() -> None:
    with pytest.raises(ValidationError):
        ActionRequest(
            action_id="abcdefgh",
            agent_id="local-agent",
            session_id="s1",
            type=ActionType.SYSTEM_CPU,
            sudo=True,
        )


def test_extra_param_rejected() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        make_request("system.cpu", params={"interval_s": 0.1, "shell": "/bin/sh"})


def test_params_are_validated_against_their_own_action() -> None:
    """A process.list payload cannot be smuggled as process.inspect params."""
    with pytest.raises(ValidationError, match="invalid params for process.inspect"):
        make_request("process.inspect", params={"limit": 10})


def test_limit_bounds_enforced() -> None:
    with pytest.raises(ValidationError):
        make_request("process.list", params={"limit": 0})
    with pytest.raises(ValidationError):
        make_request("process.list", params={"limit": 10_000})


def test_pid_bounds_enforced() -> None:
    with pytest.raises(ValidationError):
        make_request("process.inspect", params={"pid": 0})
    with pytest.raises(ValidationError):
        make_request("process.inspect", params={"pid": -1})
    with pytest.raises(ValidationError):
        make_request("process.inspect", params={"pid": 99_999_999_999})


def test_sort_by_is_an_enum_not_a_string() -> None:
    with pytest.raises(ValidationError):
        make_request("process.list", params={"sort_by": "cpu; id"})


def test_control_characters_rejected_in_name_filter() -> None:
    with pytest.raises(ValidationError, match="control characters"):
        make_request("process.list", params={"name_filter": "fire\x00fox"})


def test_nul_rejected_in_paths() -> None:
    for action in ("filesystem.stat", "filesystem.read"):
        with pytest.raises(ValidationError, match="NUL"):
            make_request(action, params={"path": "/tmp/a\x00b"})


def test_empty_path_rejected() -> None:
    with pytest.raises(ValidationError):
        make_request("filesystem.stat", params={"path": ""})


def test_path_length_bounded() -> None:
    with pytest.raises(ValidationError):
        make_request("filesystem.stat", params={"path": "/" + "a" * 5000})


def test_action_id_format_enforced() -> None:
    for bad in ("short", "has space", "semi;colon", "quote\"mark", "a" * 100):
        with pytest.raises(ValidationError):
            ActionRequest(
                action_id=bad, agent_id="local-agent", session_id="s1", type=ActionType.SYSTEM_CPU
            )


def test_agent_id_format_enforced() -> None:
    with pytest.raises(ValidationError):
        ActionRequest(
            action_id="abcdefgh",
            agent_id="agent/../../etc",
            session_id="s1",
            type=ActionType.SYSTEM_CPU,
        )


def test_request_is_frozen() -> None:
    req = make_request("system.cpu")
    with pytest.raises(ValidationError):
        req.type = ActionType.PROCESS_LIST


def test_ai_origin_maps_to_t3() -> None:
    assert make_request("system.cpu").trust_domain.value == "T3"


def test_external_origin_is_reflected() -> None:
    req = ActionRequest(
        action_id="abcdefgh",
        agent_id="local-agent",
        session_id="s1",
        type=ActionType.SYSTEM_CPU,
        origin=DataOrigin.EXTERNAL,
    )
    assert req.trust_domain.value == "T4"


def test_read_size_is_capped_by_protocol() -> None:
    with pytest.raises(ValidationError):
        make_request("filesystem.read", params={"path": "/tmp/x", "max_bytes": 10_000_000})
