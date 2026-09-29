"""Capability and scope tests.

These are the bypass tests. Each one attempts a specific way an agent might get
more than it was granted, and asserts the denial.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from aios.models.common import utcnow
from aios.security.capabilities import (
    Capability,
    RiskClass,
    ScopeDimension,
    _normalise,
    path_in_scope,
    pid_in_scope,
    risk_for,
)
from aios.security.manager import CapabilityManager

# ---------------------------------------------------------------- scope matching


def test_path_normalisation_collapses_traversal() -> None:
    assert _normalise("/home/u/./Downloads/../Downloads/x") == "/home/u/Downloads/x"
    assert _normalise("/home//u///x") == "/home/u/x"
    assert _normalise("/") == "/"
    assert _normalise("/../..") == "/"


def test_wildcard_prefix_matches_children_not_the_directory_itself() -> None:
    scope = ("/home/user/Downloads/*",)
    assert path_in_scope("/home/user/Downloads/report.pdf", scope)
    assert path_in_scope("/home/user/Downloads/sub/deep.pdf", scope)
    assert not path_in_scope("/home/user/Downloads", scope)


def test_wildcard_does_not_escape_the_prefix() -> None:
    scope = ("/home/user/Downloads/*",)
    assert not path_in_scope("/home/user/.ssh/id_rsa", scope)
    assert not path_in_scope("/home/user/Downloadsx", scope)
    assert not path_in_scope("/etc/shadow", scope)


def test_traversal_out_of_scope_is_rejected() -> None:
    scope = ("/home/user/Downloads/*",)
    assert not path_in_scope("/home/user/Downloads/../.ssh/id_rsa", scope)
    assert not path_in_scope("/home/user/Downloads/../../etc/shadow", scope)


def test_double_star_absorbs_segments() -> None:
    scope = ("/var/log/**",)
    assert path_in_scope("/var/log/syslog", scope)
    assert path_in_scope("/var/log/nginx/access.log", scope)
    assert not path_in_scope("/var/lib/secret", scope)


def test_trailing_slash_star_means_everything_under_that_directory() -> None:
    """Documented semantics: 'dir/*' is everything strictly below 'dir'.

    This is deliberate and is what makes ``/home/user/Downloads/*`` useful. It
    also means a grant of ``/home/*`` is broad, and the grant, not the matcher,
    is what limits it.
    """
    assert path_in_scope("/home/user/.ssh/id_rsa", ("/home/*",))


def test_segment_glob_does_not_cross_the_separator() -> None:
    """A '*' inside a segment matches one segment, not a subtree.

    This is the property a plain fnmatch on the whole string would get wrong:
    ``/home/u*`` would otherwise silently authorise ``/home/user/.ssh/id_rsa``.
    """
    assert path_in_scope("/home/user", ("/home/u*",))
    assert not path_in_scope("/home/user/.ssh/id_rsa", ("/home/u*",))
    assert not path_in_scope("/home/other/file", ("/home/u*",))


def test_empty_scope_matches_nothing() -> None:
    assert not path_in_scope("/home/user/x", ())
    assert not pid_in_scope(1, ())


def test_pid_scope_forms() -> None:
    assert pid_in_scope(4312, ("4312",))
    assert pid_in_scope(1500, ("1000-2000",))
    assert not pid_in_scope(2500, ("1000-2000",))
    assert pid_in_scope(7, ("1,2,7",))
    assert pid_in_scope(99999, ("*",))
    assert not pid_in_scope(3, ("1", "2"))


# ---------------------------------------------------------------- capability model


def test_capability_rejects_unknown_action() -> None:
    with pytest.raises(ValueError, match="unknown action"):
        Capability(action="process.terminate")


def test_capability_rejects_scope_on_unscopable_action() -> None:
    """system.cpu has no scope dimension, so a scope on it is a modelling bug."""
    with pytest.raises(ValueError, match="takes no scope"):
        Capability(action="system.cpu", scope=("/home/user/*",))


def test_capability_expiry_is_recorded() -> None:
    past = utcnow() - timedelta(minutes=1)
    cap = Capability(action="process.list", expires_at=past)
    assert cap.is_expired() is True
    future = Capability(action="process.list", expires_at=utcnow() + timedelta(hours=1))
    assert future.is_expired() is False


def test_unknown_action_risk_is_critical() -> None:
    assert risk_for("process.terminate") is RiskClass.CRITICAL
    assert risk_for("nonexistent.action") is RiskClass.CRITICAL


def test_read_is_medium_risk_by_design() -> None:
    assert risk_for("filesystem.read") is RiskClass.MEDIUM
    assert risk_for("process.list") is RiskClass.LOW


def test_scope_dimension_mapping() -> None:
    assert Capability(action="filesystem.read", scope=("/a/*",)).dimension is ScopeDimension.PATH
    assert Capability(action="process.inspect").dimension is ScopeDimension.PID
    assert Capability(action="system.cpu").dimension is ScopeDimension.NONE


# ---------------------------------------------------------------- manager: deny by default


def test_ungranted_action_is_denied() -> None:
    manager = CapabilityManager(default_grants=[])
    check = manager.check("local-agent", "process.list")
    assert check.allowed is False
    assert "deny by default" in check.reason


def test_no_capability_implies_no_wildcard() -> None:
    manager = CapabilityManager(default_grants=[Capability(action="process.list")])
    for action in ("process.inspect", "filesystem.list", "filesystem.read", "system.cpu"):
        assert manager.check("local-agent", action).allowed is False, action


def test_filesystem_list_does_not_imply_read() -> None:
    """Listing a directory reveals names; it must not authorise reading them."""
    manager = CapabilityManager(
        default_grants=[Capability(action="filesystem.list", scope=("/home/user/Downloads/*",))]
    )
    assert manager.check("local-agent", "filesystem.list", "/home/user/Downloads/x").allowed
    assert not manager.check("local-agent", "filesystem.read", "/home/user/Downloads/x").allowed


def test_unknown_agent_has_no_capabilities() -> None:
    manager = CapabilityManager(default_grants=[Capability(action="process.list")])
    assert manager.check("other-agent", "process.list").allowed is False


# ---------------------------------------------------------------- manager: scope enforcement


def test_in_scope_target_allowed() -> None:
    manager = CapabilityManager(
        default_grants=[Capability(action="filesystem.read", scope=("/home/user/Downloads/*",))]
    )
    check = manager.check("local-agent", "filesystem.read", "/home/user/Downloads/report.pdf")
    assert check.allowed is True
    assert check.matched_capability is not None


def test_out_of_scope_target_denied() -> None:
    manager = CapabilityManager(
        default_grants=[Capability(action="filesystem.read", scope=("/home/user/Downloads/*",))]
    )
    check = manager.check("local-agent", "filesystem.read", "/home/user/.ssh/id_rsa")
    assert check.allowed is False
    assert "outside every granted scope" in check.reason


def test_scope_bypass_attempts() -> None:
    """Every classic path-traversal spelling must be denied."""
    manager = CapabilityManager(
        default_grants=[Capability(action="filesystem.read", scope=("/home/user/Downloads/*",))]
    )
    attacks = [
        "/home/user/.ssh/id_rsa",
        "/home/user/Downloads/../.ssh/id_rsa",
        "/home/user/Downloads/../../etc/shadow",
        "/home/user/Downloads%2f..%2f.ssh/id_rsa".replace("%2f", "/"),
        "/etc/shadow",
        "/",
        "/home/user/Downloads/../../../../etc/passwd",
    ]
    for path in attacks:
        assert not manager.check("local-agent", "filesystem.read", path).allowed, path


def test_pid_scope_enforced() -> None:
    manager = CapabilityManager(
        default_grants=[Capability(action="process.inspect", scope=("1000-2000",))]
    )
    assert manager.check("local-agent", "process.inspect", "1500").allowed
    assert not manager.check("local-agent", "process.inspect", "1").allowed
    assert not manager.check("local-agent", "process.inspect", "99999").allowed


def test_non_numeric_pid_target_denied() -> None:
    manager = CapabilityManager(
        default_grants=[Capability(action="process.inspect", scope=("*",))]
    )
    assert not manager.check("local-agent", "process.inspect", "abc").allowed


# ---------------------------------------------------------------- manager: lifecycle


def test_revoke_is_sticky() -> None:
    manager = CapabilityManager(default_grants=[Capability(action="process.list")])
    assert manager.revoke("local-agent", "process.list") is True
    check = manager.check("local-agent", "process.list")
    assert check.allowed is False
    assert manager.is_revoked("local-agent", "process.list")


def test_regrant_clears_revocation() -> None:
    manager = CapabilityManager(default_grants=[Capability(action="process.list")])
    manager.revoke("local-agent", "process.list")
    manager.grant_action("local-agent", "process.list")
    assert manager.check("local-agent", "process.list").allowed is True


def test_revoke_all() -> None:
    manager = CapabilityManager(
        default_grants=[Capability(action="process.list"), Capability(action="system.cpu")]
    )
    assert manager.revoke_all("local-agent") == 2
    assert manager.check("local-agent", "process.list").allowed is False
    assert manager.check("local-agent", "system.cpu").allowed is False


def test_expired_capability_denied() -> None:
    manager = CapabilityManager(
        default_grants=[
            Capability(action="process.list", expires_at=utcnow() - timedelta(seconds=1))
        ]
    )
    check = manager.check("local-agent", "process.list")
    assert check.allowed is False
    assert check.expired is True


def test_regrant_replaces_rather_than_widens() -> None:
    """Re-granting must not silently union with the previous scope."""
    manager = CapabilityManager(
        default_grants=[Capability(action="filesystem.read", scope=("/home/*",))]
    )
    manager.grant_action("local-agent", "filesystem.read", scope=("/home/user/Downloads/*",))
    assert manager.check("local-agent", "filesystem.read", "/home/other/x").allowed is False
    assert manager.check("local-agent", "filesystem.read", "/home/user/Downloads/x").allowed


def test_describe_lists_grants_and_revocations() -> None:
    manager = CapabilityManager(default_grants=[Capability(action="process.list")])
    manager.revoke("local-agent", "process.list")
    manager.grant_action("local-agent", "system.cpu")
    described = manager.describe("local-agent")
    assert [c["action"] for c in described["granted"]] == ["system.cpu"]
    assert [c["action"] for c in described["revoked"]] == ["process.list"]


def test_default_agent_has_no_filesystem_capability() -> None:
    """The out-of-the-box grant set is read-only system visibility, nothing more."""
    manager = CapabilityManager()
    for action in ("filesystem.read", "filesystem.stat", "filesystem.list", "process.inspect"):
        assert not manager.has("local-agent", action), action
