"""The OS Gateway — the only code path from an action to Linux.

The gateway is a whitelist dispatcher. It holds a fixed registry of handler
functions keyed by action type; there is no dynamic dispatch, no string
formatting into a shell, and no fallback branch for unknown types.

Every handler:
  * receives an already-typed params model, never a raw dict;
  * re-checks its own preconditions (defence in depth, since the security
    engine and the gateway validate independently);
  * returns an :class:`Observation` whose origin reflects what it read.

Handlers must be read-only. There is intentionally no write, delete, signal,
or spawn helper in this module.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aios.actions.scanner import scan_candidates
from aios.models.actions import (
    ActionRequest,
    FilesystemCleanupScanParams,
    FilesystemListParams,
    FilesystemReadParams,
    FilesystemStatParams,
    NetworkConnectionsParams,
    ProcessInspectParams,
    ProcessListParams,
    SystemCpuParams,
    SystemMemoryParams,
    SystemStatusParams,
    SystemUptimeParams,
)
from aios.models.common import DataOrigin, Observation
from aios.observers import cpu as cpu_obs
from aios.observers import filesystem as fs_obs
from aios.observers import memory as mem_obs
from aios.observers import network as net_obs
from aios.observers import process as proc_obs
from aios.observers import system as sys_obs
from aios.observers.paths import PathEscapeError


#: Raised when an action is structurally valid but must not be executed.
class GatewayError(RuntimeError):
    pass


class ActionNotPermitted(GatewayError):
    """The action type is not in the gateway whitelist at all."""


class PreconditionFailed(GatewayError):
    """The action is whitelisted but its target is not currently readable."""


@dataclass(frozen=True)
class HandlerResult:
    """What a handler returns: a typed payload plus where it came from."""

    data: Any
    source: str
    origin: DataOrigin = DataOrigin.GATEWAY

    def to_observation(self, type_name: str) -> Observation:
        return Observation.build(
            type=type_name, source=self.source, origin=self.origin, data=self.data
        )


Handler = Callable[[Any], HandlerResult]


class OSGateway:
    """Whitelist dispatcher over the read-only observers."""

    def __init__(
        self,
        proc_root: Path | None = None,
        sys_root: Path | None = None,
        max_read_bytes: int = 1_048_576,
        max_dir_entries: int = 2000,
        quarantine_dir: Path | None = None,
    ) -> None:
        self.proc_root = Path(proc_root or "/proc")
        self.sys_root = Path(sys_root or self.proc_root.parent / "sys")
        self.max_read_bytes = max_read_bytes
        self.max_dir_entries = max_dir_entries
        self.quarantine_dir = Path(quarantine_dir) if quarantine_dir else None

        self._cpu = cpu_obs.CpuObserver(self.proc_root, self.sys_root)
        self._process = proc_obs.ProcessObserver(self.proc_root)
        self._network = net_obs.NetworkObserver(self.proc_root)

        # The whitelist. Adding a key here without adding a capability and a
        # policy is a code review question, not a runtime configuration.
        self._handlers: dict[str, Handler] = {
            "system.cpu": self._h_system_cpu,
            "system.memory": self._h_system_memory,
            "system.hostname": self._h_system_hostname,
            "system.status": self._h_system_status,
            "system.uptime": self._h_system_uptime,
            "process.list": self._h_process_list,
            "process.inspect": self._h_process_inspect,
            "network.connections": self._h_network_connections,
            "filesystem.list": self._h_filesystem_list,
            "filesystem.stat": self._h_filesystem_stat,
            "filesystem.read": self._h_filesystem_read,
            "filesystem.cleanup_scan": self._h_filesystem_cleanup_scan,
        }

    @property
    def supported_actions(self) -> frozenset[str]:
        return frozenset(self._handlers)

    # ------------------------------------------------------------ dispatch

    def execute(self, request: ActionRequest) -> Observation:
        """Run an authorized action.

        The caller is the security engine, which has already validated the
        action, checked capabilities, and obtained a policy decision. This
        method re-validates anyway: if the gateway is ever reached directly
        (a bug, a new call site, a future service), the whitelist still holds.
        """
        name = request.action_name
        handler = self._handlers.get(name)
        if handler is None:
            raise ActionNotPermitted(f"action {name} is not in the gateway whitelist")

        params = request.typed_params
        result = handler(params)
        return result.to_observation(name)

    def execute_timed(self, request: ActionRequest) -> tuple[Observation, float]:
        started = time.perf_counter()
        obs = self.execute(request)
        return obs, (time.perf_counter() - started) * 1000.0

    # ------------------------------------------------------------ handlers

    def _h_system_cpu(self, p: SystemCpuParams) -> HandlerResult:
        info = self._cpu.collect(interval_s=p.interval_s)
        if not p.include_frequencies:
            info = info.model_copy(update={"frequencies": []})
        return HandlerResult(data=info, source=f"procfs:{self.proc_root}/stat")

    def _h_system_memory(self, p: SystemMemoryParams) -> HandlerResult:
        info = mem_obs.read_memory(self.proc_root)
        if not p.include_swap:
            info = info.model_copy(
                update={
                    "swap_total_kb": 0,
                    "swap_free_kb": 0,
                    "swap_used_kb": 0,
                    "swap_used_percent": 0.0,
                }
            )
        if not p.include_fields:
            info = info.model_copy(update={"fields_kb": {}})
        return HandlerResult(data=info, source=f"procfs:{self.proc_root}/meminfo")

    def _h_system_hostname(self, p: SystemStatusParams | SystemUptimeParams) -> HandlerResult:
        info = sys_obs.read_system(self.proc_root, self.sys_root)
        return HandlerResult(
            data={"hostname": info.hostname, "os_name": info.os_name},
            source=f"procfs:{self.proc_root}/sys/kernel/hostname",
        )

    def _h_system_status(self, p: SystemStatusParams) -> HandlerResult:
        info = sys_obs.read_system(self.proc_root, self.sys_root)
        if not p.include_disks:
            info = info.model_copy(update={"block_devices": []})
        if not p.include_thermal:
            info = info.model_copy(update={"thermal_zones": {}})
        return HandlerResult(data=info, source=f"procfs:{self.proc_root}")

    def _h_system_uptime(self, p: SystemUptimeParams) -> HandlerResult:
        info = sys_obs.read_system(self.proc_root, self.sys_root)
        return HandlerResult(
            data={
                "uptime_s": info.uptime_s,
                "boot_time_utc": info.boot_time_utc,
                "now_utc": info.now_utc,
            },
            source=f"procfs:{self.proc_root}/uptime",
        )

    def _h_process_list(self, p: ProcessListParams) -> HandlerResult:
        result = self._process.list(
            limit=p.limit,
            sort_by=p.sort_by,
            name_filter=p.name_filter,
            uid_filter=p.uid_filter,
            include_cmdline=p.include_cmdline,
        )
        return HandlerResult(
            data=result, source=f"procfs:{self.proc_root}/<pid>/stat"
        )

    def _h_process_inspect(self, p: ProcessInspectParams) -> HandlerResult:
        try:
            info = self._process.inspect(p.pid, with_extras=p.include_extras)
        except proc_obs.ProcessNotFound as exc:
            raise PreconditionFailed(str(exc)) from exc
        return HandlerResult(data=info, source=f"procfs:{self.proc_root}/{p.pid}")

    def _h_network_connections(self, p: NetworkConnectionsParams) -> HandlerResult:
        result = self._network.collect(
            include_unix=p.include_unix,
            attribute_pids=p.attribute_pids,
            limit=p.limit,
            states=p.states,
            listening_only=p.listening_only,
        )
        return HandlerResult(data=result, source=f"procfs:{self.proc_root}/net")

    def _h_filesystem_list(self, p: FilesystemListParams) -> HandlerResult:
        if p.path is None:
            data = fs_obs.list_mounts(self.proc_root, pseudo=p.include_pseudo)
            return HandlerResult(
                data=data, source=f"procfs:{self.proc_root}/mounts"
            )
        target = Path(p.path)
        if fs_obs.is_sensitive(target):
            raise PreconditionFailed(f"path is outside the readable set: {p.path}")
        try:
            entries = fs_obs.list_directory(
                target, max_entries=min(p.max_entries, self.max_dir_entries),
                show_hidden=p.show_hidden,
            )
        except (OSError, ValueError) as exc:
            raise PreconditionFailed(f"cannot list {p.path}: {exc}") from exc
        return HandlerResult(
            data={"path": str(target), "entries": entries, "count": len(entries)},
            source=f"directory:{target}",
        )

    def _h_filesystem_stat(self, p: FilesystemStatParams) -> HandlerResult:
        target = Path(p.path)
        if fs_obs.is_sensitive(target):
            raise PreconditionFailed(f"path is outside the readable set: {p.path}")
        meta = fs_obs.stat_path(target)
        if not meta.exists:
            raise PreconditionFailed(f"path does not exist: {p.path}")
        return HandlerResult(data=meta, source=f"stat:{target}")

    def _h_filesystem_read(self, p: FilesystemReadParams) -> HandlerResult:
        """Read file content.

        Two things matter here. The content is returned as T4 external data
        regardless of who asked, because file bytes are attacker-controlled.
        And the gateway re-checks readability itself rather than trusting the
        caller to have done it.
        """
        target = Path(p.path)
        reason = fs_obs.check_readable(target)
        if reason is not None:
            raise PreconditionFailed(reason)
        limit = min(p.max_bytes, self.max_read_bytes)
        try:
            content = fs_obs.read_file(target, max_bytes=limit)
        except (OSError, ValueError) as exc:
            raise PreconditionFailed(f"cannot read {p.path}: {exc}") from exc
        return HandlerResult(
            data={
                "path": str(target),
                "content": content,
                "bytes": len(content.encode("utf-8", errors="replace")),
                "truncated_at": limit,
            },
            source=f"file:{target}",
            # File content is hostile by construction, whatever the caller.
            origin=DataOrigin.EXTERNAL,
        )

    def _h_filesystem_cleanup_scan(self, p: FilesystemCleanupScanParams) -> HandlerResult:
        target = Path(p.path)
        if fs_obs.is_sensitive(target):
            raise PreconditionFailed(f"path is outside the readable set: {p.path}")
        try:
            result = scan_candidates(
                target,
                min_age_days=p.min_age_days,
                min_size_bytes=p.min_size_bytes,
                max_candidates=min(p.max_candidates, self.max_dir_entries),
                include_hidden=p.include_hidden,
                exclude_roots=(self.quarantine_dir,) if self.quarantine_dir else (),
            )
        except (OSError, ValueError) as exc:
            raise PreconditionFailed(f"cannot scan {p.path}: {exc}") from exc
        return HandlerResult(data=result, source=f"scan:{result.root}")


__all__ = [
    "ActionNotPermitted",
    "GatewayError",
    "Handler",
    "HandlerResult",
    "OSGateway",
    "PathEscapeError",
    "PreconditionFailed",
]


# Type-level assertion that every whitelisted action has a params model, so a
# protocol/gateway mismatch fails at import time rather than at call time.
def _assert_registry_matches_protocol() -> None:
    """Fail at import time if the gateway and the protocol disagree.

    A new action added to one but not the other is a security bug, not a
    typing inconvenience: the security engine would authorize actions the
    gateway cannot serve, or the gateway would serve actions nothing
    authorizes.
    """
    from aios.actions.catalog import EXECUTOR_ACTIONS
    from aios.models.actions import PARAMS_MAP

    gw = OSGateway(proc_root=Path("/nonexistent-proc"))
    expected = set(PARAMS_MAP) - set(EXECUTOR_ACTIONS)
    drift = set(gw._handlers) ^ expected
    assert not drift, f"gateway/protocol drift: {sorted(drift)}"


_assert_registry_matches_protocol()
