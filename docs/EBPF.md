# M6 — eBPF observation (optional)

eBPF is an **observation source only**. It does not authorize, execute, or
gate any action, and the security engine does not depend on it. If the
tooling is missing, AIOS still starts and every read-only path still works.

## What is in the repository

| Path | Purpose |
|---|---|
| `scripts/ebpf/aios_trace.bt` | bpftrace probe: `execve`, `connect`, process exit, heartbeat |

The Python telemetry wrapper and its tests were removed with the Python
backend migration. The probe is a standalone operator tool; no package imports
or loads it, and no test starts it.

## Requirements

- Linux with eBPF tracepoints available
- `bpftrace` installed
- root (or `CAP_BPF` / `CAP_PERFMON` on kernels that support them)
- optional: `bpftool`, `clang`, `llvm-strip` only if you want to build custom
  probes; the bundled script needs none of them

This development container does **not** have `bpftrace`, has no root access,
and `/sys/fs/bpf` is permission-denied. M6 is therefore delivered as code and
documentation, with live probe validation deferred to a host where those
requirements are met.

## Running it

```bash
sudo bpftrace scripts/ebpf/aios_trace.bt > /tmp/aios-ebpf.jsonl
```

The probe writes one JSON object per line. `detail` may contain
attacker-controlled text from `execve`, so it is treated as T4 data and never
as an instruction. Malformed or partial lines should be skipped, not parsed as
commands.

## Design constraints

- **Read-only probe.** The script attaches to tracepoints and prints. It does
  not call `signal()`, `override()`, `kill()`, or write to kernel state.
- **No privilege in the control plane.** The AIOS core runs unprivileged.
  Starting a probe is an operator action, not something the agent can request.
- **Unavailable is not fatal.** Missing tooling removes this optional source;
  the Go observers and every control-plane path keep working.
- **No raw events in authorization.** Even a trusted kernel event is
  observation. Risk and capability decisions still come from the fixed catalog
  and the capability store.

## Why eBPF is not wired into the engine yet

Wiring it in would add a privileged data source to the authorization path
without improving any decision the engine makes today. The current observers
already answer the read-only questions in the protocol. eBPF becomes useful
when the protocol grows an event-driven action, which is out of scope for the
current build. Keeping it optional is the safer default.
