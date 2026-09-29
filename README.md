# AIOS

A local-first control plane that lets an AI agent observe a Linux machine
without being able to act as a user on it.

The premise: an agent that can call a shell is a compromised agent waiting to
happen, because a prompt injection in any content it reads becomes arbitrary
code execution. So the agent never gets a shell. It emits a structured action
from a closed protocol, and a security engine decides whether that action runs.
The engine, not the model, is the trust boundary.

## Status

Days 1–3 of the build are complete. The system is **read-only by
construction** — there is no code path in it that can modify the machine.

| Day | Component | State |
|-----|-----------|-------|
| 1 | Read-only observers, observation envelope, lifecycle state machine | done |
| 2 | Action protocol, OS gateway, CLI, HTTP API | done |
| 3 | Capability manager, security engine, audit ledger (PostgreSQL) | done |
| 4 | OPA/Rego policy | not started |
| 5 | AI model integration (Ollama) | not started |

## Install

```bash
pip install -e ".[dev]"
cp .env.example .env
aios db init          # create the audit schema
```

`aios db status` reports whether the audit trail is genuinely durable, and
distinguishes "database unreachable" from "schema not created" — the second
one looks healthy to a naive ping.

## The one rule

```
The AI proposes. The Security Engine decides. Nothing else may execute.
```

An agent reaches the OS through exactly one route, and every step of that
route is logged before the action runs:

```
PROPOSED → VALIDATED → AUTHORIZED → EXECUTED → OBSERVED → COMPLETED
                  ↘ DENIED          ↘ DENIED
```

A read-only command from an operator skips the engine, because the operator
is the caller and needs no grant. Anything shaped like an agent proposal does
not:

```bash
# operator observation — direct, read-only, no grant needed
aios cpu
aios processes --limit 5

# agent path — capability check, policy check, audit trail
echo '{"type":"process.list","params":{"limit":5}}' | aios act
echo '{"type":"process.inspect","params":{"pid":1}}' | aios act
#   DENY process.inspect (capability_missing) no capability grant
```

## What is allowed by default

The `local-agent` can observe the system and nothing else:

```
system.cpu  system.memory  system.hostname  system.status  system.uptime
process.list  network.connections
```

Deliberately **not** granted: `process.inspect`, and every `filesystem`
action. `filesystem.read` is MEDIUM risk, so it needs a human confirmation
that this build cannot yet provide — it is refused, not silently allowed.

## The two surfaces

**Operator observation** — `GET /system/*`, `/processes*`,
`/network/connections`. These call the gateway directly. The caller is the
local human.

**Agent action** — `POST /actions/execute` and `aios act`. These go through
the engine: protocol validation, scope consistency, capability check, policy,
then execution.

The split is deliberate. If the read routes also required a grant, the
operator could not look at their own machine. If the agent could reach them,
a grant would mean nothing.

```bash
aios serve
curl -s localhost:8000/actions/execute -H 'content-type: application/json' \
  -d '{"action_id":"act-demo-01","type":"process.list","params":{"limit":2}}'
```

A denial returns 403 with the same response body shape, and
`X-AIOS-Reason: capability_missing`.

## Watching: `-w`

Every observation command takes `-w` to re-read on an interval and redraw in
place. Ctrl-C stops it.

```bash
aios cpu -w                  # per-core bars, frequencies, 60s history
aios memory -w               # used / available / swap, with history
aios processes -w            # live top processes, cpu% per process
aios network -w             # new / changed / closed connections
aios status -w              # uptime, process count, temperatures
aios mounts -w              # disk usage per filesystem
aios inspect 1234 -w        # follow one process
```

Three things that are easy to get wrong, and how they behave here:

**The percentages are real deltas, not a running average.** `CpuObserver`
computes utilisation from the difference between two `/proc/stat` reads, so
watch mode keeps one gateway alive for the whole run. A gateway per tick would
discard the previous sample and every frame would be a delta over a
zero-length window.

**The interval has a floor of 0.1s.** Sampling faster than that costs more in
scheduler churn than the extra resolution is worth, and the overhead shows up
in the numbers being reported. `aios cpu -w --interval 0.01` is refused.

**Piping changes the output shape.** On a TTY the view redraws in place. When
stdout is redirected, an in-place redraw would land in your log as escape-
character soup, so each sample is emitted as a separate record instead:

```bash
aios cpu -w --count 60 --json | jq -r '"\(.sample) \(.data.percent.total)"'
```

`--json` requires `--count`, because an unbounded stream is unreadable in a
terminal and never terminates in a pipe. Each line keeps the full provenance
envelope, so a consumer can still tell where the reading came from.

`aios inspect -w` stops on its own when the process exits, since following a
process to its end is the point.

Watch mode calls the same read-only handlers as the one-shot commands and
writes nothing to the audit ledger. Watching a machine is not an authorised
action against it.

## Trust is derived, not asserted

Every observation carries a trust domain derived from where the data came
from, never from what the caller claims:

| Domain | Source |
|--------|--------|
| `T0` | kernel via procfs/sysfs |
| `T2` | the gateway itself |
| `T3` | an AI proposal |
| `T4` | external data — notably file *content*, which anyone can write |

File content is T4 even when the AI asked for it. Anyone who can write a file
controls its bytes.

## Verification: it really reads your machine

Fixture-based tests prove the parsing is correct. They cannot prove the numbers
come from the host, because a hardcoded value parses just as cleanly as a real
one. So `tests/test_live.py` reads the live `/proc` and checks the observers
against independently obtained ground truth:

| Field | Source of truth |
|-------|-----------------|
| memory totals | `/proc/meminfo` |
| logical cores | `nproc` |
| load average | `/proc/loadavg` |
| hostname, kernel, arch | `uname -n`, `-r`, `-m` |
| process count | `ps -e` |
| thread count | `ps -eL` |
| sockets | `/proc/net/tcp{,6}` parsed by the test itself |
| disk usage | `os.statvfs` |

Three properties are asserted, because the first one alone is easy to fake:

1. **The value matches the host.** A hardcoded figure fails on any other
   machine, and `kernel != "Linux"` is asserted directly, because that string
   was once returned as the kernel on every host ever built.
2. **The value moves.** Memory available, CPU percentages, uptime, and the
   process list are read twice and asserted to differ. A constant cannot
   change.
3. **A fake root produces fake numbers.** The same observer is pointed at a
   temporary directory and must report that directory's contents. This is the
   check that proves the values came from the filesystem rather than from the
   function.

Run just this file with `python3 -m pytest tests/test_live.py -q`.

## Security model

See [SECURITY.md](SECURITY.md) for the threat model, the trust boundaries,
and what is explicitly out of scope.

## Tests

```bash
python3 -m pytest tests/ -q      # 314 tests
python3 -m ruff check aios/ tests/
```

The PostgreSQL tests skip rather than fail when no database is reachable.

`tests/test_live.py` is the one file that reads the real `/proc` instead of a
fixture tree. It compares the observers against `nproc`, `uname`, `ps`, and
`statvfs`, so if a value were hardcoded rather than read from the host, that
file would fail. See [Verification](#verification-it-really-reads-your-machine).
