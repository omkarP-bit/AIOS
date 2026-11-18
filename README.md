# AIOS

A local-first control plane that lets an AI agent observe a Linux machine
without being able to act as a user on it. The only mutation path is a
reversible, operator-approved quarantine that never runs unapproved.

The premise: an agent that can call a shell is a compromised agent waiting to
happen, because a prompt injection in any content it reads becomes arbitrary
code execution. So the agent never gets a shell. It emits a structured action
from a closed protocol, and a security engine decides whether that action runs.
The engine, not the model, is the trust boundary.

## Architecture

```
Python planner (T3, untrusted)
  provider → text → closed ActionRequest
        │  POST /actions/validate
        │  POST /actions/execute  (dry run by default)
        ▼
Go core
  protocol → structural checks → capability → Rego/OPA
                                      │
                    ┌─────────────────┴─────────────────┐
                    ▼                                   ▼
             read-only gateway                  quarantine executor
             (T2 observations)                  (T1, plan + approval)
                    │                                   │
                    └──────────────┬────────────────────┘
                                   ▼
                         append-only JSONL ledger
```

The Go core owns validation, capabilities, policy evaluation, execution, and
auditing. Python keeps only the LLM planner (`aios/ai`), which posts proposals
over HTTP and has no policy engine, executor, approval token, or filesystem
write path. Rego remains the only place authorization rules live.

## Status

| Milestone | Component | State |
|-----------|-----------|-------|
| M1 | Read-only observers, observation envelope, lifecycle state machine | done |
| M2 | Action protocol, OS gateway, CLI, HTTP API | done |
| M3 | AI planner (Groq opt-in, optional Ollama) | done |
| M4 | OPA/Rego policy, audit persistence, capability checks | done |
| M5 | Prompt-injection defence suite | done |
| M6 | eBPF observation (code + docs) | scaffold — see [docs/EBPF.md](docs/EBPF.md) |
| M7 | Reversible cleanup: scan → plan → approve → quarantine → restore | done |
| M8 | Go core replacing the Python backend | done |
| M9 | Host-run core: plan-approved process signals and network preference | done |

## Build and install

Requirements: Go 1.23+, Python 3.11+, and the `opa` binary for policy
evaluation.

```bash
make install-go      # installs aios-core/aiosd and copies policy to ~/.aios/policies
python3 -m pip install -e ".[dev]"
cp .env.example .env
```

Run `make install-go` again after changing anything in `aios/policies/`; the installed
CLI loads the state copy so cleanup works from any directory. An explicit
`AIOS_POLICY_DIR` always takes precedence.

There are two front-ends:

- `aios` — the Python terminal client. Dashboards, AI chat, confirmation
  cards. It is a thin HTTP client: it never imports the gateway, reads
  `/proc`, or runs a subprocess.
- `aios-core` — the Go core CLI. Mutations, cleanup plans, approvals, and
  direct protocol calls. `aiosd` runs the HTTP control plane in the
  foreground.

The planner is installed as `aios-ai` or run with `python -m aios.ai`.

Installing the Go commands needs `GOBIN` (or `$(go env GOPATH)/bin`) on
`PATH`.

Upgrading from a build that installed the Go CLI as `aios`: remove the old
binary (`rm ~/.local/bin/aios`) so `aios` resolves to the Python client. The Go
core is now `aios-core`.

## Containers

The image bundles the Go CLI/daemon, OPA, and the Python planner. One command
starts the core:

```bash
cp .env.example .env
make up
make health
make logs
```

The compose stack keeps the unauthenticated API on host loopback
(`127.0.0.1:8000`), persists the ledger and quarantine in the `aios-state`
volume, and runs as an unprivileged user with all capabilities dropped.

Run the planner on demand; it is not started by `up`:

```bash
make planner ARGS='"how is memory?"'
make planner ARGS='"list 5 processes" --execute'
make planner-json ARGS='"check cpu"'
```

The planner reaches the core as `http://core:8000`. If it uses Ollama on the
host, the container default is `host.docker.internal:11434`; override it with
`AIOS_OLLAMA_URL_DOCKER`. Groq remains opt-in through the same `.env`.

By default the core observes the container's own PID namespace, not every host
process. For host-wide observation, run the local binary or add `pid: host` to
the `core` service after deciding that trade-off. To clean files under a host
directory, uncomment the bind mount in `docker-compose.yml` and use a
`/workspace/...` path.

## Host core: processes and networking

A container cannot see host processes or control host networking, and it must
not receive that privilege. Process diagnosis/signalling and network switching
therefore run through a core started on the host:

```bash
make host-serve                    # foreground, 127.0.0.1:8000
make host-install-service          # or a systemd user unit
curl -s localhost:8000/health | jq .deployment   # "host"
```

Process and network mutations are plan actions. The AI may propose them; the
core captures exact identity and builds the hash-bound plan; the operator sees
every step and applies that exact hash.

```bash
# Read-only diagnosis, safe for the AI or the operator
aios diagnose

# Signal one process: the core records PID, start ticks, UID, and name
aios plan process.signal --pid 4242 --signal TERM
aios apply plan-... --plan-hash sha256:... --step-id step-1

# Prefer an existing NetworkManager profile by exact id or UUID
aios plan network.prefer --connection "Home Wi-Fi"
aios apply plan-... --plan-hash sha256:... --step-id step-1
```

The same flow is available in chat: the AI proposes, the CLI prints the plan
and hash, and only an explicit `y` sends `/actions/apply`. In a non-interactive
turn the plan is printed but never applied.

Two limits are deliberate:

- A zombie is already dead. `process.signal` refuses it with
  `zombie_not_killable`; the parent must reap it or be restarted.
- Signals are same-UID only, never PID 1, and never the core itself. Network
  activation goes through NetworkManager's system D-Bus, never `nmcli` or a
  shell, and polkit may still require an interactive authorization.

Make targets:

```bash
make help
make build          # Go binaries in core/bin
make check          # vet + lint + all tests
make docker-config  # validate compose
make docker-build
make docker-aios ARGS='status --json'   # Go core CLI in the container
make cli ARGS='status --json'           # local Python terminal client
make shell
make down
make docker-clean   # stop and delete the state volume
```

## The one rule

```
The AI proposes. The Go core decides. Nothing else may execute.
```

An agent reaches the OS through exactly one route:

```
PROPOSED → VALIDATED → AUTHORIZED → EXECUTED → OBSERVED → COMPLETED
                  ↘ DENIED          ↘ DENIED
```

An operator observation skips the engine because the operator is the caller
and needs no grant:

```bash
aios status
aios cpu
aios --watch 2 cpu      # refresh until interrupted
aios processes --limit 5
aios network --listening
aios memory
aios disk
aios audit --denied
aios security
```

Every view is available as JSON with `--json`, which disables colour and
Rich markup so the output can be piped safely:

```bash
aios --json status | jq .health.services
aios --json audit --limit 10 > audit.json
```

Anything shaped like an agent proposal goes through the Go core CLI:

```bash
echo '{"type":"process.list","params":{"limit":5}}' | aios-core act
echo '{"type":"process.inspect","params":{"pid":1}}' | aios-core act
#   DENY process.inspect (capability_missing) no capability grant
```

Use `aios-core act --dry-run` to authorize without executing.

The local planner is one command away. It proposes, the core still decides,
and no approval token is passed to it:

```bash
aios ask "how much memory is free?"
aios ask "list 5 processes"
aios chat
```

`aios ask` runs one turn: plan → propose → verdict → confirmation → result →
answer. `aios chat` is a prompt_toolkit session with file history, multiline
input (Esc+Enter sends), a service-health toolbar, and local slash commands
(`/help`, `/clear`, `/status`, `/history`, `/audit`, `/actions`, `/session`,
`/details`, `/json`, `/exit`). A failed turn prints a friendly error and keeps
the session alive.

Chat is conversational by default: it prints only the answer, not the
thinking, proposal, verdict, or result panels. `/details` (or `aios --verbose
chat`) shows those panels for the rest of the session. A `CONFIRM` card is
always shown before asking, because the operator must see the real action and
target. A denial always produces a truthful answer that says policy refused
the action and nothing ran, plus the actual gate: an exact capability grant or
an operator-approved mutation plan. The model's prose is not reused when it
claims the action will run.

Audit times are converted from the ledger's UTC timestamps to the operator's
local timezone; `--json` keeps the exact RFC 3339 value.

The terminal client displays the verdict it receives; it never decides
authorization. `ALLOW`, `CONFIRM`, and `DENY` come from the core. A `CONFIRM`
card names the real action and target and asks `Approve? [y/N]`; the default
is No, and only an explicit `y` sends the approval back to the core.

## Terminal client

```bash
aios status                  # dashboard: host, CPU, memory, processes, network, services
aios cpu --interval 0.5
aios processes --sort mem --limit 20 --filter postgres
aios network --listening
aios audit --denied --limit 25
aios actions
aios security
aios model                  # provider, model, key presence, readiness
```

`aios model` explains why a provider is or is not ready without printing the
API key. It is the first thing to check when `aios ask` or `aios chat` reports
that the model could not answer.

If the CLI reports that the core is older than the client, the daemon predates
the routes the client calls. Rebuild and restart it with `make up`; a model
change will not help.

All views sanitize untrusted text before rendering. ANSI escapes, control
characters, and bidi overrides are stripped, long values are truncated with
`[truncated]`, and no untrusted string is ever interpreted as Rich markup.
File contents and process names are data, not formatting.

Exit codes are stable and documented:

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | general error |
| 2 | usage or configuration error |
| 3 | the core denied the action |
| 4 | the core is unreachable or returned an unexpected shape |

The CLI fails closed: an unreachable core or a malformed response is a clear
error and a non-zero exit, never a traceback and never a guess.

Configuration lives in `~/.aios/config.toml` and can be overridden by
environment variables:

```toml
[api]
url = "http://127.0.0.1:8000"
timeout_s = 10

[ui]
no_color = false

[chat]
history = "~/.aios/history"
```

`AIOS_API_URL`, `AIOS_TIMEOUT_S`, `AIOS_THEME`, `AIOS_NO_COLOR`,
`AIOS_HISTORY`, and `AIOS_CONFIG` override the file. The defaults are
loopback-only; a non-loopback URL is refused unless `AIOS_ALLOW_REMOTE=1`,
because the core is an unauthenticated local service.

`aios ask` runs the installed planner (`aios-ai`, then
`python -m aios.ai`); set `AIOS_PLANNER` to override the program where the Go
CLI looks for it. The core must be reachable at `AIOS_API_URL`
(`http://127.0.0.1:8000` by default), for example from `aiosd` or `make up`.
Use `make planner` for the containerized path.

## What is allowed by default

The `local-agent` can observe the system and nothing else:

```
system.cpu  system.memory  system.hostname  system.status  system.uptime
process.list  process.diagnose  network.connections  network.status
```

`process.signal` and `network.prefer` are plan actions: they are never
granted by default and only run after the operator approves an exact
core-built plan hash.

Deliberately **not** granted: `process.inspect`, and every `filesystem`
action. `filesystem.read` is MEDIUM risk with an `approval: confirm` class, so
it is escalated as `CONFIRM` rather than allowed silently. The terminal
client asks first; only an explicit `y` is sent to `POST /actions/confirm`,
which grants a 30-second capability for that exact action and target and
executes one request. Anything else stays denied.

## Reversible cleanup

`filesystem.quarantine` is the first non-read-only action. It is deliberately
narrow: one regular file per step, a plan bound by hash, an operator approval,
and an inverse (`filesystem.restore`). Hard delete is not implemented, and
`filesystem.purge` is permanently forbidden.

```bash
aios-core cleanup scan ~/Downloads --min-age-days 30 --plan-out plan.json
# inspect plan.json, then approve the exact hash it printed
aios-core cleanup quarantine plan.json --confirm-plan-hash sha256:...
aios-core cleanup restore plan.json --confirm-plan-hash sha256:...
```

Four properties keep it reversible and non-delegable:

- The scanner chooses candidates. The model may rank or explain them; it
  cannot add a path or change a threshold.
- Approval is an HMAC token over the plan hash, short-lived and single-use.
  Only the CLI mints it, and it is never persisted or sent to Python.
- The executor re-checks `(dev, ino, size, mtime, mode, uid)` immediately
  before `renameat2(RENAME_NOREPLACE)`. A file edited after approval is
  refused, not moved.
- Quarantine must be on the same filesystem, so the move is atomic and the
  bytes never transit through the AI. Every move writes a sidecar record that
  restore validates.

Set `AIOS_APPROVAL_SECRET` for approvals that survive a restart, and keep
`AIOS_QUARANTINE_DIR` on the same filesystem as the targets. The design and
its limits are in [docs/ACTIONS.md](docs/ACTIONS.md).

## Policy is Rego

Authorization rules are not implemented in Go or Python. They live in
`aios/policies/authz.rego`, with the action allowlist, risk table, and
forbidden names in `aios/policies/data.json`.

```bash
opa test aios/policies          # policy unit tests
opa eval -d aios/policies ...   # inspect a decision
```

The Go engine builds a normalized input document, evaluates the policy, and
enforces the answer. `ALLOW`, `CONFIRM`, and `DENY` all come from the same
rules. If OPA cannot run, the answer is `DENY` with `policy_unavailable` —
there is no second implementation to drift from the Rego. The standalone CLI
resolves the policy from `AIOS_POLICY_DIR`, `~/.aios/policies`, a checkout near
the binary, or a checkout above the working directory, so `cleanup scan` does
not depend on where you invoked it. If you see `DENIED policy_unavailable`,
run `make install-go` or set `AIOS_POLICY_DIR` to this checkout's
`aios/policies` directory.

## The AI planner

The model is an untrusted text generator. It proposes; it never authorizes.
The terminal client fetches the action catalog and an aggregate observation
snapshot from the Go core, asks the provider for JSON, shows the verdict, and
posts the resulting proposal back to the core.

```bash
aiosd                              # or: make up
aios ask "how is the cpu?"
aios ask "list 5 processes"
aios chat
python -m aios.ai "how is the cpu?" --execute
```

`aios ask` always runs through the core. A model answer alone can never cause
an action: the core performs validation, capability checks, and policy, and
the client only displays the resulting verdict.

### Groq is opt-in

Groq is supported because the development laptop cannot hold a local model.
External inference is **disabled by default**. All three settings are required:

```bash
AIOS_MODEL_PROVIDER=groq
AIOS_ALLOW_EXTERNAL_MODEL=true
AIOS_GROQ_API_KEY=...
AIOS_GROQ_MODEL=qwen/qwen3.8-27b   # must be a model your key can use
```

Run `aios model` after editing `.env`; it shows the selected provider, the
model, whether the key is present, and whether external use is allowed. A key
alone does not enable Groq: without `AIOS_ALLOW_EXTERNAL_MODEL=true` the
planner stays local and does not send anything. The default Groq model name
changes over time, so set one that appears in the provider's model list.

The `.env` file is resolved independently of the shell's working directory:
`$AIOS_ENV_FILE`, then `~/.aios/.env`, then the project-root `.env` of a
checkout, then `./.env`. This keeps a command run from another directory from
silently falling back to local Ollama. The core reads the same file; its
service unit sets `WorkingDirectory` to the project root.

Only a compact aggregate snapshot can leave the machine: hostname, kernel,
CPU/memory totals, process names, and network counts. **Raw file contents are
never sent.** The provider, model, and a SHA-256 hash of the prompt are
recorded; the prompt itself is not. Model output stays T3 and still passes
through capability checks and OPA in the Go core.

A local provider remains the default:

```bash
AIOS_MODEL_PROVIDER=ollama
AIOS_OLLAMA_MODEL=qwen2.5:3b-instruct-q4_K_M
```

## The two HTTP surfaces

**Operator observation** — `GET /system/*`, `/processes*`,
`/network/connections`, `/audit`, `/security/summary`, `/health`. These call
the read-only gateway or the ledger directly. The caller is the local human.

**Agent action** — `POST /actions/execute`. This goes through the engine:
protocol validation, scope consistency, capability check, policy, then
execution. `POST /actions/validate` checks the wire shape without deciding.
`POST /actions/propose` returns a decision without executing, so the client
can show a `CONFIRM` card. `POST /actions/confirm` re-decides a confirm-class
action as a user-origin request and executes exactly one approved read.

The split is deliberate. If the read routes also required a grant, the
operator could not look at their own machine. If the agent could reach them, a
grant would mean nothing.

```bash
aiosd
curl -s localhost:8000/actions/execute -H 'content-type: application/json' \
  -d '{"action_id":"act-demo-01","type":"process.list","params":{"limit":2}}'
curl -s localhost:8000/security/summary | jq .counts
```

A denial returns 403 with the same response body shape and
`X-AIOS-Reason: capability_missing`.

## Trust is derived, not asserted

Every observation carries a trust domain derived from where the data came
from, never from what the caller claims:

| Domain | Source |
|--------|--------|
| `T0` | kernel via procfs/sysfs |
| `T1` | trusted Go core / executor |
| `T2` | the gateway itself |
| `T3` | an AI proposal |
| `T4` | external data — notably file *content*, which anyone can write |

File content is T4 even when the AI asked for it. Anyone who can write a file
controls its bytes. A verdict therefore reports two fields: `trust_domain` is
the trust the action ran under (for an operator-confirmed read, T3), and
`data_trust` is the trust of what it returned (T4 for file content). The CLI
labels the Result card with `data_trust`, so an approved action cannot make
untrusted bytes look trusted.

## Audit ledger

The core appends one JSON object per transition to a durable JSONL file
(`AIOS_LEDGER_PATH`, default `~/.local/state/aios/ledger.jsonl`) and fsyncs
each row. An empty path keeps the ledger in memory. `aios-core ledger` prints it;
`/health` reports whether it is durable.

## Tests

```bash
cd core
go test ./... -race
go vet ./...

cd ..
python3 -m pytest tests/ -q
python3 -m ruff check aios/ tests/
opa test aios/policies
```

The Go suites cover the protocol, catalog parity with Rego data, capabilities,
plan hashing and approval parity, scanner/executor round-trips, observers,
engine outcomes, the HTTP API, and the CLI cleanup workflow. The Python suite
covers the provider boundary, planner parsing, context construction, the HTTP
client against a mock core, and the terminal client: sanitization, renderer
snapshots, error and exit-code mapping, JSON cleanliness, hostile process
names, and an import guard proving the CLI never imports the gateway or runs a
subprocess.

`tests/test_injection.py` is the planner's attack corpus: every entry must
either fail to parse or remain an allowed read action. The Go engine tests
assert that forbidden and mutation actions are denied even when the planner
produces a well-formed request.

eBPF remains code and documentation only; no privileged probe is run by the
test suite. See [docs/EBPF.md](docs/EBPF.md).

## Security model

See [SECURITY.md](SECURITY.md) for the threat model, the trust boundaries, and
what is explicitly out of scope.
