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

## Build and install

Requirements: Go 1.23+, Python 3.11+, and the `opa` binary for policy
evaluation.

```bash
cd core
go build ./...
go install ./cmd/aios ./cmd/aiosd

cd ..
python3 -m pip install -e ".[dev]"
cp .env.example .env
```

`aios` is the operator CLI. `aiosd` runs the HTTP control plane in the
foreground. The Python planner is installed as `aios-ai` or run with
`python -m aios.ai`.

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
aios processes --limit 5
aios network --listening
```

Anything shaped like an agent proposal goes through the core:

```bash
echo '{"type":"process.list","params":{"limit":5}}' | aios act
echo '{"type":"process.inspect","params":{"pid":1}}' | aios act
#   DENY process.inspect (capability_missing) no capability grant
```

Use `aios act --dry-run` to authorize without executing.

## What is allowed by default

The `local-agent` can observe the system and nothing else:

```
system.cpu  system.memory  system.hostname  system.status  system.uptime
process.list  network.connections
```

Deliberately **not** granted: `process.inspect`, and every `filesystem`
action. `filesystem.read` is MEDIUM risk, so it needs a human confirmation that
this build cannot yet provide — it is refused, not silently allowed.

## Reversible cleanup

`filesystem.quarantine` is the first non-read-only action. It is deliberately
narrow: one regular file per step, a plan bound by hash, an operator approval,
and an inverse (`filesystem.restore`). Hard delete is not implemented, and
`filesystem.purge` is permanently forbidden.

```bash
aios cleanup scan ~/Downloads --min-age-days 30 --plan-out plan.json
# inspect plan.json, then approve the exact hash it printed
aios cleanup quarantine plan.json --confirm-plan-hash sha256:...
aios cleanup restore plan.json --confirm-plan-hash sha256:...
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
there is no second implementation to drift from the Rego.

## The AI planner

The model is an untrusted text generator. It proposes; it never authorizes.
The Python planner fetches the action catalog and an aggregate observation
snapshot from the Go core, asks the provider for JSON, and posts the resulting
proposal back to the core.

```bash
aiosd                              # or: aios serve
python -m aios.ai "how is the cpu?"
python -m aios.ai "list 5 processes" --execute
```

Without `--execute` the core performs a dry run: it validates and authorizes
but does not execute. A model answer alone can never cause an action.

### Groq is opt-in

Groq is supported because the development laptop cannot hold a local model.
External inference is **disabled by default**. All three settings are required:

```bash
AIOS_MODEL_PROVIDER=groq
AIOS_ALLOW_EXTERNAL_MODEL=true
AIOS_GROQ_API_KEY=...
```

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
`/network/connections`. These call the read-only gateway directly. The caller
is the local human.

**Agent action** — `POST /actions/execute`. This goes through the engine:
protocol validation, scope consistency, capability check, policy, then
execution. `POST /actions/validate` checks the wire shape without deciding.

The split is deliberate. If the read routes also required a grant, the
operator could not look at their own machine. If the agent could reach them, a
grant would mean nothing.

```bash
aios serve
curl -s localhost:8000/actions/execute -H 'content-type: application/json' \
  -d '{"action_id":"act-demo-01","type":"process.list","params":{"limit":2}}'
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
controls its bytes.

## Audit ledger

The core appends one JSON object per transition to a durable JSONL file
(`AIOS_LEDGER_PATH`, default `~/.local/state/aios/ledger.jsonl`) and fsyncs
each row. An empty path keeps the ledger in memory. `aios ledger` prints it;
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
covers the provider boundary, planner parsing, context construction, and the
HTTP client against a mock core.

`tests/test_injection.py` is the planner's attack corpus: every entry must
either fail to parse or remain an allowed read action. The Go engine tests
assert that forbidden and mutation actions are denied even when the planner
produces a well-formed request.

eBPF remains code and documentation only; no privileged probe is run by the
test suite. See [docs/EBPF.md](docs/EBPF.md).

## Security model

See [SECURITY.md](SECURITY.md) for the threat model, the trust boundaries, and
what is explicitly out of scope.
