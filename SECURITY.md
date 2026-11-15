# Security Model

## What this system is defending against

The threat is not a malicious user. It is a **compromised agent**: a model
that has been persuaded, by content it read, to do something its operator
never asked for.

Every design decision below follows from that. The classic failure is a tool
like `bash` in the agent's tool list, because the blast radius of "the model
was wrong" becomes the blast radius of "the model read a hostile web page".

So there is no shell. There is no `exec`. There is no way to construct a
command string. The agent emits an action from a closed enum, and the engine
decides whether it runs. The agent's influence over the system is bounded by
what is written in `core/internal/protocol` and nothing else.

The operator CLI's `aios ai` convenience launches the local planner as a
child process. That is an operator action, not agent-controlled: the planner
receives no shell, no approval token, and no executor access, and its output
is still only a proposal.

## Trust boundaries

```
  untrusted          ┌───────────────┐        trusted
  ─────────          │               │        ───────
  agent proposal ───▶│  Security     │──▶ OS Gateway ──▶ read-only
  (T3, untrusted)    │  Engine (T1)  │        (T2)         observers
                     │               │                     (T0)
  file content (T4) ─┤               │
                     └───────────────┘
                            │
                            ▼
                     audit ledger (append-only)
```

The engine is the boundary. Everything left of it is adversarial input;
everything right of it is a whitelist of read-only operations.

**Trust domains are derived, never asserted.** An observation's domain comes
from where the data came from. A caller cannot request `T0`.

## Defence in depth

Each layer is independently sufficient to stop a given attack, and none of
them trusts the layer in front of it:

1. **Protocol** — closed action enum, strict params, strict JSON decoding.
   Unknown fields are rejected, not ignored.
2. **Structural check** — the target named in the proposal must match the
   target in the params. A proposal claiming `/tmp/allowed` while carrying
   `/etc/shadow` is denied on the mismatch.
3. **Risk classification** — from a fixed table keyed on action name. Never
   from model output.
4. **Capability check** — exact action, scope-checked, deny by default. An
   action with no grant is refused; a scope that does not contain the real
   target is refused.
5. **Policy** — OPA/Rego, deny by default. The rules live in
   `aios/policies/authz.rego`; the Go engine only supplies the input document
   and enforces the answer. If OPA is unavailable the decision is DENY, never a
   local allow. MEDIUM and above need a human; there is no ceiling above
   which something is merely "probably fine".
6. **Gateway** — re-validates the whitelist and re-checks readability itself.
   A capability for `/` still cannot read `/etc/shadow`.
7. **Ledger** — every transition written before the next step runs.

Layers 1 and 6 are the ones most likely to be "simplified away" by a future
change, and they are the two that stop a bug in the engine from becoming a
compromise.

## Capabilities

Grants are `(agent, action, scope)`, evaluated against the **real target**,
never against a scope the proposer declared. Default is deny.

Path scopes are matched segment-wise, which has one consequence worth stating
because it is easy to get wrong:

| Scope | Matches | Does not match |
|-------|---------|----------------|
| `/home/u*` | `/home/user` | `/home/user/.ssh/id_rsa` |
| `/home/*` | everything under `/home` | `/home` itself |
| `/` | **nothing** | everything |
| `/**` | everything | — |

A bare `/` matching nothing is intentional. It is the scope someone reaches
for when writing a grant by hand, and failing closed is the right response to
an ambiguous grant. `/**` is the explicit way to authorise the whole tree.

## The mutation path

Observation is still read-only by construction: the gateway dispatch table
contains only observers. Mutation is served by a separate
`QuarantineExecutor` with exactly two actions, `filesystem.quarantine` and
`filesystem.restore`. `filesystem.purge` and every other write, delete, or
move name remain forbidden, and neither action is reachable through the
gateway.

A mutation passes the same checks as an observation, plus:

1. **Plan** — an immutable list of steps, each bound to the identity of one
   regular file. The engine computes the plan hash; it is never accepted from
   the planner.
2. **Approval** — an HMAC-SHA256 token over the plan id, plan hash, scope
   digest, approver, expiry, and a single-use nonce. The key is never in the
   agent's context, and verification fails closed.
3. **Executor re-check** — before `renameat2(RENAME_NOREPLACE)`, the executor
   re-stats the target and refuses if `(dev, ino, size, mtime, mode, uid)`
   changed since the plan was approved. This is the TOCTOU boundary.
4. **Reversibility** — a sidecar record is written next to the payload, and
   restore validates it before moving the file back. A failed metadata write
   rolls the move back.
5. **No cross-device moves** — quarantine must be on the same filesystem, so
   the rename is atomic and bytes never pass through the AI.

The AI cannot mint an approval. Tokens are created by the CLI after the
operator confirms the exact plan hash, and the capability grants are
in-memory and scoped to that run.

## Failure modes

**The ledger cannot be written.** A failed append is counted and logged. It
never becomes an allow, and an executed action is never retried because the
audit row failed. An unwritable ledger path fails startup instead.

**The ledger is in-memory.** When `AIOS_LEDGER_PATH` is empty, `/health`
reports `ledger_durable: false`. The audit trail does not survive a restart,
and pretending otherwise would be worse than the loss.

**An unexpected error in the gateway.** Caught, denied, recorded as
`internal_error`. No retry — a retry of a half-processed action is a second
execution, not a no-op.

**A malformed proposal.** Rejected at the edge with 400/422. The engine is
never handed a half-built request.

**OPA is unreachable.** The policy step returns DENY with
`denial_reason: policy_unavailable`. There is no second implementation of the
Rego rules in Go or Python to fall back to: one policy, one source of truth.

**The model provider is unreachable.** `python -m aios.ai` fails before any
proposal exists. No action is submitted, so no authorization is attempted.

## Explicitly out of scope

Stating this is part of the model:

- **No authentication or authorisation of the HTTP API.** It binds to
  `127.0.0.1` and is local-first. Do not expose it without adding auth. The
  CLI warns when asked to bind elsewhere.
- **No TLS.** Same reason.
- **No sandboxing of the observer process.** It runs as the invoking user and
  reads only what that user can read.
- **No protection against a malicious operator.** The operator is the trust
  anchor.
- **No rate limiting.** A denial loop is possible locally.
- **External inference is opt-in, not private.** When Groq is enabled, the
  aggregate snapshot described in the README leaves the machine. File
  contents are never included, and the setting is off by default.
- **eBPF is not run or validated here.** The scaffold in
  [docs/EBPF.md](docs/EBPF.md) requires `bpftrace` and root, neither of which
  was available in the development environment. The Python telemetry wrapper
  was removed with the backend; the probe and parser design remain as docs.
- **No confirmation UI.** MEDIUM-risk observations are refused rather than
  confirmed. Mutations use an explicit plan-hash confirmation on the CLI,
  which is the safe direction to fail.
- **Hard delete.** `filesystem.purge` is forbidden and not implemented.
  Cleanup only quarantines; removing a payload afterwards is an operator
  action outside the AI path.

## Known limitations

- The capability store is per-process in memory; grants do not survive a
  restart, and nothing loads grants at startup yet.
- `directories` listed by `filesystem.list` are T2, not T4. Directory *names*
  are influenced by whoever can create files, so a future reader should treat
  them as untrusted display strings.
- Successful actions complete at `OBSERVED → COMPLETED` with the pipeline
  itself as the observer. When a model consumes observations, that boundary is
  where it belongs — and it needs its own checks at that point.
- Approval nonces are tracked in memory, so a restart forgets which tokens
  were consumed. Keep `AIOS_APPROVAL_TTL_S` short; a durable nonce store is
  future work. An empty `AIOS_APPROVAL_SECRET` makes tokens ephemeral, so they
  cannot survive a restart either.
- Quarantine refuses cross-device targets instead of copying them. A target
  mount without a same-device quarantine directory therefore cannot be
  cleaned through this path.

## Reporting

This is a pre-release local system. Do not expose the API to a network you do
not control.
