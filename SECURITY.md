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
what is written in `aios/models/actions.py` and nothing else.

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

1. **Protocol** — closed action enum, strict params, `extra="forbid"`.
   Unknown fields are rejected, not ignored.
2. **Structural check** — the target named in the proposal must match the
   target in the params. A proposal claiming `/tmp/allowed` while carrying
   `/etc/shadow` is denied on the mismatch.
3. **Risk classification** — from a fixed table keyed on action name. Never
   from model output.
4. **Capability check** — exact action, scope-checked, deny by default. An
   action with no grant is refused; a scope that does not contain the real
   target is refused.
5. **Policy** — deterministic and local in this build. MEDIUM and above need a
   human; there is no ceiling above which something is merely "probably fine".
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

## Failure modes

**The database is down.** Actions still run or are denied on the same terms.
A ledger failure never becomes an allow. The failure is counted, logged, and
reported by `/health` as `ledger_durable: false`.

**The ledger is in-memory.** `/health` and `aios db status` both say so. The
audit trail does not survive a restart, and pretending otherwise would be
worse than the outage.

**An unexpected error in the gateway.** Caught, denied, recorded as
`internal_error`. No retry — a retry of a half-processed action is a second
execution, not a no-op.

**A malformed proposal.** Rejected at the edge with 400/422. The engine is
never handed a half-built request.

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
- **OPA policy is not integrated.** The engine runs local policy and already
  fails closed. OPA replaces the policy step, not the layers around it.
- **No confirmation UI.** MEDIUM-risk actions are refused rather than
  confirmed, which is the safe direction to fail.

## Known limitations

- The capability store is per-process in memory; grants do not survive a
  restart. `PostgresLedger` can persist them and the schema is in place, but
  nothing loads grants at startup yet.
- `directories` listed by `filesystem.list` are T2, not T4. Directory *names*
  are influenced by whoever can create files, so a future reader should treat
  them as untrusted display strings.
- Successful actions complete at `OBSERVED → COMPLETED` with the pipeline
  itself as the observer. When a model consumes observations, that boundary is
  where it belongs — and it needs its own checks at that point.

## Reporting

This is a pre-release local system. Do not expose the API to a network you do
not control.
