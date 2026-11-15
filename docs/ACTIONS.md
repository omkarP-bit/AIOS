# AIOS Action Framework

Status: implemented for the first mutation path. `filesystem.cleanup_scan`,
`filesystem.quarantine`, and `filesystem.restore` run in the Go core; this
document defines the model every future action — filesystem, service, package,
configuration, process, user — must follow.

The read-only protocol answers "what can the agent observe?". This document
answers "what may the agent change, under whose authority, and how is it
undone?".

## 1. Principles

1. **The AI proposes; the operator authorizes; the executor applies.** None of
   these roles may be collapsed into another.
2. **Authorization is per plan, not per model utterance.** A plan is an
   immutable, hashed, bounded list of typed steps. Approval binds to that hash.
3. **Only reversible, bounded actions may run without a human.** Everything
   irreversible or unbounded stays outside the AI execution path.
4. **The executor is a closed interpreter.** It knows a fixed catalog of
   operations. It never receives a command string, a URL, or an arbitrary
   syscall number.
5. **Policy lives in Rego.** The action catalog describes what an action *is*;
   Rego decides whether *this* plan may run now.
6. **Every step is verified immediately before it runs.** Approval time is not
   execution time, so identity is re-checked to close the TOCTOU window.
7. **Every effect has an audit trail and, where possible, an inverse.**

## 2. Effect classes

Effect class, not the action name, drives authorization.

| Class | Meaning | Examples | AI role | Default approval |
|---|---|---|---|---|
| `OBSERVE` | No state change | `system.cpu`, `process.list`, `filesystem.read` | propose + execute | policy |
| `STAGE` | Reversible, no live impact | `filesystem.quarantine`, snapshot, draft config | propose + execute | policy |
| `REVERSIBLE` | Live change with a verified inverse | `filesystem.restore`, `service.restart`, `config.apply` | propose only | human + plan |
| `DESTRUCTIVE` | No reliable inverse | hard delete, `kill -9`, data drop | propose only | operator typed confirmation |
| `FORBIDDEN` | No safe model | shell, arbitrary exec, raw sysctl write | never | — |

Two additional properties are mandatory for every action:

- **bounded**: the action has explicit limits (items, bytes, time, rate).
- **identified**: the action names a concrete target whose identity can be
  re-checked (`dev` + `ino` + `mtime_ns`, unit name + file hash, pid +
  start time).

An action that is unbounded or cannot be identified is `DESTRUCTIVE` at best
and usually `FORBIDDEN`.

## 3. Action descriptor

One record per action, shared by the Go core and Rego. The catalog is the
single source of truth; the protocol enum, risk table, gateway registry, and
policy data are generated from it or validated against it. The Python planner
reads the same catalog from `GET /actions/schema`.

```json
{
  "id": "filesystem.quarantine",
  "version": 1,
  "effect": "STAGE",
  "risk": "HIGH",
  "scope": "path",
  "params_schema": "FilesystemQuarantineParams",
  "preconditions": [
    "plan.approved",
    "plan.hash_matches",
    "target.identity_matches",
    "target.not_mountpoint",
    "target.not_symlink",
    "target.not_open",
    "target.under_allowed_root",
    "target.same_filesystem_as_quarantine"
  ],
  "postconditions": ["target.absent", "quarantine_record.written"],
  "inverse": "filesystem.restore",
  "limits": {"max_items": 500, "max_bytes": 10737418240},
  "approval": "plan",
  "owasp": ["OWASP-LLM06:2025", "OWASP-A01:2021", "OWASP-A08:2021"],
  "timeout_s": 60
}
```

Required fields:

| Field | Purpose |
|---|---|
| `id` | Stable action name in the protocol |
| `version` | Descriptor version; part of the plan hash |
| `effect` | One of the effect classes above |
| `risk` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `scope` | `none`, `path`, `pid`, `uid`, `unit`, `package`, `repo`, `config` |
| `params_schema` | Typed parameter model; unknown fields are rejected |
| `preconditions` | Checked before each step, not only at plan time |
| `postconditions` | Checked after each step; failure triggers rollback |
| `inverse` | Action that undoes this one, or `null` |
| `limits` | Bounds enforced by the core and by Rego |
| `approval` | `none`, `confirm`, or `plan` |
| `owasp` | Assurance tags; see `docs/OWASP.md` |

A descriptor may not set `effect: FORBIDDEN`, may not name a member of
`forbidden_actions`, and may not have `inverse: null` while claiming
`STAGE` or `REVERSIBLE`. Tests enforce all three.

## 4. Plan lifecycle

```text
DRAFT ──► PROPOSED ──► APPROVED ──► APPLYING ──► APPLIED ──► VERIFIED
              │            │            │
              │            │            ├──► PARTIAL ──► ROLLED_BACK
              │            │            └──► FAILED  ──► ROLLED_BACK
              │            └──► EXPIRED / REVOKED
              └──► REJECTED
```

| State | Meaning |
|---|---|
| `DRAFT` | Scanner or planner is assembling steps. Not executable. |
| `PROPOSED` | Immutable plan stored with hash. Awaiting a decision. |
| `APPROVED` | Operator issued a token bound to the plan hash. |
| `APPLYING` | Executor is running steps; token is single-use. |
| `APPLIED` | All steps ran; postconditions pending. |
| `VERIFIED` | Postconditions hold. Terminal. |
| `PARTIAL` | Some steps ran, some were skipped or failed. |
| `ROLLED_BACK` | Inverse steps ran; original state restored. |
| `FAILED` | Rollback also failed; operator intervention required. |
| `EXPIRED` / `REVOKED` | Token or plan is no longer usable. |

A plan is immutable after `PROPOSED`. Any change produces a new plan and a new
hash, which invalidates any existing approval.

### Plan body

```json
{
  "plan_id": "plan-01J...",
  "catalog_version": "2026-11-13",
  "agent_id": "local-agent",
  "session_id": "sess-...",
  "intent": "free space on /home",
  "created_at": "2026-11-13T20:00:00Z",
  "steps": [
    {
      "step_id": "step-1",
      "action": "filesystem.quarantine",
      "target": {
        "path": "/home/u/.cache/foo",
        "dev": 2049,
        "ino": 12345,
        "size_bytes": 104857600,
        "mtime_ns": 1763000000000000000,
        "mode": 33188,
        "uid": 1000
      }
    }
  ],
  "limits": {"max_items": 500, "max_bytes": 10737418240},
  "rollback": [
    {
      "step_id": "step-1",
      "action": "filesystem.restore",
      "target": {"quarantine_id": "q-..."}
    }
  ]
}
```

### Plan hash

`plan_hash = sha256(canonical_json(plan_body) || canonical_json({"catalog_version": ...}))`.

Canonical JSON means sorted keys, UTF-8, no insignificant whitespace, and
integers for all numeric identity fields. The hash is computed by the trusted
core, never accepted from the planner.

## 5. Approval tokens

An approval is an operator decision, not a model output.

```json
{
  "token_version": 1,
  "plan_id": "plan-01J...",
  "plan_hash": "sha256:...",
  "approved_by": "uid:1000",
  "approved_at": "2026-11-13T20:01:00Z",
  "expires_at": "2026-11-13T20:16:00Z",
  "nonce": "base64url-...",
  "scope_digest": "sha256:...",
  "signature": "hex-hmac-sha256"
}
```

Rules:

- The signing key is held by the trusted core, never by the Python planner and
  never by the model provider.
- The token is single-use. The core marks the nonce consumed before the first
  step runs.
- Default lifetime is 15 minutes. Expired tokens are rejected by Rego.
- `scope_digest` binds the approval to the allowed roots and limits, so a
  token for `/home/u/.cache` cannot be replayed against `/etc`.
- The AI never sees a token, and cannot construct a policy input that claims
  one. The Go `policy.Doc` takes the token from the core's verified state,
  not from request parameters.

## 6. Capability extension

The existing capability model (`action` + `scope`) is extended, not replaced.

```json
{
  "action": "filesystem.quarantine",
  "scope": ["/home/u/.cache/*"],
  "constraints": {
    "filesystem_read_only": false,
    "require_managed_resource": true,
    "maintenance_window": "Sat 02:00-04:00",
    "max_items": 500,
    "max_bytes": 10737418240
  },
  "budget": {"mutations_per_hour": 20, "mutations_per_day": 100},
  "approval": "plan",
  "expires_at": "2026-12-31T00:00:00Z"
}
```

Still no wildcards across actions, no implication, and no inheritance. A grant
for `filesystem.quarantine` does not imply `filesystem.restore`; restoration is
a separate grant.

### Budgets

Budgets exist so that a compromised agent cannot achieve a large effect through
many individually small approved actions. Counters are maintained by the core
and passed to Rego as read-only input.

## 7. Rego policy shape

Policy input gains the descriptor, the plan, the verified approval, and the
budget counters:

```json
{
  "action": "filesystem.quarantine",
  "effect": "STAGE",
  "descriptor_version": 1,
  "risk": "HIGH",
  "agent_id": "local-agent",
  "trust_domain": "T3",
  "capability": {"allowed": true, "target_in_scope": true},
  "target": {"path": "/home/u/.cache/foo", "under_allowed_root": true},
  "plan": {"id": "plan-01J...", "hash": "sha256:...", "steps": 1, "forbidden_step": false},
  "approval": {"valid": true, "plan_hash": "sha256:...", "expires_at_ns": 1763000160000000000},
  "budget": {"remaining_hour": 19, "remaining_day": 99},
  "limits": {"items_ok": true, "bytes_ok": true}
}
```

The rule set stays deny-by-default:

```rego
package aios.authz

import future.keywords.if

default decision := {
  "decision": "DENY",
  "reason": "deny by default",
  "policy_id": "aios.authz.default",
}

descriptor := data.aios.actions[input.action]

deny_reason := "forbidden_action" if {
  input.action in data.aios.forbidden_actions
} else := "unknown_action" if {
  not descriptor
} else := "effect_forbidden" if {
  descriptor.effect == "FORBIDDEN"
} else := "untrusted_origin" if {
  input.trust_domain != "T3"
} else := "capability_missing" if {
  not input.capability.allowed
} else := "scope_mismatch" if {
  not input.capability.target_in_scope
} else := "risk_ceiling" if {
  input.risk == "CRITICAL"
} else := "approval_missing" if {
  descriptor.approval == "plan"
  not input.approval.valid
} else := "approval_plan_mismatch" if {
  descriptor.approval == "plan"
  input.approval.plan_hash != input.plan.hash
} else := "approval_expired" if {
  descriptor.approval == "plan"
  input.approval.expires_at_ns < time.now_ns()
} else := "plan_contains_forbidden_step" if {
  input.plan.forbidden_step
} else := "budget_exhausted" if {
  input.budget.remaining_hour <= 0
} else := "limits_exceeded" if {
  not input.limits.items_ok
} else := "limits_exceeded" if {
  not input.limits.bytes_ok
} else := ""

decision := {"decision": "DENY", "reason": deny_reason, "policy_id": "aios.authz.deny"} if {
  deny_reason != ""
}

decision := {
  "decision": "CONFIRM",
  "reason": "human confirmation required",
  "policy_id": "aios.authz.confirm",
} if {
  deny_reason == ""
  descriptor.approval == "confirm"
}

decision := {
  "decision": "ALLOW",
  "reason": "approved plan within policy limits",
  "policy_id": "aios.authz.allow-plan",
} if {
  deny_reason == ""
  descriptor.approval == "plan"
  input.approval.valid
}
```

`OBSERVE` actions keep the existing `ALLOW` path. Rego never performs an
operation, opens a file, or calls an external service.

## 8. Execution contract

The executor is a separate trusted component. It receives an approved plan and
a token, and it owns every side effect.

### Per-step sequence

1. Verify token signature, nonce, expiry, plan hash, and `scope_digest`.
2. Open the allowed root with `openat2` using
   `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
3. Re-stat the target relative to that directory descriptor. Compare `dev`,
   `ino`, `size_bytes`, `mtime_ns`, and `mode` with the plan. Abort the step on
   any mismatch.
4. Refuse mount points, symlinks, hardlinked files, immutable attributes, and
   files outside the root.
5. Write a `step_started` journal record containing the before image.
6. Perform the fixed operation:
   - `filesystem.quarantine`: `renameat2(..., RENAME_NOREPLACE)` into the
     quarantine directory on the same filesystem.
   - `filesystem.restore`: `renameat2(..., RENAME_NOREPLACE)` back to the
     recorded parent.
   - `filesystem.purge`: `unlinkat` on an already-quarantined object, never on
     an arbitrary live path.
7. Write a `step_finished` record with the after image.
8. Check postconditions. On failure, run the inverse for completed steps in
   reverse order.

### Guarantees

- **Bounded:** `max_items`, `max_bytes`, `timeout_s`, and budget counters are
  checked before and during the run.
- **Idempotent by identity:** a step whose target no longer matches is skipped
  and reported, never retried against a different inode.
- **No recursion by default:** recursive operations require an explicit plan
  with per-entry identity records and a higher approval class.
- **No shell:** the executor has no `exec`, no `system`, no shell interpreter.
- **No privilege in the core:** the core runs unprivileged. Running the
  executor as a dedicated user with Landlock and seccomp confinement is
  planned.
- **Crash safe:** writing every step to the audit ledger before the effect is
  implemented. Automatic reconciliation of an interrupted plan at startup is
  planned; until then restart recovery is an operator action.

## 9. First reference action: quarantine and restore

### `filesystem.cleanup_scan` — `OBSERVE`

Deterministic scanner. The model may rank or explain the result; it may not
invent candidates.

Input: allowed roots, age threshold, size threshold, exclusion patterns.

Output per candidate:

```json
{
  "candidate_id": "c-01J...",
  "path": "/home/u/.cache/foo",
  "dev": 2049,
  "ino": 12345,
  "size_bytes": 104857600,
  "mtime_ns": 1763000000000000000,
  "reason": "cache older than 30 days",
  "tags": ["cache", "regenerable"]
}
```

The scanner skips:

- paths outside the allowed roots
- mount points
- symlinks
- files with `nlink > 1`
- files currently open by any process
- files owned by another uid
- immutable or append-only files
- sensitive prefixes (`/etc`, `/boot`, `/root`, `/home/*/.ssh`, shadow files,
  kernel memory devices)
- files on a different filesystem than the quarantine root

### `filesystem.quarantine` — `STAGE`, `HIGH`

Moves approved candidates into
`$AIOS_QUARANTINE_DIR/<plan_id>/<candidate_id>/payload`, with a sidecar
`meta.json` containing the original path, identity, plan id, and approver.
The quarantine root is configured per allowed root and must be on the same
filesystem. There is no cross-device copy fallback; a cross-device candidate
is rejected.

### `filesystem.restore` — `REVERSIBLE`, `HIGH`

Moves a quarantined object back to its recorded parent. Requires the parent to
exist and the target path to be absent. Uses `RENAME_NOREPLACE`. The sidecar is
the authority for the original path; the model never supplies a restore target.

### `filesystem.purge` — `DESTRUCTIVE`, `CRITICAL`

Not implemented. Intended to be operator-only, unreachable from the AI
proposal path even with an approval token, and restricted to quarantined
objects after a retention period.

## 10. Action families after quarantine

Once the envelope exists, new actions reuse it without new architecture:

| Family | STAGE / REVERSIBLE | DESTRUCTIVE (operator-only) |
|---|---|---|
| Filesystem | `filesystem.quarantine`, `filesystem.restore`, `filesystem.move` | `filesystem.purge` |
| Service | `service.restart`, `service.stop`, `service.start` | `service.mask` |
| Config | `config.apply` with validated diff and rollback | `config.reset` |
| Package | `package.install` from pinned, signed repo | `package.remove` |
| Process | `process.stop` with pid + starttime binding | `process.kill` |
| User | `user.lock`, `user.expire_password` | `user.delete` |
| Network | `network.deny_temporary` with a TTL | `firewall.modify` |

Each one still declares an effect class, a target identity, a bound, an
inverse, and an approval class. None of them receives a free-form command.

## 11. Permanent exclusions

These remain in `forbidden_actions` and can never appear in a descriptor:

```text
shell.exec
command.run
exec
kernel.modify
sysctl.write
system.shutdown
system.reboot
```

Plus, by rule rather than by name: raw package URLs, unpinned repositories,
arbitrary syscalls, free-form firewall match expressions, recursive deletion of
a live directory, writes outside declared roots, and any action whose target
cannot be re-identified.

## 12. Go core, Python LLM, Rego

```text
┌──────────────────────┐
│ Python planner       │  T3. Provider text, closed ActionRequest, HTTP
│ (untrusted)          │  client. No policy engine, executor, approval token,
│                      │  filesystem write, or direct /proc access.
└──────────┬───────────┘
           │ POST /actions/validate, /actions/execute
┌──────────▼───────────┐
│ Go core (T1)         │  protocol, capability, plan hash, approval,
│                      │  Rego client, engine, ledger, CLI, HTTP API.
└──────────┬───────────┘
           │ authorized, re-validated request
┌──────────▼───────────┐
│ Gateway / executor   │  read-only observers (T2); quarantine and restore
│ (in-process)         │  with renameat2, identity re-check, sidecar, rollback.
└──────────────────────┘

OPA/Rego is the only policy decision point. The Go catalog, Rego data, and the
Python planner's fetched schema are kept aligned by tests and by the HTTP
schema route.
```

The executor currently shares the core process. Running it under a dedicated
user with Landlock and seccomp is planned, not implemented.

Parity tests pin the Go plan hash, scope digest, and approval signature against
a Python-canonical-JSON fixture, so the two languages cannot silently disagree
about what was approved. The Python side has no reference executor; the Go
executor tests cover TOCTOU refusal, replay refusal, rollback, and round-trip
restore.

## 13. Delivery phases

1. **Catalog and docs** — descriptor schema, effect classes, OWASP tags, this
   document, and `docs/OWASP.md`.
2. **Read-only plan path** — `filesystem.cleanup_scan` returning candidates and
   a plan draft; no mutation.
3. **Approval and quarantine** — trusted-core plan hash, approval token,
   `filesystem.quarantine`, journal, and audit events.
4. **Restore and reconciliation** — `filesystem.restore`, crash recovery,
   rollback tests.
5. **Go migration** — port the catalog, core, and executor; parity tests.
   Done.
6. **Additional families** — service, config, package, process, user. Not
   started.

## 14. Acceptance criteria

- No mutation action can be constructed without a plan and a valid token.
- A changed plan body invalidates the token.
- A changed inode between approval and apply aborts the step.
- Quarantine is reversible; restore returns the object to its original parent.
- Purge is unreachable from the AI path.
- Every step writes an executed/completed audit pair to the ledger.
- Budgets and per-plan limits are enforced in both the core and Rego.
- Every descriptor has a non-empty OWASP tag list.
- Refusal is reported as `policy_denial`, not as prompt injection, unless the
  proposal itself came from untrusted content.
