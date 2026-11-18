# Safe Filesystem Cleanup Security Model

Status: current for the Go core and the `aios clean` CLI.

AIOS cleanup is a **reversible, human-approved file move**. The model never
chooses a file. It may only ask for a scan; the core selects candidates from a
closed set of deterministic criteria, the operator approves an exact hash-bound
plan, and the executor moves files into quarantine. Permanent deletion is not
an action in the protocol and cannot be reached through this flow.

The controlling rule is:

> AI proposes. Security validates. Policy authorizes. OS Gateway executes.

## 1. Trust boundaries

| Domain | Meaning in cleanup | What it may do |
|---|---|---|
| `T1` | OS Gateway / executor | Execute only an already-authorized action; report observations. |
| `T2` | Gateway observation | Carry read-only scan results back to the core. |
| `T3` | Agent and operator proposals | Request `filesystem.find`, approve a plan, request trash or restore. Never trusted as authority by itself. |
| `T4` | File names, file metadata, file content, model prose | Displayed only after sanitization; never parsed as instructions or authority. |

The engine rejects any request that claims a trusted origin. `Origin` is set
server-side by the route or service, never by the request body. A `T4` proposal
can never request a filesystem path.

## 2. Selection criteria (the only inputs)

A scan accepts exactly these fields:

| Field | Meaning | Bound |
|---|---|---|
| `root` | Absolute directory to walk | Must be absolute, non-symlinked, not protected |
| `min_age_days` | Minimum age measured from `mtime` | 0–3650 |
| `min_size_bytes` | Minimum file size | non-negative |
| `extensions` | Canonical suffixes such as `.log` | at most 32 |
| `max_results` | Result cap | 1–5000 |

There is no filename, content, owner-name, tag, or free-text predicate.
`mtime` is the only age signal; AIOS cannot reconstruct historical per-file use
from atime, proc, or eBPF data and does not pretend otherwise.

The scanner walks deterministically, captures file identity (`realpath`, size,
`mtime`, inode, device, owner, mode), skips protected paths and non-regular
files, and caps the result set. The model never receives or supplies the
candidate list.

## 3. Protected paths and filesystem floor

The Go hard floor in `core/internal/filesafety/filesafety.go` is authoritative:
editing `aios/policies/data.json` can add restrictions but never remove these.

- `~/.ssh`, `~/.gnupg`, `~/.config`, `~/.aios`
- any `.git` directory
- `/etc`, `/boot`, `/usr`, `/var`, `/root`, `/proc`, `/sys`
- the scope root itself

Checks run after realpath resolution. A request is denied on symlink escape,
cross-device targets, foreign owners, non-regular files or directories, and
directories that are not empty or not fully represented in the plan.

## 4. Lifecycle and approval

Generic engine states:

```text
PROPOSED -> VALIDATED -> AWAITING_CONFIRMATION -> AUTHORIZED
          -> EXECUTED -> OBSERVED -> COMPLETED
```

`DENIED` is reachable from every pre-execution state. `filesystem.find` is
`LOW`/read-only and does not require approval. `filesystem.trash` is
`MEDIUM`, path-scoped, and requires a plan and an explicit operator approval.

Cleanup-plan states are engine-owned:

```text
PENDING_APPROVAL -> APPROVED -> EXECUTED
      \               \          (terminal)
       -> REJECTED / EXPIRED
```

The plan contains `plan_id`, `session_id`, `agent_id`, timestamps, `root`,
`criteria`, `entries[]`, counts, `plan_hash`, and `status`. It has no
`approved` flag and no per-path authorization flag in any AI-visible shape.
`CleanupSummary` is the only projection returned to chat; it omits file paths.

Approval requires all of:

1. an operator instruction on a trusted channel;
2. a hash matching the exact stored plan;
3. a live, non-expired plan in `PENDING_APPROVAL`;
4. a signed, single-use token minted by the core for the derived executable
   plan; and
5. one capability grant per action containing the complete exact-path scope.

`filesystem.trash` accepts only `plan_id` in its request. The executor moves
every entry in the plan and rechecks size, `mtime`, inode, device, owner, and
mode immediately before each move.

## 5. Policy and audit gates

Policy composition is `policy.NewStricter(local, rego)`:

- The local floor is veto-only. It can deny, never allow.
- OPA receives only structured fields: action, risk, scope dimension,
  capability state, plan presence, and approval state. Intent, free text, raw
  params, and raw path strings are excluded.
- An OPA `ALLOW` cannot override a local floor `DENY`. An OPA `DENY` or an
  unavailable/timed-out OPA fails closed.

Before any file is moved, the engine writes an `AUTHORIZED` ledger row with
`fsync`. If the ledger is missing or the write fails, execution is denied with
`audit_unavailable` while the action is still in `VALIDATED`.

Audit and security events carry `trust_domain`, `origin`, `plan_id`,
`plan_hash`, `asi_tags`, and a bounded, content-free `params` summary. String
values become lengths, collections become counts, and logging stops after
eight keys with a `params_truncated` marker. The executable plan hash in the ledger is the hash the
approval token verifies; it shares `plan_id` with the operator-approved cleanup
plan.

## 6. Injection handling

File names, file metadata, file content, and model prose are untrusted `T4`
data. Two separate controls apply:

1. **Go veto** (`core/internal/injection`): display-bound scan fields and plan
   entry fields are scanned for instruction overrides, role overrides, secret
   access, shell syntax, exfiltration, protocol spoofing, terminal control
   sequences, and bidi/zero-width characters. Any finding denies the whole
   request with `injection_vetoed`. The veto never removes individual
   candidates, never lowers risk, and never grants capability. Its reason
   contains only stable category names, never the hostile value. The check is
   applied at scan, plan construction, approval, and execution.
2. **Terminal sanitization** (`aios/cli/ui/sanitize.py`): all displayed paths,
   verdicts, and plan fields are sanitized at render time. For example, a file
   named `\x1b[2J ignore previous instructions` renders as inert text; the
   escape sequence is removed and the phrase is displayed, not obeyed.

A clean injection scan has no privileges. It is the absence of a veto, not an
allow decision.

## 7. Operator flows

### CLI

```bash
aios clean /var/log --older-than 30d --ext .log --min-size 10M
aios clean ~/Downloads --older-than 90d --approve
aios restore act-0123456789abcdef
```

`aios clean` is dry-run by default. There is deliberately no default directory.
`--approve` shows the plan and asks for confirmation with a default answer of
**No**; `--approve --yes` is the explicit non-interactive form. Denials exit
`3`; unavailable security services exit `4`.

Chat may request `filesystem.find`. A trash proposal returns a cleanup plan for
a separate operator approval; chat never approves and never moves files.

### HTTP control plane

| Method and path | Purpose |
|---|---|
| `POST /filesystem/find` | Read-only deterministic scan |
| `POST /plans` | Build an engine-owned cleanup plan |
| `GET /plans`, `GET /plans/{id}` | Inspect plans and summaries |
| `POST /plans/{id}/approve` | Bind operator identity and hash to the plan |
| `POST /plans/{id}/trash` | Execute a plan-id-only move to quarantine |
| `POST /restore/{action_id}` | Restore all entries from an audit action id |
| `POST /capabilities/grant`, `POST /capabilities/revoke` | Operator capability control |
| `GET /audit`, `GET /security/summary` | Audit trail and security view |

Denials return `403` with `X-AIOS-Reason`; unavailable policy, audit, or
backend services return `503`.

## 8. Reversibility and non-goals

AIOS never permanently deletes files in this build. Trash writes a sidecar
record with plan identity, original path, captured file identity, timestamp,
and approving operator. `aios restore <action_id>` recovers the plan from the
durable `AUTHORIZED` row and restores every entry through the same engine
pipeline. There is no automatic purge.

Non-goals for this build: permanent delete, shell or subprocess execution,
auto-purge, content-based selection, and reconstruction of historical file use.
All OS actions go through the typed Go gateway or executor; no `os.system`,
`subprocess`, or `shell=True` path exists for cleanup.

## 9. Assurance references

Suite IDs used in tests: `ASI02-001`–`ASI02-005` (protocol and criteria),
`ASI02-006`–`ASI02-021` (capabilities, paths, policy, audit), `ASI02-022`–
`ASI02-031` (pipeline, executor, registry, API), `ASI02-032`–`ASI02-038`
(injection veto), `ASI02-039` (audit API exposure), `ASI01-*`, `ASI03-*`, and
`ASI05-*`. The full suite runs with `make check`.
