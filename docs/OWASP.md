# OWASP Assurance Mapping

Status: current. OWASP tags live in the Go catalog and in
`aios/policies/data.json`, and a parity test keeps the two aligned. This
document maps tags to controls that exist today and lists the gaps. Tags
describe controls; they never grant authority.

## 1. Rules

1. A tag is metadata attached to an action descriptor, a Rego rule, or a test.
2. A tag must point to a control that exists, not to an aspiration.
3. A tag may not appear as the sole reason for an `ALLOW` in Rego. Policy
   decisions are made from capability, scope, risk, plan, and approval state.
4. Every action descriptor must carry at least one tag. A Go catalog test
   enforces this.
5. Rego policy results carry the catalog tags through `owasp_tags`; tags never
   participate in the decision itself.
6. Status values are explicit: `implemented`, `partial`, `planned`, `n/a`.
   "Partial" is not allowed to masquerade as coverage.

## 2. Tag format

| Prefix | Standard |
|---|---|
| `OWASP-A01:2021` … `OWASP-A10:2021` | OWASP Top 10 2021 |
| `OWASP-LLM01:2025` … `OWASP-LLM10:2025` | OWASP Top 10 for LLM Applications 2025 |
| `OWASP-API1:2023` … `OWASP-API10:2023` | OWASP API Security Top 10 2023 |
| `OWASP-ASVS4-V4` … `OWASP-ASVS4-V14` | OWASP ASVS 4.0.3 chapter |

Tags are uppercase, colon-delimited, and stable. A tag is retired, never
renamed, so historical audit rows remain readable.

## 3. OWASP Top 10 2021

| Tag | Control in AIOS | Where | Status |
|---|---|---|---|
| `OWASP-A01:2021` Broken Access Control | Deny-by-default capabilities, exact-action grants, scope checked against the real target, plan-level approval | `core/internal/capability/`, `core/internal/engine/`, `aios/policies/authz.rego` | implemented |
| `OWASP-A02:2021` Cryptographic Failures | Secrets loaded from environment, never logged; no TLS because the API is localhost-only | `core/internal/config/`, `core/internal/api/` | partial |
| `OWASP-A03:2021` Injection | No shell or `exec`, closed action enum, strict JSON decoding, typed params, no SQL | `core/internal/protocol/`, `core/internal/gateway/` | implemented |
| `OWASP-A04:2021` Insecure Design | Threat model, trust domains, fail-closed policy, effect classes and reversibility | `SECURITY.md`, `docs/ACTIONS.md` | implemented for cleanup; future action families planned |
| `OWASP-A05:2021` Security Misconfiguration | Deny-by-default policy, restrictive defaults, `AIOS_ALLOW_EXTERNAL_MODEL=false` | `.env.example`, `core/internal/config/` | partial — no API auth or TLS |
| `OWASP-A06:2021` Vulnerable Components | Dependencies declared in `pyproject.toml`; OPA is an external binary | `pyproject.toml`, `core/go.mod` | partial — no lockfile or SBOM |
| `OWASP-A07:2021` Authentication Failures | API bound to `127.0.0.1`; no user authentication | `core/internal/api/` | n/a by scope — local single-user |
| `OWASP-A08:2021` Integrity Failures | Strict schema validation, derived provenance, append-only ledger, plan hash and HMAC approval | `core/internal/protocol/`, `core/internal/plan/`, `core/internal/ledger/` | implemented for cleanup |
| `OWASP-A09:2021` Logging and Monitoring Failures | Durable JSONL audit ledger, security events, policy decisions | `core/internal/ledger/`, `core/internal/engine/` | partial — no alerting or metrics |
| `OWASP-A10:2021` SSRF | No URL-fetching action; outbound endpoints are fixed configuration | `aios/ai/providers.py`, `core/internal/policy/` | implemented |

## 4. OWASP Top 10 for LLM Applications 2025

This is the primary taxonomy for AIOS.

| Tag | Control in AIOS | Where | Status |
|---|---|---|---|
| `OWASP-LLM01:2025` Prompt Injection | Attack corpus, T4 data handling, model output parsed into a closed protocol, no shell | `aios/ai/injection.py`, `tests/test_injection.py`, `aios/ai/planner.py`, `core/internal/engine/` | implemented |
| `OWASP-LLM02:2025` Sensitive Information Disclosure | Raw file content is excluded from model context; external inference is opt-in; `filesystem.read` is `MEDIUM` and confirmation-gated | `aios/ai/context.py`, `aios/ai/client.py` | partial — model context still contains host aggregates |
| `OWASP-LLM03:2025` Supply Chain | Dependencies and the OPA binary are declared; provider base URL is configuration | `pyproject.toml`, `core/go.mod` | partial — no SBOM, signature, or lock |
| `OWASP-LLM04:2025` Data and Model Poisoning | Observations are untrusted input; no training or fine-tuning occurs | `aios/ai/`, `SECURITY.md` | n/a for training; partial for observation trust |
| `OWASP-LLM05:2025` Improper Output Handling | Planner rejects non-JSON and unknown fields; output becomes a typed `ActionRequest`, never executed directly | `aios/ai/planner.py`, `core/internal/protocol/` | implemented |
| `OWASP-LLM06:2025` Excessive Agency | Fixed action catalog, capability + policy gates, no shell, plan-bound mutation approval | `core/internal/catalog/`, `core/internal/plan/`, `core/internal/engine/` | implemented |
| `OWASP-LLM07:2025` System Prompt Leakage | Prompts contain no secrets; provider keys never enter the prompt | `aios/ai/planner.py`, `aios/ai/context.py` | partial — no dedicated leakage tests |
| `OWASP-LLM08:2025` Vector and Embedding Weaknesses | No RAG or vector store | — | n/a |
| `OWASP-LLM09:2025` Misinformation | Model output is never treated as fact or authorization | `core/internal/engine/` | implemented by design |
| `OWASP-LLM10:2025` Unbounded Consumption | Timeouts, entry caps, byte caps, output-token cap | `aios/ai/providers.py`, `core/internal/protocol/` | partial — no rate limiting |

## 5. OWASP API Security Top 10 2023

| Tag | Control in AIOS | Where | Status |
|---|---|---|---|
| `OWASP-API1:2023` BOLA | Capability is checked per agent and per action; target scope is re-checked | `core/internal/capability/` | partial — no authenticated object ownership |
| `OWASP-API2:2023` Broken Authentication | Localhost-only control plane | `core/internal/api/` | n/a by scope |
| `OWASP-API3:2023` BOPLA | `extra="forbid"`, typed params, no caller-supplied provenance | `core/internal/protocol/` | implemented |
| `OWASP-API4:2023` Unrestricted Resource Consumption | Entry limits, byte limits, timeouts, plan limits | `core/internal/gateway/`, `core/internal/plan/`, `docs/ACTIONS.md` | partial — no rate limit |
| `OWASP-API5:2023` BFLA | Action-level capability, forbidden-action list, no role inheritance | `core/internal/catalog/`, `aios/policies/data.json` | implemented |
| `OWASP-API6:2023` Sensitive Business Flows | No business flows exist | — | n/a |
| `OWASP-API7:2023` SSRF | No URL or host parameter in the protocol | `core/internal/protocol/` | implemented |
| `OWASP-API8:2023` Misconfiguration | Deny-by-default, restrictive defaults | `.env.example`, `core/internal/config/` | partial |
| `OWASP-API9:2023` Inventory Management | Versioned action catalog and `/actions/schema` | `core/internal/api/`, `core/internal/catalog/` | implemented |
| `OWASP-API10:2023` Unsafe Consumption of APIs | OPA and provider responses are parsed and validated; provider failure is fatal to the request | `core/internal/policy/`, `aios/ai/providers.py` | partial |

## 6. OWASP ASVS 4.0.3 chapters

| Tag | Area | Status |
|---|---|---|
| `OWASP-ASVS4-V1` | Architecture, design, threat modelling | implemented |
| `OWASP-ASVS4-V2` | Authentication | n/a by scope |
| `OWASP-ASVS4-V3` | Session management | n/a by scope |
| `OWASP-ASVS4-V4` | Access control | implemented |
| `OWASP-ASVS4-V5` | Validation, sanitization, encoding | implemented |
| `OWASP-ASVS4-V6` | Stored cryptography | partial — no encryption at rest |
| `OWASP-ASVS4-V7` | Error handling and logging | partial — audit exists, alerting does not |
| `OWASP-ASVS4-V8` | Data protection | partial — no file content egress, no encryption at rest |
| `OWASP-ASVS4-V9` | Communication | n/a — localhost only |
| `OWASP-ASVS4-V10` | Malicious code | implemented — no dynamic code loading from the agent |
| `OWASP-ASVS4-V11` | Business logic | implemented — plan limits; budgets for future families |
| `OWASP-ASVS4-V12` | Files and resources | implemented |
| `OWASP-ASVS4-V13` | API and web service | partial — no authentication |
| `OWASP-ASVS4-V14` | Configuration | partial |

## 7. Where tags will live

### Action descriptors

```yaml
id: filesystem.quarantine
effect: STAGE
risk: HIGH
approval: plan
owasp:
  - OWASP-LLM06:2025
  - OWASP-A01:2021
  - OWASP-A08:2021
  - OWASP-ASVS4-V4
  - OWASP-ASVS4-V12
```

### Rego policy

```rego
allow_plan := {
  "decision": "ALLOW",
  "reason": "approved plan within policy limits",
  "policy_id": "aios.authz.allow-plan",
  "owasp_tags": ["OWASP-LLM06:2025", "OWASP-A01:2021", "OWASP-A08:2021"],
} if { ... }
```

Policy decisions persist their tags so an audit row can be grouped by
assurance area without parsing rule bodies.

### Tests

```go
func TestCatalogMatchesPolicyData(t *testing.T) {
    // tags are compared action by action
}
```

`core/internal/catalog/catalog_test.go` asserts:

- every descriptor has at least one tag;
- the Go catalog and `data.json` agree on every tag;
- no tag changes a policy decision.

## 8. Current gaps

These are the items that must not be described as covered:

| Gap | Affects | Consequence |
|---|---|---|
| No API authentication | A07, API2, ASVS V2 | Safe only because the API is localhost-only |
| No TLS | A02, ASVS V9 | Local-only traffic; no remote deployment |
| No dependency lock or SBOM | A06, LLM03 | Reproducibility and supply-chain assurance are incomplete |
| No rate limiting | LLM10, API4 | A denial loop can grow the ledger and consume CPU |
| No encryption at rest | A02, ASVS V6 | Audit ledger confidentiality depends on the host |
| No alerting | A09, ASVS V7 | Events are recorded but not monitored |
| Process `cmdline`/`name` labelled T2 | LLM01, A08 | Attacker-influenced text is trusted in the provenance envelope |
| Executor isolation not implemented | A04, LLM06, V4 | The executor shares the unprivileged core process; dedicated user, Landlock, and seccomp are planned |

## 9. Maintenance

- A new action descriptor must add tags before review.
- A new Rego rule that changes the decision must update the catalog tags before review.
- A control change must update its status and its test reference in the same
  change.
- Removing a test downgrades the matching row to `partial` until a replacement
  exists.
- The tag list is part of the audit schema; retire tags, never reuse them.
