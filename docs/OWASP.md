# OWASP Assurance Mapping

Status: design. The repository currently has **no OWASP tags in code**. This
document defines the tag scheme, maps it to controls that exist today, and
lists the gaps. Tags describe controls; they never grant authority.

## 1. Rules

1. A tag is metadata attached to an action descriptor, a Rego rule, or a test.
2. A tag must point to a control that exists, not to an aspiration.
3. A tag may not appear as the sole reason for an `ALLOW` in Rego. Policy
   decisions are made from capability, scope, risk, plan, and approval state.
4. Every action descriptor must carry at least one tag. A test enforces this.
5. Every `ALLOW` rule in Rego must carry at least one tag. A test enforces this.
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
| `OWASP-A01:2021` Broken Access Control | Deny-by-default capabilities, exact-action grants, scope checked against the real target, plan-level approval | `aios/security/`, `aios/policies/authz.rego` | implemented for read-only; plan approval planned |
| `OWASP-A02:2021` Cryptographic Failures | Secrets loaded from environment, never logged; no TLS because the API is localhost-only | `aios/config.py`, `aios/api.py` | partial |
| `OWASP-A03:2021` Injection | No shell or `exec`, closed action enum, `extra="forbid"`, typed params, SQLAlchemy bindings | `aios/models/actions.py`, `aios/gateway.py` | implemented |
| `OWASP-A04:2021` Insecure Design | Threat model, trust domains, fail-closed policy, effect classes and reversibility | `SECURITY.md`, `docs/ACTIONS.md` | implemented for read-only; mutation design planned |
| `OWASP-A05:2021` Security Misconfiguration | Deny-by-default policy, restrictive defaults, `AIOS_ALLOW_EXTERNAL_MODEL=false` | `.env.example`, `aios/config.py` | partial — no API auth or TLS |
| `OWASP-A06:2021` Vulnerable Components | Dependencies declared in `pyproject.toml`; OPA is an external binary | `pyproject.toml` | partial — no lockfile, SBOM, or pin verification |
| `OWASP-A07:2021` Authentication Failures | API bound to `127.0.0.1`; no user authentication | `aios/api.py` | n/a by scope — local single-user |
| `OWASP-A08:2021` Integrity Failures | Strict schema validation, derived provenance, append-only ledger; plan hash planned | `aios/models/`, `aios/db/ledger.py` | partial |
| `OWASP-A09:2021` Logging and Monitoring Failures | Durable audit ledger, security events, policy decisions | `aios/db/`, `aios/security/engine.py` | partial — no alerting or metrics |
| `OWASP-A10:2021` SSRF | No URL-fetching action; outbound endpoints are fixed configuration | `aios/ai/providers.py`, `aios/security/opa.py` | implemented |

## 4. OWASP Top 10 for LLM Applications 2025

This is the primary taxonomy for AIOS.

| Tag | Control in AIOS | Where | Status |
|---|---|---|---|
| `OWASP-LLM01:2025` Prompt Injection | Attack corpus, T4 data handling, model output parsed into a closed protocol, no shell | `aios/security/injection.py`, `tests/test_injection.py`, `aios/ai/planner.py` | implemented |
| `OWASP-LLM02:2025` Sensitive Information Disclosure | Raw file content is excluded from model context; external inference is opt-in; `filesystem.read` is `MEDIUM` and confirmation-gated | `aios/ai/context.py`, `aios/config.py` | partial — model context still contains host aggregates |
| `OWASP-LLM03:2025` Supply Chain | Dependencies and the OPA binary are declared; provider base URL is configuration | `pyproject.toml`, `aios/config.py` | partial — no SBOM, signature, or lock |
| `OWASP-LLM04:2025` Data and Model Poisoning | Observations are untrusted input; no training or fine-tuning occurs | `aios/ai/`, `SECURITY.md` | n/a for training; partial for observation trust |
| `OWASP-LLM05:2025` Improper Output Handling | Planner rejects non-JSON and unknown fields; output becomes a typed `ActionRequest`, never executed directly | `aios/ai/planner.py`, `aios/models/actions.py` | implemented |
| `OWASP-LLM06:2025` Excessive Agency | Fixed action catalog, capability + policy gates, no shell, mutation plan approval planned | `aios/security/`, `docs/ACTIONS.md` | implemented for read-only; planned for mutation |
| `OWASP-LLM07:2025` System Prompt Leakage | Prompts contain no secrets; provider keys never enter the prompt | `aios/ai/planner.py`, `aios/ai/context.py` | partial — no dedicated leakage tests |
| `OWASP-LLM08:2025` Vector and Embedding Weaknesses | No RAG or vector store | — | n/a |
| `OWASP-LLM09:2025` Misinformation | Model output is never treated as fact or authorization | `aios/security/engine.py` | implemented by design |
| `OWASP-LLM10:2025` Unbounded Consumption | Timeouts, entry caps, byte caps, output-token cap | `aios/ai/providers.py`, `aios/models/actions.py` | partial — no rate limiting |

## 5. OWASP API Security Top 10 2023

| Tag | Control in AIOS | Where | Status |
|---|---|---|---|
| `OWASP-API1:2023` BOLA | Capability is checked per agent and per action; target scope is re-checked | `aios/security/manager.py` | partial — no authenticated object ownership |
| `OWASP-API2:2023` Broken Authentication | Localhost-only control plane | `aios/api.py` | n/a by scope |
| `OWASP-API3:2023` BOPLA | `extra="forbid"`, typed params, no caller-supplied provenance | `aios/models/actions.py` | implemented |
| `OWASP-API4:2023` Unrestricted Resource Consumption | Entry limits, byte limits, timeouts, plan limits planned | `aios/gateway.py`, `docs/ACTIONS.md` | partial — no rate limit |
| `OWASP-API5:2023` BFLA | Action-level capability, forbidden-action list, no role inheritance | `aios/security/`, `aios/policies/data.json` | implemented |
| `OWASP-API6:2023` Sensitive Business Flows | No business flows exist | — | n/a |
| `OWASP-API7:2023` SSRF | No URL or host parameter in the protocol | `aios/models/actions.py` | implemented |
| `OWASP-API8:2023` Misconfiguration | Deny-by-default, restrictive defaults | `.env.example`, `aios/config.py` | partial |
| `OWASP-API9:2023` Inventory Management | Versioned action catalog and `/actions/schema` | `aios/api.py`, `docs/ACTIONS.md` | implemented for read-only |
| `OWASP-API10:2023` Unsafe Consumption of APIs | OPA and provider responses are parsed and validated; provider failure is fatal to the request | `aios/security/opa.py`, `aios/ai/providers.py` | partial |

## 6. OWASP ASVS 4.0.3 chapters

| Tag | Area | Status |
|---|---|---|
| `OWASP-ASVS4-V1` | Architecture, design, threat modelling | implemented |
| `OWASP-ASVS4-V2` | Authentication | n/a by scope |
| `OWASP-ASVS4-V3` | Session management | n/a by scope |
| `OWASP-ASVS4-V4` | Access control | implemented for read-only; plan approval planned |
| `OWASP-ASVS4-V5` | Validation, sanitization, encoding | implemented |
| `OWASP-ASVS4-V6` | Stored cryptography | partial — no encryption at rest |
| `OWASP-ASVS4-V7` | Error handling and logging | partial — audit exists, alerting does not |
| `OWASP-ASVS4-V8` | Data protection | partial — no file content egress, no encryption at rest |
| `OWASP-ASVS4-V9` | Communication | n/a — localhost only |
| `OWASP-ASVS4-V10` | Malicious code | implemented — no dynamic code loading from the agent |
| `OWASP-ASVS4-V11` | Business logic | planned — plan limits and budgets |
| `OWASP-ASVS4-V12` | Files and resources | implemented for read-only; quarantine/restore planned |
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

```python
@pytest.mark.owasp("OWASP-LLM01:2025")
def test_file_content_is_never_instruction() -> None:
    ...
```

A planned `tests/test_owasp_tags.py` asserts:

- every descriptor has at least one tag;
- every tag matches the canonical format;
- every Rego `ALLOW` rule has a non-empty `owasp_tags` array;
- every tag in code appears in this document;
- every `implemented` row references a test that exists.

## 8. Current gaps

These are the items that must not be described as covered:

| Gap | Affects | Consequence |
|---|---|---|
| No API authentication | A07, API2, ASVS V2 | Safe only because the API is localhost-only |
| No TLS | A02, ASVS V9 | Local-only traffic; no remote deployment |
| No dependency lock or SBOM | A06, LLM03 | Reproducibility and supply-chain assurance are incomplete |
| No rate limiting | LLM10, API4 | A denial loop can grow the ledger and consume CPU |
| No encryption at rest | A02, ASVS V6 | Audit database confidentiality depends on the host |
| No alerting | A09, ASVS V7 | Events are recorded but not monitored |
| Process `cmdline`/`name` labelled T2 | LLM01, A08 | Attacker-influenced text is trusted in the provenance envelope |
| No mutation implementation yet | A04, LLM06, V4, V12 | `docs/ACTIONS.md` defines the design; nothing is enforced yet |

## 9. Maintenance

- A new action descriptor must add tags before review.
- A new Rego `ALLOW` rule must add tags before review.
- A control change must update its status and its test reference in the same
  change.
- Removing a test downgrades the matching row to `partial` until a replacement
  exists.
- The tag list is part of the audit schema; retire tags, never reuse them.
