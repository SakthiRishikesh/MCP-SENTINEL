# Risk engine: gated cascade + evidence fusion

Risk is decided in two stages:

1. **Hard gates.** These are binary and run first: identity, agent binding, server/tool trust, integrity, input validation, RBAC × capability, admin rules, lockdown, data-flow exfiltration and critical runtime deviation. If any gate fails, the decision is **BLOCK**, whatever the score. Neither the LLM nor a good score can override a gate.
2. **Evidence fusion.** Every signal that is not a hard failure becomes a piece of *evidence*: an independent likelihood `pᵢ` that this call is unsafe. The engine combines the evidence with the **impact** of the action and returns a 0–100 score, a band and an obligation.

```
L = 1 − Π (1 − pᵢ)                 noisy-OR fusion: diminishing returns, never above 1
I = impact(action)                  capability, data class, destructiveness, external egress
R = 100 · L · (α + (1 − α) · I)     α = SENTINEL_RISK_ALPHA (default 0.5)
```

The earlier model added points together. Five weak signals would add up past the block threshold, so a normal `get_credentials` call during an investigation was hard-blocked instead of stepped up. With noisy-OR, weak signals have diminishing returns, strong evidence still dominates, and *impact* separates "suspicious but harmless" from "suspicious and dangerous".

## Bands and the response ladder

| Score | Band | Response (`sentinel/response.py`) |
|---|---|---|
| any | hard gate failed | **BLOCK** |
| ≥ 80 | CRITICAL | **BLOCK**: MFA never converts a critical score into an allow |
| — | approval obligation (policy rule, lockdown, changed tool) | **HUMAN_APPROVAL**: single-use and bound to the request hash |
| ≥ 60, or ≥ 40 on a state-changing capability, or an MFA policy obligation | HIGH / SUSPICIOUS | **MFA_REQUIRED** until step-up is satisfied |
| 40–79 with assurance satisfied | SUSPICIOUS / HIGH | **RESTRICT**: executes with strict output sanitisation (secrets redacted, injections quarantined) |
| 20–39 | MONITOR | **MONITOR**: executes with heightened monitoring |
| < 20 | NORMAL | **ALLOW** |

All thresholds are configurable: `SENTINEL_RESTRICT_RISK_THRESHOLD`, `SENTINEL_MFA_RISK_THRESHOLD` and `SENTINEL_BLOCK_RISK_THRESHOLD`.

## Impact

| Capability | Impact |
|---|---|
| READ | 0.25 |
| EXTERNAL_LOOKUP | 0.30 |
| WRITE | 0.50 |
| DATA_TRANSFER | 0.80 |
| SECRET_ACCESS | 0.90 |
| INFRASTRUCTURE_CONTROL | 0.95 |
| CODE_EXECUTION | 1.00 |

Adjustments:

* CRITICAL sensitivity raises impact to 0.9.
* A destructive action adds 0.15.
* SECRET or CRITICAL data raises it to at least 0.9; CONFIDENTIAL data raises it to at least 0.6.
* External egress adds 0.1.

## Evidence sources

| Evidence | Typical p | Source |
|---|---|---|
| `trust_prior` | 0.02 (TRUSTED) to 0.25 (RESTRICTED) | server/tool trust status |
| `integrity_drift`, `unreviewed_tool`, `tool_metadata`, `supply_chain` | 0.05–0.6 | discovery / scanner / supply-chain analysis |
| input soft findings, `prompt_injection_args` | 0.2–0.5 | `sentinel/validation.py`, `sentinel/injection.py` |
| `sequence_transition` | 0.15–0.5 | e.g. EXTERNAL_LOOKUP → SECRET_ACCESS 0.35; SECRET_ACCESS → DATA_TRANSFER 0.5; EXTERNAL_LOOKUP → CODE_EXECUTION 0.35 |
| `untrusted_then_sensitive` | 0.3 | a sensitive / exec / infra action after untrusted content was ingested *anywhere* earlier in the workflow (`workflow/analyzer.py`) |
| `privilege_escalation`, probing, velocity | 0.15–0.4 | `workflow/analyzer.py` |
| `intent_mismatch` | 0.3 | `workflow/context_engine.py` |
| `lethal_trifecta`, `confidential_transfer`, `secret_then_egress` | 0.2–0.7 | `dataflow/guard.py` |
| `behavior_drift`, `runtime`, `sandbox` | up to 0.6–0.9 | behavioural baseline, process monitor, honeypot |
| `entity_new_sensitive_capability`, `entity_new_agent`, `entity_new_server*`, `entity_off_hours`, `entity_volume_spike`, `entity_denial_history` | 0.08–0.4 | caller behaviour analytics (UEBA) — the call deviates from this user/agent's learned baseline (`monitoring/entity.py`); suppressed while the caller is still being learned |
| `corroboration` | 0.25 | three or more independent detector categories flagged the same call |
| `authn_assurance` | 0.25 | the call is sensitive and no MFA context is present |
| `workflow_memory` | ≤ 0.6 | decayed anomalies from earlier calls in the same workflow |

### Workflow risk memory

Zero trust re-evaluates continuously, so suspicion carries over between calls. Anomalies (category `anomaly`, `dataflow`, `behavior` or `runtime`, with p ≥ 0.15) are remembered per workflow and keyed by kind. They decay with a half-life of `SENTINEL_RISK_MEMORY_HALF_LIFE_SECONDS` (600 s by default). Before reuse they are damped (× 0.6) and capped at 0.6. When the current call already carries a kind of evidence, the remembered evidence of that kind is excluded, so an honest retry does not push risk up step by step. Structural signals such as the lethal trifecta are recomputed on every call rather than remembered.

## Explainability: the risk waterfall

Each factor's displayed contribution is its share of `−ln(1 − pᵢ)`. The contributions add up to the final score, so the dashboard can draw an additive waterfall. Every receipt stores the factors, `likelihood`, `impact`, `impact_reasons` and the full gate trace.

### Worked example

A trusted server's SECRET_ACCESS tool (for example `vault__get_secret`) runs right after an EXTERNAL_LOOKUP tool (for example `fetch__fetch`). The workflow's declared intent was an investigation, and the user has no MFA context:

| Factor | p | Contribution |
|---|---|---|
| sequence_transition: EXTERNAL_LOOKUP → SECRET_ACCESS | 0.35 | 23 |
| intent_mismatch: SECRET_ACCESS is not implied by the declared user intent | 0.30 | 19 |
| authn_assurance: no MFA context | 0.25 | 16 |
| privilege_escalation: monotonic escalation | 0.15 | 9 |
| trust_prior: TRUSTED | 0.02 | 1 |

L = 1 − (0.65 · 0.70 · 0.75 · 0.85 · 0.98) = **0.7157**. Impact = **0.9** (SECRET_ACCESS, SECRET data). R = 100 · 0.7157 · (0.5 + 0.5 · 0.9) = **68**, which is HIGH, so the decision is **MFA_REQUIRED**.

After a TOTP step-up, `authn_assurance` disappears and the score drops to **59** (SUSPICIOUS). The call executes as **RESTRICT**, so the returned secret is redacted. Any later attempt to send that secret to an external destination is a hard data-flow **BLOCK**.

## Swapping the model

The scoring model is isolated in `risk/engine.py` (`RiskEngine.assess` and `RiskEngine.impact`). The pipeline only builds a list of `Evidence(name, likelihood, reason, category)` and an impact value, so a different fusion function (a Bayesian network, a learned model or a weighted sum) can replace `assess` without touching the gates, the obligations or the receipts.
## Caller behaviour analytics (UEBA)

Sentinel profiles the *caller*, not only the server. Every executed call updates a per-subject baseline (`monitoring/entity.py`, persisted in the `entity_profiles` table): which tools, servers and capabilities it uses, at which UTC hours, how often (peak calls/minute), through which agents, and how much of that is sensitive. After a short learning window (`LEARN_MIN` = 8 calls) deviations from the baseline become risk evidence with category `behavior`:

| Signal | Meaning |
|---|---|
| `entity_new_sensitive_capability` | the subject uses a sensitive capability (SECRET_ACCESS, DATA_TRANSFER, CODE_EXECUTION, INFRASTRUCTURE_CONTROL) for the first time |
| `entity_new_agent` | a known subject suddenly acts through an agent it has never used — a classic token-reuse / impersonation indicator |
| `entity_new_server` / `entity_new_server_sensitive` | first use of a server (weighted up when the call is sensitive) |
| `entity_off_hours` | a sensitive call at an hour the subject is never otherwise active |
| `entity_volume_spike` | a burst of calls far above the subject's usual peak rate (runaway agent / automation) |
| `entity_denial_history` | the subject keeps attempting sensitive calls after repeated denials (probing / confused-deputy abuse) |

A brand-new subject is never penalised for doing things for the first time — during the learning window novelty is expected, not anomalous. The dashboard's **Entities** view shows each caller's learned baseline, hour-of-day activity and the anomalies it triggered. This is evidence about the caller and is fused with the server-side detectors by the same risk engine, so "malicious behaviour from the user" and "malicious behaviour from the MCP server" are scored together.

