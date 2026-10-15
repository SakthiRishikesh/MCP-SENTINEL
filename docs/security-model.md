# Security model

## Assumptions

* The LLM, the MCP client and **every byte returned by a tool** are untrusted. Prompt injection may succeed against the model, so Sentinel never relies on the model's cooperation.
* MCP servers can change or be compromised after review (rug pulls, supply-chain updates, compromised hosts).
* Tool annotations (`readOnlyHint`, `destructiveHint`, …) are hints from an untrusted server. They can raise risk, never lower it.
* Network location does not grant trust. Loopback binding and Host/Origin checks exist only to stop browsers and the LAN from reaching a local control plane.
* The trusted computing base is the Sentinel process, its database, its key files and the identity provider.

## Hard rules (always override the score)

| Rule | Result |
|---|---|
| Missing, expired or invalid token, wrong issuer or audience, empty subject, or HS* in OIDC mode | BLOCK |
| Agent id in the request disagrees with the token | BLOCK |
| Unknown, disabled, QUARANTINED or BLOCKED server; unknown, REJECTED, QUARANTINED, BLOCKED or removed tool | BLOCK |
| Role lacks **any** capability the tool needs (RBAC × capability, multi-capability aware) | BLOCK |
| Admin DENY rule, or lockdown `deny_all` | BLOCK |
| RESTRICTED server or tool asked to run a sensitive capability | BLOCK |
| Path traversal, credential paths, shell chaining in non-content fields, dangerous commands on exec tools, cloud metadata or dangerous-scheme destinations | BLOCK |
| Secret bytes seen earlier in the workflow leave through any egress tool (content taint, including encoded forms) | BLOCK |
| SECRET or CRITICAL data to an external sink | BLOCK |
| Critical runtime deviation during or before the call | BLOCK, with QUARANTINE |
| Risk ≥ 80 | BLOCK (MFA cannot lift it) |

## Least privilege for sensitive capabilities

`ANALYST` gets READ, EXTERNAL_LOOKUP and WRITE (tokens carrying the older `SOC_ANALYST` role name are mapped to it). `DEVELOPER` also gets CODE_EXECUTION. Only administrators get SECRET_ACCESS, DATA_TRANSFER and INFRASTRUCTURE_CONTROL. A sensitive call needs all of the following:

1. a role that includes the capability;
2. step-up assurance when policy or risk demands it: RFC 6238 TOTP (replay-protected, secret encrypted at rest), IdP `acr`/`amr`, or demo confirmation (demo mode only);
3. a **capability lease** bound to workflow + subject + server + tool + capability, with a TTL. For CRITICAL tools the lease is also bound to the exact arguments (`scope_hash`);
4. passing the sequence, context, data-flow, taint and runtime checks on **every** call, even with a lease.

MFA raises assurance. It never turns a hard deny or a CRITICAL score into an allow. Human approvals are single-use, bound to a request hash, and expire. Separation of duties applies: requesters cannot approve their own requests outside demo mode.

## Output is data, not instructions

Before results reach the model:

* invisible, bidi, Unicode-tag and ANSI characters are stripped;
* secrets are redacted (unless SECRET_ACCESS was authorised and the call was not RESTRICTED);
* prompt-injection content is spotlighted, or quarantined (withheld) for high-confidence or RESTRICT cases;
* the output is withheld when the tool misbehaved during the call (suspicious children, new remote hosts, canary access).

Secret values are fingerprinted (salted SHA-256, never stored in clear) for taint tracking.

## Secrets and keys

* Upstream server configurations (commands, arguments, environment, headers) and TOTP secrets are encrypted with Fernet (`keys/secrets.key` or `SENTINEL_SECRETS_KEY`). The API only ever returns masked values.
* Receipts are signed with Ed25519 (`keys/receipts.key`) and hash-chained. `/v1/audit/verify` detects modified, reordered or deleted rows.
* Key files are created with mode 0600 and git-ignored.
* stdio servers receive a minimal inherited environment (PATH, HOME, locale and similar) plus only the variables configured for them, so your shell's tokens do not leak into third-party servers.

## Local deployment hardening

* The API binds to `127.0.0.1`. `TrustedHostMiddleware` rejects unknown Host headers, and `/mcp` rejects foreign Origins. Together these defeat DNS rebinding.
* Demo tokens are only issued to loopback clients (`SENTINEL_DEMO_TOKEN_LOOPBACK_ONLY`).
* CORS never allows credentials, and tokens are sent as bearer headers.
* Runtime evidence comes only from Sentinel's own sensors (sandbox pre-flight, process monitor, honeypot, behavioural baselines). A tool's annotations and description are claims the sandbox checks, never evidence of safety. Telemetry fields in client requests are ignored.

## Production extensions

* OIDC with WebAuthn/FIDO2 step-up at the IdP (Keycloak realm included)
* mTLS or SPIFFE identities for agents and remote servers
* an external policy engine (for example OPA) with signed policy bundles, fed the same inputs as the built-in PDP (lockdown, admin rules, review state)
* container or eBPF runtime sensors in place of best-effort process monitoring
* signed server attestations (Sigstore, in-toto) consumed as integrity evidence
