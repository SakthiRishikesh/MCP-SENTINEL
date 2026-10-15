# Notifications and incident reports

## Approvals and alerts where people are

Sentinel holds a risky call open while a person decides. That only works if the person finds out. **Alerts** (dashboard) pushes the decision to them the moment it is needed:

| Channel | What is sent | Configure with |
|---|---|---|
| Slack | Block Kit message with a **Review in Sentinel** button | an incoming-webhook URL |
| Microsoft Teams | Adaptive Card with an *Open* action | a Workflows webhook URL |
| ntfy (phone / desktop push) | push notification; tapping it opens the approval page | a topic URL (`https://ntfy.sh/<secret-topic>` or self-hosted), optional access token |
| Generic webhook | JSON (`event`, `title`, `message`, `severity`, `url`, `preview_headline`, `files`, `details`) | any URL; with a secret, each request carries `X-Sentinel-Signature: sha256=<HMAC-SHA256 of the body>` |

Events (each can be switched off):

| Event | When |
|---|---|
| `approval` | a call waits for human approval (including sandbox escalations) |
| `mfa` | a call waits for step-up authentication |
| `sandbox_block` | the sandbox blocked a call (MALICIOUS or DANGEROUS) |
| `sandbox_evasion` | a real call changed files the sandbox did not predict; they were reverted |
| `server_unsafe` | a server was judged NOT SAFE |
| `rug_pull` | a tool definition changed after approval and was classified MALICIOUS |

Messages carry the **effect preview** from the sandbox run ("Would modify 1 file", the paths involved) but never the call's arguments. One message is sent per approval or step-up, not per retry.

**A notification never approves anything.** Its link opens Sentinel's approval page, where the person still signs in and passes step-up. That keeps a leaked Slack message or a forwarded push from turning into an approval.

Channels added in the dashboard are stored encrypted with Sentinel's secrets key and are never shown again (only the host and the start of the path). Channels can also come from the environment: `SENTINEL_NOTIFY_SLACK_WEBHOOK_URL`, `SENTINEL_NOTIFY_TEAMS_WEBHOOK_URL`, `SENTINEL_NOTIFY_NTFY_URL` (+ `SENTINEL_NOTIFY_NTFY_TOKEN`), `SENTINEL_NOTIFY_WEBHOOK_URLS` (comma-separated, + `SENTINEL_NOTIFY_WEBHOOK_SECRET`), with the event list in `SENTINEL_NOTIFY_EVENTS`.

Delivery happens on a background thread with one retry and a 6-second timeout, so a slow or failing channel never delays or fails a tool call. The last 50 deliveries and their HTTP status are listed on the Alerts page. **Send test** checks every channel.

API: `GET /v1/notifications`, `POST /v1/notifications/channels`, `DELETE /v1/notifications/channels/{index}`, `PUT /v1/notifications/kinds`, `POST /v1/notifications/test` (all admin).

## Workflow replay and signed incident reports

**Workflows → (a workflow) → Replay & incident report** merges everything Sentinel recorded for one agent session into one ordered timeline:

* every decision, from its signed receipt (decision, risk, policy, reasons), including receipts that superseded others (a sandbox block or escalation);
* every sandbox pre-flight with its verdict and the files it would have changed;
* approval requests and who resolved them;
* file changes of executed calls (undo journal) and any sandbox-evasion revert;
* related security events (output injection, behaviour anomalies, quarantines, …).

**▶ Replay** steps through the session one event at a time, which is useful when walking someone through an incident.

**Export HTML / JSON** produces a self-contained incident report. When it is built, every receipt in it is re-verified (recomputed SHA-256 hash and Ed25519 signature) and marked valid or invalid. The report itself is then signed:

```
integrity.digest_sha256      = sha256(canonical_json(report without "integrity"))
integrity.signature_ed25519  = Ed25519(receipt key, digest)
integrity.public_key_pem     = the verifying key
```

Anyone holding the public key can check the export offline. Sentinel also exposes `POST /v1/reports/verify`, which returns `{"valid": false}` if a single byte was edited after export. The HTML report is served with a no-script Content-Security-Policy and escapes all recorded content.

API: `GET /v1/workflows/{id}/report` (JSON for the dashboard), `GET /v1/workflows/{id}/report.json` · `.html` (`?download=1` for an attachment), `POST /v1/reports/verify`.
