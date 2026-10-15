"""Workflow replay and signed incident reports.

Everything Sentinel recorded about one agent session - each decision (signed receipt), each
sandbox pre-flight and its effect preview, approvals and step-ups, file changes and undo
journals, security events - merged into one ordered timeline that the dashboard can replay
step by step and that can be exported as a self-contained HTML or JSON incident report.

The report is evidence: every receipt in it is re-verified (hash + Ed25519 signature), and the
report itself is signed with the same key, so a reader with the public key can check that
nothing was edited after export.
"""

from __future__ import annotations

import base64
import hashlib
import html
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from sqlalchemy.orm import Session

from sentinel.db import ApprovalRow, EventRow, ReceiptRow, SandboxRunRow, UndoRow, WorkflowCallRow
from sentinel.receipts import _receipt_hash, _sha, _signing_key, _ts, canonical_json, public_key_pem
from sentinel.types import as_utc

SEVERITY = {"BLOCK": "CRITICAL", "QUARANTINE": "CRITICAL", "HUMAN_APPROVAL": "HIGH", "MFA_REQUIRED": "HIGH", "RESTRICT": "MEDIUM",
            "MONITOR": "LOW", "ALLOW": "INFO"}


def _iso(value: datetime | None) -> str:
    v = as_utc(value)
    return v.isoformat() if v else ""


def _verify_receipt(row: ReceiptRow) -> bool:
    try:
        recomputed = _receipt_hash(row.seq, row.prev_hash or "", _sha(canonical_json(row.payload or {})), row.receipt_id, _ts(row))
        if recomputed != row.receipt_hash:
            return False
        _signing_key().public_key().verify(base64.b64decode(row.signature or ""), (row.receipt_hash or "").encode())
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def build_report(session: Session, workflow_id: str) -> dict[str, Any] | None:
    receipts = session.query(ReceiptRow).filter(ReceiptRow.workflow_id == workflow_id).order_by(ReceiptRow.timestamp.asc()).all()
    calls = session.query(WorkflowCallRow).filter(WorkflowCallRow.workflow_id == workflow_id).order_by(WorkflowCallRow.id.asc()).all()
    if not receipts and not calls:
        return None
    runs = session.query(SandboxRunRow).filter(SandboxRunRow.workflow_id == workflow_id).order_by(SandboxRunRow.created_at.asc()).all()
    undo = session.query(UndoRow).filter(UndoRow.workflow_id == workflow_id).order_by(UndoRow.created_at.asc()).all()
    approvals = session.query(ApprovalRow).filter(ApprovalRow.workflow_id == workflow_id).order_by(ApprovalRow.created_at.asc()).all()
    receipt_ids = {r.receipt_id for r in receipts}
    events = []
    for e in session.query(EventRow).order_by(EventRow.timestamp.desc()).limit(5000).all():
        d = e.details or {}
        if e.event_type == "decision":
            continue  # already represented by its receipt
        if d.get("workflow_id") == workflow_id or d.get("receipt_id") in receipt_ids:
            events.append(e)
    events.reverse()

    timeline: list[dict[str, Any]] = []
    receipt_view = []
    for r in receipts:
        payload = r.payload or {}
        explain = payload.get("explainability") or {}
        verified = _verify_receipt(r)
        item = {
            "receipt_id": r.receipt_id, "seq": r.seq, "at": _iso(r.timestamp), "identity": r.identity, "agent": r.agent,
            "server": r.server, "tool": r.tool, "decision": r.decision, "risk_score": r.risk_score, "state": r.state,
            "policy_id": payload.get("policy_id"), "reasons": r.reasons or [], "arguments_preview": payload.get("arguments_preview") or {},
            "restrictions": payload.get("restrictions") or [], "sandbox": explain.get("sandbox"),
            "superseded_receipt": explain.get("superseded_receipt"), "receipt_hash": r.receipt_hash, "verified": verified,
        }
        receipt_view.append(item)
        timeline.append({"at": item["at"], "kind": "decision", "severity": SEVERITY.get(r.decision, "INFO"),
                         "title": f"{r.decision} {r.tool}", "detail": "; ".join((r.reasons or [])[:3]),
                         "risk": r.risk_score, "ref": r.receipt_id, "policy": item["policy_id"], "verified": verified})
    for run in runs:
        timeline.append({"at": _iso(run.created_at), "kind": "sandbox", "severity": {"MALICIOUS": "CRITICAL", "DANGEROUS": "HIGH",
                         "SUSPICIOUS": "MEDIUM"}.get(run.verdict, "INFO"), "title": f"sandbox {run.verdict.lower()} · {run.exposed_name}",
                         "detail": (run.preview or {}).get("headline", "") + (f" — {run.reasons[0]}" if run.reasons else ""),
                         "ref": run.run_id, "preview": run.preview, "action": run.action})
    for a in approvals:
        timeline.append({"at": _iso(a.created_at), "kind": "approval", "severity": "HIGH", "title": f"approval requested · {a.tool_name}",
                         "detail": "; ".join((a.reasons or [])[:2]), "ref": a.approval_id})
        if a.resolved_at:
            timeline.append({"at": _iso(a.resolved_at), "kind": "approval", "severity": "INFO" if a.status == "APPROVED" else "MEDIUM",
                             "title": f"approval {a.status.lower()} · {a.tool_name}", "detail": f"by {a.resolver}", "ref": a.approval_id})
    for u in undo:
        timeline.append({"at": _iso(u.created_at), "kind": "files", "severity": "CRITICAL" if u.evasion else "INFO",
                         "title": f"files changed · {u.exposed_name}", "detail": u.summary + (" (sandbox evasion reverted)" if u.evasion else ""),
                         "ref": u.undo_id, "status": u.status})
    for e in events:
        timeline.append({"at": _iso(e.timestamp), "kind": "event", "severity": e.severity, "title": e.event_type.replace("_", " "),
                         "detail": e.message, "ref": e.event_id})
    timeline.sort(key=lambda t: t["at"])

    decisions: dict[str, int] = {}
    for r in receipts:
        decisions[r.decision] = decisions.get(r.decision, 0) + 1
    started = timeline[0]["at"] if timeline else ""
    ended = timeline[-1]["at"] if timeline else ""
    report: dict[str, Any] = {
        "format": "mcp-sentinel-incident-report/1",
        "workflow_id": workflow_id,
        "started_at": started,
        "ended_at": ended,
        "summary": {
            "decisions": decisions,
            "calls": len(calls),
            "executed": sum(1 for c in calls if c.allowed),
            "blocked": decisions.get("BLOCK", 0) + decisions.get("QUARANTINE", 0),
            "escalated": decisions.get("HUMAN_APPROVAL", 0) + decisions.get("MFA_REQUIRED", 0),
            "max_risk": max((r.risk_score for r in receipts), default=0),
            "tools": sorted({r.tool for r in receipts}),
            "servers": sorted({r.server for r in receipts}),
            "identities": sorted({r.identity for r in receipts}),
            "data_classes": sorted({c.data_class for c in calls if c.data_class}),
            "sandbox_runs": len(runs),
            "sandbox_blocks": sum(1 for r in runs if r.action == "BLOCKED"),
            "files_changed": sum(len(u.entries or []) for u in undo),
            "receipts_verified": sum(1 for r in receipt_view if r["verified"]),
            "receipts_total": len(receipt_view),
        },
        "timeline": timeline,
        "receipts": receipt_view,
    }
    digest = hashlib.sha256(canonical_json(report).encode()).hexdigest()
    report["integrity"] = {
        "digest_sha256": digest,
        "signature_ed25519": base64.b64encode(_signing_key().sign(digest.encode())).decode(),
        "public_key_pem": public_key_pem(),
        "how_to_verify": "Remove the 'integrity' object, serialise the rest as canonical JSON (sorted keys, compact separators, "
                         "UTF-8), SHA-256 it, and verify the Ed25519 signature over the hex digest with the public key.",
    }
    return report


def verify_report(report: dict[str, Any]) -> bool:
    """Check an exported report against Sentinel's key (used by the API and tests)."""
    integrity = report.get("integrity") or {}
    body = {k: v for k, v in report.items() if k != "integrity"}
    digest = hashlib.sha256(canonical_json(body).encode()).hexdigest()
    if digest != integrity.get("digest_sha256"):
        return False
    try:
        _signing_key().public_key().verify(base64.b64decode(integrity.get("signature_ed25519") or ""), digest.encode())
        return True
    except (InvalidSignature, ValueError):
        return False


def render_html(report: dict[str, Any]) -> str:
    e = html.escape
    s = report["summary"]
    rows = []
    for t in report["timeline"]:
        preview = t.get("preview") or {}
        files = "".join(f"<li><code>{e(str(f.get('change')))}</code> {e(str(f.get('path')))}</li>" for f in (preview.get("files") or [])[:10])
        rows.append(
            f"<tr class='sev-{e(str(t.get('severity', 'INFO')))}'><td class='mono'>{e(t['at'][11:23] if len(t['at']) > 20 else t['at'])}</td>"
            f"<td>{e(t['kind'])}</td><td><strong>{e(t['title'])}</strong>"
            + (f" <span class='pill'>risk {int(t['risk'])}</span>" if t.get("risk") is not None else "")
            + (" <span class='pill bad'>signature check failed</span>" if t.get("verified") is False else "")
            + f"<div class='muted'>{e(str(t.get('detail') or ''))}</div>" + (f"<ul>{files}</ul>" if files else "") + "</td></tr>"
        )
    receipts = "".join(
        f"<tr><td class='mono'>{e(str(r['seq']))}</td><td class='mono'>{e(r['receipt_id'][:8])}</td><td>{e(r['decision'])}</td>"
        f"<td>{e(r['tool'])}</td><td>{e(str(r['policy_id'] or ''))}</td><td class='mono'>{e((r['receipt_hash'] or '')[:16])}…</td>"
        f"<td>{'✔' if r['verified'] else '✘'}</td></tr>"
        for r in report["receipts"]
    )
    integ = report.get("integrity") or {}
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Incident report · {e(report['workflow_id'])}</title>
<style>
:root{{color-scheme:light dark;--bg:#fff;--ink:#16181d;--muted:#5b616e;--line:#d9dce3;--bad:#b42323;--warn:#8a5a00;--ok:#006300}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111318;--ink:#e8eaf0;--muted:#9aa1ae;--line:#2a2e37;--bad:#ff7a7a;--warn:#f5c04a;--ok:#4fd36a}}}}
body{{font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--ink);margin:0 auto;max-width:1100px;padding:24px 16px}}
h1{{font-size:22px;margin:0 0 4px}}.muted{{color:var(--muted)}}.mono,code{{font-family:ui-monospace,monospace;font-size:12px}}
table{{width:100%;border-collapse:collapse;margin:12px 0}}td,th{{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin:16px 0}}
.tile{{border:1px solid var(--line);border-radius:8px;padding:8px 10px}}.tile b{{display:block;font-size:20px}}
.pill{{border:1px solid var(--line);border-radius:99px;padding:0 6px;font-size:11px}}.pill.bad{{color:var(--bad)}}
tr.sev-CRITICAL td:first-child{{border-left:3px solid var(--bad)}}tr.sev-HIGH td:first-child{{border-left:3px solid var(--warn)}}
ul{{margin:4px 0 0 18px;padding:0}}pre{{white-space:pre-wrap;word-break:break-all;font-size:11px}}
</style></head><body>
<h1>MCP-Sentinel incident report</h1>
<div class="muted">Workflow <span class="mono">{e(report['workflow_id'])}</span> · {e(report['started_at'])} → {e(report['ended_at'])}</div>
<div class="grid">
<div class="tile"><b>{s['calls']}</b>tool calls</div><div class="tile"><b>{s['blocked']}</b>blocked</div>
<div class="tile"><b>{s['escalated']}</b>sent to a person</div><div class="tile"><b>{s['max_risk']}</b>max risk</div>
<div class="tile"><b>{s['sandbox_runs']}</b>sandbox runs</div><div class="tile"><b>{s['files_changed']}</b>files changed</div>
<div class="tile"><b>{s['receipts_verified']}/{s['receipts_total']}</b>receipts verified</div></div>
<p>Identities: {e(', '.join(s['identities']) or '—')} · Tools: <span class="mono">{e(', '.join(s['tools']) or '—')}</span></p>
<h2>Timeline</h2><table><thead><tr><th>Time (UTC)</th><th>Kind</th><th>What happened</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<h2>Signed receipts</h2><table><thead><tr><th>Seq</th><th>Receipt</th><th>Decision</th><th>Tool</th><th>Policy</th><th>Hash</th><th>Valid</th></tr></thead><tbody>{receipts}</tbody></table>
<h2>Integrity</h2><p class="muted">{e(integ.get('how_to_verify', ''))}</p>
<p>SHA-256 <span class="mono">{e(integ.get('digest_sha256', ''))}</span></p>
<p>Ed25519 signature <span class="mono">{e(integ.get('signature_ed25519', ''))}</span></p>
<pre>{e(integ.get('public_key_pem', ''))}</pre>
</body></html>"""
