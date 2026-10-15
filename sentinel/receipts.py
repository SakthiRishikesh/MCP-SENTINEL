"""Decision receipts as a tamper-evident ledger.

Every receipt carries ``seq``, ``prev_hash`` and ``receipt_hash = SHA-256(seq, prev_hash,
payload_hash, receipt_id, timestamp)`` and an Ed25519 signature over that hash. Editing,
deleting or re-ordering any historical receipt breaks the chain, which
``verify_chain`` reports with the first broken sequence number.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import uuid
from datetime import timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from integrity.crypto import canonical_json
from sentinel.config import get_settings
from sentinel.db import EventRow, ReceiptRow
from sentinel.types import utcnow

GENESIS = "0" * 64
_chain_lock = threading.Lock()
_key_lock = threading.Lock()
_keys: dict[str, Ed25519PrivateKey] = {}


def _signing_key() -> Ed25519PrivateKey:
    path = get_settings().receipt_key_file
    with _key_lock:
        key = _keys.get(path)
        if key is not None:
            return key
        p = Path(path)
        if p.exists():
            loaded = serialization.load_pem_private_key(p.read_bytes(), password=None)
            if not isinstance(loaded, Ed25519PrivateKey):
                raise RuntimeError("receipt signing key must be Ed25519")
            key = loaded
        else:
            key = Ed25519PrivateKey.generate()
            p.parent.mkdir(parents=True, exist_ok=True)
            pem = key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
            fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(pem)
        _keys[path] = key
        return key


def public_key_pem() -> str:
    return (
        _signing_key()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def _json_safe(payload: dict[str, Any]) -> dict[str, Any]:
    return json.loads(canonical_json(payload))


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _receipt_hash(seq: int, prev_hash: str, payload_hash: str, receipt_id: str, timestamp: str) -> str:
    return _sha(canonical_json({"seq": seq, "prev": prev_hash, "payload": payload_hash, "id": receipt_id, "ts": timestamp}))


def _ts(row: ReceiptRow) -> str:
    ts = row.timestamp
    if ts.tzinfo is None:  # SQLite drops tzinfo on round-trip
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).isoformat()


class AuditStore:
    def __init__(self, session: Session) -> None:
        self.session = session

    def write_receipt(self, payload: dict[str, Any]) -> ReceiptRow:
        safe = _json_safe(payload)
        key = _signing_key()
        for _attempt in range(6):
            with _chain_lock:
                last = (
                    self.session.query(ReceiptRow)
                    .filter(ReceiptRow.seq.isnot(None))
                    .order_by(ReceiptRow.seq.desc())
                    .first()
                )
                seq = (last.seq or 0) + 1 if last else 1
                prev_hash = (last.receipt_hash or GENESIS) if last else GENESIS
                receipt_id = str(uuid.uuid4())
                current = utcnow()
                now = current.replace(microsecond=(current.microsecond // 1000) * 1000)
                row = ReceiptRow(
                    receipt_id=receipt_id,
                    workflow_id=safe.get("workflow_id", ""),
                    identity=safe.get("identity", ""),
                    agent=safe.get("agent", ""),
                    server=safe.get("server", ""),
                    tool=safe.get("tool", ""),
                    decision=safe.get("decision", ""),
                    risk_score=int(safe.get("risk_score") or 0),
                    state=safe.get("state", ""),
                    reasons=safe.get("reasons") or [],
                    previous_tools=safe.get("previous_tools") or [],
                    payload=safe,
                    timestamp=now,
                    seq=seq,
                    prev_hash=prev_hash,
                )
                row.receipt_hash = _receipt_hash(seq, prev_hash, _sha(canonical_json(safe)), receipt_id, _ts(row))
                row.signature = base64.b64encode(key.sign(row.receipt_hash.encode())).decode()
                self.session.add(row)
                try:
                    self.session.commit()
                    return row
                except IntegrityError:  # another process appended the same seq; retry on the new head
                    self.session.rollback()
        raise RuntimeError("could not append receipt to the audit chain")

    def write_event(self, event_type: str, severity: str, message: str, details: dict[str, Any] | None = None) -> EventRow:
        row = EventRow(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            severity=severity,
            message=message,
            details=json.loads(canonical_json(details or {})),
            timestamp=utcnow(),
        )
        self.session.add(row)
        self.session.commit()
        return row


def verify_chain(session: Session, limit: int | None = None) -> dict[str, Any]:
    """Recompute every hash and signature. Returns the first broken link, if any."""
    public: Ed25519PublicKey = _signing_key().public_key()
    query = session.query(ReceiptRow).filter(ReceiptRow.seq.isnot(None)).order_by(ReceiptRow.seq.asc())
    rows = query.all() if limit is None else query.limit(limit).all()
    expected_prev = GENESIS
    expected_seq = 1
    for row in rows:
        problem = None
        if row.seq != expected_seq:
            problem = f"sequence gap: expected {expected_seq}, found {row.seq} (receipt deleted or inserted)"
        elif (row.prev_hash or "") != expected_prev:
            problem = "prev_hash does not match the previous receipt (chain re-ordered or rewritten)"
        else:
            recomputed = _receipt_hash(row.seq, row.prev_hash or "", _sha(canonical_json(row.payload or {})), row.receipt_id, _ts(row))
            if recomputed != row.receipt_hash:
                problem = "receipt content was modified after it was written"
            else:
                try:
                    public.verify(base64.b64decode(row.signature or ""), (row.receipt_hash or "").encode())
                except (InvalidSignature, ValueError):
                    problem = "signature verification failed"
        if problem:
            return {"ok": False, "checked": expected_seq - 1, "broken_seq": row.seq, "receipt_id": row.receipt_id, "reason": problem}
        expected_prev = row.receipt_hash or ""
        expected_seq += 1
    return {"ok": True, "checked": len(rows), "head": expected_prev, "algorithm": "sha256-chain+ed25519"}
