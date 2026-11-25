"""Hash-chained append-only audit log (DESIGN.md §Audit).

One JSONL record per tool call; ``hash = sha256(prev_hash | canonical)``.
Bodies never land here; recipients/subject do for send-class ops only.

The chain head (last hash + sequence number) persists in
``audit/chain.state`` so the chain continues across restarts instead of
silently restarting at GENESIS — without that, deleting a whole day's
file was undetectable. ``scripts/verify_audit_chain.py`` walks the files
and re-derives every link.

When one process serves many mailboxes, each mailbox has its own chain
(:func:`mailbox_audit`) under ``DATA_DIR/mailboxes/<key>/audit`` whose
records name the acting mailbox: one person's trail can be exported or
verified on its own, and mailboxes never contend for one chain lock.
"""

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional


class AuditLog:
    def __init__(self, data_dir: str, *, directory: Optional[str] = None,
                 mailbox: Optional[str] = None):
        self._dir = Path(directory) if directory else Path(data_dir) / "audit"
        self._mailbox = mailbox
        self._state_path = self._dir / "chain.state"
        self._lock = threading.Lock()
        self._prev = "GENESIS"
        self._seq = 0
        try:  # resume the persisted chain head; a fresh dir starts at GENESIS
            state = json.loads(self._state_path.read_text(encoding="utf-8"))
            self._prev = str(state["prev"])
            self._seq = int(state["seq"])
        except Exception:
            pass

    @property
    def directory(self) -> Path:
        return self._dir

    def record(
        self,
        tool: str,
        side_effect_class: str,
        outcome: str,
        latency_ms: int,
        transport: str = "-",
        detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        entry: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "tool": tool,
            "class": side_effect_class,
            "outcome": outcome,
            "latency_ms": latency_ms,
            "transport": transport,
        }
        if self._mailbox:
            entry["mailbox"] = self._mailbox
        if detail:
            entry["detail"] = detail
        try:
            with self._lock:
                self._seq += 1
                entry["seq"] = self._seq
                entry["prev"] = self._prev[:12]
                canonical = json.dumps(entry, sort_keys=True, ensure_ascii=False)
                digest = hashlib.sha256(f"{self._prev}|{canonical}".encode()).hexdigest()
                entry["h"] = digest
                self._prev = digest
                self._dir.mkdir(parents=True, exist_ok=True)
                path = self._dir / f"audit-{time.strftime('%Y%m%d')}.jsonl"
                with path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
                self._state_path.write_text(
                    json.dumps({"prev": self._prev, "seq": self._seq}),
                    encoding="utf-8",
                )
        except Exception:
            # Auditing must never take a tool call down.
            pass


def mailbox_audit_dir(data_dir: str, mailbox_key: str) -> Path:
    if not mailbox_key or not mailbox_key.isalnum():
        raise ValueError("mailbox_key must be a non-empty alphanumeric key")
    return Path(data_dir) / "mailboxes" / mailbox_key / "audit"


def mailbox_audit(data_dir: str, mailbox_key: str, mailbox: str) -> AuditLog:
    """The audit chain of one mailbox; its records name the acting mailbox."""
    return AuditLog(data_dir, directory=str(mailbox_audit_dir(data_dir, mailbox_key)),
                    mailbox=mailbox)
