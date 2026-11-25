"""Audit chain persistence (Phase B robustness) + the ported verifier.

Before this, the chain restarted at GENESIS on every boot, so deleting a
whole day's audit file was undetectable. The chain head now persists in
``audit/chain.state`` and ``scripts/verify_audit_chain.py`` re-derives
every link across files and restarts.
"""

import importlib.util
import json
from pathlib import Path

from ewsmcp.audit import AuditLog

_VERIFIER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "verify_audit_chain.py"
_spec = importlib.util.spec_from_file_location("verify_audit_chain", _VERIFIER_PATH)
verifier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verifier)


def _record(log: AuditLog, n: int) -> None:
    for i in range(n):
        log.record(tool=f"t{i}", side_effect_class="read", outcome="ok",
                   latency_ms=1)


def test_chain_continues_across_restarts(tmp_path):
    _record(AuditLog(str(tmp_path)), 2)
    _record(AuditLog(str(tmp_path)), 1)  # a "restarted process"
    audit_dir = tmp_path / "audit"
    lines = []
    for path in sorted(audit_dir.glob("audit-*.jsonl")):
        lines += path.read_text(encoding="utf-8").strip().splitlines()
    seqs = [json.loads(line)["seq"] for line in lines]
    assert seqs == [1, 2, 3]  # no GENESIS restart at seq 3
    state = json.loads((audit_dir / "chain.state").read_text(encoding="utf-8"))
    assert state["seq"] == 3
    assert state["prev"] == json.loads(lines[-1])["h"]


def test_verifier_passes_on_intact_chain(tmp_path):
    _record(AuditLog(str(tmp_path)), 3)
    _record(AuditLog(str(tmp_path)), 2)
    assert verifier.verify(tmp_path / "audit") == 0


def test_verifier_catches_edited_record(tmp_path):
    _record(AuditLog(str(tmp_path)), 3)
    audit_dir = tmp_path / "audit"
    path = next(iter(sorted(audit_dir.glob("audit-*.jsonl"))))
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    doctored = json.loads(lines[1])
    doctored["tool"] = "something_else"  # tamper with the middle record
    lines[1] = json.dumps(doctored, sort_keys=True, ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verifier.verify(audit_dir) == 1


def test_verifier_catches_truncated_tail(tmp_path):
    _record(AuditLog(str(tmp_path)), 3)
    audit_dir = tmp_path / "audit"
    path = next(iter(sorted(audit_dir.glob("audit-*.jsonl"))))
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    assert verifier.verify(audit_dir) == 1  # chain.state no longer matches


# --- one chain per mailbox ---------------------------------------------------


def test_each_mailbox_has_its_own_chain_naming_the_actor(tmp_path):
    from ewsmcp.audit import mailbox_audit

    alice = mailbox_audit(str(tmp_path), "aaa111", "alice@corp.example")
    bob = mailbox_audit(str(tmp_path), "bbb222", "bob@corp.example")
    _record(alice, 2)
    _record(bob, 1)
    assert alice.directory != bob.directory
    a_lines = [json.loads(line) for path in sorted(alice.directory.glob("audit-*.jsonl"))
               for line in path.read_text(encoding="utf-8").splitlines()]
    b_lines = [json.loads(line) for path in sorted(bob.directory.glob("audit-*.jsonl"))
               for line in path.read_text(encoding="utf-8").splitlines()]
    assert [r["seq"] for r in a_lines] == [1, 2]
    assert [r["seq"] for r in b_lines] == [1]  # independent chains
    assert {r["mailbox"] for r in a_lines} == {"alice@corp.example"}
    assert {r["mailbox"] for r in b_lines} == {"bob@corp.example"}
    assert verifier.verify(alice.directory) == 0
    assert verifier.verify(bob.directory) == 0


def test_verify_all_walks_every_mailbox_chain(tmp_path):
    from ewsmcp.audit import mailbox_audit

    _record(AuditLog(str(tmp_path)), 1)
    alice = mailbox_audit(str(tmp_path), "aaa111", "alice@corp.example")
    _record(alice, 2)
    _record(mailbox_audit(str(tmp_path), "bbb222", "bob@corp.example"), 2)
    assert verifier.verify_all(tmp_path) == 0
    path = next(iter(sorted(alice.directory.glob("audit-*.jsonl"))))
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    doctored = json.loads(lines[0])
    doctored["mailbox"] = "someone-else@corp.example"  # re-attribute a call
    lines[0] = json.dumps(doctored, sort_keys=True, ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verifier.verify_all(tmp_path) == 1


def test_mailbox_audit_dir_refuses_unsafe_keys(tmp_path):
    import pytest

    from ewsmcp.audit import mailbox_audit_dir

    for bad in ("", "../x", "a/b"):
        with pytest.raises(ValueError):
            mailbox_audit_dir(str(tmp_path), bad)
