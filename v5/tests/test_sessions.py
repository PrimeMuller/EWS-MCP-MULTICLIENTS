"""Mailbox sessions: token proof, isolation, and eviction (no network)."""

import asyncio
import threading

import pytest

from conftest import make_settings
from ewsmcp.errors import ToolError
from ewsmcp.identity import Principal, mailbox_key
from ewsmcp.sessions import MAX_TOKENS_PER_MAILBOX, SessionParts, SessionPool

NOW = 1_800_000_000.0


class FakeGateway:
    """Stands in for EWSGateway: counts proofs, can be told to fail them."""

    def __init__(self, principal, slots, outcome="ok"):
        self.principal = principal
        self.slots = slots
        self.proven = False
        self.closed = False
        self.rejected = False
        self.proofs = 0
        self.outcome = outcome
        self._lock = threading.Lock()

    def prove(self):
        with self._lock:
            self.proofs += 1
        if self.outcome == "rejected":
            self.rejected = True
            raise ToolError("auth_failed", "Exchange rejected credentials (HTTP 401)")
        if self.outcome == "transient":
            raise ToolError("upstream_unavailable", "front door down", retry_after_s=30)

    def learned_version(self):
        return "v2016"

    def close(self):
        self.closed = True


class Harness:
    def __init__(self, outcome="ok", clock=None, **settings):
        self.outcome = outcome
        self.gateways = []
        self.parts = {}
        self.now = [NOW]
        settings.setdefault("ews_max_concurrency", 4)
        self.pool = SessionPool(
            make_settings(**settings),
            parts_factory=self._parts,
            gateway_factory=self._gateway,
            clock=clock or (lambda: self.now[0]),
        )

    def _parts(self, mailbox, key):
        record = {"mailbox": mailbox, "key": key, "closed": 0}

        def close():
            record["closed"] += 1

        self.parts[mailbox] = record
        return SessionParts(aliaser=f"aliases:{key}", audit=f"audit:{key}", close=close)

    def _gateway(self, principal, slots):
        gw = FakeGateway(principal, slots, self.outcome)
        self.gateways.append(gw)
        return gw


def bearer(mailbox, fp="t1", expires_at=NOW + 3600):
    return Principal(mailbox=mailbox, token=f"token-{fp}", fingerprint=fp,
                     expires_at=expires_at)


def run(coro):
    return asyncio.run(coro)


def test_missing_or_static_principal_is_refused():
    h = Harness()
    for principal in (None, Principal(mailbox="exec@corp.example")):
        with pytest.raises(ToolError) as info:
            run(h.pool.checkout(principal))
        assert info.value.code == "auth_failed"
    assert h.gateways == [] and h.parts == {}


def test_expired_token_is_refused_without_building_anything():
    h = Harness()
    with pytest.raises(ToolError) as info:
        run(h.pool.checkout(bearer("a@corp.example", expires_at=NOW - 3600)))
    assert info.value.code == "auth_failed"
    assert h.gateways == [] and h.parts == {}


def test_a_token_is_proven_once_then_reused():
    h = Harness()

    async def scenario():
        first = await h.pool.checkout(bearer("a@corp.example"))
        first.session.in_flight -= 1
        second = await h.pool.checkout(bearer("a@corp.example"))
        second.session.in_flight -= 1
        return first, second

    first, second = run(scenario())
    assert first.session is second.session
    assert first.gateway is second.gateway
    assert first.gateway.proofs == 1 and first.gateway.proven
    assert h.pool._version == "v2016"


def test_concurrent_first_calls_with_one_token_prove_it_once():
    h = Harness()

    async def scenario():
        leases = await asyncio.gather(*(h.pool.checkout(bearer("a@corp.example"))
                                        for _ in range(5)))
        return leases

    leases = run(scenario())
    assert len({id(lease.session) for lease in leases}) == 1
    assert len(h.gateways) == 1 and h.gateways[0].proofs == 1
    assert leases[0].session.in_flight == 5


def test_rejected_token_is_remembered_and_never_sent_again():
    h = Harness(outcome="rejected")
    with pytest.raises(ToolError) as info:
        run(h.pool.checkout(bearer("victim@corp.example")))
    assert info.value.code == "auth_failed"
    assert h.gateways[0].proofs == 1 and h.gateways[0].closed
    # Same token again: refused locally, no new gateway, no new proof.
    with pytest.raises(ToolError) as again:
        run(h.pool.checkout(bearer("victim@corp.example")))
    assert again.value.code == "auth_failed"
    assert len(h.gateways) == 1
    # The rejection is per token: another token for the mailbox is tried.
    h.outcome = "ok"
    lease = run(h.pool.checkout(bearer("victim@corp.example", fp="t2")))
    assert lease.gateway.proven and len(h.gateways) == 2


def test_transient_proof_failure_does_not_condemn_the_token():
    h = Harness(outcome="transient")
    with pytest.raises(ToolError) as info:
        run(h.pool.checkout(bearer("a@corp.example")))
    assert info.value.code == "upstream_unavailable"
    h.outcome = "ok"
    h.gateways[0].outcome = "ok"
    lease = run(h.pool.checkout(bearer("a@corp.example")))
    assert lease.gateway is h.gateways[0] and lease.gateway.proofs == 2
    assert lease.session.in_flight == 1


def test_mailboxes_get_separate_sessions_and_parts():
    h = Harness()

    async def scenario():
        a = await h.pool.checkout(bearer("alice@corp.example", fp="ta"))
        b = await h.pool.checkout(bearer("bob@corp.example", fp="tb"))
        return a, b

    a, b = run(scenario())
    assert a.session is not b.session
    assert a.session.key == mailbox_key("alice@corp.example")
    assert a.session.aliaser != b.session.aliaser
    assert a.session.audit != b.session.audit
    assert a.session.request_slots is not b.session.request_slots
    assert a.gateway.slots is a.session.request_slots


def test_token_rotation_keeps_one_session_and_caps_live_tokens():
    h = Harness()

    async def scenario():
        leases = []
        for i in range(MAX_TOKENS_PER_MAILBOX + 2):
            lease = await h.pool.checkout(bearer("a@corp.example", fp=f"t{i}"))
            lease.session.in_flight -= 1
            leases.append(lease)
        return leases

    leases = run(scenario())
    assert len({id(lease.session) for lease in leases}) == 1
    session = leases[0].session
    assert session.gateway_count == MAX_TOKENS_PER_MAILBOX
    assert [gw.closed for gw in h.gateways[:2]] == [True, True]
    assert not any(gw.closed for gw in h.gateways[2:])


def test_idle_sessions_are_evicted_and_busy_ones_kept():
    h = Harness(ews_mailbox_idle_seconds=600)

    async def scenario():
        idle = await h.pool.checkout(bearer("idle@corp.example", fp="ti"))
        idle.session.in_flight -= 1
        busy = await h.pool.checkout(bearer("busy@corp.example", fp="tb"))
        h.now[0] += 601
        closed = await h.pool.evict_idle()
        return idle, busy, closed

    idle, busy, closed = run(scenario())
    assert closed == 1
    assert idle.session.closed and h.parts["idle@corp.example"]["closed"] == 1
    assert idle.gateway.closed
    assert not busy.session.closed and h.parts["busy@corp.example"]["closed"] == 0
    assert h.pool.get("busy@corp.example") is busy.session
    assert h.pool.get("idle@corp.example") is None


def test_session_cap_evicts_least_recently_used_idle_sessions():
    h = Harness(ews_max_mailboxes=2)

    async def scenario():
        for i, name in enumerate(("a", "b", "c")):
            h.now[0] = NOW + i
            lease = await h.pool.checkout(bearer(f"{name}@corp.example", fp=f"t{name}"))
            lease.session.in_flight -= 1

    run(scenario())
    assert h.pool.get("a@corp.example") is None
    assert h.pool.get("b@corp.example") is not None
    assert h.pool.get("c@corp.example") is not None
    assert h.parts["a@corp.example"]["closed"] == 1


def test_bind_releases_the_session_even_when_the_call_fails():
    h = Harness()

    async def scenario():
        with pytest.raises(RuntimeError):
            async with h.pool.bind(bearer("a@corp.example")) as lease:
                assert lease.session.in_flight == 1
                raise RuntimeError("handler blew up")
        return h.pool.get("a@corp.example")

    session = run(scenario())
    assert session.in_flight == 0


def test_expired_tokens_are_dropped_from_live_sessions():
    h = Harness(ews_mailbox_idle_seconds=7200)

    async def scenario():
        lease = await h.pool.checkout(bearer("a@corp.example", expires_at=NOW + 100))
        h.now[0] += 500
        await h.pool.evict_idle()
        return lease

    lease = run(scenario())
    assert lease.gateway.closed and lease.session.gateway_count == 0
    assert not lease.session.closed


def test_stats_are_aggregate_only():
    h = Harness()

    async def scenario():
        await h.pool.checkout(bearer("alice@corp.example", fp="ta"))
        return h.pool.stats()

    stats = run(scenario())
    assert stats["mailboxes"] == 1 and stats["in_flight"] == 1 and stats["tokens"] == 1
    assert "alice" not in repr(stats)


def test_close_releases_every_session():
    h = Harness()

    async def scenario():
        lease = await h.pool.checkout(bearer("a@corp.example"))
        lease.session.in_flight -= 1
        await h.pool.close()
        return lease

    lease = run(scenario())
    assert lease.session.closed and lease.gateway.closed
    assert h.pool.sessions() == []
