"""Shared state: one contract, two backends, and the guarantees across pods.

Two RedisState clients over one fakeredis server stand in for two server
processes behind a load balancer.
"""

import asyncio
import time

import fakeredis
import pytest

from conftest import make_settings
from ewsmcp import state
from ewsmcp.confirm import consume_token, make_token, token_consumed
from ewsmcp.errors import ToolError
from ewsmcp.ids import RedisAliaser
from ewsmcp.tools import writes
from ewsmcp.tools.base import Context, ToolSpec, dispatch, send_slots_used

NOW = 1_800_000_000.0


def two_pods():
    server = fakeredis.FakeServer()
    return (state.RedisState(fakeredis.FakeRedis(server=server), prefix="t"),
            state.RedisState(fakeredis.FakeRedis(server=server), prefix="t"))


@pytest.fixture(params=["local", "redis"])
def store(request):
    if request.param == "local":
        return state.LocalState()
    return state.RedisState(fakeredis.FakeRedis(), prefix="t")


# --- the contract, on both backends --------------------------------------


def test_claim_is_single_use_until_expiry(store):
    assert store.claim("spent:a", expires_at=NOW + 60, now=NOW) is True
    assert store.claim("spent:a", expires_at=NOW + 60, now=NOW) is False
    assert store.exists("spent:a", now=NOW) is True
    assert store.exists("spent:b", now=NOW) is False


def test_reserve_enforces_a_sliding_window_and_release_returns_a_slot(store):
    s1, _ = store.reserve("sends:x", limit=2, window_s=3600, now=NOW)
    s2, _ = store.reserve("sends:x", limit=2, window_s=3600, now=NOW + 10)
    refused, retry = store.reserve("sends:x", limit=2, window_s=3600, now=NOW + 20)
    assert s1 and s2 and refused is None
    assert 3500 < retry <= 3600  # until the oldest send leaves the window
    assert store.window_count("sends:x", window_s=3600, now=NOW + 20) == 2
    store.release("sends:x", s2)
    s3, _ = store.reserve("sends:x", limit=2, window_s=3600, now=NOW + 30)
    assert s3 is not None
    # An hour after the first send, its slot is free again.
    s4, _ = store.reserve("sends:x", limit=2, window_s=3600, now=NOW + 3601)
    assert s4 is not None


def test_hit_counts_a_fixed_window_budget(store):
    assert [store.hit("calls:x", limit=3, window_s=60, now=NOW + i) for i in range(3)] == [
        None, None, None]
    retry = store.hit("calls:x", limit=3, window_s=60, now=NOW + 5)
    assert retry is not None and 0 < retry <= 60
    assert store.hit("calls:x", limit=3, window_s=60, now=NOW + 61) is None  # next window


def test_records_expire(store):
    store.put("idem:k", {"draft_id": "D"}, expires_at=NOW + 10, now=NOW)
    assert store.get("idem:k", now=NOW + 5) == {"draft_id": "D"}
    if isinstance(store, state.LocalState):  # redis expiry is driven by its own clock
        assert store.get("idem:k", now=NOW + 11) is None
    store.put("idem:gone", {"x": 1}, expires_at=NOW - 1, now=NOW)
    assert store.get("idem:gone", now=NOW) is None


def test_local_records_are_capped_per_namespace():
    local = state.LocalState()
    for i in range(3):
        local.put(f"idem:k{i}", {"i": i}, expires_at=NOW + 100 + i, now=NOW, max_entries=2)
    local.put("other:z", {"z": 1}, expires_at=NOW + 50, now=NOW, max_entries=2)
    assert local.get("idem:k0", now=NOW) is None
    assert local.get("idem:k2", now=NOW) == {"i": 2}
    assert local.get("other:z", now=NOW) == {"z": 1}


# --- across pods ---------------------------------------------------------


def test_a_token_spent_on_one_pod_cannot_be_replayed_on_another():
    pod_a, pod_b = two_pods()
    token = make_token(mailbox="a@corp.example", action="send_draft", target_id="T",
                       chash="h", secret="s")["confirm_token"]
    state.use_backend(pod_a)
    assert consume_token(token) is True
    state.use_backend(pod_b)
    assert token_consumed(token) is True
    assert consume_token(token) is False


def test_send_caps_hold_across_pods_per_mailbox_and_globally():
    pod_a, pod_b = two_pods()
    assert pod_a.reserve("sends:alice", limit=1, window_s=3600, now=NOW)[0]
    assert pod_b.reserve("sends:alice", limit=1, window_s=3600, now=NOW)[0] is None
    assert pod_b.reserve("sends:bob", limit=1, window_s=3600, now=NOW)[0]
    assert pod_a.reserve("sends:*", limit=2, window_s=3600, now=NOW)[0]
    assert pod_b.reserve("sends:*", limit=2, window_s=3600, now=NOW)[0]
    assert pod_a.reserve("sends:*", limit=2, window_s=3600, now=NOW)[0] is None


def test_send_receipts_are_visible_on_every_pod():
    pod_a, pod_b = two_pods()
    state.use_backend(pod_a)
    writes._idempotency_put("alice\x1fsend-1", {"draft_id": "D", "result": {"sent": True},
                                                "ts": time.time()})
    state.use_backend(pod_b)
    assert writes._idempotency_get("alice\x1fsend-1")["draft_id"] == "D"


def test_store_outage_fails_closed_for_tokens_and_sends_open_for_budgets():
    class Down:
        def __getattr__(self, name):
            def broken(*_a, **_k):
                raise ConnectionError("store down")
            return broken

    down = state.RedisState(Down(), prefix="t")
    with pytest.raises(ToolError) as spend:
        down.claim("spent:x", expires_at=NOW + 60, now=NOW)
    assert spend.value.code == "upstream_unavailable"
    with pytest.raises(ToolError) as reserve:
        down.reserve("sends:x", limit=1, window_s=3600, now=NOW)
    assert reserve.value.code == "upstream_unavailable"
    assert down.hit("calls:x", limit=1, window_s=60, now=NOW) is None
    assert down.get("idem:x", now=NOW) is None


def test_dispatcher_send_cap_counts_every_pod_and_keeps_mailboxes_apart(tmp_path):
    pod_a, pod_b = two_pods()

    async def sent(ctx, **_):
        return {"sent": True}

    spec = ToolSpec(name="send_now", description="t", side_effect_class="send",
                    input_schema={"type": "object", "properties": {}}, handler=sent,
                    requires_ews=False)

    def ctx_for(mailbox):
        return Context(settings=make_settings(send_enabled=True, ews_capability_tier="full",
                                              ews_max_sends_per_hour=1, ews_email=mailbox),
                       gateway=None, manager=None, aliaser=None,
                       audit=type("A", (), {"record": lambda *a, **k: None})())

    alice, bob = ctx_for("alice@corp.example"), ctx_for("bob@corp.example")
    state.use_backend(pod_a)
    assert asyncio.run(dispatch(alice, spec, {}))["sent"] is True
    state.use_backend(pod_b)
    second = asyncio.run(dispatch(alice, spec, {}))
    assert second["error"]["code"] == "rate_capped"
    assert asyncio.run(dispatch(bob, spec, {}))["sent"] is True
    assert send_slots_used(alice) == 1 and send_slots_used(bob) == 1


def test_global_send_cap_spans_mailboxes(tmp_path):
    async def sent(ctx, **_):
        return {"sent": True}

    spec = ToolSpec(name="send_now", description="t", side_effect_class="send",
                    input_schema={"type": "object", "properties": {}}, handler=sent,
                    requires_ews=False)
    results = []
    for mailbox in ("a@corp.example", "b@corp.example", "c@corp.example"):
        ctx = Context(settings=make_settings(send_enabled=True, ews_capability_tier="full",
                                             ews_max_sends_per_hour=10,
                                             ews_global_max_sends_per_hour=2,
                                             ews_email=mailbox),
                      gateway=None, manager=None, aliaser=None,
                      audit=type("A", (), {"record": lambda *a, **k: None})())
        results.append(asyncio.run(dispatch(ctx, spec, {})))
    assert [r.get("sent") for r in results[:2]] == [True, True]
    assert results[2]["error"]["code"] == "rate_capped"
    assert "all mailboxes" in results[2]["error"]["message"]
    # The refused call released its per-mailbox reservation.
    assert send_slots_used(ctx) == 0


# --- shared aliases ------------------------------------------------------


def aliasers(namespace="aaa111", ttl=3600):
    server = fakeredis.FakeServer()
    make = lambda ns=namespace: RedisAliaser(  # noqa: E731
        fakeredis.FakeRedis(server=server), prefix="t", namespace=ns, ttl_seconds=ttl)
    return make


def test_an_alias_minted_on_one_pod_resolves_on_another():
    make = aliasers()
    pod_a, pod_b = make(), make()
    alias = pod_a.alias_for("RAW-1", "m", internet_message_id="<1@corp.example>")
    assert alias == "m1"
    assert pod_b.resolve("m1") == "RAW-1"
    assert pod_b.alias_for("RAW-1", "m") == "m1"  # idempotent across pods
    assert pod_b.imid_for("m1") == "<1@corp.example>"
    assert pod_b.imid_for("RAW-1") == "<1@corp.example>"


def test_shared_aliases_are_namespaced_per_mailbox():
    make = aliasers()
    alice, bob = make("aaa111"), make("bbb222")
    assert alice.alias_for("RAW-ALICE", "m") == bob.alias_for("RAW-BOB", "m") == "m1"
    assert alice.resolve("m1") == "RAW-ALICE" and bob.resolve("m1") == "RAW-BOB"
    alice.alias_for("RAW-ALICE-2", "m")
    with pytest.raises(KeyError):
        bob.resolve("m2")


def test_shared_alias_many_mints_a_page_and_keeps_existing_handles():
    make = aliasers()
    pod = make()
    first = pod.alias_many([("A", "m", None, None), ("B", "m", None, None),
                            ("E", "e", None, None)])
    assert first == {"A": "m1", "B": "m2", "E": "e1"}
    again = pod.alias_many([("B", "m", None, None), ("C", "m", None, "<c@x>"),
                            ("C", "m", None, None)])
    assert again == {"B": "m2", "C": "m3"}
    assert pod.stats() == {"m": 3, "e": 1}
    assert pod.resolve("not-an-alias-AAMk==") == "not-an-alias-AAMk=="


def test_concurrent_mint_of_one_id_on_two_pods_converges_on_one_alias():
    server = fakeredis.FakeServer()
    pod_a = RedisAliaser(fakeredis.FakeRedis(server=server), prefix="t",
                         namespace="aaa111", ttl_seconds=3600)

    class StaleFirstRead:
        """Pod B's first lookup happens just before pod A publishes."""

        def __init__(self, client):
            self._client, self._stale = client, True

        def hmget(self, key, ids):
            if self._stale:
                self._stale = False
                result = [None] * len(ids)
                pod_a.alias_for("RAW-X", "m")  # pod A wins the race right now
                return result
            return self._client.hmget(key, ids)

        def __getattr__(self, name):
            return getattr(self._client, name)

    pod_b = RedisAliaser(StaleFirstRead(fakeredis.FakeRedis(server=server)), prefix="t",
                         namespace="aaa111", ttl_seconds=3600)
    b = pod_b.alias_many([("RAW-X", "m", None, None)])["RAW-X"]
    assert b == "m1"  # pod B adopted pod A's alias instead of its own m2
    assert pod_a.resolve("m1") == "RAW-X"
    assert pod_b.resolve("m2") == "RAW-X"  # B's spare handle is harmless


def test_shared_rebind_keeps_the_handle_the_model_holds():
    make = aliasers()
    pod = make()
    pod.alias_for("OLD", "m", internet_message_id="<m@x>")
    pod.alias_for("NEW", "m")  # the new id was already seen under m2
    assert pod.rebind("OLD", "NEW") == "m1"
    assert pod.resolve("m1") == "NEW"
    with pytest.raises(KeyError):
        pod.resolve("m2")  # the duplicate handle is dropped
    assert pod.imid_for("NEW") == "<m@x>"
    assert pod.rebind("UNKNOWN", "X") is None


def test_shared_alias_keys_expire_after_inactivity():
    server = fakeredis.FakeServer()
    client = fakeredis.FakeRedis(server=server)
    pod = RedisAliaser(client, prefix="t", namespace="aaa111", ttl_seconds=3600)
    pod.alias_for("RAW-1", "m")
    ttls = [client.ttl(k) for k in client.keys("t:alias:aaa111:*")]
    assert ttls and all(0 < t <= 3600 for t in ttls)


def test_shared_alias_store_outage_fails_open_to_raw_ids():
    class Down:
        def __getattr__(self, name):
            def broken(*_a, **_k):
                raise ConnectionError("store down")
            return broken

    pod = RedisAliaser(Down(), prefix="t", namespace="aaa111", ttl_seconds=3600)
    assert pod.alias_for("RAW-1", "m") == "RAW-1"
    assert pod.resolve("m1") == "m1"
    assert pod.rebind("A", "B") is None and pod.imid_for("m1") is None
    assert pod.stats() == {}


def test_redis_backend_requires_a_url_and_the_parts_use_shared_aliases(tmp_path):
    from pydantic import ValidationError

    from ewsmcp.server import mailbox_parts_factory

    with pytest.raises(ValidationError, match="EWS_REDIS_URL"):
        make_settings(ews_state_backend="redis")
    settings = make_settings(ews_state_backend="redis", ews_redis_url="redis://unused:6379/0")
    state.use_backend(state.RedisState(fakeredis.FakeRedis(), prefix="t"))
    parts = mailbox_parts_factory(settings)("alice@corp.example", "aaa111")
    assert isinstance(parts.aliaser, RedisAliaser)
    assert parts.aliaser.alias_for("RAW", "m") == "m1"
