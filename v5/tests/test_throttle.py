"""Exchange protection: budgets, stated back-offs, and the upstream circuit."""

import asyncio

import pytest
from exchangelib.errors import (
    ErrorExceededConnectionCount,
    ErrorServerBusy,
    ErrorTooManyObjectsOpened,
    RateLimitError,
)

from conftest import make_settings
from test_bearer_mode import bearer_ctx, call_as, token_for

from ewsmcp.audit import AuditLog
from ewsmcp.errors import explicit_backoff_seconds, map_exception
from ewsmcp.gateway.client import RejectingFaultTolerance
from ewsmcp.ids import get_aliaser
from ewsmcp.tools.base import Context, ToolSpec, dispatch


class _Gateway:
    async def call(self, fn):
        return fn(None)


def static_ctx(tmp_path, **overrides) -> Context:
    return Context(settings=make_settings(**overrides), gateway=_Gateway(), manager=None,
                   aliaser=get_aliaser(str(tmp_path / "mem")),
                   audit=AuditLog(str(tmp_path / "data")))


def failing_spec(make_exc, calls):
    async def handler(ctx, **_):
        calls.append(ctx.mailbox)
        exc = make_exc()
        if exc is not None:
            raise exc
        return {"done": True}

    return ToolSpec(name="t", description="t", side_effect_class="read",
                    input_schema={"type": "object", "properties": {}}, handler=handler)


# --- what Exchange said ------------------------------------------------------


@pytest.mark.parametrize("exc, retry", [
    (RateLimitError("Max timeout reached", wait=37.2), 38),
    (ErrorServerBusy("busy", back_off=12), 12),
    (ErrorServerBusy("busy"), 60),  # no stated wait: default hint only
    (ErrorExceededConnectionCount("too many connections"), 60),
    (ErrorTooManyObjectsOpened("too many objects"), 60),
])
def test_throttling_errors_carry_exchanges_own_wait(exc, retry):
    err = map_exception(exc)
    assert err.code == "throttled" and err.retry_after_s == retry


def test_explicit_backoff_is_found_through_exception_chains():
    try:
        try:
            raise ErrorServerBusy("busy", back_off=9)
        except ErrorServerBusy as inner:
            raise RuntimeError("wrapped") from inner
    except RuntimeError as outer:
        assert explicit_backoff_seconds(outer) == 9
    assert explicit_backoff_seconds(ValueError("x")) is None


def test_long_server_backoff_is_returned_not_slept_through():
    """With the 5 s default, exchangelib refuses to sleep through a longer
    back-off inside a worker thread: the caller gets retry_after_s."""
    assert make_settings().ews_retry_max_wait_seconds == 5
    policy = RejectingFaultTolerance(max_wait=make_settings().ews_retry_max_wait_seconds)
    with pytest.raises(RateLimitError) as info:
        policy.back_off(30)
    err = map_exception(info.value)
    assert err.code == "throttled" and err.retry_after_s == 30


def test_scale_defaults():
    s = make_settings()
    assert s.ews_fanout_max_folders == 50
    assert s.ews_mailbox_calls_per_minute == 0  # static mode: off
    assert s.ews_global_circuit_threshold == 20


# --- stated back-off holds the mailbox locally ----------------------------


def test_a_stated_backoff_holds_that_mailbox_and_only_it(tmp_path, monkeypatch):
    clock = [1_800_000_000.0]
    monkeypatch.setattr("ewsmcp.tools.base.time.time", lambda: clock[0])
    monkeypatch.setattr("ewsmcp.throttle.time.time", lambda: clock[0])
    ctx = bearer_ctx(tmp_path)
    calls = []
    throttle_once = {"alice@corp.example": True}

    def make_exc():
        mailbox = calls[-1]
        if throttle_once.pop(mailbox, False):
            return ErrorServerBusy("busy", back_off=30)
        return None

    ctx.registry["t"] = failing_spec(make_exc, calls)
    alice, bob = token_for("alice@corp.example"), token_for("bob@corp.example")

    async def scenario():
        first = await call_as(ctx, alice, "t")
        held = await call_as(ctx, alice, "t")
        other = await call_as(ctx, bob, "t")
        clock[0] += 31
        after = await call_as(ctx, alice, "t")
        return first, held, other, after

    first, held, other, after = asyncio.run(scenario())
    assert first["error"]["code"] == "throttled" and first["error"]["retry_after_s"] == 30
    assert held["error"]["code"] == "throttled"
    assert 1 <= held["error"]["retry_after_s"] <= 30
    assert other.get("done") is True
    assert after.get("done") is True
    # The held call never reached the handler (nor Exchange).
    assert calls == ["alice@corp.example", "bob@corp.example", "alice@corp.example"]


def test_a_busy_error_without_a_stated_wait_does_not_hold_the_mailbox(tmp_path):
    calls = []
    outcomes = iter([ErrorServerBusy("busy"), None])
    ctx = static_ctx(tmp_path)
    spec = failing_spec(lambda: next(outcomes), calls)
    first = asyncio.run(dispatch(ctx, spec, {}))
    second = asyncio.run(dispatch(ctx, spec, {}))
    assert first["error"]["code"] == "throttled"
    assert second.get("done") is True and len(calls) == 2


def test_static_mode_also_honours_a_stated_backoff(tmp_path):
    calls = []
    outcomes = iter([RateLimitError("Max timeout reached", wait=20), None])
    ctx = static_ctx(tmp_path)
    spec = failing_spec(lambda: next(outcomes), calls)
    asyncio.run(dispatch(ctx, spec, {}))
    held = asyncio.run(dispatch(ctx, spec, {}))
    assert held["error"]["code"] == "throttled" and len(calls) == 1


# --- per-mailbox call budget --------------------------------------------------


def test_call_budget_caps_each_mailbox_separately(tmp_path):
    ctx = bearer_ctx(tmp_path, ews_mailbox_calls_per_minute=3)
    calls = []
    ctx.registry["t"] = failing_spec(lambda: None, calls)
    alice, bob = token_for("alice@corp.example"), token_for("bob@corp.example")

    async def scenario():
        a = [await call_as(ctx, alice, "t") for _ in range(4)]
        b = await call_as(ctx, bob, "t")
        return a, b

    a, b = asyncio.run(scenario())
    assert [r.get("done") for r in a[:3]] == [True, True, True]
    assert a[3]["error"]["code"] == "rate_capped"
    assert 1 <= a[3]["error"]["retry_after_s"] <= 60
    assert b.get("done") is True
    assert calls.count("alice@corp.example") == 3


def test_bearer_mode_budget_defaults_to_60_a_minute():
    from test_bearer_mode import bearer_settings

    assert bearer_settings().ews_mailbox_calls_per_minute == 60


# --- process-wide upstream circuit -------------------------------------------


def test_exchange_failing_for_everyone_pauses_all_calls(tmp_path):
    ctx = bearer_ctx(tmp_path, ews_global_circuit_threshold=3, circuit_failure_threshold=99)
    calls = []

    def down():
        return ConnectionError("connection refused")

    ctx.registry["t"] = failing_spec(down, calls)
    tokens = [token_for(f"user{i}@corp.example") for i in range(5)]

    async def scenario():
        failures = [await call_as(ctx, tok, "t") for tok in tokens[:3]]
        paused = await call_as(ctx, tokens[3], "t")
        return failures, paused

    failures, paused = asyncio.run(scenario())
    assert [f["error"]["code"] for f in failures] == ["upstream_unavailable"] * 3
    assert paused["error"]["code"] == "upstream_unavailable"
    assert "paused" in paused["error"]["message"]
    assert paused["error"]["retry_after_s"] >= 1
    # The paused caller was never bound: no session, no token proof.
    assert ctx.pool.get("user3@corp.example") is None
    assert len(calls) == 3
    assert ctx.pool.stats()["upstream_circuit_open"] is True


def test_any_answer_from_exchange_resets_the_upstream_count(tmp_path):
    ctx = bearer_ctx(tmp_path, ews_global_circuit_threshold=3, circuit_failure_threshold=99)
    outcomes = iter([ConnectionError("down"), ConnectionError("down"), None,
                     ConnectionError("down"), ConnectionError("down")])
    calls = []
    ctx.registry["t"] = failing_spec(lambda: next(outcomes), calls)

    async def scenario():
        return [await call_as(ctx, token_for(f"u{i}@corp.example"), "t") for i in range(5)]

    results = asyncio.run(scenario())
    assert results[2].get("done") is True
    assert ctx.pool.upstream_retry_after() is None  # 2 + 2 failures, never 3 in a row


def test_local_refusals_never_count_as_exchange_failures(tmp_path):
    ctx = bearer_ctx(tmp_path, ews_global_circuit_threshold=2,
                     ews_mailbox_calls_per_minute=1)
    calls = []
    ctx.registry["t"] = failing_spec(lambda: None, calls)
    tok = token_for("alice@corp.example")

    async def scenario():
        return [await call_as(ctx, tok, "t") for _ in range(4)]

    results = asyncio.run(scenario())
    assert results[0].get("done") is True
    assert {r["error"]["code"] for r in results[1:]} == {"rate_capped"}
    assert ctx.pool.upstream.failures == 0


# --- load shedding -------------------------------------------------------------


def test_calls_that_cannot_get_a_worker_in_time_are_shed_not_queued():
    from ewsmcp.gateway.client import WorkerGate
    from ewsmcp.throttle import LocalRefusal

    async def scenario():
        gate = WorkerGate(size=1, timeout=0.05)
        async with gate.slot():
            assert gate.busy == 1
            with pytest.raises(LocalRefusal) as info:
                async with gate.slot():
                    pass
        async with gate.slot():  # free again afterwards
            pass
        return gate, info.value

    gate, refusal = asyncio.run(scenario())
    assert refusal.code == "throttled" and refusal.retry_after_s >= 1
    assert gate.shed == 1 and gate.busy == 0


def test_a_saturated_server_sheds_calls_through_the_dispatcher(tmp_path):
    ctx = bearer_ctx(tmp_path, ews_queue_timeout_seconds=0.5)

    class GatedGateway:
        """Runs handler work through the pool's real worker gate."""

        def __init__(self, principal, slots):
            self.principal, self.mailbox = principal, principal.mailbox
            self.proven, self.closed, self.rejected = True, False, False
            self.slots = slots

        async def call(self, fn):
            async with self.slots, ctx.pool.workers.slot():
                return fn(None)

        def learned_version(self):
            return None

        def close(self):
            self.closed = True

    ctx.pool._gateway_factory = GatedGateway

    async def handler(ctx, **_):
        return {"done": await ctx.gateway.call(lambda _a: True)}

    ctx.registry["t"] = ToolSpec(name="t", description="t", side_effect_class="read",
                                 input_schema={"type": "object", "properties": {}},
                                 handler=handler)

    async def scenario():
        held = []
        for _ in range(ctx.pool.workers.size):  # every worker busy elsewhere
            await ctx.pool.workers._sem.acquire()
            held.append(True)
        try:
            return await call_as(ctx, token_for("alice@corp.example"), "t")
        finally:
            for _ in held:
                ctx.pool.workers._sem.release()

    shed = asyncio.run(scenario())
    assert shed["error"]["code"] == "throttled"
    assert "busy" in shed["error"]["message"]
    assert ctx.pool.stats()["calls_shed"] == 1
    assert ctx.pool.upstream.failures == 0  # shedding is not an Exchange failure


def test_pool_metrics_are_aggregate_only(tmp_path):
    from ewsmcp.http import _metrics_text

    ctx = bearer_ctx(tmp_path)
    asyncio.run(call_as(ctx, token_for("alice@corp.example"), "whoami"))
    text = _metrics_text(ctx)
    assert "ewsmcp_mailbox_sessions 1" in text
    assert "ewsmcp_exchange_workers_max 32" in text
    assert "ewsmcp_calls_shed_total 0" in text
    assert "alice" not in text
