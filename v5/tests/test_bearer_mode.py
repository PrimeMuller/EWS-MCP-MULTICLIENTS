"""Bearer mode end to end: every call acts on its caller's mailbox, only."""

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from pydantic import ValidationError

from conftest import make_settings
from test_identity import make_jwt

from ewsmcp.audit import AuditLog
from ewsmcp.config import Settings
from ewsmcp.errors import ToolError
from ewsmcp.http import build_app
from ewsmcp.identity import SCOPE_KEY, mailbox_key, principal_from_bearer, use_principal
from ewsmcp.ids import NullAliaser
from ewsmcp.server import _request_principal, build_context, mailbox_parts_factory
from ewsmcp.sessions import SessionPool
from ewsmcp.tools import rules as rules_pack
from ewsmcp.tools import writes
from ewsmcp.tools.base import Context, ToolSpec, dispatch

ENDPOINT = "https://mail.corp.example/EWS/Exchange.asmx"


def bearer_settings(**overrides):
    base = dict(ews_auth_mode="bearer", mcp_transport="http", ews_email=None)
    base.update(overrides)
    return make_settings(**base)


def token_for(mailbox: str, *, jti: str = "1", exp_in: int = 3600) -> str:
    return make_jwt({"upn": mailbox, "jti": jti, "exp": time.time() + exp_in})


class FakeGateway:
    """Proves tokens unless told the token is forged; runs handler work on a
    stand-in account that knows only its own mailbox."""

    forged = set()

    def __init__(self, principal, slots):
        self.principal = principal
        self.mailbox = principal.mailbox
        self.proven = False
        self.closed = False
        self.rejected = False
        self.account = NS(primary_smtp_address=principal.mailbox)

    def prove(self):
        if self.principal.token in FakeGateway.forged:
            self.rejected = True
            raise ToolError("auth_failed", "Exchange rejected credentials (HTTP 401)")

    async def call(self, fn):
        return fn(self.account)

    def learned_version(self):
        return None

    def close(self):
        self.closed = True


async def _whoami(ctx, **_kwargs):
    alias = ctx.aliaser.alias_for(f"RAW-{ctx.mailbox}-{len(ctx.aliaser.stats())}", "m")
    return {"mailbox": ctx.mailbox, "alias": alias,
            "gateway_mailbox": await ctx.gateway.call(lambda a: a.primary_smtp_address)}


async def _mint(ctx, *, raw: str):
    return {"alias": ctx.aliaser.alias_for(raw, "m")}


async def _echo_id(ctx, *, id: str):
    return {"raw": id}


def _spec(name, handler, **kw) -> ToolSpec:
    return ToolSpec(name=name, description=name, side_effect_class=kw.pop("cls", "read"),
                    input_schema={"type": "object", "properties": {}},
                    handler=handler, **kw)


SPECS = {
    "whoami": _spec("whoami", _whoami),
    "mint": _spec("mint", _mint, resolve_ids=False),
    "echo_id": _spec("echo_id", _echo_id),
    "confirm_write": _spec("confirm_write", _echo_id, cls="write", confirm=True),
}


def bearer_ctx(tmp_path, **settings_overrides) -> Context:
    settings = bearer_settings(data_dir=str(tmp_path / "data"), **settings_overrides)
    pool = SessionPool(settings, parts_factory=mailbox_parts_factory(settings),
                       gateway_factory=FakeGateway)
    ctx = Context(settings=settings, gateway=None, manager=None, aliaser=NullAliaser(),
                  audit=AuditLog(settings.data_dir), pool=pool)
    ctx.registry = dict(SPECS)
    return ctx


async def call_as(ctx, token, name, **kwargs):
    principal = principal_from_bearer(token) if token else None
    with use_principal(principal):
        return await dispatch(ctx, ctx.registry[name], kwargs, transport="test")


@pytest.fixture(autouse=True)
def _reset_forged():
    FakeGateway.forged = set()
    yield
    FakeGateway.forged = set()


# --- configuration -----------------------------------------------------------


def test_bearer_mode_needs_no_service_credentials_and_picks_scale_defaults():
    s = Settings(ews_server_url=ENDPOINT, ews_auth_mode="bearer", mcp_transport="http")
    assert s.bearer_mode and s.ews_email is None
    assert s.ews_max_concurrency == 32
    assert s.ews_cache_enabled is False


def test_static_mode_still_requires_a_mailbox():
    with pytest.raises(ValidationError, match="EWS_EMAIL"):
        Settings(ews_server_url=ENDPOINT)
    s = Settings(ews_server_url=ENDPOINT, ews_email="exec@corp.example")
    assert s.ews_max_concurrency == 4 and s.ews_cache_enabled is True


def test_bearer_mode_mirror_is_opt_in_and_a_short_snippet_window():
    off = Settings(ews_server_url=ENDPOINT, ews_auth_mode="bearer", mcp_transport="http")
    on = Settings(ews_server_url=ENDPOINT, ews_auth_mode="bearer", mcp_transport="http",
                  ews_cache_enabled=True)
    assert off.ews_cache_enabled is False
    assert on.ews_cache_enabled is True
    assert (on.ews_cache_window_days, on.ews_cache_body_chars) == (14, 300)
    static = Settings(ews_server_url=ENDPOINT, ews_email="exec@corp.example")
    assert (static.ews_cache_window_days, static.ews_cache_body_chars) == (365, 20_000)


@pytest.mark.parametrize("overrides, message", [
    ({"mcp_transport": "stdio"}, "MCP_TRANSPORT=http"),
    ({"ews_semantic_index": "pgvector"}, "EWS_SEMANTIC_INDEX"),
])
def test_bearer_mode_refuses_settings_that_would_mix_mailboxes(overrides, message):
    base = dict(ews_server_url=ENDPOINT, ews_auth_mode="bearer", mcp_transport="http")
    base.update(overrides)
    with pytest.raises(ValidationError, match=message):
        Settings(**base)


# --- isolation through the dispatcher ------------------------------------


def test_each_call_acts_on_its_callers_mailbox_only(tmp_path):
    ctx = bearer_ctx(tmp_path)
    alice, bob = token_for("alice@corp.example"), token_for("bob@corp.example")

    async def scenario():
        a = await call_as(ctx, alice, "whoami")
        b = await call_as(ctx, bob, "whoami")
        a_echo = await call_as(ctx, alice, "echo_id", id=a["alias"])
        b_echo = await call_as(ctx, bob, "echo_id", id=b["alias"])
        a2 = await call_as(ctx, alice, "mint", raw="RAW-ALICE-PRIVATE")
        stolen = await call_as(ctx, bob, "echo_id", id=a2["alias"])
        return a, b, a_echo, b_echo, a2, stolen

    a, b, a_echo, b_echo, a2, stolen = asyncio.run(scenario())
    assert a["mailbox"] == a["gateway_mailbox"] == "alice@corp.example"
    assert b["mailbox"] == b["gateway_mailbox"] == "bob@corp.example"
    assert a["alias"] == b["alias"] == "m1"  # same handle, different mailboxes
    assert a_echo["raw"].startswith("RAW-alice@corp.example")
    assert b_echo["raw"].startswith("RAW-bob@corp.example")
    # Alice's second alias means nothing in Bob's namespace.
    assert a2["alias"] == "m2"
    assert stolen["ok"] is False and stolen["error"]["code"] == "validation"
    assert "RAW-ALICE-PRIVATE" not in json.dumps(stolen)


def test_no_token_means_no_mailbox(tmp_path):
    ctx = bearer_ctx(tmp_path)
    ran = []

    async def handler(ctx, **_):
        ran.append(True)
        return {}

    ctx.registry["probe"] = _spec("probe", handler)
    res = asyncio.run(call_as(ctx, None, "probe"))
    assert res["ok"] is False and res["error"]["code"] == "auth_failed"
    assert ran == []


def test_forged_token_touches_nothing_stored_for_the_mailbox_it_names(tmp_path):
    ctx = bearer_ctx(tmp_path)
    forged = token_for("victim@corp.example", jti="forged")
    FakeGateway.forged.add(forged)
    res = asyncio.run(call_as(ctx, forged, "whoami"))
    assert res["error"]["code"] == "auth_failed"
    victim_dir = Path(ctx.settings.data_dir) / "mailboxes" / mailbox_key("victim@corp.example")
    assert not victim_dir.exists()
    # The refusal is recorded, without a mailbox, in the process chain.
    process_chain = list((Path(ctx.settings.data_dir) / "audit").glob("audit-*.jsonl"))
    records = [json.loads(line) for p in process_chain
               for line in p.read_text(encoding="utf-8").splitlines()]
    assert [r["outcome"] for r in records] == ["auth_failed"]
    assert "mailbox" not in records[0]


def test_confirm_tokens_are_bound_to_the_mailbox(tmp_path):
    ctx = bearer_ctx(tmp_path)
    alice, bob = token_for("alice@corp.example"), token_for("bob@corp.example")

    async def scenario():
        phase1 = await call_as(ctx, alice, "confirm_write", id="RAW-1")
        stolen = await call_as(ctx, bob, "confirm_write", id="RAW-1",
                               confirm_token=phase1["confirm_token"])
        own = await call_as(ctx, alice, "confirm_write", id="RAW-1",
                            confirm_token=phase1["confirm_token"])
        return phase1, stolen, own

    phase1, stolen, own = asyncio.run(scenario())
    assert phase1["requires_confirmation"] is True
    assert stolen["error"]["code"] == "confirm_invalid"
    assert own["ok"] is True and own["raw"] == "RAW-1"


def test_audit_records_land_in_each_mailboxs_own_chain(tmp_path):
    ctx = bearer_ctx(tmp_path)

    async def scenario():
        await call_as(ctx, token_for("alice@corp.example"), "whoami")
        await call_as(ctx, token_for("alice@corp.example"), "whoami")
        await call_as(ctx, token_for("bob@corp.example"), "whoami")

    asyncio.run(scenario())

    def chain(mailbox):
        d = Path(ctx.settings.data_dir) / "mailboxes" / mailbox_key(mailbox) / "audit"
        return [json.loads(line) for p in sorted(d.glob("audit-*.jsonl"))
                for line in p.read_text(encoding="utf-8").splitlines()]

    assert [(r["seq"], r["mailbox"]) for r in chain("alice@corp.example")] == [
        (1, "alice@corp.example"), (2, "alice@corp.example")]
    assert [(r["seq"], r["mailbox"]) for r in chain("bob@corp.example")] == [
        (1, "bob@corp.example")]


def test_sessions_are_released_after_each_call(tmp_path):
    ctx = bearer_ctx(tmp_path)
    asyncio.run(call_as(ctx, token_for("alice@corp.example"), "whoami"))
    session = ctx.pool.get("alice@corp.example")
    assert session.in_flight == 0 and session.gateway_count == 1


def test_get_server_status_reports_aggregates_without_binding(tmp_path):
    settings = bearer_settings(data_dir=str(tmp_path / "data"))
    ctx = build_context(settings)
    assert ctx.pool is not None and ctx.gateway is None
    res = asyncio.run(dispatch(ctx, ctx.registry["get_server_status"], {}))
    assert res["ok"] is True
    assert res["connection"]["state"] == "per_mailbox"
    assert res["connection"]["mailboxes"] == 0
    assert "find_similar" not in ctx.registry


def test_send_receipts_are_per_mailbox():
    alice, bob = NS(mailbox="alice@corp.example"), NS(mailbox="bob@corp.example")
    writes._idempotency_put(writes._idempotency_scope(alice, "send-1"),
                            {"draft_id": "D1", "result": {"sent": True}, "ts": time.time()})
    replay = {"idempotency_key": "send-1", "draft_id": "D1"}
    assert writes._send_confirm_needed(replay, alice) is False  # alice's replay
    assert writes._send_confirm_needed(replay, bob) is True  # bob sees nothing


def test_rule_writes_serialise_per_mailbox_not_globally():
    async def scenario():
        order = []
        async with rules_pack._rules_lock("alice@corp.example"):
            # Bob's rule write is not held up by Alice's.
            async with rules_pack._rules_lock("bob@corp.example"):
                order.append("bob")
            order.append("alice")
        return order

    assert asyncio.run(scenario()) == ["bob", "alice"]
    assert rules_pack._RULE_LOCK_STATES == {}  # no lock state left behind


# --- HTTP: no token, no access ----------------------------------------------


def _drive(app, path, *, headers=(), body=b"{}", method="POST"):
    scope = {"type": "http", "path": path, "method": method,
             "headers": [(k.encode(), v.encode()) for k, v in headers]}
    queue = [{"type": "http.request", "body": body, "more_body": False}]
    sent = []

    async def receive():
        return queue.pop(0)

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], dict(start["headers"]), json.loads(raw or b"{}")


def _http_ctx(tmp_path, **overrides):
    ctx = bearer_ctx(tmp_path, **overrides)
    ctx.registry["whoami"].input_schema = {"type": "object", "properties": {}}
    return ctx


@pytest.mark.parametrize("path", ["/api/tools/whoami", "/mcp", "/api/tools", "/metrics"])
def test_requests_without_a_token_get_401_with_a_bearer_challenge(tmp_path, path):
    ctx = _http_ctx(tmp_path)
    app = build_app(ctx, ctx.settings)
    method = "GET" if path in ("/api/tools", "/metrics") else "POST"
    status, headers, body = _drive(app, path, method=method)
    assert status == 401
    assert headers[b"www-authenticate"].startswith(b"Bearer")
    assert body["error"]["code"] == "auth_failed"


@pytest.mark.parametrize("token", [
    "not-a-jwt",
    make_jwt({"upn": "alice@corp.example", "exp": 1}),  # expired
    make_jwt({"sub": "no-mailbox-claim"}),
])
def test_unusable_tokens_get_401(tmp_path, token):
    ctx = _http_ctx(tmp_path)
    status, _, body = _drive(build_app(ctx, ctx.settings), "/api/tools/whoami",
                             headers=[("authorization", f"Bearer {token}")])
    assert status == 401 and body["error"]["code"] == "auth_failed"


def test_valid_token_acts_for_its_own_mailbox_over_rest(tmp_path):
    ctx = _http_ctx(tmp_path)
    app = build_app(ctx, ctx.settings)
    status, _, body = _drive(app, "/api/tools/whoami",
                             headers=[("authorization", f"Bearer {token_for('alice@corp.example')}")])
    assert status == 200 and body["mailbox"] == "alice@corp.example"


def test_token_exchange_rejected_is_refused_at_the_door_next_time(tmp_path):
    ctx = _http_ctx(tmp_path)
    app = build_app(ctx, ctx.settings)
    forged = token_for("victim@corp.example", jti="forged")
    FakeGateway.forged.add(forged)
    status1, headers1, body1 = _drive(app, "/api/tools/whoami",
                                      headers=[("authorization", f"Bearer {forged}")])
    assert status1 == 401 and headers1[b"www-authenticate"].startswith(b"Bearer")
    status2, _, body2 = _drive(app, "/api/tools/whoami",
                               headers=[("authorization", f"Bearer {forged}")])
    assert status2 == 401 and "already rejected" in body2["error"]["message"]


def test_api_key_rides_x_api_key_because_authorization_carries_the_token(tmp_path):
    ctx = _http_ctx(tmp_path, mcp_api_key="service-key")
    app = build_app(ctx, ctx.settings)
    tok = token_for("alice@corp.example")
    no_key, _, _ = _drive(app, "/api/tools/whoami", headers=[("authorization", f"Bearer {tok}")])
    assert no_key == 401
    key_as_bearer, _, _ = _drive(app, "/api/tools/whoami",
                                 headers=[("authorization", "Bearer service-key")])
    assert key_as_bearer == 401
    ok, _, body = _drive(app, "/api/tools/whoami", headers=[
        ("authorization", f"Bearer {tok}"), ("x-api-key", "service-key")])
    assert ok == 200 and body["mailbox"] == "alice@corp.example"


def test_health_probes_stay_public_and_readyz_reports_per_mailbox(tmp_path):
    ctx = _http_ctx(tmp_path)
    app = build_app(ctx, ctx.settings)
    status, _, body = _drive(app, "/readyz", method="GET")
    assert status == 200 and body["connection"]["state"] == "per_mailbox"
    assert _drive(app, "/livez", method="GET")[0] == 200


def test_mcp_tool_calls_read_the_principal_from_the_request_scope():
    principal = principal_from_bearer(token_for("alice@corp.example"))
    server = NS(request_context=NS(request=NS(scope={SCOPE_KEY: principal})))
    assert _request_principal(server) is principal

    class NoRequest:
        @property
        def request_context(self):
            raise LookupError("no request in flight")

    assert _request_principal(NoRequest()) is None
    assert _request_principal(NS(request_context=NS(request=None))) is None
