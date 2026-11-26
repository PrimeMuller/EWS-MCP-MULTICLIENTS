"""Bearer-mode window mirror: bounded, on demand, snippets only, short-lived."""

import asyncio
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import MagicMock

import pytest

from test_bearer_mode import FakeGateway, bearer_settings, call_as, token_for
from test_mail_read import _ctx, _msg, _Query, _run

from ewsmcp.audit import AuditLog
from ewsmcp.cache.store import CacheStore
from ewsmcp.cache.sync import row_from_message
from ewsmcp.cache.window import WINDOW_PAGE_SIZE, WindowSync
from ewsmcp.identity import mailbox_key
from ewsmcp.ids import NullAliaser
from ewsmcp.server import mailbox_cache_path, mailbox_parts_factory
from ewsmcp.sessions import SessionPool
from ewsmcp.tools.base import Context, ToolSpec

UTC = timezone.utc
NOW = datetime.now(UTC)
LONG_BODY = "Quarterly figures attached. " * 200  # ~5,600 chars


def item(raw_id, *, days_ago=1.0, changekey="ck1", subject=None, body=LONG_BODY,
         sender="alice@corp.example", conv=None, is_read=False):
    return NS(
        id=raw_id, changekey=changekey, subject=subject or f"subject {raw_id}",
        sender=NS(name="Alice", email_address=sender),
        datetime_received=NOW - timedelta(days=days_ago), is_read=is_read,
        has_attachments=False, importance="Normal", categories=[],
        conversation_id=NS(id=conv or f"CONV-{raw_id}"), message_id=f"<{raw_id}@x>",
        to_recipients=[NS(email_address="me@corp.example")], text_body=body,
    )


class WindowQuery:
    def __init__(self, items):
        self.items = items
        self.page_size = None
        self.only_fields = None

    def only(self, *fields):
        self.only_fields = fields
        return self

    def order_by(self, *args):
        assert args == ("-datetime_received",)
        return self

    def __getitem__(self, window):
        return self.items[window]


class WindowFolder:
    def __init__(self, items):
        self.items = list(items)
        self.queries = []

    def filter(self, **kwargs):
        floor = kwargs["datetime_received__gte"]
        visible = sorted((i for i in self.items if i.datetime_received >= floor),
                         key=lambda i: i.datetime_received, reverse=True)
        query = WindowQuery([NS(id=i.id, changekey=i.changekey,
                                datetime_received=i.datetime_received) for i in visible])
        self.queries.append(query)
        return query


class WindowAccount:
    def __init__(self, inbox=(), sent=(), events=()):
        self.inbox = WindowFolder(inbox)
        self.sent = WindowFolder(sent)
        self.calendar = NS(view=lambda start, end, max_items: list(events))
        self.fetched = []

    def fetch(self, ids, only_fields=None):
        self.fetched.append([raw_id for raw_id, _ck in ids])
        by_id = {i.id: i for i in [*self.inbox.items, *self.sent.items]}
        return [by_id.get(raw_id, ValueError("ErrorItemNotFound")) for raw_id, _ck in ids]


def window_sync(tmp_path, **overrides):
    settings = bearer_settings(data_dir=str(tmp_path / "data"), ews_cache_enabled=True,
                               **overrides)
    store = CacheStore(tmp_path / "mirror.db", body_chars=settings.ews_cache_body_chars)
    return WindowSync(settings, store, limiter=asyncio.Semaphore(1)), store


def rows(store, folder="inbox"):
    with store._read() as conn:
        return {r["ews_id"]: dict(r) for r in conn.execute(
            "SELECT * FROM messages WHERE folder=?", (folder,))}


# --- the refresh itself ------------------------------------------------------


def test_first_refresh_mirrors_the_window_as_headers_and_snippets(tmp_path):
    sync, store = window_sync(tmp_path)
    account = WindowAccount(inbox=[item("A", days_ago=1), item("B", days_ago=3),
                                   item("OLD", days_ago=40)],
                            events=[NS(id="E1", subject="Standup", start=NOW, end=NOW)])
    sync.refresh_once(account)
    mirrored = rows(store)
    assert set(mirrored) == {"A", "B"}  # OLD is outside the 14-day window
    assert all(len(r["body_clean"]) <= 300 for r in mirrored.values())
    assert account.fetched == [["A", "B"]]
    assert account.inbox.queries[0].page_size == WINDOW_PAGE_SIZE
    assert account.inbox.queries[0].only_fields == ("id", "changekey", "datetime_received")
    assert store.watermark("item:inbox") and store.watermark("item:sent")
    assert store.watermark("events")
    with store._read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM sender_sigs").fetchone()[0] == 0


def test_next_refresh_fetches_only_what_changed_and_drops_what_left(tmp_path):
    sync, store = window_sync(tmp_path)
    account = WindowAccount(inbox=[item("A"), item("B"), item("C")])
    sync.refresh_once(account)
    account.inbox.items = [item("A"),  # unchanged
                           item("B", changekey="ck2", is_read=True),  # read elsewhere
                           item("D", days_ago=0.1)]  # new; C was deleted
    account.fetched.clear()
    sync.refresh_once(account)
    assert account.fetched == [["D", "B"]]  # listing is newest first
    mirrored = rows(store)
    assert set(mirrored) == {"A", "B", "D"}
    assert mirrored["B"]["is_read"] == 1


def test_window_keeps_only_the_newest_items_when_capped(tmp_path):
    sync, store = window_sync(tmp_path, ews_cache_max_window_items=50)
    account = WindowAccount(inbox=[item(f"M{i:03d}", days_ago=i * 0.1) for i in range(60)])
    sync.refresh_once(account)
    mirrored = rows(store)
    assert len(mirrored) == 50
    assert "M000" in mirrored and "M049" in mirrored and "M050" not in mirrored


def test_items_vanishing_between_listing_and_fetch_are_skipped(tmp_path):
    sync, store = window_sync(tmp_path)
    account = WindowAccount(inbox=[item("A")])
    account.fetch = lambda ids, only_fields=None: [ValueError("ErrorItemNotFound")]
    sync.refresh_once(account)
    assert rows(store) == {}
    assert store.watermark("item:inbox")


# --- when refreshes happen ----------------------------------------------------


class Gateway:
    def __init__(self, account):
        self.account = account
        self.calls = 0

    async def call(self, fn):
        self.calls += 1
        return fn(self.account)


def test_refresh_is_on_demand_rate_limited_and_never_blocks(tmp_path):
    clock = [1000.0]
    sync, store = window_sync(tmp_path)
    sync._clock = lambda: clock[0]
    gw = Gateway(WindowAccount(inbox=[item("A")]))

    async def scenario():
        started = [sync.maybe_refresh(gw)]
        started.append(sync.maybe_refresh(gw))  # one at a time
        await sync._task
        clock[0] += 10
        started.append(sync.maybe_refresh(gw))  # not due yet (60 s)
        clock[0] += 60
        started.append(sync.maybe_refresh(gw))
        await sync._task
        return started

    assert asyncio.run(scenario()) == [True, False, False, True]
    assert gw.calls == 2 and sync.refreshes == 2
    assert sync.status()["mode"] == "on_demand_window"


def test_refreshes_are_skipped_not_queued_at_the_process_cap(tmp_path):
    sync, _store = window_sync(tmp_path)
    gw = Gateway(WindowAccount())

    async def scenario():
        await sync._limiter.acquire()  # every refresh slot is busy
        try:
            return sync.maybe_refresh(gw)
        finally:
            sync._limiter.release()

    assert asyncio.run(scenario()) is False
    assert sync.skipped == 1 and gw.calls == 0


def test_a_failed_refresh_degrades_and_waits_for_the_next_interval(tmp_path):
    sync, _store = window_sync(tmp_path)

    class Broken:
        async def call(self, fn):
            raise ConnectionError("down")

    async def scenario():
        assert sync.maybe_refresh(Broken()) is True
        await sync._task
        return sync.maybe_refresh(Broken())

    assert asyncio.run(scenario()) is False  # same interval: no hammering
    assert sync.last_error == "ConnectionError"


# --- the store --------------------------------------------------------------


def test_closed_mirror_refuses_writes_and_destroy_removes_the_files(tmp_path):
    store = CacheStore(tmp_path / "m" / "mirror.db", body_chars=300)
    store.upsert_messages([row_from_message(item("A"), "inbox", "UTC", body_chars=300)])
    assert (tmp_path / "m" / "mirror.db").exists()
    store.destroy()
    assert not (tmp_path / "m" / "mirror.db").exists()
    with pytest.raises(Exception):
        store.upsert_messages([row_from_message(item("B"), "inbox", "UTC", body_chars=300)])
    assert not (tmp_path / "m" / "mirror.db").exists()  # not quietly recreated


def test_full_mirror_flags_are_unchanged_for_static_mode(tmp_path):
    full = CacheStore(tmp_path / "full.db")
    snippet = CacheStore(tmp_path / "snip.db", body_chars=300)
    assert full.full_bodies and full.learn_signatures
    assert not snippet.full_bodies and not snippet.learn_signatures


# --- what a snippet mirror may answer ----------------------------------------


def snippet_ctx(tmp_path, full=False):
    msg = _msg("RAW-1", subject="Q3 report", text_body=LONG_BODY,
               dt=datetime(2026, 6, 10, 9, 0, tzinfo=UTC))
    store = CacheStore(tmp_path / "mirror.db", body_chars=20_000 if full else 300)
    store.upsert_messages([row_from_message(msg, "inbox", "UTC",
                                            body_chars=20_000 if full else 300)])
    store.set_sync_state("item:inbox", None, time.time())
    account = MagicMock(name="account")
    account.inbox = _Query([msg])
    account.sent = _Query()
    account.fetch = MagicMock(return_value=[msg])
    return _ctx(tmp_path, account, cache=store), account


def test_snippet_mirror_never_answers_full_reads_or_full_text_search(tmp_path):
    ctx, account = snippet_ctx(tmp_path)
    full = _run(ctx, "get_message", id="RAW-1")
    assert full["source"] == "live" and len(full["message"]["body"]) > 300
    text = _run(ctx, "search_messages", folder="f:inbox", query="figures")
    assert text["source"] == "live"
    listing = _run(ctx, "search_messages", folder="f:inbox", sender="alice")
    assert listing["source"] == "cache" and listing["count"] == 1


def test_full_mirror_still_answers_full_reads(tmp_path):
    ctx, _account = snippet_ctx(tmp_path, full=True)
    full = _run(ctx, "get_message", id="RAW-1")
    assert full["source"] == "cache"


def test_overview_needs_both_mail_and_calendar_mirrored(tmp_path):
    ctx, account = snippet_ctx(tmp_path)
    account.calendar.view = MagicMock(return_value=[])
    first = _run(ctx, "get_mailbox_overview")
    assert first["source"] == "live"  # no calendar watermark yet
    ctx.cache.replace_events([])
    ctx.cache.set_sync_state("events", None, time.time())
    second = _run(ctx, "get_mailbox_overview")
    assert second["source"] == "cache"


# --- end to end in bearer mode -----------------------------------------------


class MirroringGateway(FakeGateway):
    accounts = {}

    def __init__(self, principal, slots):
        super().__init__(principal, slots)
        self.account = MirroringGateway.accounts[principal.mailbox]


def test_a_users_calls_fill_their_mirror_and_eviction_deletes_it(tmp_path):
    settings = bearer_settings(data_dir=str(tmp_path / "data"), ews_cache_enabled=True,
                               ews_mailbox_idle_seconds=60)
    MirroringGateway.accounts = {"alice@corp.example": WindowAccount(inbox=[item("A")])}
    clock = [time.time()]
    pool = SessionPool(settings, parts_factory=mailbox_parts_factory(settings),
                       gateway_factory=MirroringGateway, clock=lambda: clock[0])
    ctx = Context(settings=settings, gateway=None, manager=None, aliaser=NullAliaser(),
                  audit=AuditLog(settings.data_dir), pool=pool)

    async def touch(ctx, **_):
        return {"mirrored": ctx.cache.watermark("item:inbox") is not None}

    ctx.registry["touch"] = ToolSpec(name="touch", description="t", side_effect_class="read",
                                     input_schema={"type": "object", "properties": {}},
                                     handler=touch)
    tok = token_for("alice@corp.example")
    mirror = Path(mailbox_cache_path(settings, mailbox_key("alice@corp.example")))

    async def scenario():
        first = await call_as(ctx, tok, "touch")
        session = pool.get("alice@corp.example")
        await session.syncer._task  # the refresh the first call started
        second = await call_as(ctx, tok, "touch")
        existed = mirror.exists()
        clock[0] += 61
        await pool.evict_idle()
        return first, second, existed

    first, second, existed = asyncio.run(scenario())
    assert first["mirrored"] is False  # the first call never waits for the mirror
    assert second["mirrored"] is True
    assert existed and not mirror.exists()  # deleted with the idle session


# --- mail older than the window ----------------------------------------------


def _windowed(tmp_path, live_items):
    """A snippet mirror holding one recent message (alice, 2026-06-10) whose
    inbox window starts on 2026-06-01; Exchange holds ``live_items``."""
    ctx, account = snippet_ctx(tmp_path)
    floor = int(datetime(2026, 6, 1, tzinfo=UTC).timestamp())
    ctx.cache.set_sync_state("floor:inbox", None, floor)
    account.inbox = _Query(live_items)
    return ctx, account


def test_a_search_reaching_past_the_window_asks_exchange(tmp_path):
    old = _msg("RAW-OLD", subject="Contract", sender="dana@corp.example",
               dt=datetime(2026, 4, 20, 9, 0, tzinfo=UTC))
    ctx, _account = _windowed(tmp_path, [old])
    res = _run(ctx, "search_messages", folder="f:inbox", sender="dana")
    assert res["source"] == "live"  # the mirror never says "nothing" for older mail
    assert [card["subject"] for card in res["items"]] == ["Contract"]


def test_a_search_inside_the_window_is_answered_by_the_mirror(tmp_path):
    ctx, _account = _windowed(tmp_path, [])
    res = _run(ctx, "search_messages", folder="f:inbox", sender="alice", since="2026-06-05")
    assert res["source"] == "cache" and res["count"] == 1 and res["total_available"] == 1


def test_a_full_page_of_newest_matches_needs_no_exchange(tmp_path):
    ctx, _account = _windowed(tmp_path, [])
    res = _run(ctx, "search_messages", folder="f:inbox", sender="alice", limit=1)
    assert res["source"] == "cache" and res["count"] == 1
    assert res["total_available"] is None and res["next_offset"] == 1  # more may be older


def test_overview_counts_unread_mail_from_exchange_when_the_mirror_is_a_window(tmp_path):
    ctx, account = _windowed(tmp_path, [])
    account.calendar.view = MagicMock(return_value=[])
    ctx.cache.set_sync_state("events", None, time.time())
    assert _run(ctx, "get_mailbox_overview")["source"] == "live"
