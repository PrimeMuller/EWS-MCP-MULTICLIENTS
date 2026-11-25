"""On-demand window mirror for bearer mode (DESIGN.md §Cache).

Static mode keeps one mailbox warm with a background SyncFolderItems loop.
That design cannot scale to many mailboxes: polling makes Exchange load grow
with headcount instead of use, and a first SyncFolderItems enumerates a
folder's whole history (there is no "start from now"), which a session that
is deleted after 30 idle minutes would pay again and again.

Bearer mode mirrors only what an active user is likely to ask about, and
only while they are asking:

* **On demand.** A tool call starts at most one background refresh, and only
  if the last attempt is older than ``EWS_CACHE_REFRESH_SECONDS`` (60). It
  runs on the caller's own token while that token is valid, never blocks the
  call, and never queues: when ``EWS_CACHE_MAX_CONCURRENT_REFRESHES``
  refreshes already run in this process, this one is skipped.
* **A bounded window.** Each refresh lists the last ``EWS_CACHE_WINDOW_DAYS``
  (14) of each mirrored folder — ids, change keys and dates only, newest
  first, at most ``EWS_CACHE_MAX_WINDOW_ITEMS`` — then fetches details only
  for items that are new or changed, drops items that left the window or the
  folder, and refreshes the calendar window. Its cost follows the window,
  not the size of the mailbox.
* **Headers and a snippet.** Rows keep ``EWS_CACHE_BODY_CHARS`` (300) of
  cleaned body; full bodies and full-text search always go live.
* **Short-lived.** The mirror file is deleted when the session is evicted
  after ``EWS_MAILBOX_IDLE_SECONDS`` without calls.

Failures only degrade: reads fall back to live Exchange.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

from exchangelib.errors import UnauthorizedError

from .store import CacheStore
from .sync import ITEM_FIELDS, refresh_calendar_window, row_from_message

logger = logging.getLogger(__name__)

# Items per FindItem page when listing the window (Exchange's default
# throttling policy allows up to 1000; the library default is 100).
WINDOW_PAGE_SIZE = 500
# Items per GetItem request when fetching new or changed messages.
FETCH_CHUNK = 50
LISTING_FIELDS = ("id", "changekey", "datetime_received")


class WindowSync:
    """Refreshes one mailbox's window mirror when its user is active."""

    def __init__(self, settings: Any, store: CacheStore, *, limiter: asyncio.Semaphore,
                 clock: Callable[[], float] = time.time):
        self.settings = settings
        self.store = store
        self._limiter = limiter
        self._clock = clock
        self.folder_keys = [
            k.strip().lower()
            for k in (settings.ews_cache_folders or "").split(",") if k.strip()
        ]
        self.window_days = int(settings.ews_cache_window_days)
        self.min_interval = int(settings.ews_cache_refresh_seconds)
        self.max_items = int(settings.ews_cache_max_window_items)
        self.body_chars = int(settings.ews_cache_body_chars)
        self.last_attempt_ts: Optional[float] = None
        self.last_refresh_ts: Optional[float] = None
        self.last_error: Optional[str] = None
        self.refreshes = 0
        self.skipped = 0
        self._task: Optional[asyncio.Task] = None
        self._stopped = False

    # ---------------------------------------------------------- triggering

    def maybe_refresh(self, gateway: Any) -> bool:
        """Start one background refresh if due. Never waits, never queues."""
        if self._stopped or (self._task is not None and not self._task.done()):
            return False
        now = self._clock()
        if self.last_attempt_ts is not None and now - self.last_attempt_ts < self.min_interval:
            return False
        if self._limiter.locked():
            self.skipped += 1  # the process is at its refresh cap; a later call retries
            return False
        self.last_attempt_ts = now
        self._task = asyncio.create_task(self._refresh(gateway), name="mirror-refresh")
        return True

    async def _refresh(self, gateway: Any) -> None:
        try:
            async with self._limiter:
                await gateway.call(self.refresh_once)
            self.refreshes += 1
            self.last_refresh_ts = self._clock()
            self.last_error = None
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.last_error = type(exc).__name__
            logger.warning("mirror refresh failed (%s); reads stay live", self.last_error)

    async def stop(self) -> None:
        self._stopped = True
        task = self._task
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    def status(self) -> Dict[str, Any]:
        return {
            "mode": "on_demand_window",
            "window_days": self.window_days,
            "refreshes": self.refreshes,
            "skipped_at_cap": self.skipped,
            "last_refresh_age_s": (int(self._clock() - self.last_refresh_ts)
                                   if self.last_refresh_ts else None),
            "last_error": self.last_error,
        }

    # ------------------------------------------------------------- refresh

    def refresh_once(self, account: Any) -> None:
        """One full refresh (blocking; runs on the gateway's worker pool)."""
        tz = self.settings.ews_tz
        floor = datetime.now(ZoneInfo(tz)) - timedelta(days=self.window_days)
        for key in self.folder_keys:
            folder = getattr(account, key, None)
            if folder is not None:
                self._refresh_folder(account, folder, key, floor, tz)
        try:
            refresh_calendar_window(account, self.store, tz)
        except UnauthorizedError:
            raise
        except Exception as exc:
            logger.debug("calendar window refresh failed: %s", exc)

    def _list_window(self, folder: Any, floor: datetime) -> Tuple[List[Tuple[str, Optional[str], Optional[int]]], bool]:
        qs = (folder.filter(datetime_received__gte=floor)
              .only(*LISTING_FIELDS).order_by("-datetime_received"))
        qs.page_size = WINDOW_PAGE_SIZE
        listing = []
        for item in qs[: self.max_items + 1]:
            raw_id = getattr(item, "id", None)
            if not raw_id:
                continue
            received = getattr(item, "datetime_received", None)
            ts = int(received.timestamp()) if hasattr(received, "timestamp") else None
            listing.append((str(raw_id), getattr(item, "changekey", None), ts))
        truncated = len(listing) > self.max_items
        return listing[: self.max_items], truncated

    def _refresh_folder(self, account: Any, folder: Any, key: str, floor: datetime,
                        tz: str) -> None:
        floor_ts = int(floor.timestamp())
        listing, truncated = self._list_window(folder, floor)
        known = self.store.window_changekeys(key, floor_ts)
        changed = [raw_id for raw_id, ck, _ in listing
                   if raw_id not in known or known[raw_id] != ck]
        rows: List[Dict[str, Any]] = []
        for start in range(0, len(changed), FETCH_CHUNK):
            chunk = [(raw_id, None) for raw_id in changed[start:start + FETCH_CHUNK]]
            for item in account.fetch(ids=chunk, only_fields=ITEM_FIELDS):
                if isinstance(item, Exception) or not getattr(item, "id", None):
                    continue  # gone since the listing: the next refresh settles it
                rows.append(row_from_message(item, key, tz, body_chars=self.body_chars))
        self.store.upsert_messages(rows)
        # The window's lower edge: the floor date, or — when only the newest
        # max_items fit — the oldest listed item. Below it nothing is kept;
        # above it, a mirrored item Exchange no longer lists was deleted or
        # moved away.
        edge = floor_ts
        if truncated:
            edge = min((ts for _, _, ts in listing if ts is not None), default=floor_ts)
        self.store.prune_folder_before(key, edge)
        listed = {raw_id for raw_id, _, _ in listing}
        gone = [raw_id for raw_id in self.store.window_changekeys(key, edge)
                if raw_id not in listed]
        self.store.delete_messages_by_id(gone)
        self.store.set_sync_state(f"item:{key}", None, time.time())
