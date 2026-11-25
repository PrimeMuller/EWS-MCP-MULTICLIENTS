"""Exchange protection: this server's limits in front of Exchange's own.

Exchange throttles each user (its EWS throttling policy), and the servers
behind it suffer when many users push at once. These gates make the server a
polite client, cheaply, before any request leaves the process:

* **Per-mailbox call budget** (``EWS_MAILBOX_CALLS_PER_MINUTE``; default 60
  in bearer mode, off in static mode): a runaway agent loop is stopped here
  with ``rate_capped`` and ``retry_after_s``, not by Exchange.
* **Explicit back-off**: when Exchange tells a mailbox to back off
  (``BackOffMilliseconds``, surfaced by exchangelib as
  ``ErrorServerBusy.back_off`` or ``RateLimitError.wait``), that mailbox's
  calls are refused locally until the time is up — across every pod when the
  state backend is shared. Generic busy errors without a stated wait set no
  marker; the caller still gets ``retry_after_s``.
* **No blocking retries**: exchangelib may sleep at most
  ``EWS_RETRY_MAX_WAIT_SECONDS`` inside a worker thread; longer requested
  waits come straight back to the caller as ``throttled``.

The concurrency caps live with the connections (``EWS_MAILBOX_MAX_CONCURRENCY``
per mailbox, ``EWS_MAX_CONCURRENCY`` per process) and the process-wide
upstream circuit in ``sessions.SessionPool``.

Refusals raised here are :class:`LocalRefusal`: Exchange was not contacted,
so they never count as upstream failures or extend a back-off.
"""

from __future__ import annotations

import math
import time
from typing import Any, Optional

from . import state
from .errors import THROTTLED_HINT, ToolError
from .identity import mailbox_key

CALL_WINDOW_SECONDS = 60
# Never honour a stated back-off longer than this (a corrupt or hostile value
# must not lock a mailbox out for hours).
MAX_BACKOFF_SECONDS = 900

BUDGET_HINT = (
    "This mailbox has used its call budget for the minute. Wait retry_after_s "
    "seconds; batch work into fewer calls (get_messages takes up to 20 ids, "
    "search with a query instead of paging folders)."
)


class LocalRefusal(ToolError):
    """Refused by this server's own limits; Exchange was not contacted."""


def _backoff_key(ctx: Any) -> str:
    return f"backoff:{mailbox_key(ctx.mailbox)}"


def check_backoff(ctx: Any, now: Optional[float] = None) -> None:
    """Refuse while Exchange's stated back-off for this mailbox runs."""
    current = time.time() if now is None else now
    marker = state.backend().get(_backoff_key(ctx), now=current)
    until = (marker or {}).get("until")
    if isinstance(until, (int, float)) and until > current:
        raise LocalRefusal(
            "throttled",
            "Exchange asked this mailbox to back off; the call was not sent.",
            hint=THROTTLED_HINT,
            retry_after_s=max(1, math.ceil(until - current)),
        )


def record_backoff(ctx: Any, seconds: float, now: Optional[float] = None) -> None:
    current = time.time() if now is None else now
    wait = min(float(seconds), MAX_BACKOFF_SECONDS)
    if wait <= 0:
        return
    until = current + wait
    state.backend().put(_backoff_key(ctx), {"until": until}, expires_at=until, now=current)


def check_call_budget(ctx: Any, now: Optional[float] = None) -> None:
    limit = int(getattr(ctx.settings, "ews_mailbox_calls_per_minute", 0) or 0)
    if limit <= 0:
        return
    current = time.time() if now is None else now
    retry = state.backend().hit(f"calls:{mailbox_key(ctx.mailbox)}", limit=limit,
                                window_s=CALL_WINDOW_SECONDS, now=current)
    if retry is not None:
        raise LocalRefusal(
            "rate_capped", f"call budget reached ({limit}/minute for this mailbox)",
            hint=BUDGET_HINT, retry_after_s=max(1, math.ceil(retry)),
        )
