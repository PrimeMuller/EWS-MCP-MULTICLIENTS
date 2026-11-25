"""Error taxonomy — every failure the model sees is one of these codes,
with a hint written for the model, never a traceback (DESIGN.md §Errors)."""

import math
import re
from typing import Optional

from exchangelib.errors import ErrorServerBusy, RateLimitError, UnauthorizedError

from .toolerror import HTTP_BY_CODE, ToolError

__all__ = [
    "AUTH_FAILED_HINT", "HTTP_BY_CODE", "ToolError", "explicit_backoff_seconds",
    "map_exception",
]

AUTH_FAILED_HINT = (
    "Retrying will not help: credentials are read once at startup and "
    "repeated failures risk locking the directory account. Ask the operator "
    "to check the configured address/username and password, update the "
    "configuration, and restart the server."
)
THROTTLED_HINT = (
    "Exchange asked this mailbox to slow down. Wait retry_after_s seconds "
    "before calling again; prefer fewer, narrower calls (a query or a date "
    "range instead of scanning folders)."
)
DEFAULT_THROTTLE_SECONDS = 60

_AUTH_STATUS_RE = re.compile(
    r"\bunauthorized\b|\bhttp\s+401\b|\bstatus(?:\s+code)?[:=\s]+401\b"
)
_THROTTLE_MARKERS = (
    "errorserverbusy", "back off", "ratelimit", "errorexceededconnectioncount",
    "errortoomanyobjectsopened",
)


def explicit_backoff_seconds(exc: BaseException) -> Optional[float]:
    """The wait Exchange explicitly asked for, if this failure carries one.

    exchangelib surfaces Exchange's ``BackOffMilliseconds`` (or an HTTP
    ``Retry-After``) as ``ErrorServerBusy.back_off``, and raises
    ``RateLimitError(wait=...)`` when that wait exceeds
    ``EWS_RETRY_MAX_WAIT_SECONDS``. Generic busy errors carry no wait.
    """
    seen = set()
    current: Optional[BaseException] = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, RateLimitError):
            wait = getattr(current, "wait", None)
        elif isinstance(current, ErrorServerBusy):
            wait = getattr(current, "back_off", None)
        else:
            wait = None
        if isinstance(wait, (int, float)) and not isinstance(wait, bool) and wait > 0:
            return float(wait)
        current = current.__cause__ or current.__context__
    return None


def map_exception(exc: Exception) -> ToolError:
    """Classify an arbitrary upstream/library exception."""
    if isinstance(exc, ToolError):
        return exc
    name = type(exc).__name__
    text = f"{name}: {exc}"
    lowered = f"{name} {exc}".lower()
    if isinstance(exc, UnauthorizedError) or name == "UnauthorizedError":
        return ToolError("auth_failed", text, hint=AUTH_FAILED_HINT)
    if isinstance(exc, (RateLimitError, ErrorServerBusy)) or any(
        marker in lowered for marker in _THROTTLE_MARKERS
    ):
        wait = explicit_backoff_seconds(exc)
        return ToolError(
            "throttled", text, hint=THROTTLED_HINT,
            retry_after_s=max(1, math.ceil(wait)) if wait else DEFAULT_THROTTLE_SECONDS,
        )
    if "erroritemnotfound" in lowered or "errorinvalidid" in lowered:
        return ToolError(
            "not_found", text,
            hint=(
                "The item id is stale (items move). Re-run search_messages "
                "and use a fresh id."
            ),
        )
    if "invalid credentials" in lowered or _AUTH_STATUS_RE.search(lowered):
        return ToolError("auth_failed", text, hint=AUTH_FAILED_HINT)
    if any(
        k in lowered
        for k in ("connection", "timeout", "timed out", "transport", "auth type")
    ):
        return ToolError(
            "upstream_unavailable", text,
            hint="Exchange is unreachable or refusing fresh sessions; check /readyz.",
            retry_after_s=30,
        )
    return ToolError("upstream_error", text)
