"""Shared state: the few small facts every server process must agree on.

No mail ever lives here. What does:

* spent confirmation tokens — a token is single-use across every process;
* send-rate windows — per mailbox (``EWS_MAX_SENDS_PER_HOUR``) and for all
  mailboxes together (``EWS_GLOBAL_MAX_SENDS_PER_HOUR``);
* per-mailbox call budgets and Exchange back-off markers (throttling);
* ``send_draft`` idempotency receipts.

Two backends share one interface. :class:`LocalState` (the default) holds it
in this process, which is exact for a single process. :class:`RedisState`
(``EWS_STATE_BACKEND=redis``, Redis or Valkey) makes the caps and single-use
guarantees hold across every pod. Short-id aliases have their own Redis
store (``ids.RedisAliaser``) on the same connection.

Every call takes ``now`` from the caller, so the time base is the caller's
(and tests can pin it). When the shared store cannot be reached, operations
that protect people — spending a token, reserving a send — fail closed with
``upstream_unavailable``; the rest degrade open.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from collections import deque
from typing import Any, Deque, Dict, Optional, Protocol, Tuple

from .errors import ToolError

try:  # optional dependency: only needed for EWS_STATE_BACKEND=redis
    import redis
except ImportError:  # pragma: no cover - absence is the default posture
    redis = None

logger = logging.getLogger(__name__)

STORE_DOWN_HINT = (
    "The shared state store is unreachable, so the server cannot prove this "
    "action is within its limits. Nothing was done; retry shortly."
)

Reservation = Tuple[Optional[str], Optional[float]]  # (slot id, retry_after_s)


class StateBackend(Protocol):
    def claim(self, key: str, *, expires_at: float, now: float) -> bool: ...

    def exists(self, key: str, *, now: float) -> bool: ...

    def reserve(self, key: str, *, limit: int, window_s: float, now: float) -> Reservation: ...

    def release(self, key: str, slot: str) -> None: ...

    def window_count(self, key: str, *, window_s: float, now: float) -> int: ...

    def hit(self, key: str, *, limit: int, window_s: int, now: float) -> Optional[float]: ...

    def put(self, key: str, value: Dict[str, Any], *, expires_at: float, now: float,
            max_entries: Optional[int] = None) -> None: ...

    def get(self, key: str, *, now: float) -> Optional[Dict[str, Any]]: ...

    def clear(self, prefix: str = "") -> None: ...


def _namespace(key: str) -> str:
    return key.split(":", 1)[0]


class LocalState:
    """In-process state: exact for one process, invisible to any other."""

    shared = False

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._marks: Dict[str, float] = {}  # key -> expires_at
        self._windows: Dict[str, Deque[Tuple[float, str]]] = {}
        self._counters: Dict[str, Tuple[int, int]] = {}  # key -> (bucket, count)
        self._records: Dict[str, Tuple[float, Dict[str, Any]]] = {}

    # -- single-use markers ---------------------------------------------------

    def claim(self, key: str, *, expires_at: float, now: float) -> bool:
        """Set ``key`` unless it is already set; prunes expired markers."""
        with self._lock:
            for stale in [k for k, exp in self._marks.items() if exp < now]:
                del self._marks[stale]
            if key in self._marks:
                return False
            self._marks[key] = expires_at
            return True

    def exists(self, key: str, *, now: float) -> bool:
        """Read-only: no pruning side effects (a stale entry still reads as
        set until a claim prunes it)."""
        with self._lock:
            return key in self._marks

    # -- sliding windows (strict caps) -------------------------------------

    def _trim(self, key: str, window_s: float, now: float) -> Deque[Tuple[float, str]]:
        window = self._windows.setdefault(key, deque())
        while window and now - window[0][0] > window_s:
            window.popleft()
        return window

    def reserve(self, key: str, *, limit: int, window_s: float, now: float) -> Reservation:
        with self._lock:
            window = self._trim(key, window_s, now)
            if len(window) >= limit:
                return None, max(1.0, window_s - (now - window[0][0]))
            slot = uuid.uuid4().hex
            window.append((now, slot))
            return slot, None

    def release(self, key: str, slot: str) -> None:
        with self._lock:
            window = self._windows.get(key)
            if not window:
                return
            for idx in range(len(window) - 1, -1, -1):
                if window[idx][1] == slot:
                    del window[idx]
                    return

    def window_count(self, key: str, *, window_s: float, now: float) -> int:
        with self._lock:
            return len(self._trim(key, window_s, now))

    # -- fixed windows (budgets) ------------------------------------------------

    def hit(self, key: str, *, limit: int, window_s: int, now: float) -> Optional[float]:
        """Count one use; return seconds to wait when over ``limit``."""
        bucket = int(now // window_s)
        with self._lock:
            current, count = self._counters.get(key, (bucket, 0))
            if current != bucket:
                count = 0
            count += 1
            self._counters[key] = (bucket, count)
        if count > limit:
            return max(1.0, window_s - (now % window_s))
        return None

    # -- small records -------------------------------------------------------

    def put(self, key: str, value: Dict[str, Any], *, expires_at: float, now: float,
            max_entries: Optional[int] = None) -> None:
        """Store ``value`` until ``expires_at``. ``max_entries`` bounds the
        records sharing this key's namespace (oldest expiry evicted first)."""
        with self._lock:
            self._prune_records(now)
            if max_entries is not None:
                ns = _namespace(key)
                same = [k for k in self._records if _namespace(k) == ns and k != key]
                while len(same) >= max_entries:
                    oldest = min(same, key=lambda k: self._records[k][0])
                    del self._records[oldest]
                    same.remove(oldest)
            self._records[key] = (expires_at, dict(value))

    def get(self, key: str, *, now: float) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._prune_records(now)
            entry = self._records.get(key)
            return dict(entry[1]) if entry is not None else None

    def _prune_records(self, now: float) -> None:
        for stale in [k for k, (exp, _) in self._records.items() if exp <= now]:
            del self._records[stale]

    # -- tests and inspection ------------------------------------------------

    def clear(self, prefix: str = "") -> None:
        with self._lock:
            for store in (self._marks, self._windows, self._counters, self._records):
                for k in [k for k in store if k.startswith(prefix)]:
                    del store[k]

    def marks(self) -> Dict[str, float]:
        with self._lock:
            return dict(self._marks)


class RedisState:
    """State shared through Redis/Valkey: caps and single use hold across pods.

    Built only from primitives that are atomic on their own or inside one
    MULTI/EXEC (no server-side scripts), so it runs on any Redis-compatible
    store. Sliding windows reserve-then-verify: under a race at the edge of
    a cap both contenders may back off — never both proceed.
    """

    shared = True

    def __init__(self, client: Any, *, prefix: str = "ewsmcp") -> None:
        self._r = client
        self._prefix = prefix

    @classmethod
    def from_url(cls, url: str, *, prefix: str = "ewsmcp") -> "RedisState":
        if redis is None:
            raise RuntimeError(
                "EWS_STATE_BACKEND=redis needs the redis package: "
                "pip install 'ews-mcp[redis]'"
            )
        client = redis.Redis.from_url(
            url, socket_timeout=2.0, socket_connect_timeout=2.0,
            health_check_interval=30,
        )
        return cls(client, prefix=prefix)

    @property
    def client(self) -> Any:
        return self._r

    @property
    def prefix(self) -> str:
        return self._prefix

    def _k(self, key: str) -> str:
        return f"{self._prefix}:{key}"

    @staticmethod
    def _down(exc: Exception) -> ToolError:
        logger.error("shared state store unreachable: %s", type(exc).__name__)
        return ToolError("upstream_unavailable", "shared state store unavailable",
                         hint=STORE_DOWN_HINT, retry_after_s=5)

    def claim(self, key: str, *, expires_at: float, now: float) -> bool:
        ttl_ms = max(1, int((expires_at - now) * 1000))
        try:
            return bool(self._r.set(self._k(key), b"1", nx=True, px=ttl_ms))
        except Exception as exc:  # fail closed: never spend a token twice
            raise self._down(exc) from exc

    def exists(self, key: str, *, now: float) -> bool:
        try:
            return bool(self._r.exists(self._k(key)))
        except Exception as exc:
            raise self._down(exc) from exc

    def reserve(self, key: str, *, limit: int, window_s: float, now: float) -> Reservation:
        k = self._k(key)
        slot = f"{now:.6f}:{uuid.uuid4().hex}"
        try:
            pipe = self._r.pipeline(transaction=True)
            pipe.zremrangebyscore(k, "-inf", now - window_s)
            pipe.zadd(k, {slot: now})
            pipe.zcard(k)
            pipe.zrange(k, 0, 0, withscores=True)
            pipe.pexpire(k, int(window_s * 1000) + 1000)
            _, _, count, oldest, _ = pipe.execute()
            if count > limit:
                self._r.zrem(k, slot)
                first = float(oldest[0][1]) if oldest else now
                return None, max(1.0, window_s - (now - first))
            return slot, None
        except Exception as exc:  # fail closed: never exceed a send cap
            raise self._down(exc) from exc

    def release(self, key: str, slot: str) -> None:
        try:
            self._r.zrem(self._k(key), slot)
        except Exception as exc:
            logger.warning("could not release a reserved slot: %s", type(exc).__name__)

    def window_count(self, key: str, *, window_s: float, now: float) -> int:
        k = self._k(key)
        pipe = self._r.pipeline(transaction=True)
        pipe.zremrangebyscore(k, "-inf", now - window_s)
        pipe.zcard(k)
        return int(pipe.execute()[1])

    def hit(self, key: str, *, limit: int, window_s: int, now: float) -> Optional[float]:
        k = self._k(f"{key}:{int(now // window_s)}")
        try:
            pipe = self._r.pipeline(transaction=True)
            pipe.incr(k)
            pipe.expire(k, int(window_s) + 1)
            count = int(pipe.execute()[0])
        except Exception as exc:  # budgets degrade open; caps on concurrency still hold
            logger.warning("call budget unavailable (%s); allowing", type(exc).__name__)
            return None
        if count > limit:
            return max(1.0, window_s - (now % window_s))
        return None

    def put(self, key: str, value: Dict[str, Any], *, expires_at: float, now: float,
            max_entries: Optional[int] = None) -> None:
        ttl_ms = int((expires_at - now) * 1000)
        if ttl_ms <= 0:
            return
        try:
            self._r.set(self._k(key), json.dumps(value, default=str), px=ttl_ms)
        except Exception as exc:
            logger.warning("could not store a record: %s", type(exc).__name__)

    def get(self, key: str, *, now: float) -> Optional[Dict[str, Any]]:
        try:
            raw = self._r.get(self._k(key))
        except Exception as exc:
            logger.warning("could not read a record: %s", type(exc).__name__)
            return None
        if not raw:
            return None
        try:
            value = json.loads(raw)
        except ValueError:
            return None
        return value if isinstance(value, dict) else None

    def clear(self, prefix: str = "") -> None:
        for k in self._r.scan_iter(match=f"{self._prefix}:{prefix}*"):
            self._r.delete(k)


# --- the process's backend ----------------------------------------------------

_BACKEND: Any = LocalState()
_BACKEND_LOCK = threading.Lock()


def backend() -> StateBackend:
    return _BACKEND


def configure(settings: Any) -> StateBackend:
    """Select the backend for this process from settings (once, at boot)."""
    global _BACKEND
    with _BACKEND_LOCK:
        if getattr(settings, "ews_state_backend", "local") == "redis":
            if not isinstance(_BACKEND, RedisState):
                _BACKEND = RedisState.from_url(
                    settings.ews_redis_url, prefix=settings.ews_state_prefix)
        elif not isinstance(_BACKEND, LocalState):
            _BACKEND = LocalState()
        return _BACKEND


def use_backend(store: Any) -> None:
    """Install a specific backend (tests, embedding)."""
    global _BACKEND
    with _BACKEND_LOCK:
        _BACKEND = store


def reset_local(prefix: str = "") -> None:
    """Tests only: clear the in-process store."""
    if isinstance(_BACKEND, LocalState):
        _BACKEND.clear(prefix)
