"""Per-mailbox sessions: many mailboxes in one process (DESIGN.md §Mailboxes).

Everything that belongs to one mailbox lives in its :class:`MailboxSession`
and nowhere else:

* its gateways — one per bearer token the mailbox has presented. Tokens
  rotate (typically hourly); each keeps its own Account/Protocol, so one
  token never rides on another's connection and a rejected token takes only
  its own gateway down. All of a mailbox's gateways share its request slots
  (``EWS_MAILBOX_MAX_CONCURRENCY``) and the process-wide worker pool
  (``EWS_MAX_CONCURRENCY``).
* its stored state — alias namespace, audit chain, optional mirror, the
  attachment-text cache — and its own upstream circuit.

**Token proof.** A call is bound to a session only through a gateway whose
token Exchange has accepted once: one GetFolder on the mailbox's root, which
names the mailbox (``EWSGateway.prove``). The mailbox comes from the token's
unverified claims, so until that round trip succeeds nothing stored for the
mailbox may be read or written on the token's behalf. A token Exchange
rejects — or that cannot open the mailbox its claims name — is remembered
until it expires and refused locally, without contacting Exchange again.

**Lifecycle.** Sessions are created on first use and evicted after
``EWS_MAILBOX_IDLE_SECONDS`` without calls (and, beyond
``EWS_MAX_MAILBOXES``, least recently used first). Eviction closes the
mailbox's connections and lets its parts release what they hold (the
mirror deletes itself; aliases and audit persist). Sessions with calls in
flight are never evicted.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable, Dict, Optional

from .errors import ToolError
from .gateway.client import BEARER_HINT, EWSGateway
from .identity import Principal, mailbox_key

logger = logging.getLogger(__name__)

# A mailbox seldom holds more than two live tokens (old + refreshed); more
# than this and the least recently used token's connection is closed.
MAX_TOKENS_PER_MAILBOX = 3
# Rejected-token memory: bounded, and kept until the token would have
# expired anyway (or this long when it carries no expiry).
MAX_REJECTED_TOKENS = 10_000
REJECTED_TOKEN_TTL_SECONDS = 3600
JANITOR_INTERVAL_SECONDS = 60.0

EXPIRED_HINT = "The access token has expired. Obtain a fresh token and call again."


@dataclass
class CircuitState:
    """Consecutive upstream failures and when the circuit may close again."""

    failures: int = 0
    open_until: float = 0.0


@dataclass
class SessionParts:
    """A mailbox's stored state, built by the pool's ``parts_factory``.

    ``close`` releases them on eviction (closing the mirror and deleting its
    files); aliases and the audit chain are meant to outlive the session.
    """

    aliaser: Any
    audit: Any
    cache: Any = None
    syncer: Any = None
    close: Callable[[], None] = field(default=lambda: None)


class MailboxSession:
    """One mailbox's connections and state inside this process.

    ``parts`` (the stored state) stays ``None`` until a token has been
    proven for this mailbox: an unproven caller can create, at most, an
    empty in-memory session that touches nothing on disk.
    """

    def __init__(self, mailbox: str, *, request_slots: int, now: float):
        self.mailbox = mailbox
        self.key = mailbox_key(mailbox)
        self.parts: Optional[SessionParts] = None
        self.parts_lock = asyncio.Lock()
        self.request_slots = asyncio.Semaphore(max(1, int(request_slots)))
        self.circuit = CircuitState()
        self.text_cache: Any = None  # AttachmentTextCache, created on first use
        self.in_flight = 0
        self.created_at = now
        self.last_used = now
        self.closed = False
        self._gateways: "OrderedDict[str, EWSGateway]" = OrderedDict()
        self._proof_locks: Dict[str, asyncio.Lock] = {}

    def _part(self, name: str) -> Any:
        if self.parts is None:
            raise RuntimeError("mailbox state requested before any token was proven")
        return getattr(self.parts, name)

    @property
    def aliaser(self) -> Any:
        return self._part("aliaser")

    @property
    def audit(self) -> Any:
        return self._part("audit")

    @property
    def cache(self) -> Any:
        return self._part("cache")

    @property
    def syncer(self) -> Any:
        return self._part("syncer")

    @property
    def gateway_count(self) -> int:
        return len(self._gateways)

    def gateway_for(self, principal: Principal,
                    build: Callable[[Principal, asyncio.Semaphore], EWSGateway]) -> EWSGateway:
        fp = principal.fingerprint
        gateway = self._gateways.get(fp)
        if gateway is not None and not (gateway.rejected or gateway.closed):
            self._gateways.move_to_end(fp)
            return gateway
        if gateway is not None:
            self._drop(fp)
        gateway = build(principal, self.request_slots)
        self._gateways[fp] = gateway
        while len(self._gateways) > MAX_TOKENS_PER_MAILBOX:
            oldest = next(iter(self._gateways))
            self._drop(oldest)
        return gateway

    def proof_lock(self, fingerprint: str) -> asyncio.Lock:
        lock = self._proof_locks.get(fingerprint)
        if lock is None:
            lock = self._proof_locks[fingerprint] = asyncio.Lock()
        return lock

    def drop_token(self, fingerprint: str) -> None:
        self._drop(fingerprint)

    def _drop(self, fingerprint: str) -> None:
        gateway = self._gateways.pop(fingerprint, None)
        self._proof_locks.pop(fingerprint, None)
        if gateway is not None:
            _close_quietly(gateway)

    def drop_expired_tokens(self, now: float) -> None:
        for fp, gateway in list(self._gateways.items()):
            principal = gateway.principal
            if principal is not None and principal.expired(now):
                self._drop(fp)

    def close(self) -> None:
        self.closed = True
        for fp in list(self._gateways):
            self._drop(fp)
        if self.parts is None:
            return
        try:
            self.parts.close()
        except Exception as exc:
            logger.warning("mailbox session parts failed to close: %s", exc)


def _close_quietly(gateway: EWSGateway) -> None:
    try:
        gateway.close()
    except Exception as exc:
        logger.debug("gateway close failed: %s", exc)


@dataclass
class Lease:
    """One call's binding to its mailbox: the session and the proven gateway
    of the token the call presented."""

    session: MailboxSession
    gateway: EWSGateway


class SessionPool:
    """Creates, proves, hands out, and evicts mailbox sessions."""

    def __init__(
        self,
        settings: Any,
        *,
        parts_factory: Callable[[str, str], SessionParts],
        gateway_factory: Optional[Callable[..., EWSGateway]] = None,
        executor: Optional[ThreadPoolExecutor] = None,
        clock: Callable[[], float] = time.time,
    ):
        self.settings = settings
        self._parts_factory = parts_factory
        self._clock = clock
        self._owns_executor = executor is None
        self.executor = executor or ThreadPoolExecutor(
            max_workers=max(1, int(settings.ews_max_concurrency)),
            thread_name_prefix="ews",
        )
        self._gateway_factory = gateway_factory or self._default_gateway
        self._sessions: Dict[str, MailboxSession] = {}
        self._rejected: "OrderedDict[str, float]" = OrderedDict()
        self._version: Any = None
        self._janitor: Optional[asyncio.Task] = None
        self.idle_seconds = max(60, int(settings.ews_mailbox_idle_seconds))
        self.max_sessions = max(1, int(settings.ews_max_mailboxes))
        self.evictions = 0

    # ----------------------------------------------------------- gateways

    def _default_gateway(self, principal: Principal,
                         slots: asyncio.Semaphore) -> EWSGateway:
        return EWSGateway(
            self.settings, principal=principal, executor=self.executor,
            request_slots=slots, version=self._version,
        )

    # ------------------------------------------------------- binding calls

    @asynccontextmanager
    async def bind(self, principal: Optional[Principal]) -> AsyncIterator[Lease]:
        """Bind one call to its mailbox for the duration of the block."""
        lease = await self.checkout(principal)
        try:
            yield lease
        finally:
            lease.session.in_flight -= 1
            lease.session.last_used = self._clock()

    async def checkout(self, principal: Optional[Principal]) -> Lease:
        """Return the call's session and proven gateway; the caller must
        decrement ``session.in_flight`` when done (``bind`` does)."""
        if principal is None or not principal.is_bearer:
            raise ToolError(
                "auth_failed", "This server needs the caller's EWS access token.",
                hint="Send it as 'Authorization: Bearer <token>'.",
            )
        now = self._clock()
        if principal.expired(now):
            raise ToolError("auth_failed", "The access token has expired.", hint=EXPIRED_HINT)
        if self._is_rejected(principal.fingerprint, now):
            raise ToolError("auth_failed", "Exchange already rejected this access token.",
                            hint=BEARER_HINT)
        session = self._session(principal.mailbox)
        gateway = session.gateway_for(principal, self._gateway_factory)
        session.in_flight += 1  # from here on the janitor leaves it alone
        try:
            if len(self._sessions) > self.max_sessions:
                await self._evict_lru()
            await self._prove(session, gateway, principal)
            await self._ensure_parts(session)
        except BaseException:
            session.in_flight -= 1
            raise
        session.last_used = now
        return Lease(session=session, gateway=gateway)

    async def _ensure_parts(self, session: MailboxSession) -> None:
        """Open the mailbox's stored state — only ever after a proof."""
        if session.parts is not None:
            return
        async with session.parts_lock:
            if session.parts is None:
                session.parts = await asyncio.to_thread(
                    self._parts_factory, session.mailbox, session.key)

    async def _prove(self, session: MailboxSession, gateway: EWSGateway,
                     principal: Principal) -> None:
        if gateway.proven:
            return
        async with session.proof_lock(principal.fingerprint):
            if gateway.proven:  # another call with the same token proved it
                return
            loop = asyncio.get_running_loop()
            try:
                async with session.request_slots:
                    await loop.run_in_executor(self.executor, gateway.prove)
            except ToolError as err:
                if err.code == "auth_failed":
                    self._reject(principal)
                    session.drop_token(principal.fingerprint)
                raise
            gateway.proven = True
            if self._version is None:
                self._version = gateway.learned_version()

    def _reject(self, principal: Principal) -> None:
        until = principal.expires_at or (self._clock() + REJECTED_TOKEN_TTL_SECONDS)
        self._rejected[principal.fingerprint] = until
        self._rejected.move_to_end(principal.fingerprint)
        while len(self._rejected) > MAX_REJECTED_TOKENS:
            self._rejected.popitem(last=False)

    def is_rejected(self, principal: Principal) -> bool:
        """True when Exchange already refused this exact token."""
        return self._is_rejected(principal.fingerprint, self._clock())

    def _is_rejected(self, fingerprint: str, now: float) -> bool:
        until = self._rejected.get(fingerprint)
        if until is None:
            return False
        if until <= now:
            del self._rejected[fingerprint]
            return False
        return True

    # ----------------------------------------------------------- sessions

    def _session(self, mailbox: str) -> MailboxSession:
        """Get or create (empty, without touching storage) — synchronous, so
        two first calls for one mailbox can never create two sessions."""
        key = mailbox_key(mailbox)
        session = self._sessions.get(key)
        if session is None or session.closed:
            session = MailboxSession(
                mailbox,
                request_slots=self.settings.ews_mailbox_max_concurrency,
                now=self._clock(),
            )
            self._sessions[key] = session
        return session

    def get(self, mailbox: str) -> Optional[MailboxSession]:
        return self._sessions.get(mailbox_key(mailbox))

    def sessions(self) -> list:
        return list(self._sessions.values())

    async def _close_session(self, session: MailboxSession) -> None:
        if self._sessions.get(session.key) is session:
            del self._sessions[session.key]
        self.evictions += 1
        await asyncio.to_thread(session.close)

    async def _evict_lru(self) -> None:
        idle = sorted(
            (s for s in self._sessions.values() if s.in_flight == 0),
            key=lambda s: s.last_used,
        )
        excess = len(self._sessions) - self.max_sessions
        for session in idle[:max(0, excess)]:
            await self._close_session(session)
        if len(self._sessions) > self.max_sessions:
            logger.warning(
                "mailbox session cap exceeded (%d > %d): every session is busy",
                len(self._sessions), self.max_sessions,
            )

    async def evict_idle(self, now: Optional[float] = None) -> int:
        """Close sessions idle for ``idle_seconds``; drop expired tokens and
        stale rejection records. Returns the number of sessions closed."""
        current = self._clock() if now is None else now
        closed = 0
        for session in list(self._sessions.values()):
            if session.in_flight == 0 and current - session.last_used >= self.idle_seconds:
                await self._close_session(session)
                closed += 1
            else:
                session.drop_expired_tokens(current)
        for fp, until in list(self._rejected.items()):
            if until <= current:
                del self._rejected[fp]
        if len(self._sessions) > self.max_sessions:
            await self._evict_lru()
        return closed

    # ---------------------------------------------------------- lifecycle

    async def start(self) -> None:
        if self._janitor is None:
            self._janitor = asyncio.create_task(self._janitor_loop(), name="mailbox-janitor")

    async def _janitor_loop(self) -> None:
        interval = min(JANITOR_INTERVAL_SECONDS, self.idle_seconds / 4)
        while True:
            await asyncio.sleep(interval)
            try:
                await self.evict_idle()
            except Exception as exc:
                logger.warning("mailbox janitor pass failed: %s", exc)

    async def close(self) -> None:
        if self._janitor is not None:
            self._janitor.cancel()
            try:
                await self._janitor
            except (asyncio.CancelledError, Exception):
                pass
            self._janitor = None
        for session in list(self._sessions.values()):
            await self._close_session(session)
        if self._owns_executor:
            self.executor.shutdown(wait=False, cancel_futures=True)

    def stats(self) -> Dict[str, Any]:
        """Aggregate numbers only — never which mailboxes are active."""
        sessions = list(self._sessions.values())
        return {
            "mailboxes": len(sessions),
            "max_mailboxes": self.max_sessions,
            "in_flight": sum(s.in_flight for s in sessions),
            "tokens": sum(s.gateway_count for s in sessions),
            "rejected_tokens": len(self._rejected),
            "evictions": self.evictions,
            "idle_seconds": self.idle_seconds,
        }
