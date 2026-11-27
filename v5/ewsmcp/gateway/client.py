"""EWS gateway — one Account per credential, EWS off the event loop.

A gateway owns exactly one credential: the configured service credentials
of static mode, or one caller's bearer token in bearer mode (one gateway per
token; ``sessions.py`` keeps them per mailbox). Many gateways share one
bounded worker pool, and each mailbox's gateways share one request-slot
semaphore, so neither one mailbox nor the whole process can exceed its cap
on concurrent Exchange requests.

Authentication auto-negotiation is the default for static credentials
because it adapts to what the Exchange server offers; forcing a scheme via
``ews_auth_type_force`` skips the unauthenticated probe request. Bearer
tokens are presented as-is (``Authorization: Bearer``) with no probe.

HTTP 401 credential rejections fail fast via ``RejectingFaultTolerance`` and
trip the gateway's authentication circuit breaker so a stale password can
never be resubmitted in a loop or lock out the directory account, and a
rejected token is never presented again.
"""

import asyncio
import logging
import math
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Tuple

from exchangelib import (
    BASIC,
    DELEGATE,
    DIGEST,
    NTLM,
    OAUTH2,
    Account,
    Configuration,
    Credentials,
    EWSTimeZone,
    OAuth2AuthorizationCodeCredentials,
)
from exchangelib.errors import (
    ErrorAccessDenied,
    ErrorInvalidSmtpAddress,
    ErrorNonExistentMailbox,
    UnauthorizedError,
)
from exchangelib.protocol import (
    BaseProtocol,
    CachingProtocol,
    FaultTolerance,
    NoVerifyHTTPAdapter,
)

from ..config import Settings
from ..errors import AUTH_FAILED_HINT, ToolError, map_exception
from ..identity import Principal, token_fingerprint
from ..throttle import LocalRefusal

logger = logging.getLogger(__name__)

# Setting value -> exchangelib constant. They are not the same strings: the
# library spells NTLM in upper case, so passing the setting through as is
# made a forced NTLM fail validation before any request was sent.
AUTH_TYPE_BY_SETTING = {"basic": BASIC, "ntlm": NTLM, "digest": DIGEST}

BEARER_HINT = (
    "Exchange rejected the access token. Retrying with the same token will "
    "not help: obtain a fresh token for this user and call again."
)
MAILBOX_REFUSED_HINT = (
    "Exchange accepted the token but will not open the mailbox named by its "
    "claims. The operator should check EWS_TOKEN_MAILBOX_CLAIMS: the chosen "
    "claim must hold the user's primary SMTP address."
)
# Exchange answered, and the answer is no: this token cannot open the
# mailbox its claims name. Never transient, so never retried.
_MAILBOX_REFUSED = (ErrorAccessDenied, ErrorInvalidSmtpAddress, ErrorNonExistentMailbox)


class CallerTokenCredentials(OAuth2AuthorizationCodeCredentials):
    """One caller's access token, issued upstream (e.g. on-behalf-of) and used
    as it is: exchangelib's own OAuth2 credentials, with three guards for a
    token this server did not obtain and cannot renew.

    - No expiry is given to the OAuth library. Otherwise it would itself
      declare the token expired and ask exchangelib to refresh it, which
      exchangelib retries immediately with no limit. Exchange decides
      instead: an expired token gets HTTP 401, the gateway stops for good,
      and the caller comes back with a new token.
    - ``refresh`` refuses: tokens are never refreshed here.
    - Equality and hash follow the token. The base class hashes without the
      token, which would put every user's credentials in one slot of
      exchangelib's protocol cache; here each token gets its own Protocol
      and connections, and nothing is shared between users.
    """

    def __init__(self, token: str):
        super().__init__(access_token={"access_token": token, "token_type": "Bearer"})
        self._token_fingerprint = token_fingerprint(token)

    def refresh(self, session: Any) -> None:
        raise UnauthorizedError(
            "Access tokens are not refreshed by this server; send a new token."
        )

    def __eq__(self, other: object) -> bool:
        return (type(other) is type(self)
                and other._token_fingerprint == self._token_fingerprint)

    def __hash__(self) -> int:
        return hash((type(self), self._token_fingerprint))

WELL_KNOWN = {
    "f:inbox": "inbox", "f:sent": "sent", "f:drafts": "drafts",
    "f:trash": "trash", "f:junk": "junk", "f:outbox": "outbox",
    "f:calendar": "calendar", "f:contacts": "contacts", "f:tasks": "tasks",
    "f:sentitems": "sent", "f:deleteditems": "trash", "f:junkemail": "junk",
}

_QUOTED_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_SCHEME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")
_THREAD_LOCAL = threading.local()


def _thread_401_seq() -> int:
    return int(getattr(_THREAD_LOCAL, "http_401_seq", 0))


def _mark_thread_401() -> None:
    _THREAD_LOCAL.http_401_seq = _thread_401_seq() + 1


def _thread_breaker_seq(breaker: "AuthBreaker") -> int:
    by_breaker = getattr(_THREAD_LOCAL, "breaker_seq", None)
    if by_breaker is None:
        return 0
    return int(by_breaker.get(id(breaker), 0))


def _mark_thread_breaker_rejection(breaker: "AuthBreaker") -> None:
    by_breaker = getattr(_THREAD_LOCAL, "breaker_seq", None)
    if by_breaker is None:
        by_breaker = {}
        _THREAD_LOCAL.breaker_seq = by_breaker
    key = id(breaker)
    by_breaker[key] = int(by_breaker.get(key, 0)) + 1


def _www_authenticate_schemes(response: Any) -> List[str]:
    """Extract bare scheme tokens from a response's WWW-Authenticate header(s).

    Strips quoted auth-param values and skips key=value pairs and challenge
    payloads so realms, host identifiers and NTLM/Negotiate tokens never enter
    logs.
    """
    headers = getattr(response, "headers", None)
    if headers is None:
        return []
    raw_values: List[str] = []
    if hasattr(headers, "get_all"):
        raw_values.extend(str(v) for v in (headers.get_all("WWW-Authenticate") or []))
    elif hasattr(headers, "getlist"):
        raw_values.extend(str(v) for v in (headers.getlist("WWW-Authenticate") or []))
    elif hasattr(headers, "items"):
        for k, v in headers.items():
            key = k.decode("latin-1") if isinstance(k, bytes) else str(k)
            if key.lower() == "www-authenticate" and v is not None:
                val = v.decode("latin-1", "replace") if isinstance(v, bytes) else str(v)
                raw_values.append(val)
    elif isinstance(headers, (list, tuple)):
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                k, v = item
                key = k.decode("latin-1") if isinstance(k, bytes) else str(k)
                if key.lower() == "www-authenticate" and v is not None:
                    val = v.decode("latin-1", "replace") if isinstance(v, bytes) else str(v)
                    raw_values.append(val)
    schemes: List[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        scrubbed = _QUOTED_RE.sub('""', raw)
        for segment in scrubbed.split(","):
            part = segment.strip()
            if not part:
                continue
            token = part.split()[0]
            if "=" in token or not _SCHEME_RE.match(token):
                continue
            lowered = token.lower()
            if lowered not in seen:
                seen.add(lowered)
                schemes.append(token)
    return schemes


_LOCKED_OUT_MARKER = b"currently locked out"


class RejectingFaultTolerance(FaultTolerance):
    """FaultTolerance policy that raises UnauthorizedError immediately on 401.

    exchangelib 5.0.3's ``FaultTolerance`` maps HTTP 401 onto
    ``ErrorServerBusy("Caused by HTTP 401 response")`` and retries with
    exponential back-off up to ``max_wait``. Here every 401 is counted and
    raised as ``UnauthorizedError`` at once, with the library's message when
    the body says the account is locked out (delegating that case would let
    a ``Connection: close`` header turn it into a retried busy-server error).
    Every other status delegates to ``super()`` unchanged.
    """

    def __init__(
        self,
        *args: Any,
        configured_auth_type: Optional[str] = None,
        on_rejection: Optional[Callable[[], None]] = None,
        **kwargs: Any,
    ):
        super().__init__(*args, **kwargs)
        self.configured_auth_type = configured_auth_type
        self._on_rejection = on_rejection

    def raise_response_errors(self, response: Any) -> Any:
        if getattr(response, "status_code", None) == 401:
            _mark_thread_401()
            raw_body = getattr(response, "content", b"") or b""
            body = (
                raw_body.encode("utf-8", "replace")
                if isinstance(raw_body, str)
                else bytes(raw_body)
            )
            locked_out = _LOCKED_OUT_MARKER in body
            schemes = _www_authenticate_schemes(response)
            offered = ", ".join(schemes) if schemes else "none"
            configured = self.configured_auth_type or "auto-negotiated"
            logger.warning(
                "Exchange HTTP 401 rejection%s: WWW-Authenticate schemes [%s]; "
                "ews_auth_type_force=%s",
                " (account locked out)" if locked_out else "",
                offered,
                configured,
            )
            # Raised here for the locked-out case too: the library checks a
            # `Connection: close` header first and would report a locked
            # account as a busy server, to be retried.
            err = UnauthorizedError(
                "The referenced account is currently locked out" if locked_out
                else "Exchange rejected credentials (HTTP 401)"
            )
            if self._on_rejection is not None:
                self._on_rejection()
            raise err
        return super().raise_response_errors(response)


class AuthBreaker:
    """Thread-safe circuit breaker guarding all Exchange credential use."""

    def __init__(
        self,
        cooldown_seconds: int = 900,
        max_rejections: int = 3,
        clock: Optional[Callable[[], float]] = None,
        bearer: bool = False,
    ):
        self._cooldown = max(0, int(cooldown_seconds))
        # Bearer mode guards one caller's token, not the server's own
        # credentials: a rejection is answered with "get a new token".
        self._bearer = bool(bearer)
        self._max_rejections = max(1, int(max_rejections))
        self._clock = clock
        self._lock = threading.Lock()
        self._rejections = 0
        self._open_until_ts: Optional[float] = None
        self._permanent = False
        self._probe_in_flight = False
        self._seq = 0
        self._listeners: List[Callable[[], None]] = []

    def add_rejection_listener(self, callback: Callable[[], None]) -> None:
        with self._lock:
            if callback not in self._listeners:
                self._listeners.append(callback)

    def remove_rejection_listener(self, callback: Callable[[], None]) -> None:
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)

    def _now(self) -> float:
        return float(self._clock()) if self._clock is not None else time.time()

    def _error_locked(self, now: float) -> ToolError:
        if self._permanent and self._bearer:
            return ToolError("auth_failed", "Exchange rejected this access token.",
                             hint=BEARER_HINT)
        if self._permanent:
            return ToolError(
                "auth_failed",
                f"Exchange rejected credentials {self._rejections} time(s); "
                "authentication circuit breaker is permanently open until restart.",
                hint=AUTH_FAILED_HINT,
                retry_after_s=None,
            )
        remaining = 0
        if self._open_until_ts is not None and now < self._open_until_ts:
            remaining = max(1, math.ceil(self._open_until_ts - now))
        return ToolError(
            "auth_failed",
            f"Exchange rejected credentials ({self._rejections}/{self._max_rejections}); "
            f"authentication circuit breaker is open for {remaining}s.",
            hint=AUTH_FAILED_HINT,
            retry_after_s=remaining,
        )

    def check_open(self) -> None:
        with self._lock:
            now = self._now()
            if self._permanent:
                raise self._error_locked(now)
            if self._rejections > 0:
                if self._open_until_ts is not None and now < self._open_until_ts:
                    raise self._error_locked(now)
                if self._probe_in_flight:
                    raise self._error_locked(now)

    def before_call(self) -> Tuple[int, bool]:
        """Gate an Exchange operation; returns (rejection_seq, claimed_half_open)."""
        with self._lock:
            now = self._now()
            if self._permanent:
                raise self._error_locked(now)
            if self._rejections > 0:
                if self._open_until_ts is not None and now < self._open_until_ts:
                    raise self._error_locked(now)
                if self._probe_in_flight:
                    raise self._error_locked(now)
                self._probe_in_flight = True
                return self._seq, True
            return self._seq, False

    def release_half_open(self) -> None:
        with self._lock:
            self._probe_in_flight = False

    def record_rejection(self) -> ToolError:
        _mark_thread_breaker_rejection(self)
        with self._lock:
            now = self._now()
            self._rejections += 1
            self._seq += 1
            self._probe_in_flight = False
            if self._rejections >= self._max_rejections:
                self._permanent = True
                self._open_until_ts = None
            else:
                self._open_until_ts = now + self._cooldown
            err = self._error_locked(now)
            listeners = list(self._listeners)
        for callback in listeners:
            try:
                callback()
            except Exception as exc:
                logger.debug("auth rejection listener failed: %s", exc)
        return err

    def record_success(self) -> None:
        with self._lock:
            self._rejections = 0
            self._open_until_ts = None
            self._permanent = False
            self._probe_in_flight = False

    def current_error(self) -> ToolError:
        with self._lock:
            return self._error_locked(self._now())

    @property
    def seq(self) -> int:
        with self._lock:
            return self._seq

    def status(self) -> Dict[str, Any]:
        with self._lock:
            now = self._now()
            if self._permanent:
                next_retry_in_s: Optional[int] = None
                cooldown_remaining_s: Optional[float] = None
                open_now = True
            elif self._rejections > 0:
                if self._open_until_ts is not None and now < self._open_until_ts:
                    cooldown_remaining_s = self._open_until_ts - now
                    next_retry_in_s = max(1, math.ceil(cooldown_remaining_s))
                    open_now = True
                else:
                    cooldown_remaining_s = 0.0
                    next_retry_in_s = 0
                    open_now = self._probe_in_flight
            else:
                next_retry_in_s = None
                cooldown_remaining_s = None
                open_now = False
            return {
                "rejections": self._rejections,
                "max_rejections": self._max_rejections,
                "permanent": self._permanent,
                "open": open_now,
                "next_retry_in_s": next_retry_in_s,
                "cooldown_remaining_s": cooldown_remaining_s,
            }


SHED_RETRY_AFTER_SECONDS = 3
SHED_HINT = (
    "This server is at its limit of requests in flight to Exchange, so the "
    "call was not sent. Wait retry_after_s seconds and try again."
)


class WorkerGate:
    """The process-wide cap on Exchange requests in flight, with load shedding.

    Sized like the worker pool, so work never queues inside the executor:
    a call waits here, on the event loop, for at most ``timeout`` seconds and
    is then refused with ``throttled`` + ``retry_after_s`` — Exchange never
    sees it. Under overload the server sheds calls instead of building a
    queue whose latency nobody can bound.
    """

    def __init__(self, size: int, timeout: float):
        self.size = max(1, int(size))
        self.timeout = float(timeout)
        self._sem = asyncio.Semaphore(self.size)
        self.busy = 0
        self.shed = 0

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        try:
            await asyncio.wait_for(self._sem.acquire(), self.timeout)
        except asyncio.TimeoutError:
            self.shed += 1
            raise LocalRefusal(
                "throttled", "Server busy: no Exchange worker became free in time.",
                hint=SHED_HINT, retry_after_s=SHED_RETRY_AFTER_SECONDS,
            ) from None
        self.busy += 1
        try:
            yield
        finally:
            self.busy -= 1
            self._sem.release()


class EWSGateway:
    def __init__(
        self,
        settings: Settings,
        clock: Optional[Callable[[], float]] = None,
        *,
        principal: Optional[Principal] = None,
        executor: Optional[ThreadPoolExecutor] = None,
        request_slots: Optional[asyncio.Semaphore] = None,
        worker_gate: Optional[WorkerGate] = None,
        version: Any = None,
    ):
        """One credential's connection to Exchange.

        ``principal`` carries a bearer token in bearer mode; without one the
        configured service credentials of static mode are used. ``executor``
        is the process-wide worker pool (a private one is created when
        omitted), ``request_slots`` the mailbox's cap on concurrent requests
        shared by all of its gateways, and ``version`` the server version
        already learned by another gateway, which spares the per-connection
        version probe.
        """
        self.settings = settings
        self._clock = clock
        self.principal = principal
        self.mailbox = (
            principal.mailbox if principal is not None else (settings.ews_email or "")
        )
        bearer = principal is not None and principal.is_bearer
        self._breaker = AuthBreaker(
            cooldown_seconds=settings.ews_auth_failure_cooldown_seconds,
            # A rejected token never becomes valid again: one strike latches
            # this gateway, and the caller must come back with a new token.
            max_rejections=1 if bearer else settings.ews_auth_max_rejections,
            clock=clock,
            bearer=bearer,
        )
        self._account: Optional[Account] = None
        self._account_lock = threading.Lock()
        self._closed = False
        self._cache_key: Optional[Tuple[Any, Any]] = None
        self._owns_pool = executor is None
        self._pool = executor or ThreadPoolExecutor(
            max_workers=max(1, settings.ews_max_concurrency),
            thread_name_prefix="ews",
        )
        self._slots = request_slots
        self._workers = worker_gate
        self._version = version
        # Bearer mode: set once Exchange has accepted this token for this
        # mailbox (see prove()); the session layer hands out the mailbox's
        # stored state only through a proven gateway.
        self.proven = False
        self.last_connection_error: Optional[str] = None
        self.last_connection_exc: Optional[BaseException] = None
        self._folder_cache: Dict[str, Any] = {}
        self._folder_cache_ts = 0.0
        if settings.ews_insecure_skip_verify:
            BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter
            logger.warning("TLS verification DISABLED for Exchange traffic")

    def _now(self) -> float:
        return float(self._clock()) if self._clock is not None else time.time()

    def auth_status(self) -> Dict[str, Any]:
        """Thread-safe snapshot of the authentication circuit breaker."""
        return self._breaker.status()

    @property
    def rejected(self) -> bool:
        """True once Exchange refused this gateway's credential for good."""
        return bool(self._breaker.status()["permanent"])

    def learned_version(self) -> Any:
        """The server version this gateway negotiated, once it has one."""
        account = self._account
        protocol = getattr(account, "protocol", None) if account is not None else None
        config = getattr(protocol, "config", None)
        version = getattr(config, "version", None)
        return version if getattr(version, "build", None) else None

    # ------------------------------------------------------------- account

    def _get_or_build_account(self) -> Account:
        with self._account_lock:
            if self._account is None:
                if self._closed:
                    # An evicted gateway must not quietly rebuild a protocol
                    # nobody tracks; the next call gets a fresh gateway.
                    raise ToolError(
                        "upstream_unavailable", "This connection was closed; call again.",
                        retry_after_s=1,
                    )
                self._account = self._build_account()
            return self._account

    @property
    def account(self) -> Account:
        self._breaker.check_open()
        return self._get_or_build_account()

    def _credentials(self) -> Tuple[Any, Optional[str]]:
        """(exchangelib credentials, auth_type or None to negotiate)."""
        s = self.settings
        principal = self.principal
        if principal is not None and principal.is_bearer:
            return CallerTokenCredentials(principal.token or ""), OAUTH2
        creds = Credentials(s.ews_username or s.ews_email, s.ews_password or "")
        if s.ews_auth_type_force:
            logger.info("Using forced Exchange auth scheme: %s", s.ews_auth_type_force)
            return creds, AUTH_TYPE_BY_SETTING[s.ews_auth_type_force]
        return creds, None

    def _build_account(self) -> Account:
        s = self.settings
        BaseProtocol.TIMEOUT = s.request_timeout
        policy = RejectingFaultTolerance(
            max_wait=s.ews_retry_max_wait_seconds,
            configured_auth_type=s.ews_auth_type_force,
            on_rejection=lambda: self._breaker.record_rejection(),
        )
        credentials, auth_type = self._credentials()
        kwargs: Dict[str, Any] = dict(
            service_endpoint=s.ews_server_url,
            credentials=credentials,
            retry_policy=policy,
            # exchangelib opens one TCP connection per session; matching the
            # pool to the mailbox's request cap keeps threads from queueing
            # inside the library.
            max_connections=int(s.ews_mailbox_max_concurrency),
        )
        if auth_type is not None:
            kwargs["auth_type"] = auth_type
        if self._version is not None:
            kwargs["version"] = self._version.copy()
        config = Configuration(**kwargs)
        self._cache_key = (config.service_endpoint, config.credentials)
        account = Account(
            primary_smtp_address=self.mailbox,
            config=config,
            autodiscover=False,
            access_type=DELEGATE,
            default_timezone=EWSTimeZone(s.ews_tz),
        )
        # CachingProtocol keys on (service_endpoint, credentials), so a second
        # gateway sharing those gets back the cached Protocol carrying the
        # earlier gateway's retry_policy. Rebind it to this gateway's policy.
        protocol = getattr(account, "protocol", None)
        if protocol is not None and getattr(protocol, "retry_policy", None) is not policy:
            protocol.config.retry_policy = policy
        return account

    def _evict_protocol(self, account: Optional[Account]) -> None:
        """Close this gateway's sessions and drop ITS protocol-cache entry.

        Dropping only our Account is not enough: ``CachingProtocol`` hands
        the same wedged Protocol (with its already-negotiated auth type)
        right back on the next build, so a session that died mid-outage
        would never renegotiate. The cache is global to the process and
        never evicts on its own, so only this gateway's key is removed —
        clearing it all would cut every other mailbox's live sessions — and
        removing it is what keeps per-token protocols from accumulating.
        """
        protocol = getattr(account, "protocol", None) if account is not None else None
        if protocol is not None:
            try:
                protocol.close()
            except Exception:
                pass
        key = self._cache_key
        if key is None:
            return
        try:
            with CachingProtocol._protocol_cache_lock:
                entry = CachingProtocol._protocol_cache.get(key)
                if entry is not None and (
                    protocol is None or entry[0] is protocol
                    or isinstance(entry[0], Exception)
                ):
                    del CachingProtocol._protocol_cache[key]
        except Exception as e:
            logger.debug("protocol cache eviction failed: %s", e)

    def reset(self) -> None:
        """Drop the cached account and this credential's protocol-cache
        entry, forcing a genuinely fresh session + auth negotiation on the
        next access."""
        with self._account_lock:
            account, self._account = self._account, None
            self._evict_protocol(account)
        self._folder_cache.clear()
        self._folder_cache_ts = 0.0

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        """Release everything this gateway holds (idle eviction, shutdown)."""
        with self._account_lock:
            self._closed = True
        self.reset()
        if self._owns_pool:
            self._pool.shutdown(wait=False, cancel_futures=True)

    def _handle_auth_rejection(
        self, exc: UnauthorizedError, thread_breaker_before: int
    ) -> ToolError:
        if (
            _thread_breaker_seq(self._breaker) != thread_breaker_before
            and self._breaker.status()["rejections"] > 0
        ):
            err = self._breaker.current_error()
        else:
            err = self._breaker.record_rejection()
        self.last_connection_error = f"{type(exc).__name__}: {exc}"
        return err

    def _handle_swallowed_auth_rejection(self, thread_breaker_before: int) -> ToolError:
        if (
            _thread_breaker_seq(self._breaker) != thread_breaker_before
            and self._breaker.status()["rejections"] > 0
        ):
            err = self._breaker.current_error()
        else:
            err = self._breaker.record_rejection()
        self.last_connection_error = f"ToolError: {err.message}"
        return err

    def test_connection(self) -> bool:
        """Real network probe — must round-trip on EVERY call.

        ``inbox.total_count`` is a cached property after its first read, so
        probing it reported warm forever once it had succeeded once (the
        false-warm bug: /readyz lied through outages and the reset ladder
        never ran). ``root.refresh()`` issues a GetFolder request each time.

        While the auth breaker is open, or when Exchange rejects credentials
        with HTTP 401, raises ``ToolError("auth_failed", ...)`` without
        retrying.
        """
        seq_before, claimed = self._breaker.before_call()
        claim_released = False
        t401_before = _thread_401_seq()
        tbrk_before = _thread_breaker_seq(self._breaker)
        try:
            account = self._get_or_build_account()
            account.root.refresh()
            if (
                _thread_401_seq() != t401_before
                or _thread_breaker_seq(self._breaker) != tbrk_before
            ):
                err = self._handle_swallowed_auth_rejection(tbrk_before)
                claim_released = True
                raise err
            if self._breaker.seq != seq_before:
                # Another thread was rejected while this probe ran. Reporting
                # "warm" here would end the warm-up loop with the breaker
                # still open and nothing left to probe again.
                raise self._breaker.current_error()
            self._breaker.record_success()
            self.last_connection_error = None
            claim_released = True
            return True
        except ToolError as err:
            if err.code == "auth_failed":
                self.last_connection_error = f"ToolError: {err.message}"
                raise
            self.last_connection_error = f"{type(err).__name__}: {err}"
            self.last_connection_exc = err
            logger.error("connection test failed: %s", self.last_connection_error)
            return False
        except UnauthorizedError as exc:
            err = self._handle_auth_rejection(exc, tbrk_before)
            claim_released = True
            logger.error("connection test rejected credentials: %s", err.message)
            raise err from exc
        except Exception as e:
            if (
                _thread_401_seq() != t401_before
                or _thread_breaker_seq(self._breaker) != tbrk_before
            ):
                err = self._handle_swallowed_auth_rejection(tbrk_before)
                claim_released = True
                self.last_connection_error = f"ToolError: {err.message}"
                raise err from e
            self.last_connection_error = f"{type(e).__name__}: {e}"
            self.last_connection_exc = e
            logger.error("connection test failed: %s", self.last_connection_error)
            return False
        finally:
            if claimed and not claim_released:
                self._breaker.release_half_open()

    def prove(self) -> None:
        """Bearer mode: show that Exchange accepts this token for this mailbox.

        One real round trip — GetFolder on the mailbox's root, which names the
        mailbox — so success means the token is valid AND opens the mailbox
        its own claims name. Blocking; run it on the worker pool. Raises
        ``ToolError``: ``auth_failed`` when Exchange rejects the token (401)
        or refuses that mailbox to it (both final for this token), and the
        mapped transient code (``upstream_unavailable``, ``throttled``, …)
        for anything else, which must not condemn the token.
        """
        self.last_connection_exc = None
        if self.test_connection():
            return
        exc = self.last_connection_exc
        if isinstance(exc, _MAILBOX_REFUSED):
            raise ToolError(
                "auth_failed",
                f"Exchange will not open this mailbox for the token ({type(exc).__name__}).",
                hint=MAILBOX_REFUSED_HINT,
            )
        if isinstance(exc, ToolError):
            raise exc
        if exc is not None:
            raise map_exception(exc)
        raise ToolError(
            "upstream_unavailable", "Exchange did not answer the token check.",
            retry_after_s=30,
        )

    # ------------------------------------------------------------- calling

    def _release_if_cancelled(self, fut: Any) -> None:
        if fut.cancelled():
            self._breaker.release_half_open()

    async def call(self, fn: Callable[[Account], Any]) -> Any:
        """Run blocking EWS work on the bounded worker pool.

        Two caps apply: the mailbox's request slots (when given) bound how
        many requests ONE mailbox has in flight — waiting here, on the event
        loop, instead of holding a worker thread — and the shared pool size
        bounds the whole process; with a worker gate, a call that cannot get
        a worker in time is shed instead of queued.
        """
        if self._slots is None and self._workers is None:
            return await self._call_on_pool(fn)
        async with AsyncExitStack() as caps:
            if self._slots is not None:
                await caps.enter_async_context(self._slots)
            if self._workers is not None:
                await caps.enter_async_context(self._workers.slot())
            return await self._call_on_pool(fn)

    async def _call_on_pool(self, fn: Callable[[Account], Any]) -> Any:
        loop = asyncio.get_running_loop()
        seq_gate, claimed = self._breaker.before_call()

        def run_on_pool() -> Any:
            claim_released = False
            try:
                if not claimed:
                    self._breaker.check_open()
                elif self._breaker.seq != seq_gate:
                    # A rejection landed while this half-open call waited for
                    # a worker: the breaker is open again. Do not probe.
                    raise self._breaker.current_error()
                t401_before = _thread_401_seq()
                tbrk_before = _thread_breaker_seq(self._breaker)
                try:
                    account = self._get_or_build_account()
                    if claimed:
                        # Half-open: prove the credentials with a real round
                        # trip first. Only that may close the breaker; a
                        # function that answers from memory must not.
                        account.root.refresh()
                        if (
                            _thread_401_seq() != t401_before
                            or _thread_breaker_seq(self._breaker) != tbrk_before
                        ):
                            # The probe saw a 401 that something swallowed.
                            err = self._handle_swallowed_auth_rejection(tbrk_before)
                            claim_released = True
                            raise err
                        if self._breaker.seq != seq_gate:
                            # Another thread was rejected during the probe.
                            raise self._breaker.current_error()
                        self._breaker.record_success()
                        claim_released = True
                    out = fn(account)
                except UnauthorizedError as exc:
                    err = self._handle_auth_rejection(exc, tbrk_before)
                    claim_released = True
                    raise err from exc
                except Exception as exc:
                    if isinstance(exc, ToolError) and exc.code == "auth_failed":
                        raise
                    if (
                        _thread_401_seq() != t401_before
                        or _thread_breaker_seq(self._breaker) != tbrk_before
                    ):
                        # A 401 was swallowed and something else failed after
                        # it: the cause is still the rejected credentials.
                        err = self._handle_swallowed_auth_rejection(tbrk_before)
                        claim_released = True
                        raise err from exc
                    raise
                if (
                    _thread_401_seq() != t401_before
                    or _thread_breaker_seq(self._breaker) != tbrk_before
                ):
                    err = self._handle_swallowed_auth_rejection(tbrk_before)
                    claim_released = True
                    raise err
                return out
            finally:
                if claimed and not claim_released:
                    self._breaker.release_half_open()

        try:
            c_fut = self._pool.submit(run_on_pool)
        except BaseException:
            if claimed:
                self._breaker.release_half_open()
            raise
        if claimed:
            c_fut.add_done_callback(self._release_if_cancelled)
        return await asyncio.wrap_future(c_fut, loop=loop)

    # ------------------------------------------------------------- folders

    def _folder_map(self, account: Account) -> Dict[str, Any]:
        """{raw_id|lower_path: Folder} cache, rebuilt every 300s (sync)."""
        now = self._now()
        if self._folder_cache and now - self._folder_cache_ts < 300:
            return self._folder_cache
        cache: Dict[str, Any] = {}
        try:
            for folder in account.msg_folder_root.walk():
                if getattr(folder, "id", None):
                    cache[folder.id] = folder
                try:
                    path = "/".join(
                        p.name for p in folder.parts[2:]  # drop root/Top of Info Store
                    ) or folder.name
                except Exception:
                    path = folder.name
                cache[path.lower()] = folder
        except UnauthorizedError:
            raise
        except Exception as e:
            logger.warning("folder walk failed: %s", e)
        if cache:
            self._folder_cache = cache
            self._folder_cache_ts = now
        return cache

    def mail_folders(self, account: Account) -> List[Tuple[str, Any]]:
        """(path, folder) of every mail folder, without deleted items, junk,
        drafts, outbox and what lies below them (sync)."""
        skip: set[str] = set()
        for attr in ("trash", "junk", "drafts", "outbox"):
            try:
                wf = getattr(account, attr, None)
                fid = getattr(wf, "id", None) if wf is not None else None
            except UnauthorizedError:
                raise  # never ask again after a rejection
            except Exception:
                fid = None
            if isinstance(fid, str) and fid:
                skip.add(fid)
        out: List[Tuple[str, Any]] = []
        for key, folder in self._folder_map(account).items():
            if key != getattr(folder, "id", None):
                continue  # the same folder under its path key
            if not str(getattr(folder, "folder_class", "") or "").startswith("IPF.Note"):
                continue
            parts = list(folder.parts)
            if any(getattr(p, "id", None) in skip for p in parts):
                continue
            out.append(("/".join(p.name for p in parts[2:]) or folder.name, folder))
        return out

    def resolve_folder(self, account: Account, ref: Optional[str], aliaser) -> Any:
        """well-known alias | folder alias (f12) | path | raw id → Folder (sync)."""
        if not ref:
            return account.inbox
        key = ref.strip()
        attr = WELL_KNOWN.get(key.lower()) or WELL_KNOWN.get(f"f:{key.lower()}")
        if attr:
            return getattr(account, attr)
        try:
            key = aliaser.resolve(key)  # f12 → raw id; raw/path pass through
        except KeyError as e:
            raise ToolError("validation", str(e.args[0] if e.args else e))
        cache = self._folder_map(account)
        folder = cache.get(key) or cache.get(key.lower())
        if folder is None:
            raise ToolError(
                "not_found", f"No folder matches {ref!r}.",
                hint="Use list_folders and pass one of its ids or paths.",
            )
        return folder


def paginate(query: Any, *, offset: int, limit: int,
             chunk: int = 50) -> Tuple[List[Any], Optional[int]]:
    """Materialize query[offset:offset+limit] in chunks (sync, raises on
    mid-iteration failure — the caller's error mapper classifies it).

    Returns ``(items, next_offset)``. NEVER calls ``QuerySet.count()`` —
    in exchangelib that iterates every matching id server-side, so a 20k
    inbox paid ~20k ids of round trips on every "read 10 emails". Whether
    another page exists comes from a one-item lookahead instead; callers
    that want an exact total use a refreshed ``folder.total_count`` (only
    valid for unfiltered listings) or a local mirror count.
    """
    offset = max(0, offset)
    limit = max(0, limit)
    lookahead = limit + 1
    items: List[Any] = []
    cursor = offset
    chunk = max(1, min(chunk, 250))
    while len(items) < lookahead:
        want = min(chunk, lookahead - len(items))
        batch = list(query[cursor:cursor + want])
        if not batch:
            break
        items.extend(batch)
        cursor += len(batch)
        if len(batch) < want:
            break
    next_offset = offset + limit if len(items) > limit else None
    return items[:limit], next_offset
