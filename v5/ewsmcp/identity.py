"""Request identity: which mailbox a tool call acts on (DESIGN.md §Mailboxes).

The server authenticates no one. In ``bearer`` mode every HTTP request carries
the caller's own EWS OAuth2 access token, issued and validated upstream, and
this module only READS it:

* The mailbox comes from the token's own claims (``EWS_TOKEN_MAILBOX_CLAIMS``,
  first match wins) — never from a header or a tool argument, so a caller
  cannot name another person's mailbox.
* ``exp`` / ``nbf`` are checked locally, so an expired token never costs
  Exchange a round trip.
* The signature is NOT checked here; Exchange checks it on every request.
  Until Exchange has accepted a token once (the token proof in
  ``sessions.py``), nothing stored for its mailbox — aliases, mirror, audit —
  is read or written on its behalf.

The raw token never appears in ``repr``, logs, audit records, or file names;
state is keyed by :func:`mailbox_key` and tokens by their fingerprint.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Optional, Sequence, Tuple

# Upper bound on an accepted bearer token. Tokens carrying group claims run
# to a few KiB; anything larger is refused before it is parsed.
MAX_TOKEN_CHARS = 16 * 1024
# Clock skew tolerated on ``exp`` / ``nbf`` between this host and the issuer.
CLOCK_LEEWAY_SECONDS = 60
DEFAULT_MAILBOX_CLAIMS = ("email", "upn", "preferred_username", "unique_name")
MAX_SUBJECT_CHARS = 256

_MAILBOX_RE = re.compile(r"^[^@\s<>\"',;]{1,64}@[^@\s<>\"',;]{1,255}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class BearerError(Exception):
    """The request's bearer token cannot identify a mailbox (HTTP 401)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Principal:
    """The mailbox a call acts on, and the credential it presents.

    ``token`` is the caller's bearer token in bearer mode and ``None`` for
    the single configured mailbox of static mode. It is excluded from
    ``repr`` and equality so it cannot leak through logs or exceptions.
    """

    mailbox: str
    token: Optional[str] = field(default=None, repr=False, compare=False)
    fingerprint: str = "static"
    expires_at: Optional[float] = None
    # Stable user identifier from EWS_TOKEN_IDENTITY_CLAIM (e.g. the SID).
    # When present it, not the address, keys the user's stored state.
    subject: Optional[str] = None

    @property
    def is_bearer(self) -> bool:
        return self.token is not None

    @property
    def key(self) -> str:
        return subject_key(self.subject) if self.subject else mailbox_key(self.mailbox)

    def expired(self, now: Optional[float] = None) -> bool:
        if self.expires_at is None:
            return False
        current = time.time() if now is None else now
        return self.expires_at <= current - CLOCK_LEEWAY_SECONDS


def mailbox_key(mailbox: str) -> str:
    """Stable, path- and key-safe name for a mailbox's stored state.

    A hash rather than the address: file names and Redis keys then carry no
    personal data and need no escaping.
    """
    return hashlib.sha256(mailbox.strip().lower().encode("utf-8")).hexdigest()[:24]


def subject_key(subject: str) -> str:
    """State key for a stable user identifier (a SID survives renames and
    address changes; the hash keeps it out of paths and Redis keys)."""
    normalized = subject.strip().lower()
    return hashlib.sha256(f"subject:{normalized}".encode("utf-8")).hexdigest()[:24]


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]


def static_principal(mailbox: str) -> Principal:
    return Principal(mailbox=mailbox.strip().lower())


def parse_claim_order(raw: Optional[str]) -> Tuple[str, ...]:
    names = tuple(p.strip() for p in (raw or "").split(",") if p.strip())
    return names or DEFAULT_MAILBOX_CLAIMS


def bearer_token_from_headers(headers: Optional[Iterable[Tuple[Any, Any]]]) -> Optional[str]:
    """Return the token of an ``Authorization: Bearer`` header (ASGI pairs)."""
    for name, value in headers or ():
        key = name.decode("latin-1") if isinstance(name, bytes) else str(name)
        if key.lower() != "authorization":
            continue
        raw = value.decode("latin-1") if isinstance(value, bytes) else str(value)
        scheme, _, credential = raw.strip().partition(" ")
        if scheme.lower() == "bearer" and credential.strip():
            return credential.strip()
        return None
    return None


def _b64url_json(segment: str) -> Any:
    if not segment or not _B64URL_RE.match(segment):
        raise BearerError("malformed")
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        return json.loads(raw.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise BearerError("malformed") from exc


def _numeric_claim(claims: dict, name: str) -> Optional[float]:
    value = claims.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BearerError(f"malformed {name}")
    return float(value)


def principal_from_bearer(
    token: str,
    *,
    claims: Sequence[str] = DEFAULT_MAILBOX_CLAIMS,
    identity_claim: Optional[str] = None,
    now: Optional[float] = None,
) -> Principal:
    """Read the mailbox and expiry from a JWT access token's payload.

    ``claims`` name where the mailbox address may be (first match wins);
    ``identity_claim``, when set, names a stable user identifier (e.g.
    ``sid``) that must be present and keys the user's stored state.

    Raises :class:`BearerError` when the token is not a JWS compact token,
    has expired, is not yet valid, names no mailbox in ``claims``, or lacks
    the identity claim.
    """
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_CHARS:
        raise BearerError("malformed")
    parts = token.split(".")
    if len(parts) != 3:
        raise BearerError("malformed")
    payload = _b64url_json(parts[1])
    if not isinstance(payload, dict):
        raise BearerError("malformed")
    current = time.time() if now is None else now
    exp = _numeric_claim(payload, "exp")
    if exp is not None and exp <= current - CLOCK_LEEWAY_SECONDS:
        raise BearerError("expired")
    nbf = _numeric_claim(payload, "nbf")
    if nbf is not None and nbf > current + CLOCK_LEEWAY_SECONDS:
        raise BearerError("not yet valid")
    subject: Optional[str] = None
    if identity_claim:
        raw_subject = payload.get(identity_claim)
        if not isinstance(raw_subject, str) or not raw_subject.strip() \
                or len(raw_subject) > MAX_SUBJECT_CHARS:
            raise BearerError("no identity claim")
        subject = raw_subject.strip()
    for claim in claims:
        value = payload.get(claim)
        if isinstance(value, str) and _MAILBOX_RE.match(value.strip()):
            return Principal(
                mailbox=value.strip().lower(),
                token=token,
                fingerprint=token_fingerprint(token),
                expires_at=exp,
                subject=subject,
            )
    raise BearerError("no mailbox claim")


# --- request scope -----------------------------------------------------------

# ASGI scope key under which the HTTP layer leaves the parsed principal. The
# MCP SDK runs stateless tool calls in a task it started at boot, so a
# ContextVar set by the HTTP handler does not reach them; the request scope
# (``request_context.request.scope``) does.
SCOPE_KEY = "ewsmcp.principal"

# Set by the transports for the duration of one tool call; read by the
# dispatcher to bind the call to its mailbox session.
CURRENT_PRINCIPAL: ContextVar[Optional[Principal]] = ContextVar(
    "ewsmcp_principal", default=None
)


def current_principal() -> Optional[Principal]:
    return CURRENT_PRINCIPAL.get()


@contextmanager
def use_principal(principal: Optional[Principal]) -> Iterator[None]:
    reset = CURRENT_PRINCIPAL.set(principal)
    try:
        yield
    finally:
        CURRENT_PRINCIPAL.reset(reset)
