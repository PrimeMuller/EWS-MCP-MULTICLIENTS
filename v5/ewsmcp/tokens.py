"""Local validation of callers' access tokens (bearer mode).

Exchange validates every token on every request. This check runs first, in
the HTTP layer, so a forged, expired or foreign token is refused with HTTP
401 before it costs Exchange anything, and the claims the server acts on
(the mailbox, the SID) are authentic from the first line that reads them:

* the signature, against the identity provider's published keys (JWKS),
  with the algorithm pinned to an allow-list — never ``none``, never HMAC,
  so a token cannot pick its own verification method;
* ``iss`` must be one of ``EWS_TOKEN_ISSUER`` and ``aud`` one of
  ``EWS_TOKEN_AUDIENCE``; ``exp`` is required; ``nbf`` / ``iat`` are
  honoured, all with the 60 s clock skew of ``identity.py``.

Keys come from ``EWS_TOKEN_JWKS_URL`` (``https://`` or ``file://``), fetched
with the same TLS trust as Exchange traffic (``REQUESTS_CA_BUNDLE`` for an
internal CA), refreshed hourly, and re-fetched at most once a minute when a
token names a key id the set does not hold — tokens with made-up key ids
cannot make the server hammer the identity provider. A verified token is
remembered until it expires, so each token costs one signature check per
process. If no keys can be obtained, tokens are refused (fail closed).
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse
from urllib.request import url2pathname

import jwt
import requests

from .config import ALLOWED_TOKEN_ALGORITHMS
from .identity import CLOCK_LEEWAY_SECONDS, BearerError, token_fingerprint

logger = logging.getLogger(__name__)

KEY_REFRESH_SECONDS = 3600  # routine refresh of the key set
UNKNOWN_KID_REFETCH_SECONDS = 60  # a token naming an unknown key: once a minute
NO_KEYS_RETRY_SECONDS = 5  # while no keys are held at all
JWKS_TIMEOUT_SECONDS = 5
MAX_VERIFIED_TOKENS = 20_000

# Most specific first: PyJWT's InvalidSignatureError is a DecodeError.
_REASONS: Tuple[Tuple[type, str], ...] = (
    (jwt.ExpiredSignatureError, "expired"),
    (jwt.ImmatureSignatureError, "not yet valid"),
    (jwt.InvalidAudienceError, "wrong audience"),
    (jwt.InvalidIssuerError, "wrong issuer"),
    (jwt.MissingRequiredClaimError, "missing required claim"),
    (jwt.InvalidAlgorithmError, "algorithm not allowed"),
    (jwt.InvalidSignatureError, "bad signature"),
    (jwt.DecodeError, "malformed"),
)


class TokenKeysUnavailable(BearerError):
    """The identity provider's signing keys could not be obtained (HTTP 503)."""


def _reason(exc: Exception) -> str:
    for kind, reason in _REASONS:
        if isinstance(exc, kind):
            return reason
    return "invalid token"


class TokenVerifier:
    """Verifies bearer tokens against one identity provider."""

    def __init__(
        self,
        *,
        jwks_url: str,
        issuers: Sequence[str],
        audiences: Sequence[str],
        algorithms: Sequence[str] = ("RS256",),
        fetch: Optional[Callable[[], Dict[str, Any]]] = None,
        clock: Callable[[], float] = time.time,
    ):
        self._url = jwks_url
        self._issuers = list(issuers)
        self._audiences = list(audiences)
        self._algorithms = [a for a in algorithms if a in ALLOWED_TOKEN_ALGORITHMS]
        if not (self._issuers and self._audiences and self._algorithms):
            raise ValueError("a token verifier needs issuers, audiences and algorithms")
        self._fetch = fetch or self._fetch_jwks
        self._clock = clock
        self._keys_lock = threading.Lock()
        self._keys: Dict[Optional[str], Any] = {}
        self._keys_at = 0.0
        self._last_attempt: Optional[float] = None
        self.fetches = 0
        self._verified: "OrderedDict[str, Tuple[Dict[str, Any], float]]" = OrderedDict()
        self._verified_lock = threading.Lock()

    # ------------------------------------------------------------------ keys

    def _fetch_jwks(self) -> Dict[str, Any]:
        if self._url.startswith("file://"):
            path = Path(url2pathname(urlparse(self._url).path))
            return json.loads(path.read_text(encoding="utf-8"))
        response = requests.get(self._url, timeout=JWKS_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json()

    def _may_fetch(self, now: float, *, unknown_kid: bool) -> bool:
        if self._last_attempt is None:
            return True
        if not self._keys:
            return now - self._last_attempt >= NO_KEYS_RETRY_SECONDS
        if now - self._keys_at >= KEY_REFRESH_SECONDS:
            return True
        return unknown_kid and now - self._last_attempt >= UNKNOWN_KID_REFETCH_SECONDS

    def _refresh(self, now: float) -> None:
        self._last_attempt = now
        self.fetches += 1
        try:
            keyset = jwt.PyJWKSet.from_dict(self._fetch())
        except Exception as exc:  # keep any keys already held
            logger.warning("token signing keys could not be fetched (%s)", type(exc).__name__)
            return
        self._keys = {key.key_id: key for key in keyset.keys}
        self._keys_at = now

    def _keys_for(self, kid: Optional[str]) -> List[Any]:
        now = self._clock()
        with self._keys_lock:
            unknown = kid is not None and kid not in self._keys
            if self._may_fetch(now, unknown_kid=unknown):
                self._refresh(now)
            if not self._keys:
                raise TokenKeysUnavailable("signing keys unavailable")
            if kid is None:  # no key id: try every key the provider publishes
                return list(self._keys.values())
            key = self._keys.get(kid)
            if key is None:
                raise BearerError("unknown signing key")
            return [key]

    # ---------------------------------------------------------- verifying

    def _remembered(self, fingerprint: str, now: float) -> Optional[Dict[str, Any]]:
        with self._verified_lock:
            entry = self._verified.get(fingerprint)
            if entry is None:
                return None
            claims, until = entry
            if until <= now:
                del self._verified[fingerprint]
                return None
            self._verified.move_to_end(fingerprint)
            return claims

    def _remember(self, fingerprint: str, claims: Dict[str, Any]) -> None:
        until = float(claims["exp"]) + CLOCK_LEEWAY_SECONDS
        with self._verified_lock:
            self._verified[fingerprint] = (claims, until)
            self._verified.move_to_end(fingerprint)
            while len(self._verified) > MAX_VERIFIED_TOKENS:
                self._verified.popitem(last=False)

    def verify(self, token: str) -> Dict[str, Any]:
        """Return the token's verified claims or raise ``BearerError``.

        Blocking on a key fetch; the HTTP layer uses :meth:`averify`.
        """
        fingerprint = token_fingerprint(token)
        cached = self._remembered(fingerprint, self._clock())
        if cached is not None:
            return cached
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise BearerError("malformed") from exc
        algorithm = header.get("alg")
        if algorithm not in self._algorithms:
            raise BearerError("algorithm not allowed")
        kid = header.get("kid")
        if kid is not None and not isinstance(kid, str):
            raise BearerError("malformed")
        claims: Optional[Dict[str, Any]] = None
        for key in self._keys_for(kid):
            try:
                claims = jwt.decode(
                    token, key.key, algorithms=[algorithm],
                    audience=self._audiences, issuer=self._issuers,
                    leeway=CLOCK_LEEWAY_SECONDS,
                    options={"require": ["exp", "iss", "aud"]},
                )
                break
            except (jwt.InvalidSignatureError, jwt.InvalidKeyError, TypeError, ValueError):
                continue  # not this key (only possible when the token names none)
            except jwt.InvalidTokenError as exc:
                raise BearerError(_reason(exc)) from exc
        if claims is None:
            raise BearerError("bad signature")
        self._remember(fingerprint, claims)
        return claims

    async def averify(self, token: str) -> Dict[str, Any]:
        """:meth:`verify` without blocking the event loop on a key fetch;
        a token already verified is answered from memory."""
        cached = self._remembered(token_fingerprint(token), self._clock())
        if cached is not None:
            return cached
        return await asyncio.to_thread(self.verify, token)


def split_setting(raw: Optional[str]) -> List[str]:
    return [part.strip() for part in (raw or "").split(",") if part.strip()]


def build_token_verifier(settings: Any) -> Optional[TokenVerifier]:
    """The verifier for bearer mode, or None when validation is left to
    Exchange (``EWS_TOKEN_VALIDATION=none``)."""
    if not getattr(settings, "bearer_mode", False):
        return None
    if getattr(settings, "ews_token_validation", "none") != "signature":
        return None
    return TokenVerifier(
        jwks_url=settings.ews_token_jwks_url,
        issuers=split_setting(settings.ews_token_issuer),
        audiences=split_setting(settings.ews_token_audience),
        algorithms=split_setting(settings.ews_token_algorithms),
    )
