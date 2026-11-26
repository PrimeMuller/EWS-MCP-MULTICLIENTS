"""ToolSpec + the dispatcher: every gate from DESIGN.md §Safety in one chain.

Gate order (policy before connectivity, nothing irreversible without two
model decisions): kill-switch → tier → mailbox binding (bearer mode: the
caller's token proven, the call bound to ITS mailbox session) → circuit →
cold / auth gate → recipient guard (argument-borne recipients on EVERY
tool, resolved recipients via the preview hook) → two-phase confirm
(content-bound + single-use when the spec supplies a preview hook) → send
rate cap → alias resolution → handler (on the EWS pool) → audit.

Handlers never take a mailbox argument: they receive a context already
bound to one mailbox (``ctx.mailbox``, ``ctx.gateway``, ``ctx.aliaser``,
``ctx.cache``, ``ctx.audit`` all belong to it).
"""

import asyncio
import dataclasses
import fnmatch
import inspect
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union

from ..confirm import (
    consume_token,
    content_hash,
    make_token,
    token_consumed,
    verify_token,
)
from .. import state
from ..errors import AUTH_FAILED_HINT, ToolError, explicit_backoff_seconds, map_exception
from ..identity import current_principal, mailbox_key
from ..sessions import CircuitState
from ..throttle import LocalRefusal, check_backoff, check_call_budget, record_backoff

TIER_RANK = {"read": 0, "draft": 1, "full": 2}
# Outcomes that prove Exchange answered (they close the upstream circuit).
_EXCHANGE_ANSWERED = frozenset({"ok", "phase1", "not_found"})
CLASS_TIER = {"read": "read", "write": "draft", "send": "full", "destructive": "full"}
ID_KEYS = frozenset({
    "id", "message_id", "draft_id", "event_id", "thread_id", "reply_to", "folder",
})
ID_LIST_KEYS = frozenset({"ids"})
RECIPIENT_KEYS = ("to", "cc", "bcc", "attendees")
UNVERIFIABLE_RECIPIENTS_KEY = "_unverifiable_recipients"

CONFIRM_TOKEN_PROPERTY = {
    "type": "string",
    "description": (
        "Two-phase confirm: omit on the first call to get a preview + token "
        "(nothing executes). Call again with identical arguments plus this "
        "token to execute. Tokens are argument-bound and expire."
    ),
}

def reset_send_rate_window() -> None:
    """Tests only."""
    state.reset_local("sends:")


def _positional_arity(fn: Callable[..., Any]) -> int:
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return 1
    return sum(
        1 for p in params
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
    )


@dataclass
class ToolSpec:
    name: str
    description: str
    side_effect_class: str  # read | write | send | destructive
    input_schema: Dict[str, Any]
    handler: Callable[..., Awaitable[Dict[str, Any]]]  # handler(ctx, **kwargs)
    requires_ews: bool = True
    confirm: Union[bool, Callable[[Dict[str, Any]], bool]] = False
    output_schema: Optional[Dict[str, Any]] = None
    # Optional async hook ``preview(ctx, kwargs) -> content dict`` that
    # resolves the REAL content the confirm token must bind (e.g. fetch the
    # draft and return its subject/recipients/body_text). When present the
    # gate hashes that content — not just the caller's literal arguments —
    # so an update_draft between preview and confirm invalidates the token
    # (TOCTOU defense), and the resolved recipients pass the recipient
    # guard. Reserved key "body_text" is hashed in full but previewed as a
    # snippet.
    preview: Optional[Callable[[Any, Dict[str, Any]], Awaitable[Dict[str, Any]]]] = None
    # Optional predicate ``notifies(kwargs, content) -> bool`` for non-send
    # tools whose calls send mail to other people on certain paths.
    notifies: Optional[
        Callable[[Dict[str, Any], Optional[Dict[str, Any]]], bool]
    ] = None
    kill_switch_hint: Optional[str] = None
    resolve_ids: bool = True
    # False only for tools that report on the server itself and touch no
    # mailbox (get_server_status): in bearer mode they are not bound to one.
    mailbox_scoped: bool = True

    def confirm_needed(self, kwargs: Dict[str, Any], ctx: Any = None) -> bool:
        """``confirm`` may be a bool, ``predicate(kwargs)``, or
        ``predicate(kwargs, ctx)`` when the answer depends on the bound
        mailbox (send_draft's idempotent replays are per mailbox)."""
        if not callable(self.confirm):
            return bool(self.confirm)
        if _positional_arity(self.confirm) >= 2:
            return bool(self.confirm(kwargs, ctx))
        return bool(self.confirm(kwargs))

    def sends_mail(
        self, kwargs: Dict[str, Any], content: Optional[Dict[str, Any]] = None
    ) -> bool:
        if self.side_effect_class == "send":
            return True
        return bool(self.notifies(kwargs, content)) if callable(self.notifies) else False

    def public_schema(self) -> Dict[str, Any]:
        schema = {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }
        if self.confirm is not False:
            props = schema["inputSchema"].setdefault("properties", {})
            props.setdefault("confirm_token", dict(CONFIRM_TOKEN_PROPERTY))
        return schema


@dataclass
class Context:
    """What a handler works with.

    In static mode one Context serves the single configured mailbox. In
    bearer mode the process-wide Context holds the session ``pool`` and
    :meth:`bind` derives, per call, a Context whose gateway, aliases,
    mirror, audit chain and circuit all belong to the caller's mailbox.
    ``registry``, ``counters`` and ``started_at`` are shared by reference.
    """

    settings: Any
    gateway: Any
    manager: Any  # ConnectionManager | None
    aliaser: Any
    audit: Any
    cache: Any = None  # CacheStore | None (None = cache disabled/broken)
    sync: Any = None  # SyncEngine | None
    semantic: Any = None  # SemanticIndex adapter | None
    lease: Any = None  # SyncLease | None
    registry: Dict[str, ToolSpec] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    counters: Dict[str, int] = field(default_factory=dict)
    mailbox: str = ""  # the mailbox this context acts on ("" = not bound)
    pool: Any = None  # SessionPool (bearer mode)
    session: Any = None  # MailboxSession this context is bound to
    token_verifier: Any = None  # tokens.TokenVerifier (bearer mode)
    circuit: CircuitState = field(default_factory=CircuitState)

    def __post_init__(self) -> None:
        if not self.mailbox and self.pool is None:
            self.mailbox = getattr(self.settings, "ews_email", None) or ""

    @property
    def _circuit_failures(self) -> int:
        return self.circuit.failures

    @_circuit_failures.setter
    def _circuit_failures(self, value: int) -> None:
        self.circuit.failures = value

    @property
    def _circuit_open_until(self) -> float:
        return self.circuit.open_until

    @_circuit_open_until.setter
    def _circuit_open_until(self, value: float) -> None:
        self.circuit.open_until = value

    def bump(self, key: str) -> None:
        self.counters[key] = self.counters.get(key, 0) + 1

    @property
    def state_key(self) -> str:
        """Key of this mailbox's shared state (send windows, budgets,
        back-offs): the session's key when bound, else from the address."""
        if self.session is not None:
            return self.session.key
        return mailbox_key(self.mailbox)

    def bind(self, lease: Any) -> "Context":
        """A per-call Context acting on ``lease``'s mailbox and nothing else."""
        session = lease.session
        return dataclasses.replace(
            self,
            gateway=lease.gateway,
            manager=None,
            aliaser=session.aliaser,
            audit=session.audit,
            cache=session.cache,
            sync=session.syncer,
            lease=None,
            semantic=None,
            mailbox=session.mailbox,
            session=session,
            circuit=session.circuit,
        )


def _split(raw: str) -> List[str]:
    return [p.strip().lower() for p in (raw or "").split(",") if p.strip()]


def _normalise_recipient(raw: str) -> Optional[str]:
    s = raw.strip()
    if "<" in s or ">" in s:
        if s.count("<") != 1 or s.count(">") != 1 or not s.endswith(">"):
            return None
        s = s[s.index("<") + 1 : -1].strip()
    s = s.lower()
    if not s or any(ch.isspace() for ch in s) or "<" in s or ">" in s:
        return None
    parts = s.split("@")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    return s


def _recipients(kwargs: Dict[str, Any], *, strict: bool = False) -> List[str]:
    out: List[str] = []
    for key in RECIPIENT_KEYS:
        value = kwargs.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            items = [value]
        elif isinstance(value, list):
            items = value
        else:
            raise ToolError(
                "validation",
                f"invalid {key!r}: expected string or list of strings",
            )
        for item in items:
            if not isinstance(item, str):
                raise ToolError(
                    "validation",
                    f"invalid recipient in {key!r}: expected string",
                )
            addr = _normalise_recipient(item)
            if addr is None:
                if strict:
                    raise ToolError(
                        "validation",
                        f"invalid recipient in {key!r}: {item!r}",
                    )
                continue
            out.append(addr)
    return out


def _recipient_guard(ctx: Context, kwargs: Dict[str, Any]) -> None:
    deny = _split(ctx.settings.ews_recipient_denylist)
    allow = _split(ctx.settings.ews_recipient_allowlist)
    has_lists = bool(deny or allow)
    addrs = _recipients(kwargs, strict=has_lists)
    if not has_lists:
        return
    for r in addrs:
        if any(fnmatch.fnmatch(r, p) for p in deny):
            raise ToolError("recipient_blocked",
                            f"recipient '{r}' is denylisted (EWS_RECIPIENT_DENYLIST)")
        if allow and not any(fnmatch.fnmatch(r, p) for p in allow):
            raise ToolError("recipient_blocked",
                            f"recipient '{r}' is not allowlisted (EWS_RECIPIENT_ALLOWLIST)")
    unverifiable = kwargs.get(UNVERIFIABLE_RECIPIENTS_KEY, 0)
    if (
        isinstance(unverifiable, int)
        and not isinstance(unverifiable, bool)
        and unverifiable > 0
    ):
        who = (
            "one recipient has"
            if unverifiable == 1
            else f"{unverifiable} recipients have"
        )
        raise ToolError(
            "recipient_blocked",
            f"cannot verify recipients: {who} no address that can be checked "
            "against the recipient lists",
        )


def _kill_switch_guard(ctx: Context, spec: ToolSpec) -> None:
    if ctx.settings.send_enabled:
        return
    if spec.side_effect_class == "send":
        raise ToolError(
            "kill_switch",
            f"{spec.name} is blocked: SEND_ENABLED=false on this server.",
            hint=(
                spec.kill_switch_hint
                or "Create a draft instead; sending requires the operator "
                "to flip SEND_ENABLED."
            ),
        )
    raise ToolError(
        "kill_switch",
        f"{spec.name} is blocked: notifying attendees sends mail and "
        "SEND_ENABLED=false on this server.",
        hint=(
            spec.kill_switch_hint
            or "Run without notifying attendees, or have the operator flip "
            "SEND_ENABLED."
        ),
    )


SEND_WINDOW_SECONDS = 3600
GLOBAL_SEND_KEY = "sends:*"
SendSlots = List[Tuple[str, str]]  # (window key, slot id) reserved by one call


def _mailbox_send_key(ctx: Context) -> str:
    return f"sends:{ctx.state_key}"


def _send_windows(ctx: Context) -> List[Tuple[str, int, str]]:
    """(window key, cap, label) for every send cap that applies."""
    windows = []
    cap = int(ctx.settings.ews_max_sends_per_hour or 0)
    if cap > 0:
        windows.append((_mailbox_send_key(ctx), cap, f"{cap}/hour"))
    global_cap = int(getattr(ctx.settings, "ews_global_max_sends_per_hour", 0) or 0)
    if global_cap > 0:
        windows.append((GLOBAL_SEND_KEY, global_cap, f"{global_cap}/hour for all mailboxes"))
    return windows


def _reserve_send_slot(ctx: Context) -> Optional[SendSlots]:
    """Reserve one send in every applicable window (this mailbox's, and the
    whole server's), all or nothing. Raises ``rate_capped`` when any is full."""
    now = time.time()
    store = state.backend()
    taken: SendSlots = []
    for key, cap, label in _send_windows(ctx):
        slot, retry = store.reserve(key, limit=cap, window_s=SEND_WINDOW_SECONDS, now=now)
        if slot is None:
            _release_send_slot(taken)
            raise ToolError(
                "rate_capped",
                f"send rate cap reached ({label})",
                retry_after_s=max(1, int(retry or 1)),
            )
        taken.append((key, slot))
    return taken or None


def _release_send_slot(slots: Optional[SendSlots]) -> None:
    store = state.backend()
    for key, slot in slots or ():
        store.release(key, slot)


def send_slots_used(ctx: Context) -> int:
    """Sends counted against ``ctx``'s mailbox in the current window."""
    return state.backend().window_count(
        _mailbox_send_key(ctx), window_s=SEND_WINDOW_SECONDS, now=time.time())


def _rate_guard(ctx: Context) -> None:
    _reserve_send_slot(ctx)


def _external_recipients(ctx: Context, source: Dict[str, Any]) -> List[str]:
    own = ctx.mailbox.rsplit("@", 1)[-1].lower()
    return sorted({
        r for r in _recipients(source) if r.rsplit("@", 1)[-1] != own
    })


VERIFIED_CONTENT_HASH_ARG = "_verified_content_hash"

_CONFIRM_HINTS = {
    "expired": "Token expired — call again WITHOUT confirm_token for a fresh preview.",
    "stale": ("The content changed since the preview (or the arguments differ) — "
              "re-preview to get a token bound to the current content."),
    "consumed": "This token was already used once — re-preview for a fresh one.",
    "bad_signature": "Invalid confirmation token.",
    "malformed": "Malformed confirmation token.",
}


def preview_content_hash(content: Dict[str, Any]) -> str:
    """Canonical hash of a preview hook's resolved content dict."""
    body_text = content.get("body_text")
    parts: List[Any] = [
        content.get("subject") or "",
        sorted(content.get("to") or []),
        sorted(content.get("cc") or []),
        sorted(content.get("bcc") or []),
        body_text if isinstance(body_text, str) else "",
        content.get("_attachments") or content.get("attachments") or [],
    ]
    body_html = content.get("_body_html")
    if isinstance(body_html, str) and body_html:
        parts.append(body_html)
    return content_hash(*parts)


def _accepts_kwarg(handler: Callable[..., Any], name: str) -> bool:
    try:
        params = inspect.signature(handler).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.name == name for p in params)


async def _confirm_gate(ctx: Context, spec: ToolSpec, kwargs: Dict[str, Any],
                        token: Optional[str]) -> Optional[Dict[str, Any]]:
    """Returns the phase-1 response, or None when execution may proceed.

    With ``spec.preview`` the token binds the RESOLVED content (refetched and
    re-verified at phase 2 — the TOCTOU defense) and the resolved recipients
    pass the recipient guard; without it the caller's literal arguments are
    hashed. Verified tokens are single-use.
    """
    secret = ctx.settings.send_confirm_secret
    content: Optional[Dict[str, Any]] = None
    if spec.preview is not None:
        content = await spec.preview(ctx, dict(kwargs))
        if spec.sends_mail(kwargs, content):
            _kill_switch_guard(ctx, spec)
        _recipient_guard(ctx, content)  # the draft/event's REAL recipients
        chash = preview_content_hash(content)
        target_id = str(kwargs.get("draft_id") or kwargs.get("event_id")
                        or kwargs.get("id") or "-")
    else:
        chash = content_hash(dict(kwargs))
        target_id = "-"
    if not token:
        tok = make_token(
            mailbox=ctx.mailbox, action=spec.name, target_id=target_id,
            chash=chash, ttl_seconds=ctx.settings.confirm_ttl_seconds, secret=secret,
        )
        if content is not None:
            preview = {
                k: v for k, v in content.items()
                if k != "body_text" and not k.startswith("_")
            }
            body_text = content.get("body_text")
            if isinstance(body_text, str):
                preview["body_snippet"] = body_text[:1000]
        else:
            preview = {
                k: (v[:200] if k in ("body", "message", "comment") and isinstance(v, str) else v)
                for k, v in kwargs.items()
            }
        external = _external_recipients(ctx, content if content is not None else kwargs)
        response: Dict[str, Any] = {
            "ok": True,
            "requires_confirmation": True,
            "message": (f"{spec.name} previewed — NOTHING executed. Call again "
                        "with the same arguments plus confirm_token to proceed."),
            "preview": preview,
            **tok,
        }
        if external:
            response["warnings"] = [f"external recipients: {', '.join(external)}"]
        return response
    ok, reason = verify_token(
        token, mailbox=ctx.mailbox, action=spec.name,
        target_id=target_id, chash=chash, secret=secret,
    )
    if not ok:
        raise ToolError(
            "confirm_invalid",
            f"confirm_token rejected ({reason})",
            hint=_CONFIRM_HINTS.get(
                reason,
                f"Call {spec.name} again WITHOUT confirm_token for a fresh preview."),
        )
    if token_consumed(token):
        raise ToolError(
            "confirm_invalid",
            "confirm_token rejected (consumed)",
            hint=_CONFIRM_HINTS["consumed"],
        )
    reserved_slot: Optional[SendSlots] = None
    if spec.sends_mail(kwargs, content):
        reserved_slot = _reserve_send_slot(ctx)
    if not consume_token(token):
        _release_send_slot(reserved_slot)
        raise ToolError(
            "confirm_invalid",
            "confirm_token rejected (consumed)",
            hint=_CONFIRM_HINTS["consumed"],
        )
    if spec.preview is not None and _accepts_kwarg(spec.handler, VERIFIED_CONTENT_HASH_ARG):
        kwargs[VERIFIED_CONTENT_HASH_ARG] = chash
    return None


async def mint_token(ctx: Context, spec: ToolSpec, kwargs: Dict[str, Any]) -> str:
    """Server-side pre-confirmation (e.g. a human-approved queue item).

    Mirrors ``_confirm_gate``'s binding exactly: preview-hook specs get a
    token bound to the resolved content, others to the literal arguments.
    """
    clean = {
        k: v for k, v in kwargs.items()
        if k not in ("confirm_token", VERIFIED_CONTENT_HASH_ARG)
    }
    if spec.preview is not None:
        content = await spec.preview(ctx, dict(clean))
        chash = preview_content_hash(content)
        target_id = str(clean.get("draft_id") or clean.get("event_id")
                        or clean.get("id") or "-")
    else:
        chash = content_hash(dict(clean))
        target_id = "-"
    return make_token(
        mailbox=ctx.mailbox, action=spec.name, target_id=target_id,
        chash=chash,
        ttl_seconds=ctx.settings.confirm_ttl_seconds,
        secret=ctx.settings.send_confirm_secret,
    )["confirm_token"]


def _resolve_ids(ctx: Context, kwargs: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(kwargs)
    try:
        for key, value in kwargs.items():
            if key in ID_KEYS and isinstance(value, str) and key != "folder":
                out[key] = ctx.aliaser.resolve(value)
            elif key in ID_LIST_KEYS and isinstance(value, list):
                out[key] = [ctx.aliaser.resolve(v) if isinstance(v, str) else v
                            for v in value]
    except KeyError as e:
        raise ToolError("validation", str(e.args[0] if e.args else e))
    return out


async def dispatch(ctx: Context, spec: ToolSpec, kwargs: Dict[str, Any],
                   transport: str = "-") -> Dict[str, Any]:
    start = time.time()
    outcome = "ok"
    # confirm_token and _verified_content_hash are dispatcher vocabulary,
    # never caller-supplied handler arguments — strip unconditionally before
    # any gate runs so non-confirm handlers can't receive confirm_token and a
    # caller can never spoof _verified_content_hash.
    kwargs = dict(kwargs)
    confirm_token = kwargs.pop("confirm_token", None)
    kwargs.pop(VERIFIED_CONTENT_HASH_ARG, None)
    binding = AsyncExitStack()
    pool = ctx.pool
    local_refusal = False  # refused by our own limits: Exchange never saw it
    try:
        # Kill-switch (policy precedes connectivity)
        if spec.sends_mail(kwargs):
            _kill_switch_guard(ctx, spec)
        # Tier
        tier = ctx.settings.ews_capability_tier
        need = CLASS_TIER.get(spec.side_effect_class, "draft")
        if TIER_RANK[need] > TIER_RANK.get(tier, 2):
            raise ToolError(
                "tier_blocked",
                f"{spec.name} needs capability tier '{need}'; server runs '{tier}'.",
            )
        # Process-wide upstream circuit (bearer mode): Exchange is failing
        # for everyone, so nothing is sent — not even a token proof.
        if pool is not None and spec.requires_ews:
            wait = pool.upstream_retry_after()
            if wait is not None:
                raise LocalRefusal(
                    "upstream_unavailable",
                    "Exchange is failing for every mailbox; calls are paused.",
                    retry_after_s=wait,
                )
        # Mailbox binding (bearer mode): prove the caller's token, then act
        # on ITS mailbox only. From here on ``ctx`` is the bound context, so
        # every later gate, the handler, and the audit record belong to it.
        if pool is not None and ctx.session is None and spec.mailbox_scoped:
            lease = await binding.enter_async_context(pool.bind(current_principal()))
            ctx = ctx.bind(lease)
        # Circuit breaker (this mailbox's own)
        now = time.time()
        if spec.requires_ews and ctx._circuit_open_until > now:
            raise LocalRefusal(
                "upstream_unavailable",
                "circuit open after repeated upstream failures",
                retry_after_s=int(ctx._circuit_open_until - now),
            )
        # Exchange protection: a back-off Exchange stated for this mailbox,
        # then the mailbox's call budget (refusals cost Exchange nothing).
        if spec.requires_ews:
            check_backoff(ctx, now)
            check_call_budget(ctx, now)
        # Cold / auth gate
        if spec.requires_ews and ctx.manager is not None:
            mstate = ctx.manager.state
            if mstate == "auth_failed":
                st = ctx.manager.status()
                permanent = bool(st.get("auth_permanent"))
                retry_after = None if permanent else st.get("next_retry_in_s")
                rejections = st.get("auth_rejections")
                suffix = (
                    f" ({rejections} rejection(s); permanently open until restart)"
                    if permanent and rejections is not None
                    else f" ({rejections} rejection(s))"
                    if rejections is not None
                    else ""
                )
                raise ToolError(
                    "auth_failed",
                    f"Exchange rejected configured credentials{suffix}.",
                    hint=AUTH_FAILED_HINT,
                    retry_after_s=retry_after,
                )
            if mstate == "connecting":
                st = ctx.manager.status()
                raise ToolError(
                    "upstream_unavailable",
                    f"Exchange connection still warming up (attempt {st['attempts']}; "
                    f"last error: {st['last_error'] or 'none yet'})",
                    hint="Check /readyz or call get_server_status.",
                    retry_after_s=st.get("next_retry_in_s"),
                )
        # Recipient policy — every tool whose arguments carry recipients
        # (create_draft/update_draft/create_event/…), not just send class:
        # drafts and events are how mail actually acquires recipients.
        _recipient_guard(ctx, kwargs)
        # Two-phase confirm (content-bound via spec.preview when present,
        # otherwise the caller's literal args; single-use either way)
        if spec.confirm_needed(kwargs, ctx):
            phase1 = await _confirm_gate(ctx, spec, kwargs, confirm_token)
            if phase1 is not None:
                outcome = "phase1"
                return phase1
        # Send rate cap — unconfirmed sends (confirmed sends already reserved
        # their slot inside _confirm_gate before consume_token)
        elif spec.sends_mail(kwargs):
            _rate_guard(ctx)
        # Window mirror (bearer mode): the user is active, so refresh their
        # mirror in the background when due. Never waits on it; reads stay
        # live until it is ready.
        if ctx.session is not None and spec.requires_ews:
            refresh = getattr(ctx.sync, "maybe_refresh", None)
            if callable(refresh):
                refresh(ctx.gateway)
        # Alias → raw ids
        if spec.resolve_ids:
            kwargs = _resolve_ids(ctx, kwargs)
        result = await spec.handler(ctx, **kwargs)
        ctx._circuit_failures = 0
        if isinstance(result, dict):
            result.setdefault("ok", True)
        return result
    except ToolError as err:
        outcome = err.code
        local_refusal = isinstance(err, LocalRefusal)
        return err.to_dict()
    except (TypeError, ValueError) as exc:
        # Handler contract violations (wrong kwarg names/types) are caller
        # errors, not upstream failures — never report them as 502s.
        outcome = "validation"
        return ToolError(
            "validation", f"{type(exc).__name__}: {exc}",
            hint="Check the argument names and types against the tool schema.",
        ).to_dict()
    except Exception as exc:
        err = map_exception(exc)
        outcome = err.code
        if err.code in ("upstream_unavailable", "upstream_error", "throttled"):
            ctx._circuit_failures += 1
            if ctx._circuit_failures >= ctx.settings.circuit_failure_threshold:
                ctx._circuit_open_until = time.time() + ctx.settings.circuit_open_seconds
                ctx._circuit_failures = 0
        if err.code == "throttled":
            # Exchange stated how long this mailbox must wait: hold every
            # further call for it here instead of letting them hit Exchange.
            wait = explicit_backoff_seconds(exc)
            if wait:
                record_backoff(ctx, wait)
        return err.to_dict()
    finally:
        if pool is not None and spec.requires_ews and not local_refusal:
            if outcome == "upstream_unavailable":
                pool.note_upstream(False)
            elif outcome in _EXCHANGE_ANSWERED:
                pool.note_upstream(True)
        ctx.bump(f"tool.{spec.name}")
        if outcome != "ok":
            ctx.bump(f"err.{outcome}")
        detail = None
        if spec.side_effect_class in ("send", "destructive"):
            detail = {k: kwargs.get(k)
                      for k in ("to", "cc", "subject", "id", "ids",
                                "draft_id", "event_id")
                      if kwargs.get(k) is not None}
        # Audit writes (file append + chain hash) run off the event loop —
        # one slow disk must not stall every concurrent request.
        await asyncio.to_thread(
            ctx.audit.record,
            tool=spec.name, side_effect_class=spec.side_effect_class,
            outcome=outcome, latency_ms=int((time.time() - start) * 1000),
            transport=transport, detail=detail,
        )
        await binding.aclose()  # releases the mailbox session, if bound
