"""Gateway probe/reset behavior — the false-warm fix (Phase B critical #4).

``inbox.total_count`` is a cached property after its first read, so probing
it reported warm forever (the /readyz lie). The probe must round-trip every
call, and reset() must evict exchangelib's protocol cache so a wedged
session actually renegotiates auth.
"""

import logging
from types import SimpleNamespace as NS
from unittest.mock import MagicMock

import pytest
import requests
from conftest import make_settings
from exchangelib.errors import UnauthorizedError
from exchangelib.protocol import CachingProtocol
from exchangelib.version import EXCHANGE_2016, Version

from ewsmcp.errors import ToolError
from ewsmcp.gateway import client as client_mod
from ewsmcp.gateway.client import EWSGateway, RejectingFaultTolerance
from ewsmcp.ids import get_aliaser


def _gateway_with_mock_account():
    gw = EWSGateway(make_settings())
    account = MagicMock(name="account")
    gw._account = account
    return gw, account


def test_mail_folders_skips_other_classes_and_excluded_trees(monkeypatch):
    gw, account = _gateway_with_mock_account()
    root, top = NS(id="root", name="root"), NS(id="top", name="Top")

    def folder(raw_id, name, parents=(), cls="IPF.Note"):
        made = NS(id=raw_id, name=name, folder_class=cls)
        made.parts = [root, top, *parents, made]
        return made

    inbox = folder("in", "Inbox")
    child = folder("ch", "Projects", [inbox])
    trash = folder("tr", "Deleted")
    below_trash = folder("bt", "Old", [trash])
    calendar = folder("ca", "Calendar", cls="IPF.Appointment")
    account.trash, account.junk = trash, NS(id="ju")
    account.drafts, account.outbox = NS(id="dr"), NS(id="ou")
    monkeypatch.setattr(gw, "_folder_map", lambda _a: {
        "in": inbox, "inbox": inbox, "ch": child, "tr": trash, "bt": below_trash, "ca": calendar,
    })
    assert [(p, f.id) for p, f in gw.mail_folders(account)] == [
        ("Inbox", "in"), ("Inbox/Projects", "ch"),
    ]


def test_probe_round_trips_on_every_call():
    gw, account = _gateway_with_mock_account()
    assert gw.test_connection() is True
    assert gw.test_connection() is True
    assert account.root.refresh.call_count == 2  # not a cached-property read


def test_probe_failure_is_reported_not_cached():
    gw, account = _gateway_with_mock_account()
    account.root.refresh.side_effect = ConnectionError("front door down")
    assert gw.test_connection() is False
    assert "front door down" in gw.last_connection_error
    account.root.refresh.side_effect = None
    assert gw.test_connection() is True  # recovery observed immediately
    assert gw.last_connection_error is None


def test_reset_evicts_own_protocol_entry_and_folder_cache():
    gw, account = _gateway_with_mock_account()
    key = ("https://ews.example/EWS/Exchange.asmx", "creds-of-this-gateway")
    gw._cache_key = key
    CachingProtocol._protocol_cache[key] = (account.protocol, None)
    gw._folder_cache = {"path": object()}
    gw._folder_cache_ts = 123.0
    try:
        gw.reset()
        assert gw._account is None
        account.protocol.close.assert_called_once()
        # Without this the wedged Protocol would come straight back.
        assert key not in CachingProtocol._protocol_cache
        assert gw._folder_cache == {}
        assert gw._folder_cache_ts == 0.0
    finally:
        CachingProtocol._protocol_cache.pop(key, None)


def test_reset_survives_close_failures_and_never_clears_other_protocols():
    gw, account = _gateway_with_mock_account()
    account.protocol.close.side_effect = OSError("socket gone")
    other_key = ("https://ews.example/EWS/Exchange.asmx", "someone-else")
    other = MagicMock(name="other-protocol")
    CachingProtocol._protocol_cache[other_key] = (other, None)
    try:
        gw.reset()  # must not raise
        assert gw._account is None
        assert CachingProtocol._protocol_cache[other_key] == (other, None)
        other.close.assert_not_called()
    finally:
        CachingProtocol._protocol_cache.pop(other_key, None)


def _no_network_version(monkeypatch):
    monkeypatch.setattr(
        Version, "guess",
        classmethod(lambda cls, protocol, api_version_hint=None: Version(build=EXCHANGE_2016)),
    )


def test_bearer_gateway_presents_the_callers_token_and_nothing_else(monkeypatch):
    from ewsmcp.identity import Principal

    _no_network_version(monkeypatch)
    token = "eyJ.header-payload.sig"
    principal = Principal(mailbox="alice@corp.example", token=token, fingerprint="f1")
    gw = EWSGateway(make_settings(), principal=principal)
    try:
        account = gw._build_account()
        assert account.primary_smtp_address == "alice@corp.example"
        assert account.protocol.auth_type == client_mod.BEARER
        assert token not in repr(account.protocol.credentials)
        session = account.protocol.create_session()
        prepared = requests.Request("POST", "https://ews.example/EWS/Exchange.asmx").prepare()
        session.auth(prepared)
        assert prepared.headers["Authorization"] == f"Bearer {token}"
        session.close()
        # Bearer credentials never fall back to the configured service account.
        assert account.protocol.credentials.username == "alice@corp.example"
    finally:
        gw.close()


def test_two_tokens_get_two_protocols_and_closing_one_spares_the_other(monkeypatch):
    from ewsmcp.identity import Principal

    _no_network_version(monkeypatch)
    settings = make_settings()
    gw_a = EWSGateway(settings, principal=Principal(
        mailbox="alice@corp.example", token="a.b.c", fingerprint="fa"))
    gw_b = EWSGateway(settings, principal=Principal(
        mailbox="bob@corp.example", token="d.e.f", fingerprint="fb"))
    try:
        proto_a = gw_a._build_account().protocol
        proto_b = gw_b._build_account().protocol
        assert proto_a is not proto_b
        assert gw_a._cache_key in CachingProtocol._protocol_cache
        gw_a.close()
        assert gw_a._cache_key not in CachingProtocol._protocol_cache
        assert CachingProtocol._protocol_cache[gw_b._cache_key][0] is proto_b
    finally:
        gw_a.close()
        gw_b.close()


def test_bearer_gateway_latches_after_a_single_rejection():
    from ewsmcp.identity import Principal

    gw = EWSGateway(make_settings(ews_auth_max_rejections=3), principal=Principal(
        mailbox="alice@corp.example", token="a.b.c", fingerprint="fa"))
    try:
        assert gw.rejected is False
        gw._breaker.record_rejection()
        assert gw.rejected is True
        with pytest.raises(ToolError) as info:
            gw._breaker.check_open()
        assert info.value.code == "auth_failed"
    finally:
        gw.close()


def test_static_gateway_keeps_the_configured_rejection_budget():
    gw = EWSGateway(make_settings(ews_auth_max_rejections=3))
    try:
        gw._breaker.record_rejection()
        assert gw.rejected is False
    finally:
        gw.close()


def test_learned_version_is_handed_to_new_gateways_as_a_copy(monkeypatch):
    from ewsmcp.identity import Principal

    def no_guess(cls, protocol, api_version_hint=None):
        raise AssertionError("a known version must skip the version probe")

    monkeypatch.setattr(Version, "guess", classmethod(no_guess))
    known = Version(build=EXCHANGE_2016)
    gw = EWSGateway(make_settings(), principal=Principal(
        mailbox="alice@corp.example", token="a.b.c", fingerprint="fa"), version=known)
    try:
        assert gw.learned_version() is None  # nothing negotiated yet
        account = gw._get_or_build_account()
        assert account.protocol.version == known
        assert account.protocol.config.version is not known
        assert gw.learned_version() == known
    finally:
        gw.close()


def test_request_slots_cap_one_mailbox_and_queue_on_the_event_loop():
    import asyncio
    import threading

    async def scenario():
        slots = asyncio.Semaphore(1)
        gw = EWSGateway(make_settings(ews_max_concurrency=4), request_slots=slots)
        gw._account = MagicMock(name="account")
        active, peak = [0], [0]
        guard = threading.Lock()

        def work(_account):
            with guard:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            import time as _t
            _t.sleep(0.05)
            with guard:
                active[0] -= 1
            return True

        try:
            results = await asyncio.gather(*(gw.call(work) for _ in range(4)))
        finally:
            gw.close()
        return results, peak[0]

    results, peak = asyncio.run(scenario())
    assert results == [True] * 4
    assert peak == 1


def test_gateways_can_share_one_worker_pool():
    from concurrent.futures import ThreadPoolExecutor

    pool = ThreadPoolExecutor(max_workers=2)
    try:
        gw1 = EWSGateway(make_settings(), executor=pool)
        gw2 = EWSGateway(make_settings(), executor=pool)
        assert gw1._pool is pool and gw2._pool is pool
        gw1.close()
        # Closing one gateway must not shut down the shared pool.
        assert pool.submit(lambda: 7).result(timeout=5) == 7
        gw2.close()
    finally:
        pool.shutdown(wait=True)


def test_resolve_folder_distinguished_names_and_unknown_not_found(tmp_path, monkeypatch):
    gw, account = _gateway_with_mock_account()
    account.sent = NS(id="F-SENT", name="Sent Items")
    account.trash = NS(id="F-TRASH", name="Deleted Items")
    account.junk = NS(id="F-JUNK", name="Junk Email")
    monkeypatch.setattr(gw, "_folder_map", lambda _a: {})
    aliaser = get_aliaser(str(tmp_path / "aliases"))

    for ref, expected in (
        ("sentitems", account.sent),
        ("SentItems", account.sent),
        ("f:sentitems", account.sent),
        ("deleteditems", account.trash),
        ("DeletedItems", account.trash),
        ("f:deleteditems", account.trash),
        ("junkemail", account.junk),
        ("JunkEmail", account.junk),
        ("f:junkemail", account.junk),
    ):
        assert gw.resolve_folder(account, ref, aliaser) is expected

    for unknown in ("nonexistent_folder", "msgfolderroot"):
        with pytest.raises(ToolError) as excinfo:
            gw.resolve_folder(account, unknown, aliaser)
        assert excinfo.value.code == "not_found"
        assert "list_folders" in (excinfo.value.hint or "")


def test_mail_folders_handles_missing_well_known_folders_and_none_ids(monkeypatch):
    gw = EWSGateway(make_settings())
    root = NS(id=None, name="root")
    top = NS(id=None, name="Top of Information Store")
    inbox = NS(id="in", name="Inbox", folder_class="IPF.Note")
    inbox.parts = [root, top, inbox]
    drafts = NS(id="dr", name="Drafts", folder_class="IPF.Note")
    drafts.parts = [root, top, drafts]

    class _PartialAccount:
        trash = None
        outbox = NS(id=None)

        def __init__(self):
            self.drafts = drafts

        @property
        def junk(self):
            raise RuntimeError("ErrorFolderNotFound")

    account = _PartialAccount()
    monkeypatch.setattr(gw, "_folder_map", lambda _a: {"in": inbox, "dr": drafts})
    assert [(p, f.id) for p, f in gw.mail_folders(account)] == [("Inbox", "in")]


def test_build_account_uses_rejecting_fault_tolerance_in_every_mode(monkeypatch, caplog):
    captured = []
    monkeypatch.setattr(client_mod, "Account", lambda **kw: captured.append(kw) or kw)
    for forced in (None, "basic"):
        caplog.clear()
        with caplog.at_level(logging.INFO, logger="ewsmcp.gateway.client"):
            gw = EWSGateway(
                make_settings(
                    ews_server_url="https://ews.example.com/EWS/Exchange.asmx",
                    ews_email="user@example.com",
                    ews_auth_type_force=forced,
                    ews_retry_max_wait_seconds=180,
                )
            )
            gw._build_account()
        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings == []
        infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
        if forced is None:
            assert infos == []
        else:
            assert len(infos) == 1
            assert "basic" in infos[0]
            assert "user@example.com" not in infos[0]
            assert "ews.example.com" not in infos[0]
    assert len(captured) == 2
    for built, expected_auth in zip(captured, (None, "basic")):
        policy = built["config"].retry_policy
        assert isinstance(policy, RejectingFaultTolerance)
        assert policy.max_wait == 180
        assert policy.configured_auth_type == expected_auth


def test_second_gateway_replaces_cached_protocol_policy_on_real_objects(monkeypatch):
    # Account() asks the server for its version; answer locally so the real
    # Account/Protocol objects are built without touching the network.
    monkeypatch.setattr(
        Version, "guess",
        classmethod(lambda cls, protocol, api_version_hint=None: Version(build=EXCHANGE_2016)),
    )
    CachingProtocol.clear_cache()
    try:
        settings = make_settings(
            ews_server_url="https://ews.example.com/EWS/Exchange.asmx",
            ews_email="user@example.com",
            ews_username="svc-user",
            ews_password="secret",
            ews_auth_type_force="basic",
        )
        gw1 = EWSGateway(settings)
        acc1 = gw1._build_account()
        policy1 = acc1.protocol.retry_policy
        assert isinstance(policy1, RejectingFaultTolerance)

        gw2 = EWSGateway(settings)
        acc2 = gw2._build_account()
        policy2 = acc2.protocol.retry_policy
        assert acc2.protocol is acc1.protocol
        assert isinstance(policy2, RejectingFaultTolerance)
        assert policy2 is not policy1

        resp = requests.Response()
        resp.status_code = 401
        resp._content = b"401 Unauthorized"
        resp.url = settings.ews_server_url
        with pytest.raises(UnauthorizedError) as exc_info:
            policy2.raise_response_errors(resp)
        assert not hasattr(exc_info.value, "_auth_rejection_recorded")
        assert gw1.auth_status()["rejections"] == 0
        assert gw2.auth_status()["rejections"] == 1
    finally:
        CachingProtocol.clear_cache()


def _bearer_gateway_with_root(refresh):
    from ewsmcp.identity import Principal

    gw = EWSGateway(make_settings(), principal=Principal(
        mailbox="alice@corp.example", token="a.b.c", fingerprint="fa"))
    gw._account = NS(root=NS(refresh=refresh), protocol=MagicMock(name="protocol"))
    return gw


def test_prove_succeeds_with_one_round_trip():
    calls = []
    gw = _bearer_gateway_with_root(lambda: calls.append(1))
    gw.prove()
    assert calls == [1]
    gw.close()


@pytest.mark.parametrize("error_name", [
    "ErrorNonExistentMailbox", "ErrorAccessDenied", "ErrorInvalidSmtpAddress",
])
def test_prove_treats_a_refused_mailbox_as_final(error_name):
    import exchangelib.errors as el_errors

    def refuse():
        raise getattr(el_errors, error_name)("nope")

    gw = _bearer_gateway_with_root(refuse)
    with pytest.raises(ToolError) as info:
        gw.prove()
    assert info.value.code == "auth_failed"
    assert "EWS_TOKEN_MAILBOX_CLAIMS" in info.value.hint
    gw.close()


def test_prove_reports_transient_failures_without_condemning_the_token():
    def down():
        raise ConnectionError("connection reset by peer")

    gw = _bearer_gateway_with_root(down)
    with pytest.raises(ToolError) as info:
        gw.prove()
    assert info.value.code == "upstream_unavailable"
    assert gw.rejected is False
    gw.close()


def test_prove_on_401_latches_the_gateway():
    def unauthorized():
        raise UnauthorizedError("Exchange rejected credentials (HTTP 401)")

    gw = _bearer_gateway_with_root(unauthorized)
    with pytest.raises(ToolError) as info:
        gw.prove()
    assert info.value.code == "auth_failed"
    assert gw.rejected is True
    gw.close()


def test_closed_gateway_refuses_to_rebuild_an_untracked_account():
    gw = EWSGateway(make_settings())
    gw.close()
    with pytest.raises(ToolError) as info:
        gw._get_or_build_account()
    assert info.value.code == "upstream_unavailable"
    assert gw._cache_key is None
