"""Bearer identity: the mailbox comes from the token's own claims, nothing else."""

import base64
import json

import pytest

from ewsmcp.identity import (
    CURRENT_PRINCIPAL,
    MAX_TOKEN_CHARS,
    BearerError,
    Principal,
    bearer_token_from_headers,
    current_principal,
    mailbox_key,
    parse_claim_order,
    principal_from_bearer,
    static_principal,
    token_fingerprint,
    use_principal,
)

NOW = 1_800_000_000.0


def _seg(obj) -> str:
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt(claims: dict, header: dict | None = None) -> str:
    """Unsigned JWS compact token (the server never checks signatures)."""
    return ".".join([_seg(header or {"alg": "RS256", "typ": "JWT"}),
                     _seg(claims), "c2lnbmF0dXJl"])


def test_mailbox_comes_from_first_matching_claim_lowercased():
    token = make_jwt({"upn": "Alice@Corp.Example", "email": "alice.smtp@corp.example",
                      "exp": NOW + 3600})
    p = principal_from_bearer(token, claims=("email", "upn"), now=NOW)
    assert p.mailbox == "alice.smtp@corp.example"
    p2 = principal_from_bearer(token, claims=("upn", "email"), now=NOW)
    assert p2.mailbox == "alice@corp.example"
    assert p.expires_at == NOW + 3600
    assert p.is_bearer and p.token == token


def test_non_address_claims_are_skipped():
    token = make_jwt({"email": "not-an-address", "upn": "bob@corp.example"})
    assert principal_from_bearer(token, now=NOW).mailbox == "bob@corp.example"


@pytest.mark.parametrize("claims", [
    {},
    {"upn": ""},
    {"upn": 42},
    {"upn": "two@at@signs.example"},
    {"upn": "spaced name@corp.example"},
])
def test_no_usable_mailbox_claim_is_refused(claims):
    with pytest.raises(BearerError) as info:
        principal_from_bearer(make_jwt(claims), now=NOW)
    assert info.value.reason == "no mailbox claim"


def test_expired_and_not_yet_valid_tokens_are_refused_locally():
    with pytest.raises(BearerError, match="expired"):
        principal_from_bearer(make_jwt({"upn": "a@corp.example", "exp": NOW - 3600}), now=NOW)
    with pytest.raises(BearerError, match="not yet valid"):
        principal_from_bearer(make_jwt({"upn": "a@corp.example", "nbf": NOW + 3600}), now=NOW)
    # Within the clock-skew leeway both are still accepted.
    principal_from_bearer(make_jwt({"upn": "a@corp.example", "exp": NOW - 30}), now=NOW)
    principal_from_bearer(make_jwt({"upn": "a@corp.example", "nbf": NOW + 30}), now=NOW)


@pytest.mark.parametrize("token", [
    "",
    "opaque-token-without-dots",
    "a.b",
    "a.b.c.d.e",  # JWE: encrypted tokens carry no readable claims
    "x." + "!!!" + ".y",
    "x." + base64.urlsafe_b64encode(b"[1,2]").rstrip(b"=").decode() + ".y",
    "x." + base64.urlsafe_b64encode(b"\xff\xfe").rstrip(b"=").decode() + ".y",
])
def test_malformed_tokens_are_refused(token):
    with pytest.raises(BearerError):
        principal_from_bearer(token, now=NOW)


def test_oversized_token_is_refused_before_parsing():
    big = make_jwt({"upn": "a@corp.example", "pad": "x" * MAX_TOKEN_CHARS})
    with pytest.raises(BearerError, match="malformed"):
        principal_from_bearer(big, now=NOW)


def test_non_numeric_exp_is_refused():
    with pytest.raises(BearerError):
        principal_from_bearer(make_jwt({"upn": "a@corp.example", "exp": "soon"}), now=NOW)


def test_token_never_appears_in_repr_or_equality():
    token = make_jwt({"upn": "a@corp.example"})
    p = principal_from_bearer(token, now=NOW)
    assert token not in repr(p)
    assert token not in str(p)
    assert p.fingerprint == token_fingerprint(token)
    assert len(p.fingerprint) == 32


def test_fingerprints_differ_per_token_for_the_same_mailbox():
    t1 = make_jwt({"upn": "a@corp.example", "jti": "1"})
    t2 = make_jwt({"upn": "a@corp.example", "jti": "2"})
    p1, p2 = principal_from_bearer(t1, now=NOW), principal_from_bearer(t2, now=NOW)
    assert p1.mailbox == p2.mailbox and p1.key == p2.key
    assert p1.fingerprint != p2.fingerprint


def test_mailbox_key_is_stable_case_insensitive_and_path_safe():
    k = mailbox_key("Alice@Corp.Example")
    assert k == mailbox_key(" alice@corp.example ")
    assert len(k) == 24 and all(c in "0123456789abcdef" for c in k)
    assert k != mailbox_key("bob@corp.example")


@pytest.mark.parametrize("headers, expected", [
    ([(b"authorization", b"Bearer abc.def.ghi")], "abc.def.ghi"),
    ([(b"Authorization", b"bearer   tok  ")], "tok"),
    ([("authorization", "Bearer tok")], "tok"),
    ([(b"authorization", b"Basic dXNlcjpwdw==")], None),
    ([(b"authorization", b"Bearer ")], None),
    ([(b"x-api-key", b"k")], None),
    (None, None),
])
def test_bearer_header_parsing(headers, expected):
    assert bearer_token_from_headers(headers) == expected


def test_static_principal_and_claim_order_parsing():
    p = static_principal(" Exec@Corp.Example ")
    assert p == Principal(mailbox="exec@corp.example")
    assert not p.is_bearer and not p.expired(NOW)
    assert parse_claim_order(" upn , email ") == ("upn", "email")
    assert parse_claim_order("") == ("email", "upn", "preferred_username", "unique_name")


def test_principal_scope_is_restored():
    p = static_principal("a@corp.example")
    assert current_principal() is None
    with use_principal(p):
        assert current_principal() is p
        assert CURRENT_PRINCIPAL.get() is p
    assert current_principal() is None


def test_principal_expiry_uses_leeway():
    p = Principal(mailbox="a@corp.example", token="t", fingerprint="f", expires_at=NOW)
    assert not p.expired(NOW + 30)
    assert p.expired(NOW + 61)
