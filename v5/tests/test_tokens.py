"""Local token validation: signature, algorithm, issuer, audience, expiry."""

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from conftest import make_settings
from test_bearer_mode import _drive, _http_ctx

from ewsmcp.http import build_app
from ewsmcp.identity import BearerError
from ewsmcp.tokens import TokenKeysUnavailable, TokenVerifier

ISS = "http://adfs.corp.example/adfs/services/trust"
AUD = "https://mail.corp.example/"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwks(*entries):
    keys = []
    for kid, private in entries:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
        jwk.update(kid=kid, use="sig", alg="RS256")
        keys.append(jwk)
    return {"keys": keys}


def token(private=KEY, kid="k1", alg="RS256", **claims):
    body = {"iss": ISS, "aud": AUD, "upn": "alice@corp.example", "exp": time.time() + 3600}
    body.update(claims)
    return jwt.encode(body, private, algorithm=alg, headers={"kid": kid})


class Fetch:
    def __init__(self, data):
        self.data, self.calls = data, 0

    def __call__(self):
        self.calls += 1
        if isinstance(self.data, Exception):
            raise self.data
        return self.data


def verifier(fetch=None, clock=time.time):
    return TokenVerifier(jwks_url="https://adfs.corp.example/adfs/discovery/keys",
                         issuers=[ISS], audiences=[AUD],
                         fetch=fetch or Fetch(jwks(("k1", KEY))), clock=clock)


def reason(v, tok):
    with pytest.raises(BearerError) as info:
        v.verify(tok)
    return info.value.reason


def test_a_valid_token_is_verified_once_and_remembered():
    fetch = Fetch(jwks(("k1", KEY)))
    v = verifier(fetch)
    tok = token()
    assert v.verify(tok)["upn"] == "alice@corp.example"
    assert v.verify(tok)["upn"] == "alice@corp.example"
    assert fetch.calls == 1 and len(v._verified) == 1


def test_forged_tampered_and_unsigned_tokens_are_refused():
    v = verifier()
    assert reason(v, token(OTHER_KEY)) == "bad signature"  # right kid, wrong key
    head, payload, sig = token().split(".")
    forged = jwt.utils.base64url_encode(json.dumps(
        {"iss": ISS, "aud": AUD, "upn": "ceo@corp.example", "exp": time.time() + 3600}
    ).encode()).decode()
    assert reason(v, f"{head}.{forged}.{sig}") == "bad signature"  # swapped claims
    assert reason(v, jwt.encode({"iss": ISS, "aud": AUD}, None, algorithm="none")) \
        == "algorithm not allowed"
    assert reason(v, jwt.encode({"iss": ISS, "aud": AUD}, "s" * 32, algorithm="HS256")) \
        == "algorithm not allowed"
    assert reason(v, "not.a.jwt") == "malformed"


@pytest.mark.parametrize("claims, expected", [
    ({"iss": "https://evil.example/"}, "wrong issuer"),
    ({"aud": "https://graph.microsoft.com"}, "wrong audience"),
    ({"exp": time.time() - 3600}, "expired"),
    ({"nbf": time.time() + 3600}, "not yet valid"),
])
def test_issuer_audience_and_lifetime_are_enforced(claims, expected):
    assert reason(verifier(), token(**claims)) == expected


def test_a_token_without_expiry_is_refused():
    tok = jwt.encode({"iss": ISS, "aud": AUD, "upn": "a@corp.example"}, KEY,
                     algorithm="RS256", headers={"kid": "k1"})
    assert reason(verifier(), tok) == "missing required claim"


def test_unknown_key_ids_refetch_keys_at_most_once_a_minute():
    now = [1_000_000.0]
    fetch = Fetch(jwks(("k1", KEY)))
    v = verifier(fetch, clock=lambda: now[0])
    for kid in ("made-up-1", "made-up-2", "made-up-3"):
        assert reason(v, token(kid=kid)) == "unknown signing key"
    assert fetch.calls == 1  # made-up key ids cannot hammer the identity provider
    fetch.data = jwks(("k1", KEY), ("k2", OTHER_KEY))  # the provider rotates keys
    now[0] += 61
    assert v.verify(token(OTHER_KEY, kid="k2"))["upn"] == "alice@corp.example"
    assert fetch.calls == 2


def test_no_keys_means_no_access():
    v = verifier(Fetch(ConnectionError("identity provider down")))
    with pytest.raises(TokenKeysUnavailable):
        v.verify(token())


def test_keys_can_come_from_a_local_file(tmp_path):
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps(jwks(("k1", KEY))), encoding="utf-8")
    v = TokenVerifier(jwks_url=path.as_uri(), issuers=[ISS], audiences=[AUD])
    assert v.verify(token())["upn"] == "alice@corp.example"


def test_http_layer_refuses_bad_tokens_before_dispatch(tmp_path):
    ctx = _http_ctx(tmp_path)
    ctx.token_verifier = verifier()
    app = build_app(ctx, ctx.settings)

    def call(tok):
        return _drive(app, "/api/tools/whoami", headers=[("authorization", f"Bearer {tok}")])

    status, headers, body = call(token(OTHER_KEY))
    assert status == 401 and "bad signature" in body["error"]["message"]
    assert headers[b"www-authenticate"].startswith(b"Bearer")
    assert ctx.pool.sessions() == []  # never reached the mailbox binding
    status, _, body = call(token())
    assert status == 200 and body["mailbox"] == "alice@corp.example"
    ctx.token_verifier = verifier(Fetch(ConnectionError("down")))
    app = build_app(ctx, ctx.settings)
    assert call(token(kid="k1"))[0] == 503


def test_bearer_mode_verifies_signatures_by_default():
    base = dict(ews_auth_mode="bearer", mcp_transport="http", ews_email=None)
    with pytest.raises(ValidationError, match="EWS_TOKEN_JWKS_URL"):
        make_settings(**base)
    ok = make_settings(**base, ews_token_jwks_url="https://adfs.corp.example/adfs/discovery/keys",
                       ews_token_issuer=ISS, ews_token_audience=AUD)
    assert ok.ews_token_validation == "signature"
    full = dict(base, ews_token_jwks_url="https://adfs.corp.example/adfs/discovery/keys",
                ews_token_issuer=ISS, ews_token_audience=AUD)
    with pytest.raises(ValidationError, match="EWS_TOKEN_ALGORITHMS"):
        make_settings(**full, ews_token_algorithms="HS256")
    with pytest.raises(ValidationError, match="https:// or file://"):
        make_settings(**dict(full, ews_token_jwks_url="http://adfs.corp.example/keys"))
    assert make_settings(**base, ews_token_validation="none").ews_token_validation == "none"
