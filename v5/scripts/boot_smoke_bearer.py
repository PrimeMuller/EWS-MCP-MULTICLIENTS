#!/usr/bin/env python3
"""Bearer-mode boot smoke: many-mailbox serving end to end, no Exchange needed.

Boots the real HTTP server with EWS_AUTH_MODE=bearer, no Exchange
credentials, and an unreachable Exchange, then asserts:

- the process boots and is ready without any credentials of its own;
- every non-public route needs the caller's bearer token (401 + challenge),
  and the service API key rides X-API-Key;
- tokens are verified locally (signature against a JWKS, issuer, audience):
  a token signed by another key is refused before Exchange is contacted;
- a call with a token is bound to its mailbox: the token proof reaches for
  Exchange and fails as upstream_unavailable, not as "no token" — over REST
  and over MCP Streamable HTTP, where the principal must survive the SDK's
  stateless task via the request scope;
- after EWS_GLOBAL_CIRCUIT_THRESHOLD such failures every call is paused
  without contacting Exchange;
- the MCP initialize instructions tell the client how to treat marked text.

Run from v5/:  python scripts/boot_smoke_bearer.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa

PORT = 8125
BASE = f"http://127.0.0.1:{PORT}"
KEY = "v5-smoke-key"
ISSUER = "http://idp.example.invalid/adfs/services/trust"
AUDIENCE = "https://mail.example.invalid/"
SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
STRANGER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwt(claims, key=SIGNING_KEY):
    body = {"iss": ISSUER, "aud": AUDIENCE, **claims}
    return pyjwt.encode(body, key, algorithm="RS256", headers={"kid": "smoke-1"})


def write_jwks() -> str:
    jwk = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(SIGNING_KEY.public_key()))
    jwk.update(kid="smoke-1", use="sig", alg="RS256")
    path = Path(tempfile.mkdtemp()) / "jwks.json"
    path.write_text(json.dumps({"keys": [jwk]}), encoding="utf-8")
    return path.as_uri()


def request(method, path, payload=None, *, token=None, api_key=KEY, headers=None,
            timeout=15):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if api_key:
        req.add_header("X-API-Key", api_key)
    if data:
        req.add_header("Content-Type", "application/json")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def as_json(raw):
    try:
        return json.loads(raw)
    except ValueError:
        return {}


def mcp(method, params, token, request_id):
    status, headers, raw = request(
        "POST", "/mcp",
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
        token=token, headers={"Accept": "application/json, text/event-stream"})
    for line in raw.splitlines():  # server-sent events: "data: {...}"
        if line.startswith("data:"):
            return status, json.loads(line[5:].strip())
    return status, as_json(raw)


def main() -> int:
    env = dict(os.environ)
    for name in ("EWS_EMAIL", "EWS_USERNAME", "EWS_PASSWORD"):
        env.pop(name, None)
    env.update({
        "EWS_AUTH_MODE": "bearer",
        "EWS_SERVER_URL": "https://192.0.2.1/EWS/Exchange.asmx",  # TEST-NET-1
        "MCP_TRANSPORT": "http", "MCP_HOST": "127.0.0.1", "MCP_PORT": str(PORT),
        "MCP_API_KEY": KEY,
        "EWS_TOKEN_JWKS_URL": write_jwks(),
        "EWS_TOKEN_ISSUER": ISSUER,
        "EWS_TOKEN_AUDIENCE": AUDIENCE,
        "EWS_GLOBAL_CIRCUIT_THRESHOLD": "2",
        "REQUEST_TIMEOUT": "3", "LOG_LEVEL": "WARNING",
        "DATA_DIR": os.path.join(os.environ.get("TEMP", "/tmp"), "v5-smoke-bearer-data"),
        "PYTHONPATH": os.getcwd(),
    })
    proc = subprocess.Popen([sys.executable, "-m", "ewsmcp.main"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    failures = []
    token = jwt({"upn": "smoke.user@example.invalid", "exp": time.time() + 3600})
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            if proc.poll() is not None:
                print(f"FAIL: process exited early ({proc.returncode})")
                return 1
            try:
                if request("GET", "/livez", timeout=2)[0] == 200:
                    break
            except Exception:
                time.sleep(0.5)
        else:
            print("FAIL: /livez never came up")
            return 1

        status, _, raw = request("GET", "/readyz")
        if status != 200 or as_json(raw).get("connection", {}).get("state") != "per_mailbox":
            failures.append(f"/readyz {status} {raw}")

        status, headers, raw = request("POST", "/api/tools/search_messages", {"limit": 1})
        challenge = {k.lower(): v for k, v in headers.items()}.get("www-authenticate", "")
        if status != 401 or not challenge.startswith("Bearer"):
            failures.append(f"no token: expected 401 + Bearer challenge, got {status} {raw}")

        expired = jwt({"upn": "smoke.user@example.invalid", "exp": 1})
        status, _, raw = request("POST", "/api/tools/search_messages", {"limit": 1},
                                 token=expired)
        if status != 401:
            failures.append(f"expired token: expected 401, got {status} {raw}")

        status, _, raw = request("POST", "/api/tools/search_messages", {"limit": 1},
                                 token=token, api_key=None)
        if status != 401:
            failures.append(f"missing X-API-Key: expected 401, got {status} {raw}")

        forged = jwt({"upn": "smoke.user@example.invalid", "exp": time.time() + 3600},
                     key=STRANGER_KEY)
        status, _, raw = request("POST", "/api/tools/search_messages", {"limit": 1},
                                 token=forged)
        if status != 401 or "bad signature" not in raw:
            failures.append(f"forged token: expected 401 bad signature, got {status} {raw}")

        foreign = jwt({"upn": "smoke.user@example.invalid", "exp": time.time() + 3600,
                       "aud": "https://graph.microsoft.com"})
        status, _, raw = request("POST", "/api/tools/search_messages", {"limit": 1},
                                 token=foreign)
        if status != 401 or "wrong audience" not in raw:
            failures.append(f"foreign audience: expected 401, got {status} {raw}")

        status, _, raw = request("POST", "/api/tools/get_server_status", {}, token=token)
        if status != 200 or as_json(raw).get("connection", {}).get("state") != "per_mailbox":
            failures.append(f"get_server_status {status} {raw}")

        # Bound to the mailbox: the token proof reaches for Exchange and fails.
        status, _, raw = request("POST", "/api/tools/search_messages", {"limit": 1},
                                 token=token)
        code = as_json(raw).get("error", {}).get("code")
        if status != 503 or code != "upstream_unavailable":
            failures.append(f"REST bound call: expected 503 upstream_unavailable, "
                            f"got {status} {raw}")

        # Same over MCP Streamable HTTP (stateless): the principal must arrive.
        status, init = mcp("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "boot-smoke", "version": "1"},
        }, token, 1)
        instructions = (init.get("result") or {}).get("instructions") or ""
        if status != 200 or "untrusted-content" not in instructions:
            failures.append(f"MCP initialize {status} {init}")
        status, called = mcp("tools/call", {"name": "search_messages",
                                            "arguments": {"limit": 1}}, token, 2)
        content = (called.get("result") or {}).get("content") or [{}]
        text = content[0].get("text", "")
        if "upstream_unavailable" not in text or "needs the caller" in text:
            failures.append(f"MCP bound call did not reach the mailbox binding: {called}")

        # Two upstream failures in a row (threshold 2): calls are now paused.
        started = time.time()
        status, _, raw = request("POST", "/api/tools/search_messages", {"limit": 1},
                                 token=token)
        message = as_json(raw).get("error", {}).get("message", "")
        if status != 503 or "paused" not in message or time.time() - started > 2:
            failures.append(f"global circuit: expected a fast pause, got {status} {raw}")

        status, _, raw = request("POST", "/mcp", {}, token=None,
                                 headers={"Accept": "application/json, text/event-stream"})
        if status != 401:
            failures.append(f"/mcp without token: expected 401, got {status}")

        if failures:
            print("FAILURES:")
            for failure in failures:
                print(" -", failure)
            return 1
        print("OK: v5 bearer boot smoke passed")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
