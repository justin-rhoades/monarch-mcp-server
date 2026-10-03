"""The Google-backed OAuth flow, end to end through the HTTP app."""

import base64
import hashlib
import json
import secrets
import time
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.testclient import TestClient

from monarch_mcp_server import app, oauth

PUBLIC = "https://mcp.example.com"
REDIRECT = "https://client.example.com/callback"
ALLOWED = "me@example.com"
STATIC = "s" * 64
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    },
}
MCP_HEADERS = {"Accept": "application/json, text/event-stream"}

CONFIG = oauth.OAuthConfig(
    public_url=PUBLIC,
    google_client_id="google-client",
    google_client_secret="google-secret",
    signing_key="k" * 64,
    allowed_emails=frozenset({ALLOWED}),
)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(app.mcp, "settings", app.mcp.settings.model_copy(deep=True))
    monkeypatch.setattr(app.mcp, "_session_manager", None)
    monkeypatch.setattr(app.mcp, "_auth_server_provider", None)
    monkeypatch.setattr(app.mcp, "_token_verifier", None)
    from mcp.server.transport_security import TransportSecuritySettings

    app.mcp.settings.transport_security = TransportSecuritySettings(
        allowed_hosts=["mcp.example.com"], allowed_origins=[]
    )
    google_email = {"value": ALLOWED}

    async def fake_google_email(self, code):
        assert code == "google-code"
        return google_email["value"]

    monkeypatch.setattr(oauth.GoogleOAuthProvider, "_google_email", fake_google_email)
    http_app = app.build_http_app(
        STATIC, allow_path_token=True, oauth_config=CONFIG
    )
    with TestClient(http_app, base_url=PUBLIC) as test_client:
        test_client.google_email = google_email
        yield test_client


def pkce():
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).decode().rstrip("=")


def register(client):
    response = client.post(
        "/register",
        json={
            "redirect_uris": [REDIRECT],
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_name": "test",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def sign_in(client, registration, challenge, state="xyz"):
    """Run /authorize and the Google callback; return the client redirect."""
    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "scope": "mcp",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    google = urlparse(response.headers["location"])
    assert google.netloc == "accounts.google.com"
    query = parse_qs(google.query)
    assert query["redirect_uri"] == [PUBLIC + "/oauth/google/callback"]
    assert query["login_hint"] == [ALLOWED]
    response = client.get(
        "/oauth/google/callback",
        params={"code": "google-code", "state": query["state"][0]},
        follow_redirects=False,
    )
    assert response.status_code == 302
    back = urlparse(response.headers["location"])
    assert f"{back.scheme}://{back.netloc}{back.path}" == REDIRECT
    return {k: v[0] for k, v in parse_qs(back.query).items()}


def exchange(client, registration, code, verifier):
    return client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
            "client_id": registration["client_id"],
            "client_secret": registration["client_secret"],
        },
    )


def initialize(client, token, path="/mcp"):
    headers = dict(MCP_HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return client.post(path, headers=headers, json=INITIALIZE)


def test_unauthenticated_request_points_at_metadata(client):
    response = initialize(client, None)
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert "resource_metadata=" in challenge
    for path in (
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
        "/mcp/.well-known/oauth-protected-resource",
    ):
        metadata = client.get(path).json()
        assert metadata["resource"] == PUBLIC + "/mcp"
        assert metadata["authorization_servers"] == [PUBLIC + "/"]
    server = client.get("/.well-known/oauth-authorization-server").json()
    assert server["registration_endpoint"] == PUBLIC + "/register"


def test_full_flow_and_refresh(client):
    registration = register(client)
    verifier, challenge = pkce()
    redirect = sign_in(client, registration, challenge)
    assert redirect["state"] == "xyz"

    tokens = exchange(client, registration, redirect["code"], verifier).json()
    response = initialize(client, tokens["access_token"])
    assert "serverInfo" in response.text

    refreshed = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": registration["client_id"],
            "client_secret": registration["client_secret"],
        },
    ).json()
    assert refreshed["access_token"] != tokens["access_token"]
    assert "serverInfo" in initialize(client, refreshed["access_token"]).text


def test_public_client_without_secret(client):
    response = client.post(
        "/register",
        json={
            "redirect_uris": [REDIRECT],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
        },
    )
    registration = response.json()
    assert "client_secret" not in registration
    verifier, challenge = pkce()
    code = sign_in(client, registration, challenge)["code"]
    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
            "client_id": registration["client_id"],
        },
    )
    assert "access_token" in response.json()


def test_other_google_accounts_are_refused(client):
    client.google_email["value"] = "someone@example.com"
    registration = register(client)
    _, challenge = pkce()
    redirect = sign_in(client, registration, challenge)
    assert redirect["error"] == "access_denied"
    assert "code" not in redirect


def test_failed_google_exchange_is_refused(client):
    client.google_email["value"] = None
    registration = register(client)
    _, challenge = pkce()
    assert sign_in(client, registration, challenge)["error"] == "access_denied"


def test_wrong_pkce_verifier_is_refused(client):
    registration = register(client)
    _, challenge = pkce()
    code = sign_in(client, registration, challenge)["code"]
    other_verifier, _ = pkce()
    response = exchange(client, registration, code, other_verifier)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_code_is_bound_to_its_client(client):
    first, second = register(client), register(client)
    verifier, challenge = pkce()
    code = sign_in(client, first, challenge)["code"]
    response = exchange(client, second, code, verifier)
    assert response.status_code == 400


def test_wrong_client_secret_is_refused(client):
    registration = register(client)
    verifier, challenge = pkce()
    code = sign_in(client, registration, challenge)["code"]
    registration["client_secret"] = "wrong"
    response = exchange(client, registration, code, verifier)
    assert response.status_code in (400, 401)
    assert "access_token" not in response.text


def test_tampered_and_mistyped_tokens_are_refused(client):
    registration = register(client)
    verifier, challenge = pkce()
    code = sign_in(client, registration, challenge)["code"]
    tokens = exchange(client, registration, code, verifier).json()
    body, mac = tokens["access_token"].split(".")
    assert initialize(client, body + "." + mac[:-2] + "AA").status_code == 401
    # A refresh token is not an access token, and a client ID is neither.
    assert initialize(client, tokens["refresh_token"]).status_code == 401
    assert initialize(client, registration["client_id"]).status_code == 401


def test_tokens_stop_working_when_email_is_removed(client, monkeypatch):
    registration = register(client)
    verifier, challenge = pkce()
    code = sign_in(client, registration, challenge)["code"]
    tokens = exchange(client, registration, code, verifier).json()
    provider = app.mcp._auth_server_provider
    monkeypatch.setattr(
        provider,
        "config",
        oauth.OAuthConfig(**{**CONFIG.__dict__, "allowed_emails": frozenset()}),
    )
    assert initialize(client, tokens["access_token"]).status_code == 401


def test_expired_callback_state_is_refused(client):
    response = client.get(
        "/oauth/google/callback", params={"code": "google-code", "state": "junk"}
    )
    assert response.status_code == 400


def test_static_token_still_works(client):
    assert "serverInfo" in initialize(client, STATIC).text
    assert "serverInfo" in initialize(client, None, path=f"/{STATIC}/mcp").text
    # A wrong path token is not stripped, so the request matches no route.
    response = initialize(client, None, path=f"/{'t' * 64}/mcp")
    assert response.status_code == 404
    assert "serverInfo" not in response.text


def test_signer_rejects_expired_tokens(monkeypatch):
    signer = oauth.Signer("k" * 64)
    token = signer.sign("access", {"a": 1}, ttl=60)
    assert signer.verify("access", token)["a"] == 1
    monkeypatch.setattr(time, "time", lambda: 10**12)
    assert signer.verify("access", token) is None


def test_config_problems():
    bad = oauth.OAuthConfig(
        public_url="http://x",
        google_client_id="id",
        google_client_secret="",
        signing_key="short",
        allowed_emails=frozenset(),
    )
    assert len(oauth.config_problems(bad)) == 4
    assert oauth.config_problems(CONFIG) == []


def test_main_requires_complete_oauth_settings(monkeypatch):
    for name in ("TRANSPORT", "AUTH_TOKEN", "AUTH_TOKEN_IN_PATH"):
        monkeypatch.delenv(f"MONARCH_MCP_{name}", raising=False)
    monkeypatch.setattr(app.mcp, "settings", app.mcp.settings.model_copy(deep=True))
    monkeypatch.setenv(oauth.GOOGLE_CLIENT_ID_ENV, "id")
    with pytest.raises(SystemExit) as exc:
        app.main(["--transport", "http"])
    assert exc.value.code == 2


def test_google_claims_are_checked(monkeypatch):
    provider = oauth.GoogleOAuthProvider(CONFIG)

    def id_token(**claims):
        base = {
            "iss": "https://accounts.google.com",
            "aud": "google-client",
            "exp": time.time() + 60,
            "email": "Me@Example.com",
            "email_verified": True,
        }
        payload = base64.urlsafe_b64encode(json.dumps({**base, **claims}).encode())
        return "h." + payload.decode().rstrip("=") + ".s"

    class FakeResponse:
        status_code = 200

        def __init__(self, token):
            self.token = token

        def json(self):
            return {"id_token": self.token}

    def run(token):
        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def post(self, url, data):
                assert data["client_secret"] == "google-secret"
                return FakeResponse(token)

        monkeypatch.setattr(oauth.httpx, "AsyncClient", FakeClient)
        import asyncio

        return asyncio.run(provider._google_email("code"))

    assert run(id_token()) == "me@example.com"
    assert run(id_token(email_verified=False)) is None
    assert run(id_token(aud="someone-else")) is None
    assert run(id_token(iss="https://evil.example")) is None
    assert run(id_token(exp=0)) is None
