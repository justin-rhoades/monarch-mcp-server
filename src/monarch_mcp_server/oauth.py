"""OAuth for the HTTP transport, signing in through Google.

claude.ai custom connectors (and so the Claude apps) and ChatGPT connectors
can't send a static bearer header, but they do speak the MCP authorization
flow: discover the authorization server, register themselves dynamically,
send the person through an authorization URL, then use the access token they
get back. This module is that authorization server. It hands the sign-in step
to Google and only issues tokens for allow-listed, Google-verified emails.

Hosts like Cloud Run scale to zero and have no durable disk, so nothing is
stored. Client registrations, authorization codes, and access and refresh
tokens are all HMAC-signed JSON carrying their own expiry, and the server only
checks signatures. The consequences of that choice:

- Rotating ``MONARCH_MCP_OAUTH_SIGNING_KEY`` invalidates every client and
  token at once. That is the way to sign everything out.
- Removing an email from ``MONARCH_MCP_ALLOWED_EMAILS`` stops its existing
  tokens too, because the allowlist is re-checked on every request.
- Authorization codes cannot be made strictly single-use. They expire after
  five minutes and are bound to the client's PKCE challenge, which is what
  stops a leaked code from being redeemed by anyone else.
- Revocation is a no-op for the same reason; refresh tokens rotate on use
  and expire after 30 days.
"""

import base64
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger(__name__)

PUBLIC_URL_ENV = "MONARCH_MCP_PUBLIC_URL"
GOOGLE_CLIENT_ID_ENV = "MONARCH_MCP_GOOGLE_CLIENT_ID"
GOOGLE_CLIENT_SECRET_ENV = "MONARCH_MCP_GOOGLE_CLIENT_SECRET"
SIGNING_KEY_ENV = "MONARCH_MCP_OAUTH_SIGNING_KEY"
ALLOWED_EMAILS_ENV = "MONARCH_MCP_ALLOWED_EMAILS"

MIN_SIGNING_KEY_LENGTH = 32

GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")
CALLBACK_PATH = "/oauth/google/callback"

SCOPE = "mcp"
LOGIN_TTL = 10 * 60
CODE_TTL = 5 * 60
ACCESS_TTL = 60 * 60
REFRESH_TTL = 30 * 24 * 60 * 60


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class Signer:
    """HMAC-signed, typed, expiring JSON blobs.

    The type is part of the signed payload, so a refresh token cannot be
    presented as an access token, nor a client ID as an authorization code.
    """

    def __init__(self, key: str) -> None:
        self._key = key.encode("utf-8")

    def _mac(self, body: str) -> str:
        return _b64encode(hmac.new(self._key, body.encode("ascii"), "sha256").digest())

    def sign(self, typ: str, payload: dict[str, Any], ttl: int | None) -> str:
        data = {"typ": typ, **payload}
        if ttl is not None:
            data["exp"] = int(time.time()) + ttl
        # A random nonce keeps two tokens issued in the same second distinct.
        data["n"] = secrets.token_urlsafe(8)
        body = _b64encode(json.dumps(data, separators=(",", ":")).encode("utf-8"))
        return f"{body}.{self._mac(body)}"

    def derive(self, label: str, value: str) -> str:
        """A stable secret bound to *value*, such as a client's secret."""
        message = f"{label}:{value}".encode("utf-8")
        return _b64encode(hmac.new(self._key, message, "sha256").digest())

    def verify(self, typ: str, token: str) -> dict[str, Any] | None:
        body, dot, mac = token.partition(".")
        if not dot or not hmac.compare_digest(mac, self._mac(body)):
            return None
        try:
            data = json.loads(_b64decode(body))
        except ValueError:
            return None
        if not isinstance(data, dict) or data.get("typ") != typ:
            return None
        exp = data.get("exp")
        if exp is not None and exp < time.time():
            return None
        return data


@dataclass(frozen=True)
class OAuthConfig:
    public_url: str
    google_client_id: str
    google_client_secret: str
    signing_key: str
    allowed_emails: frozenset[str]

    @property
    def callback_url(self) -> str:
        return self.public_url + CALLBACK_PATH

    @property
    def resource_url(self) -> str:
        return self.public_url + "/mcp"


def config_problems(config: OAuthConfig) -> list[str]:
    problems = []
    if not config.public_url.startswith("https://"):
        problems.append(f"{PUBLIC_URL_ENV} must be the server's https:// URL")
    if not config.google_client_secret:
        problems.append(f"{GOOGLE_CLIENT_SECRET_ENV} is required")
    if len(config.signing_key) < MIN_SIGNING_KEY_LENGTH:
        problems.append(
            f"{SIGNING_KEY_ENV} must be at least {MIN_SIGNING_KEY_LENGTH} characters"
        )
    if not config.allowed_emails:
        problems.append(f"{ALLOWED_EMAILS_ENV} must list at least one email")
    return problems


class GoogleOAuthProvider:
    """The SDK's ``OAuthAuthorizationServerProvider``, backed by Google sign-in."""

    def __init__(self, config: OAuthConfig, static_token: str = "") -> None:
        self.config = config
        self._signer = Signer(config.signing_key)
        # The pre-OAuth bearer token keeps working for header-capable clients
        # such as Claude Code and curl.
        self._static_token = static_token

    # --- Clients -----------------------------------------------------------

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        # The SDK fills in a random ID and secret, then returns this object to
        # the client after we return. Replacing them with a signed copy of the
        # registration is what lets get_client work without storage.
        metadata = client_info.model_dump(
            mode="json",
            exclude={"client_id", "client_secret", "client_id_issued_at"},
            exclude_none=True,
        )
        client_info.client_id = self._signer.sign("client", {"m": metadata}, None)
        if client_info.client_secret is not None:
            client_info.client_secret = self._signer.derive(
                "client_secret", client_info.client_id
            )

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = self._signer.verify("client", client_id)
        if data is None:
            return None
        metadata = dict(data["m"])
        # Every client may ask for the one scope this server has, whatever it
        # registered with.
        scopes = set((metadata.get("scope") or "").split()) | {SCOPE}
        metadata["scope"] = " ".join(sorted(scopes))
        client = OAuthClientInformationFull(client_id=client_id, **metadata)
        if client.token_endpoint_auth_method != "none":
            client.client_secret = self._signer.derive("client_secret", client_id)
        return client

    # --- Authorization -----------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        login = self._signer.sign(
            "login",
            {
                "client_id": client.client_id,
                "redirect_uri": str(params.redirect_uri),
                "explicit": params.redirect_uri_provided_explicitly,
                "challenge": params.code_challenge,
                "state": params.state,
                "scopes": params.scopes or [SCOPE],
                "resource": params.resource,
            },
            LOGIN_TTL,
        )
        query = {
            "client_id": self.config.google_client_id,
            "redirect_uri": self.config.callback_url,
            "response_type": "code",
            "scope": "openid email",
            "state": login,
            "prompt": "select_account",
        }
        if len(self.config.allowed_emails) == 1:
            query["login_hint"] = next(iter(self.config.allowed_emails))
        return f"{GOOGLE_AUTHORIZE_URL}?{urlencode(query)}"

    async def google_callback(self, request: Request) -> Response:
        """Finish Google sign-in and send the person back to their MCP client."""
        login = self._signer.verify("login", request.query_params.get("state", ""))
        if login is None:
            return _error_page(
                "This sign-in link has expired. Start again from your app."
            )

        redirect_uri = login["redirect_uri"]

        def back_to_client(**params: str | None) -> Response:
            url = construct_redirect_uri(redirect_uri, state=login["state"], **params)
            return RedirectResponse(url, status_code=302)

        if request.query_params.get("error"):
            return back_to_client(
                error="access_denied", error_description="Google sign-in was cancelled"
            )
        code = request.query_params.get("code")
        if not code:
            return back_to_client(error="invalid_request")

        email = await self._google_email(code)
        if email is None:
            return back_to_client(
                error="access_denied", error_description="Google sign-in failed"
            )
        if email not in self.config.allowed_emails:
            logger.warning("OAuth: refused sign-in from a non-allowed account")
            return back_to_client(
                error="access_denied",
                error_description="This Google account is not allowed",
            )

        auth_code = self._signer.sign(
            "code",
            {
                "client_id": login["client_id"],
                "redirect_uri": redirect_uri,
                "explicit": login["explicit"],
                "challenge": login["challenge"],
                "scopes": login["scopes"],
                "resource": login["resource"],
                "email": email,
            },
            CODE_TTL,
        )
        logger.info("OAuth: issued an authorization code")
        return back_to_client(code=auth_code)

    async def _google_email(self, code: str) -> str | None:
        """Exchange Google's code and return the verified email, if any."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    GOOGLE_TOKEN_URL,
                    data={
                        "code": code,
                        "client_id": self.config.google_client_id,
                        "client_secret": self.config.google_client_secret,
                        "redirect_uri": self.config.callback_url,
                        "grant_type": "authorization_code",
                    },
                )
            if response.status_code != 200:
                logger.warning(
                    "OAuth: Google token exchange returned %s", response.status_code
                )
                return None
            id_token = response.json()["id_token"]
            # Received straight from Google's token endpoint over TLS, so per
            # OpenID Connect Core 3.1.3.7 the TLS server check stands in for
            # verifying the signature. The claims are still checked.
            claims = json.loads(_b64decode(id_token.split(".")[1]))
        except (httpx.HTTPError, KeyError, IndexError, ValueError):
            logger.warning("OAuth: Google token exchange failed", exc_info=True)
            return None
        if (
            claims.get("iss") not in GOOGLE_ISSUERS
            or claims.get("aud") != self.config.google_client_id
            or claims.get("exp", 0) < time.time()
            or claims.get("email_verified") is not True
            or not isinstance(claims.get("email"), str)
        ):
            return None
        return str(claims["email"]).lower()

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        data = self._signer.verify("code", authorization_code)
        if data is None or data["client_id"] != client.client_id:
            return None
        if data["email"] not in self.config.allowed_emails:
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=data["scopes"],
            expires_at=data["exp"],
            client_id=data["client_id"],
            code_challenge=data["challenge"],
            redirect_uri=data["redirect_uri"],
            redirect_uri_provided_explicitly=data["explicit"],
            resource=data["resource"],
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        data = self._signer.verify("code", authorization_code.code)
        if data is None:  # pragma: no cover - load_authorization_code checked it
            raise TokenError("invalid_grant", "authorization code expired")
        return self._issue(
            client.client_id, data["email"], data["scopes"], data["resource"]
        )

    # --- Tokens ------------------------------------------------------------

    def _issue(
        self, client_id: str, email: str, scopes: list[str], resource: str | None
    ) -> OAuthToken:
        claims = {
            "client_id": client_id,
            "email": email,
            "scopes": scopes,
            "resource": resource,
        }
        return OAuthToken(
            access_token=self._signer.sign("access", claims, ACCESS_TTL),
            expires_in=ACCESS_TTL,
            scope=" ".join(scopes),
            refresh_token=self._signer.sign("refresh", claims, REFRESH_TTL),
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        data = self._signer.verify("refresh", refresh_token)
        if data is None or data["client_id"] != client.client_id:
            return None
        if data["email"] not in self.config.allowed_emails:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=data["client_id"],
            scopes=data["scopes"],
            expires_at=data["exp"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        data = self._signer.verify("refresh", refresh_token.token)
        if data is None:  # pragma: no cover - load_refresh_token checked it
            raise TokenError("invalid_grant", "refresh token expired")
        return self._issue(client.client_id, data["email"], scopes, data["resource"])

    async def load_access_token(self, token: str) -> AccessToken | None:
        if self._static_token and hmac.compare_digest(
            token.encode("utf-8"), self._static_token.encode("utf-8")
        ):
            return AccessToken(token=token, client_id="static-token", scopes=[SCOPE])
        data = self._signer.verify("access", token)
        if data is None or data["email"] not in self.config.allowed_emails:
            return None
        return AccessToken(
            token=token,
            client_id=data["client_id"],
            scopes=data["scopes"],
            expires_at=data["exp"],
            resource=data["resource"],
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        # Nothing is stored, so there is nothing to delete. Rotate the signing
        # key to invalidate every token.
        return None


def _error_page(message: str) -> Response:
    return HTMLResponse(
        f"<!doctype html><title>Sign-in failed</title><p>{message}</p>",
        status_code=400,
    )


def configure(
    mcp: Any, config: OAuthConfig, static_token: str = ""
) -> GoogleOAuthProvider:
    """Turn on the SDK's OAuth support on *mcp*, before its HTTP app is built.

    FastMCP only takes an auth provider in its constructor, but this module's
    ``mcp`` is created at import time, before the command line and
    environment are read. The attributes set here are exactly the ones the
    constructor would set.
    """
    from mcp.server.auth.provider import ProviderTokenVerifier
    from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions

    provider = GoogleOAuthProvider(config, static_token)
    mcp.settings.auth = AuthSettings(
        issuer_url=AnyHttpUrl(config.public_url),
        resource_server_url=AnyHttpUrl(config.resource_url),
        required_scopes=[SCOPE],
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]
        ),
    )
    mcp._auth_server_provider = provider
    mcp._token_verifier = ProviderTokenVerifier(provider)
    return provider


def add_routes(app: Any, provider: GoogleOAuthProvider) -> None:
    """Add the Google callback, and protected resource metadata where clients look.

    The SDK serves the metadata only at ``/.well-known/oauth-protected-resource``
    but its 401 points at ``/mcp/.well-known/oauth-protected-resource``, and RFC
    9728 clients try ``/.well-known/oauth-protected-resource/mcp`` first.
    """
    from starlette.routing import Route

    metadata = next(
        route
        for route in app.router.routes
        if getattr(route, "path", None) == "/.well-known/oauth-protected-resource"
    )
    app.router.routes.extend(
        [
            Route(CALLBACK_PATH, endpoint=provider.google_callback, methods=["GET"]),
            Route(
                "/.well-known/oauth-protected-resource/mcp",
                endpoint=metadata.endpoint,
                methods=["GET", "OPTIONS"],
            ),
            Route(
                "/mcp/.well-known/oauth-protected-resource",
                endpoint=metadata.endpoint,
                methods=["GET", "OPTIONS"],
            ),
        ]
    )
