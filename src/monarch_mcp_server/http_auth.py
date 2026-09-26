"""Optional bearer token check for the Streamable HTTP transport.

Host and Origin validation stops DNS rebinding but does not authenticate
anyone: every caller that can reach the port gets the full tool set against
the saved Monarch session. That is fine behind loopback or an authenticating
proxy, and not fine on a public URL such as a Cloud Run service. Setting
``MONARCH_MCP_AUTH_TOKEN`` makes the server itself refuse any HTTP request
that does not carry ``Authorization: Bearer <token>``.

The token is read from the environment only, never from a CLI flag, because
process arguments are visible to every local user through ``ps``.
"""

import hmac
import json
from typing import Any, Awaitable, Callable, MutableMapping

ENV_VAR = "MONARCH_MCP_AUTH_TOKEN"

# A short token is guessable over a public endpoint with no rate limit. 32
# characters is what `openssl rand -hex 16` produces, so the floor costs nothing
# for anyone following the documented setup.
MIN_TOKEN_LENGTH = 32

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def _presented_token(scope: Scope) -> bytes | None:
    for name, value in scope.get("headers", []):
        if name.lower() == b"authorization":
            scheme, _, token = value.partition(b" ")
            if scheme.lower() == b"bearer" and token.strip():
                return token.strip()
            return None
    return None


class BearerAuthMiddleware:
    """Reject HTTP requests whose bearer token does not match.

    Plain ASGI rather than a Starlette middleware so it wraps the MCP app
    without touching it, and so lifespan events (which start the MCP session
    manager) pass straight through.
    """

    def __init__(self, app: ASGIApp, token: str) -> None:
        self._app = app
        self._token = token.encode("utf-8")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        presented = _presented_token(scope)
        # compare_digest keeps the comparison time independent of how many
        # leading characters match, so the token cannot be recovered byte by
        # byte from response timing.
        if presented is not None and hmac.compare_digest(presented, self._token):
            await self._app(scope, receive, send)
            return

        body = json.dumps({"error": "unauthorized"}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"www-authenticate", b"Bearer"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
