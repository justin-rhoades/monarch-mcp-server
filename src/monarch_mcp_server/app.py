"""FastMCP application instance and entry point."""

import argparse
import logging
import os
from typing import Any

try:  # mcp >= 2.0 renamed FastMCP to MCPServer
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:  # mcp < 2.0
    from mcp.server.fastmcp import FastMCP

from monarch_mcp_server.http_auth import ENV_VAR as AUTH_ENV_VAR
from monarch_mcp_server import oauth
from monarch_mcp_server.http_auth import PATH_ENV_VAR as AUTH_PATH_ENV_VAR
from monarch_mcp_server.http_auth import (
    MIN_TOKEN_LENGTH,
    BearerAuthMiddleware,
    PathTokenMiddleware,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# The gql aiohttp transport logs full GraphQL requests/responses at INFO, which
# can include Monarch account payloads. Raise its floor to WARNING so those
# payloads are not written to logs. Transport-level errors still surface; drop
# this to INFO/DEBUG temporarily if you need to trace GraphQL traffic.
logging.getLogger("gql.transport.aiohttp").setLevel(logging.WARNING)

# Initialize FastMCP server
mcp = FastMCP("Monarch Money MCP Server")

# Must run before the tool modules are imported, since it works by wrapping
# mcp.tool() and registration happens at import time.
from monarch_mcp_server import tool_annotations  # noqa: E402

tool_annotations.install(mcp)

# Import tools package to trigger @mcp.tool() registration
import monarch_mcp_server.tools  # noqa: E402, F401

# Export for `mcp run`
app = mcp


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("port must be an integer") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def build_http_app(
    auth_token: str,
    *,
    allow_path_token: bool = False,
    oauth_config: "oauth.OAuthConfig | None" = None,
) -> Any:
    """The Streamable HTTP ASGI app, wrapped in its authentication.

    With OAuth configured, the SDK checks every bearer token and the static
    token is accepted as one of them; otherwise the static token is the only
    credential.
    """
    if oauth_config is None:
        return BearerAuthMiddleware(
            mcp.streamable_http_app(), auth_token, allow_path=allow_path_token
        )
    provider = oauth.configure(mcp, oauth_config, auth_token)
    app = mcp.streamable_http_app()
    oauth.add_routes(app, provider)
    if allow_path_token and auth_token:
        return PathTokenMiddleware(app, auth_token)
    return app


def _oauth_config() -> "oauth.OAuthConfig | None":
    client_id = os.environ.get(oauth.GOOGLE_CLIENT_ID_ENV, "").strip()
    if not client_id:
        return None
    return oauth.OAuthConfig(
        public_url=os.environ.get(oauth.PUBLIC_URL_ENV, "").strip().rstrip("/"),
        google_client_id=client_id,
        google_client_secret=os.environ.get(oauth.GOOGLE_CLIENT_SECRET_ENV, "").strip(),
        signing_key=os.environ.get(oauth.SIGNING_KEY_ENV, "").strip(),
        allowed_emails=frozenset(
            email.lower() for email in _env_list(oauth.ALLOWED_EMAILS_ENV)
        ),
    )


def _env_list(name: str) -> list[str]:
    return [
        value.strip() for value in os.environ.get(name, "").split(",") if value.strip()
    ]


def main(argv: list[str] | None = None) -> None:
    """Main entry point for the server."""
    parser = argparse.ArgumentParser(description="Monarch Money MCP Server")
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http", "http"),
        default=os.environ.get("MONARCH_MCP_TRANSPORT", "stdio"),
        help="MCP transport (env: MONARCH_MCP_TRANSPORT; default: stdio)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("MONARCH_MCP_HOST", "127.0.0.1"),
        help="HTTP bind address (env: MONARCH_MCP_HOST; default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=_port,
        default=os.environ.get("MONARCH_MCP_PORT", "8000"),
        help="HTTP port (env: MONARCH_MCP_PORT; default: 8000)",
    )
    parser.add_argument(
        "--allowed-host",
        action="append",
        default=None,
        help="Additional HTTP Host value, e.g. mcp.example.com (repeatable; "
        "env: MONARCH_MCP_ALLOWED_HOSTS, comma-separated)",
    )
    parser.add_argument(
        "--allowed-origin",
        action="append",
        default=None,
        help="Additional browser Origin, e.g. https://client.example.com (repeatable; "
        "env: MONARCH_MCP_ALLOWED_ORIGINS, comma-separated)",
    )
    args = parser.parse_args(argv)
    # argparse does not check choices for defaults supplied by the environment.
    if args.transport not in ("stdio", "streamable-http", "http"):
        parser.error("MONARCH_MCP_TRANSPORT must be stdio, streamable-http, or http")
    if not args.host.strip():
        parser.error("HTTP host must not be empty")

    # STDIO has no network listener to protect, so the token only applies to HTTP.
    auth_token = (
        os.environ.get(AUTH_ENV_VAR, "").strip() if args.transport != "stdio" else ""
    )
    if auth_token and len(auth_token) < MIN_TOKEN_LENGTH:
        parser.error(
            f"{AUTH_ENV_VAR} must be at least {MIN_TOKEN_LENGTH} characters; "
            "generate one with: openssl rand -hex 32"
        )
    oauth_config = _oauth_config() if args.transport != "stdio" else None
    if oauth_config is not None:
        problems = oauth.config_problems(oauth_config)
        if problems:
            parser.error("; ".join(problems))

    if args.transport != "stdio":
        from mcp.server.transport_security import TransportSecuritySettings

        mcp.settings.host = args.host
        mcp.settings.port = args.port
        # Listening on all interfaces must not disable Host/Origin validation.
        # Remote clients explicitly allow their public hostname (including port).
        mcp.settings.transport_security = TransportSecuritySettings(
            allowed_hosts=[
                "localhost",
                "localhost:*",
                "127.0.0.1",
                "127.0.0.1:*",
                "[::1]",
                "[::1]:*",
                *(
                    args.allowed_host
                    if args.allowed_host is not None
                    else _env_list("MONARCH_MCP_ALLOWED_HOSTS")
                ),
            ],
            allowed_origins=[
                "http://localhost",
                "http://localhost:*",
                "http://127.0.0.1",
                "http://127.0.0.1:*",
                "http://[::1]",
                "http://[::1]:*",
                *(
                    args.allowed_origin
                    if args.allowed_origin is not None
                    else _env_list("MONARCH_MCP_ALLOWED_ORIGINS")
                ),
            ],
        )

    if (
        args.transport != "stdio"
        and not auth_token
        and oauth_config is None
        and args.host not in ("127.0.0.1", "localhost", "::1")
    ):
        logger.warning(
            "Listening on %s without %s set: any client that can reach this "
            "port gets full access to the saved Monarch session. That is fine "
            "if the port is published only on loopback or behind an "
            "authenticating proxy; otherwise set %s.",
            args.host,
            AUTH_ENV_VAR,
            AUTH_ENV_VAR,
        )

    logger.info("Starting Monarch Money MCP Server (%s)...", args.transport)
    try:
        if args.transport == "stdio":
            mcp.run()
        elif auth_token or oauth_config is not None:
            import uvicorn

            path_setting = os.environ.get(AUTH_PATH_ENV_VAR, "").strip().lower()
            allow_path_token = bool(auth_token) and path_setting in ("1", "true", "yes")
            if oauth_config is not None:
                logger.info(
                    "OAuth enabled: Google sign-in for %d allowed account(s)",
                    len(oauth_config.allowed_emails),
                )
            if auth_token:
                logger.info("Bearer token authentication enabled")
            if allow_path_token:
                logger.info("Bearer token also accepted as the first path segment")
            uvicorn.run(
                build_http_app(
                    auth_token,
                    allow_path_token=allow_path_token,
                    oauth_config=oauth_config,
                ),
                host=mcp.settings.host,
                port=mcp.settings.port,
                log_level=mcp.settings.log_level.lower(),
                # The access log prints request paths, which would put a
                # path-embedded token into the server's logs.
                access_log=not allow_path_token,
            )
        else:
            mcp.run(transport="streamable-http")
    except Exception as e:
        logger.error(f"Failed to run server: {str(e)}")
        raise


if __name__ == "__main__":
    main()
