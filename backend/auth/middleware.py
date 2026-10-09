"""Request gate: nothing but the login flow runs unauthenticated.

Implemented as middleware rather than a per-route dependency on purpose. A
dependency has to be remembered on every new route; a route added later without
it would be silently public. Here the default is "denied", and the exemptions
are a short, explicit list that can be read in one glance.

Failure modes are deliberately different by surface:
  * an HTML page redirects to /login, preserving where the operator was going
  * an /api/* call returns 401 JSON, so a script gets a machine-readable answer
    rather than a login page it would try to parse
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.types import ASGIApp

from backend.auth.service import SESSION_COOKIE, resolve_session

__all__ = ["AuthenticationMiddleware", "PUBLIC_PATHS", "PUBLIC_PREFIXES"]

# Exact paths reachable without a session.
PUBLIC_PATHS = frozenset(
    {
        # The marketing landing page. It renders the product overview for a
        # visitor and the dashboard for a signed-in operator; it exposes no
        # scope, findings, or configuration to an anonymous request.
        "/",
        "/login",
        "/signup",
        "/logout",
        # Forgot-password. The request form reveals nothing about accounts, and
        # the reset form does nothing without a valid single-use token.
        "/forgot-password",
        "/reset-password",
        "/favicon.ico",
        # Liveness only. Reports no scope, no findings, and no configuration.
        "/api/health",
    }
)

# Prefixes reachable without a session. Static assets only — the logo and
# stylesheet are needed to render the login page itself.
PUBLIC_PREFIXES = ("/static/",)


def _is_public(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Attach `request.state.user`, or refuse the request."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        token = request.cookies.get(SESSION_COOKIE)
        # resolve_session touches SQLite; run it off the event loop so a slow
        # disk cannot stall every other request.
        user = await _resolve(token)
        request.state.user = user

        path = request.url.path

        if user is None and not _is_public(path):
            if path.startswith("/api/"):
                return JSONResponse(
                    {
                        "detail": (
                            "Authentication required. Sign in at /login, or POST "
                            "/login to obtain a session cookie."
                        )
                    },
                    status_code=401,
                )
            destination = request.url.path
            if request.url.query:
                destination = f"{destination}?{request.url.query}"
            return RedirectResponse(
                f"/login?next={_quote(destination)}", status_code=303
            )

        return await call_next(request)


async def _resolve(token: str | None):
    if not token:
        return None
    import anyio

    return await anyio.to_thread.run_sync(lambda: resolve_session(token))


def _quote(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="/?=&")
