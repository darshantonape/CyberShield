"""Login, signup, logout and forgot-password.

These are the only routes reachable without a session. Everything else is
gated by `backend.auth.middleware`, which fails closed: an unauthenticated
request never reaches a page, an API endpoint, or the scan engine.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, BackgroundTasks, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from backend.auth.service import (
    SESSION_COOKIE,
    SESSION_TTL_HOURS,
    AuthError,
    authenticate,
    create_user,
    end_session,
    start_session,
    user_count,
)
from backend.auth.password_reset import (
    RESET_TTL_MINUTES,
    RateLimiter,
    ResetError,
    request_password_reset,
    reset_error_message,
    reset_password,
    reset_token_status,
)
from backend.core.config import PROJECT_ROOT

__all__ = ["router", "set_session_cookie", "clear_session_cookie"]

router = APIRouter(tags=["auth"])
templates = Jinja2Templates(directory=str(PROJECT_ROOT / "frontend" / "templates"))

COOKIE_MAX_AGE = SESSION_TTL_HOURS * 3600


def set_session_cookie(response: Any, token: str) -> None:
    """Attach the session cookie.

    `secure` is deliberately False: CyberShield is served over plain HTTP on
    127.0.0.1 for local research use, and a Secure cookie would simply never be
    sent, making login impossible. HttpOnly blocks JavaScript access and
    SameSite=Lax blocks cross-site form posts, which is what actually matters
    here. Behind a TLS terminator this should be set to True.
    """
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )


def clear_session_cookie(response: Any) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


def _safe_next(value: str | None) -> str:
    """Sanitise a post-login redirect.

    Only a same-site absolute path is accepted. Without this check the `next`
    parameter would be an open redirect, which is a standard phishing primitive.
    """
    candidate = (value or "").strip()
    if not candidate.startswith("/") or candidate.startswith("//"):
        return "/"
    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        return "/"
    if candidate.startswith(("/login", "/signup", "/logout")):
        return "/"
    return candidate


def _client_host(request: Request) -> str | None:
    return request.client.host if request.client else None


def _render(
    request: Request,
    template: str,
    *,
    status_code: int = 200,
    **ctx: Any,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name=template,
        context={"first_run": user_count() == 0, **ctx},
        status_code=status_code,
    )


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


@router.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request, next: str = "/", error: str | None = None, notice: str | None = None
) -> HTMLResponse:
    if getattr(request.state, "user", None) is not None:
        return RedirectResponse(_safe_next(next), status_code=303)
    return _render(
        request,
        "login.html",
        next=_safe_next(next),
        error=error,
        notice=notice,
        username="",
    )


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),
):
    destination = _safe_next(next)
    try:
        user_id = authenticate(username, password)
    except AuthError as exc:
        # 200, not a redirect: the failure message must not end up in a URL or
        # in browser history alongside the username.
        return _render(
            request,
            "login.html",
            status_code=401,
            next=destination,
            error=str(exc),
            notice=None,
            username=(username or "").strip()[:32],
        )

    token, _expires = start_session(
        user_id,
        user_agent=request.headers.get("user-agent"),
        client_host=_client_host(request),
    )
    response = RedirectResponse(destination, status_code=303)
    set_session_cookie(response, token)
    return response


# ---------------------------------------------------------------------------
# Signup
# ---------------------------------------------------------------------------


@router.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request, error: str | None = None) -> HTMLResponse:
    if getattr(request.state, "user", None) is not None:
        return RedirectResponse("/", status_code=303)
    return _render(request, "signup.html", error=error, username="", email="", full_name="")


@router.post("/signup")
def signup_submit(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    full_name: str = Form(""),
):
    def failure(message: str) -> HTMLResponse:
        return _render(
            request,
            "signup.html",
            status_code=400,
            error=message,
            username=(username or "").strip()[:32],
            email=(email or "").strip()[:254],
            full_name=(full_name or "").strip()[:128],
        )

    if password != password_confirm:
        return failure("The two passwords do not match.")

    try:
        identity = create_user(username, password, email=email, full_name=full_name)
    except AuthError as exc:
        return failure(str(exc))

    # Sign the new operator straight in — this is a single-operator local tool
    # and an approval queue would serve no purpose here.
    token, _expires = start_session(
        identity.id,
        user_agent=request.headers.get("user-agent"),
        client_host=_client_host(request),
    )
    response = RedirectResponse("/", status_code=303)
    set_session_cookie(response, token)
    return response


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


@router.post("/logout")
def logout(request: Request):
    end_session(request.cookies.get(SESSION_COOKIE))
    response = RedirectResponse("/login?notice=You+have+been+signed+out.", status_code=303)
    clear_session_cookie(response)
    return response


@router.get("/logout")
def logout_get(request: Request):
    """Logout is a POST action; a GET here just returns to the login page.

    Kept so a bookmarked /logout does not 405, without making logout reachable
    by a cross-site image tag.
    """
    if getattr(request.state, "user", None) is None:
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/", status_code=303)


# ---------------------------------------------------------------------------
# Forgot password
# ---------------------------------------------------------------------------

# Per client address. Generous enough for a person who mistypes their email a
# few times; tight enough that the form cannot be used to spray reset mail.
_forgot_limiter = RateLimiter(limit=5, window_seconds=15 * 60)
# Failed redemptions per client address. Tokens are 256-bit so guessing is
# already infeasible; this just stops a script hammering the endpoint.
_reset_limiter = RateLimiter(limit=10, window_seconds=15 * 60)

_FORGOT_SENT = (
    "If an account exists with that information, a password reset link has been "
    f"sent. The link is valid for {RESET_TTL_MINUTES} minutes and can be used once."
)
_RESET_DONE = "Your password has been reset successfully. Please log in with your new password."
_THROTTLED = "Too many attempts from this address. Please wait a few minutes and try again."


def _no_store(response: HTMLResponse) -> HTMLResponse:
    """Headers for pages that carry a reset token.

    no-referrer stops the token leaving in a Referer header; no-store keeps the
    page out of the browser and proxy caches.
    """
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request) -> HTMLResponse:
    if getattr(request.state, "user", None) is not None:
        return RedirectResponse("/", status_code=303)
    return _render(request, "forgot_password.html", notice=None, error=None, identifier="")


@router.post("/forgot-password", response_class=HTMLResponse)
def forgot_password_submit(
    request: Request,
    background: BackgroundTasks,
    identifier: str = Form(""),
) -> HTMLResponse:
    """Always the same page, status and timing, whether or not the account exists.

    The lookup, token issue and delivery run as a background task after the
    response is produced, so neither a database write nor an SMTP round-trip
    for a real account can be distinguished by response time.
    """
    host = _client_host(request)
    if not _forgot_limiter.hit(host):
        return _render(
            request, "forgot_password.html", status_code=429,
            notice=None, error=_THROTTLED, identifier="",
        )

    if (identifier or "").strip():
        background.add_task(
            request_password_reset,
            identifier,
            request_base_url=str(request.base_url),
            client_host=host,
        )
    # The identifier is deliberately not echoed back.
    return _render(
        request, "forgot_password.html", notice=_FORGOT_SENT, error=None, identifier=""
    )


@router.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request, token: str = "") -> HTMLResponse:
    reason = reset_token_status(token)
    if reason is not None:
        return _no_store(
            _render(
                request, "reset_password.html", status_code=400,
                token="", error=None, invalid=reset_error_message(reason),
            )
        )
    return _no_store(
        _render(request, "reset_password.html", token=token, error=None, invalid=None)
    )


@router.post("/reset-password", response_class=HTMLResponse)
def reset_password_submit(
    request: Request,
    token: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
):
    host = _client_host(request)

    def form_error(message: str, status_code: int = 400) -> HTMLResponse:
        # Token kept so the operator can correct the password and retry.
        return _no_store(
            _render(
                request, "reset_password.html", status_code=status_code,
                token=token, error=message, invalid=None,
            )
        )

    if _reset_limiter.blocked(host):
        return form_error(_THROTTLED, status_code=429)

    if new_password != confirm_password:
        return form_error("The two passwords do not match.")

    try:
        reset_password(token, new_password, client_host=host)
    except ResetError as exc:
        _reset_limiter.hit(host)
        return _no_store(
            _render(
                request, "reset_password.html", status_code=400,
                token="", error=None, invalid=str(exc),
            )
        )
    except AuthError as exc:
        return form_error(str(exc))

    # Every session for the account is revoked; drop this browser's cookie too.
    response = RedirectResponse(f"/login?{urlencode({'notice': _RESET_DONE})}", status_code=303)
    clear_session_cookie(response)
    return response
