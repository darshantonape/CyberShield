# Operator authentication

CyberShield executes network scans and, on eligible laboratory targets,
firewall changes. Both are attributed to a person in the audit log, so the
system needs to know who that person is. This document states exactly what the
authentication layer does and — equally important for the write-up — what it
deliberately does not.

## Model

| | Decision |
|---|---|
| Accounts | Local, in the project's own SQLite database. No directory, no OAuth, no external identity provider. |
| Password hashing | bcrypt, cost factor 12. |
| Password storage | Only the hash. There is no column able to hold a plaintext password. |
| Session transport | An opaque 256-bit random token in an `HttpOnly`, `SameSite=Lax` cookie. |
| Session storage | A row in `user_sessions` holding **only the SHA-256 of the token**. |
| Session lifetime | 8 hours, then refused. Expired rows are purged a day later. |
| Logout | A real revocation (`revoked_at` is set), not a request that the client forget a cookie. |
| Roles | `operator` and `admin` exist as a field. No behaviour currently branches on it. |

## Why database sessions rather than a signed cookie

Three reasons, in order of weight:

1. **Logout has to mean something.** A signed cookie is valid until it expires;
   the server cannot withdraw it. A database row can be revoked, which matters
   for a tool that can change a firewall.
2. **No new dependency.** `itsdangerous`, which Starlette's `SessionMiddleware`
   requires, is not installed in this environment, and the environment is
   already constrained (see the README note on Homebrew Python).
3. **No server-side secret to manage.** There is no signing key to generate,
   store, rotate, or accidentally commit.

The cost is a SQLite read per request. It is run off the event loop so a slow
disk cannot stall the server.

## The request gate

`backend/auth/middleware.py` is **middleware, not a per-route dependency**. That
is the whole design decision: a dependency has to be remembered on every new
route, and a route added later without it would be silently public. Here the
default is denied, and the exemptions are a short list that can be read at a
glance:

```
/login   /signup   /logout   /favicon.ico   /api/health   /static/*
```

`/api/health` reports liveness only — no scope, no findings, no configuration.

Failure behaviour differs by surface, on purpose:

| Request | Response |
|---|---|
| HTML page, no session | `303` to `/login?next=<path>` |
| `/api/*`, no session | `401` with a JSON `detail` |

A script calling the API gets a machine-readable answer rather than a login page
it would try to parse.

## Properties the tests hold

From `tests/unit/test_auth.py` and `tests/unit/test_web.py`:

- No plaintext password appears on the user row, and no password or bcrypt hash
  appears in the audit log — including on a failed login.
- Two operators with the same password get different hashes (distinct salts).
- A password over 128 bytes is refused rather than silently truncated. bcrypt
  ignores bytes past 72, so accepting a longer one would let two different
  passwords open the same account.
- "No such user" and "wrong password" return the **identical** message, and
  a nonexistent account is still verified against a real bcrypt hash so the
  response time does not disclose whether it exists.
- The stored token is the SHA-256 of the cookie, never the cookie itself.
- A revoked, expired, unknown, or disabled-account session resolves to nothing.
- Every page and API route listed above refuses an unauthenticated request, and
  a scan cannot be started without a session.

## Deliberately not implemented

Stated so a reader does not mistake absence for oversight:

- **No password reset or email flow.** There is no mail path in this project, and
  a reset token delivered nowhere is worse than no reset at all. An operator who
  loses a password deletes the row and signs up again.
- **No account lockout.** Consecutive failures are counted and audited, but a
  lockout on a single-operator local tool is a self-inflicted denial of service.
  bcrypt at cost 12 already puts a hard floor under guessing rate.
- **No MFA.** Out of scope for a locally-served research tool.
- **No CSRF token.** The session cookie is `SameSite=Lax`, which blocks
  cross-site form posts, and the app is served on `127.0.0.1`. A token would be
  the right call behind a real origin; it is noted here rather than pretended.
- **`Secure` is not set on the cookie.** The app is served over plain HTTP on
  loopback, and a `Secure` cookie would never be sent, making login impossible.
  Behind a TLS terminator this must be changed — the single place to do it is
  `set_session_cookie` in `backend/auth/routes.py`.

## What authentication does *not* grant

Signing in authorizes **nothing** about targets. The two are separate systems:

- Being signed in does not put any address in scope.
- A scan is still refused unless the target is in
  `config/authorized_targets.yaml`.
- Remediation is still refused unless the target is `is_lab: true` with a usable
  SSH management channel, and every one of the nine decision rules passes.

An authenticated operator is a *named* operator, not a privileged one.
