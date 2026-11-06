import hmac
import secrets
import time
from functools import wraps

from flask import abort, redirect, request, session, url_for


class RateLimiter:
    """Per-key failure counter in memory (per worker process)."""

    def __init__(self, max_attempts, window_s):
        self.max, self.window, self.fails = max_attempts, window_s, {}

    def _recent(self, key):
        now = time.monotonic()
        self.fails[key] = [t for t in self.fails.get(key, []) if now - t < self.window]
        return self.fails[key]

    def blocked(self, key):
        return len(self._recent(key)) >= self.max

    def fail(self, key):
        self._recent(key).append(time.monotonic())


def password_ok(given, expected):
    return hmac.compare_digest(given.encode(), expected.encode())


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    sent = request.form.get("csrf_token", "")
    if not hmac.compare_digest(sent.encode(), session.get("csrf", "").encode()) or "csrf" not in session:
        abort(400)


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("auth"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper
