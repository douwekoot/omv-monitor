"""Web-layer security regressions: CSRF on every POST, login flow, headers, cookie, startup checks."""
import re
import time
from datetime import timedelta
from pathlib import Path

import pytest

from app import totp
from app.web import create_app
from conftest import HTTPS, TOTP_SECRET, FakeProm, csrf_of, login as full_login, totp_cfg

ROOT = Path(__file__).resolve().parent.parent
PW = "s3cret-pass-phrase"


def make(enrolled=True, tmp_path=None, **over):
    cfg = {"ADMIN_PASSWORD": PW, "SECRET_KEY": "k" * 32, "WIKI_DIR": str(ROOT / "monitor/wiki"),
           "DEVICES_FILE": str(ROOT / "monitor/config/devices.toml"), **(totp_cfg(tmp_path) if enrolled else {}), **over}
    return create_app(cfg, prom_client=FakeProm())


def password_step(c):
    t = csrf_of(c.get("/login", base_url=HTTPS).get_data(as_text=True))
    return c.post("/login", data={"password": PW, "csrf_token": t}, base_url=HTTPS)


def post_rules(app):
    return sorted((r.rule, r.endpoint) for r in app.url_map.iter_rules() if "POST" in r.methods)


def concrete(rule):
    return re.sub(r"<[^>]+>", "pc", rule)


# --- CSRF -----------------------------------------------------------------

@pytest.mark.parametrize("token", [None, "bad", ""])
def test_every_post_route_rejects_missing_or_bad_csrf(tmp_path, token):
    seen = 0
    for rule, _ in post_rules(make()):
        if rule == "/login/setup":
            continue  # redirects once enrolled; tested on an un-enrolled app below
        c = make().test_client()  # fresh app: a TOTP step can't be replayed
        if rule in ("/login", "/login/totp", "/login/setup"):
            if rule != "/login":
                password_step(c)  # reach the second-factor page legitimately
        else:
            full_login(c, PW)
        data = {} if token is None else {"csrf_token": token}
        if rule == "/login/totp":
            data["code"] = totp.code_at(TOTP_SECRET, time.time())
        if rule == "/login":
            data["password"] = PW
        r = c.post(concrete(rule), data=data, base_url=HTTPS)
        assert r.status_code in (400, 403), f"{rule} accepted a request with csrf_token={token!r}: {r.status_code}"
        if rule != "/login/setup":  # setup is unreachable once enrolled; covered below
            assert c.get("/", base_url=HTTPS).status_code != 200 or rule not in ("/login", "/login/totp"), rule
        seen += 1
    assert seen >= 14  # the parametrization really walked the url_map


def test_setup_post_rejects_bad_csrf_when_not_enrolled(tmp_path):
    c = make(enrolled=False, tmp_path=tmp_path, SETTINGS_FILE=str(tmp_path / "settings.json")).test_client()
    password_step(c)
    assert c.get("/login/setup", base_url=HTTPS).status_code == 200
    assert c.post("/login/setup", data={"code": "123456", "csrf_token": "bad"}, base_url=HTTPS).status_code in (400, 403)


def test_csrf_token_from_other_session_rejected(tmp_path):
    a, b = make().test_client(), make(SECRET_KEY="j" * 32).test_client()
    full_login(a, PW)
    full_login(b, PW)
    tb = csrf_of(b.get("/settings", base_url=HTTPS).get_data(as_text=True))
    assert a.post("/logout", data={"csrf_token": tb}, base_url=HTTPS).status_code in (400, 403)


# --- login flow -----------------------------------------------------------

def test_totp_and_setup_unreachable_without_password_step(tmp_path):
    for enrolled, path in ((True, "/login/totp"), (False, "/login/setup")):
        c = make(enrolled=enrolled, SETTINGS_FILE=str(tmp_path / f"s{enrolled}.json")).test_client()
        r = c.get(path, base_url=HTTPS)
        assert r.status_code in (301, 302, 303, 307) and "/login" in r.headers["Location"] and not r.headers["Location"].endswith(path)
        t = "x"
        r = c.post(path, data={"code": totp.code_at(TOTP_SECRET, time.time()), "csrf_token": t}, base_url=HTTPS)
        assert r.status_code in (302, 303, 400, 403)
        assert c.get("/", base_url=HTTPS).status_code in (301, 302, 303, 307)


def test_setup_attempts_rate_limited(tmp_path):
    c = make(enrolled=False, LOGIN_MAX_ATTEMPTS=3, SETTINGS_FILE=str(tmp_path / "settings.json")).test_client()
    password_step(c)
    codes = []
    for _ in range(5):
        t = csrf_of(c.get("/login/setup", base_url=HTTPS).get_data(as_text=True))
        codes.append(c.post("/login/setup", data={"code": "000000", "csrf_token": t}, base_url=HTTPS).status_code)
    assert codes[-1] == 429


def test_totp_blocked_after_limit_even_with_valid_code(tmp_path):
    c = make(tmp_path=tmp_path, LOGIN_MAX_ATTEMPTS=3).test_client()
    password_step(c)
    for _ in range(3):
        t = csrf_of(c.get("/login/totp", base_url=HTTPS).get_data(as_text=True))
        c.post("/login/totp", data={"code": "000000", "csrf_token": t}, base_url=HTTPS)
    t = csrf_of(c.get("/login/totp", base_url=HTTPS).get_data(as_text=True))
    r = c.post("/login/totp", data={"code": totp.code_at(TOTP_SECRET, time.time()), "csrf_token": t}, base_url=HTTPS)
    assert r.status_code == 429
    assert c.get("/", base_url=HTTPS).status_code != 200


def test_login_clears_preexisting_session_state(tmp_path):
    c = make(tmp_path=tmp_path).test_client()
    c.get("/login", base_url=HTTPS)
    with c.session_transaction(base_url=HTTPS) as s:
        s["planted"] = "attacker"
        s["setup"] = "attacker-id"
        before = s["csrf"]
    full_login(c, PW)
    with c.session_transaction(base_url=HTTPS) as s:
        assert s.get("auth") and "planted" not in s and "setup" not in s and "pending" not in s
        assert s.get("csrf") != before


@pytest.mark.parametrize("nxt", ["https://evil.example/", "//evil.example/", "/\\evil.example", "javascript:alert(1)"])
def test_open_redirect_params_ignored(tmp_path, nxt):
    c = make(tmp_path=tmp_path).test_client()
    t = csrf_of(c.get("/login", query_string={"next": nxt}, base_url=HTTPS).get_data(as_text=True))
    r = c.post("/login", query_string={"next": nxt}, data={"password": PW, "csrf_token": t, "next": nxt}, base_url=HTTPS)
    r2 = c.get("/login/totp", query_string={"next": nxt}, base_url=HTTPS)
    t = csrf_of(r2.get_data(as_text=True))
    r3 = c.post("/login/totp", query_string={"next": nxt},
                data={"code": totp.code_at(TOTP_SECRET, time.time()), "csrf_token": t, "next": nxt}, base_url=HTTPS)
    for resp in (r, r3):
        loc = resp.headers.get("Location", "")
        assert "evil" not in loc and "javascript" not in loc


# --- headers and cookie ---------------------------------------------------

def assert_secure_headers(r, authed=False):
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("Referrer-Policy"), "Referrer-Policy missing"
    if authed:
        assert "no-store" in r.headers.get("Cache-Control", "")


def test_headers_on_every_kind_of_response(tmp_path):
    c = make(tmp_path=tmp_path).test_client()
    for path in ("/login", "/", "/static/chart.js", "/nope-404"):  # page, redirect, send_file, error
        assert_secure_headers(c.get(path, base_url=HTTPS))
    assert_secure_headers(c.post("/login", data={"password": "x", "csrf_token": "bad"}, base_url=HTTPS))  # 400
    full_login(c, PW)
    for path in ("/", "/settings", "/wiki", "/nope-404", "/static/chart.js"):
        assert_secure_headers(c.get(path, base_url=HTTPS), authed=path != "/static/chart.js")
    assert_secure_headers(c.post("/logout", data={}, base_url=HTTPS))  # 400 while authed


def test_headers_on_rate_limited_response(tmp_path):
    c = make(tmp_path=tmp_path, LOGIN_MAX_ATTEMPTS=1).test_client()
    for _ in range(2):
        t = csrf_of(c.get("/login", base_url=HTTPS).get_data(as_text=True))
        r = c.post("/login", data={"password": "bad", "csrf_token": t}, base_url=HTTPS)
    assert r.status_code == 429
    assert_secure_headers(r)


def test_session_cookie_bounded_lifetime_and_flags(tmp_path):
    app = make(tmp_path=tmp_path)
    assert app.config["SESSION_COOKIE_SECURE"] and app.config["SESSION_COOKIE_HTTPONLY"]
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Strict"
    assert app.config["PERMANENT_SESSION_LIFETIME"] <= timedelta(days=1)
    c = app.test_client()
    cookies = []
    t = csrf_of(c.get("/login", base_url=HTTPS).get_data(as_text=True))
    cookies += c.post("/login", data={"password": PW, "csrf_token": t}, base_url=HTTPS).headers.getlist("Set-Cookie")
    t = csrf_of(c.get("/login/totp", base_url=HTTPS).get_data(as_text=True))
    cookies += c.post("/login/totp", data={"code": totp.code_at(TOTP_SECRET, time.time()), "csrf_token": t},
                      base_url=HTTPS).headers.getlist("Set-Cookie")
    final = [h for h in cookies if h.startswith("session=")][-1].lower()
    assert "secure" in final and "httponly" in final and "samesite=strict" in final
    assert "expires=" in final or "max-age=" in final  # not an unbounded browser-session cookie


# --- startup --------------------------------------------------------------

def test_missing_or_empty_secret_key_refuses_to_start(monkeypatch):
    monkeypatch.delenv("APP_SECRET_KEY", raising=False)
    base = {"ADMIN_PASSWORD": PW, "WIKI_DIR": str(ROOT / "monitor/wiki"), "DEVICES_FILE": str(ROOT / "monitor/config/devices.toml")}
    with pytest.raises(Exception):
        create_app(dict(base), prom_client=FakeProm())
    for bad in ("", None):
        with pytest.raises(Exception):
            create_app({**base, "SECRET_KEY": bad}, prom_client=FakeProm())
