import re
from pathlib import Path

import pytest

from app.web import create_app
from conftest import FakeProm, login as full_login, totp_cfg

ROOT = Path(__file__).resolve().parent.parent
HTTPS = "https://localhost"


def make(**over):
    cfg = {"ADMIN_PASSWORD": "s3cret", "SECRET_KEY": "k", "WIKI_DIR": str(ROOT / "monitor/wiki"),
           "DEVICES_FILE": str(ROOT / "monitor/config/devices.toml"), **totp_cfg(), **over}
    return create_app(cfg, prom_client=FakeProm())


def token(html):
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*name="csrf_token"', html)
    assert m, "csrf_token hidden input missing"
    return m.group(1) or m.group(2)


def login(c, pw="s3cret", csrf=True):
    t = token(c.get("/login", base_url=HTTPS).get_data(as_text=True)) if csrf else "bad"
    return c.post("/login", data={"password": pw, "csrf_token": t}, base_url=HTTPS)


@pytest.fixture
def c():
    return make().test_client()


def test_empty_password_refuses_to_start():
    with pytest.raises(Exception):
        create_app({"ADMIN_PASSWORD": ""}, prom_client=FakeProm())


@pytest.mark.parametrize("path", ["/", "/wiki", "/wiki/index", "/detail/service/smbd"])
def test_unauth_redirects(c, path):
    r = c.get(path, base_url=HTTPS)
    assert r.status_code in (301, 302, 303, 307) and "/login" in r.headers["Location"]


def test_wrong_password_rejected(c):
    r = login(c, "nope")
    assert r.status_code in (200, 401)
    assert c.get("/", base_url=HTTPS).status_code != 200


def test_correct_password_alone_does_not_log_in(c):
    assert login(c).status_code in (302, 303)
    assert c.get("/", base_url=HTTPS).status_code in (301, 302, 303, 307)


def test_password_plus_totp_logs_in(c):
    full_login(c, "s3cret")
    assert c.get("/", base_url=HTTPS).status_code == 200


def test_login_requires_csrf(c):
    r = login(c, csrf=False)
    assert r.status_code in (400, 403)
    assert c.get("/", base_url=HTTPS).status_code != 200


def test_logout(c):
    full_login(c, "s3cret")
    t = token(c.get("/", base_url=HTTPS).get_data(as_text=True))
    assert c.post("/logout", data={"csrf_token": t}, base_url=HTTPS).status_code in (200, 302, 303)
    assert c.get("/", base_url=HTTPS).status_code in (301, 302, 303, 307)


def test_logout_requires_csrf(c):
    full_login(c, "s3cret")
    assert c.post("/logout", base_url=HTTPS).status_code in (400, 403)
    assert c.get("/", base_url=HTTPS).status_code == 200


def test_rate_limit_6th_attempt_429_even_if_correct(c):
    for _ in range(5):
        assert login(c, "bad").status_code != 429
    assert login(c, "s3cret").status_code == 429


def test_rate_limit_configurable():
    c = make(LOGIN_MAX_ATTEMPTS=2).test_client()
    login(c, "x"); login(c, "x")
    assert login(c).status_code == 429


def test_session_cookie_flags(c):
    r = login(c)
    cookie = next(h for h in r.headers.getlist("Set-Cookie") if h.startswith("session="))
    low = cookie.lower()
    assert "secure" in low and "httponly" in low and "samesite=strict" in low


def test_no_mutating_routes():
    methods = {(r.rule, m) for r in make().url_map.iter_rules() for m in r.methods - {"GET", "HEAD", "OPTIONS"}}
    assert methods <= {("/login", "POST"), ("/login/totp", "POST"), ("/login/setup", "POST"),
                       ("/logout", "POST"), ("/settings", "POST"), ("/network/restart", "POST"),
                       ("/network/peer/rename", "POST"), ("/network/peer/allowed-ips", "POST"),
                       ("/network/peer/disable", "POST"), ("/network/peer/enable", "POST"),
                       ("/network/pending/confirm", "POST"), ("/network/pending/revert", "POST"),
                       ("/network/restore", "POST"),
                       ("/settings/devices", "POST"), ("/settings/backups", "POST"),
                       ("/backups/targets/<name>/run", "POST"), ("/backups/targets/<name>/export", "POST")}
