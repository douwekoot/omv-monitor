import base64
import hashlib
import json
import re
import stat
import time
from pathlib import Path

import pytest

from app import totp
from app.web import create_app
from conftest import FakeProm, HTTPS, TOTP_SECRET, csrf_of, enroll

ROOT = Path(__file__).resolve().parent.parent
NOW = 1_800_000_010.0  # fixed so step maths is deterministic


# --- module ---------------------------------------------------------------

def test_rfc6238_vector():
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert totp.code_at(secret, 59) == "287082"


def test_new_secret_is_160_bit_base32():
    s = totp.new_secret()
    assert len(base64.b32decode(s)) == 20 and s != totp.new_secret()


def test_verify_window_and_replay():
    step = int(NOW // 30)
    code = lambda off: totp.code_at(TOTP_SECRET, NOW + 30 * off)
    assert totp.verify(TOTP_SECRET, code(0), NOW, None) == step
    assert totp.verify(TOTP_SECRET, code(-1), NOW, None) == step - 1
    assert totp.verify(TOTP_SECRET, code(1), NOW, None) == step + 1
    assert totp.verify(TOTP_SECRET, code(2), NOW, None) is None
    assert totp.verify(TOTP_SECRET, code(-2), NOW, None) is None
    assert totp.verify(TOTP_SECRET, code(0), NOW, step) is None  # replay
    assert totp.verify(TOTP_SECRET, code(-1), NOW, step) is None  # older than last_step
    assert totp.verify(TOTP_SECRET, "000000x", NOW, None) is None


def test_otpauth_uri():
    u = totp.otpauth_uri(TOTP_SECRET)
    assert u.startswith("otpauth://totp/") and f"secret={TOTP_SECRET}" in u and "omv-monitor" in u


def test_recovery_codes_unique():
    codes = totp.new_recovery_codes()
    assert len(codes) == 10 and len(set(codes)) == 10 and totp.new_recovery_codes(3).__len__() == 3


def test_save_load_atomic_mode_0600(tmp_path):
    p = tmp_path / "sub" / "totp.json"
    assert totp.load(p) is None
    state = {"secret": TOTP_SECRET, "last_step": None, "recovery": ["ab"]}
    p.parent.mkdir()
    totp.save(p, state)
    assert totp.load(p) == state
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert [f.name for f in p.parent.iterdir()] == ["totp.json"]


# --- web flow -------------------------------------------------------------

@pytest.fixture
def env(tmp_path):
    return {"tf": tmp_path / "totp.json", "audit": tmp_path / "audit.jsonl", "tmp": tmp_path}


def build(env, **over):
    cfg = {"ADMIN_PASSWORD": "pw", "SECRET_KEY": "k", "WIKI_DIR": str(ROOT / "monitor/wiki"),
           "DEVICES_FILE": str(ROOT / "monitor/config/devices.toml"), "TOTP_FILE": str(env["tf"]),
           "SETTINGS_FILE": str(env["tmp"] / "settings.json"), "AUDIT_FILE": str(env["audit"]), **over}
    return create_app(cfg, prom_client=FakeProm())


def post(c, path, **data):
    t = csrf_of(c.get(path if path != "/login" else "/login", base_url=HTTPS).get_data(as_text=True))
    return c.post(path, data={"csrf_token": t, **data}, base_url=HTTPS)


def password(c, pw="pw"):
    return post(c, "/login", password=pw)


def authed(c):
    return c.get("/", base_url=HTTPS).status_code == 200


def now_code(off=0):
    return totp.code_at(TOTP_SECRET, time.time() + 30 * off)


def test_password_alone_redirects_to_totp_and_grants_nothing(env):
    enroll(env["tf"])
    c = build(env).test_client()
    r = password(c)
    assert r.status_code in (302, 303) and r.headers["Location"].endswith("/login/totp")
    assert not authed(c)
    assert c.get("/login/totp", base_url=HTTPS).status_code == 200


def test_totp_page_without_password_redirects_to_login(env):
    enroll(env["tf"])
    c = build(env).test_client()
    r = c.get("/login/totp", base_url=HTTPS)
    assert r.status_code in (302, 303) and "/login" in r.headers["Location"]
    r = c.get("/login/setup", base_url=HTTPS)
    assert r.status_code in (302, 303)


def test_valid_code_logs_in_and_saves_last_step(env):
    enroll(env["tf"])
    c = build(env).test_client()
    password(c)
    r = post(c, "/login/totp", code=now_code())
    assert r.status_code in (302, 303)
    assert authed(c)
    assert totp.load(env["tf"])["last_step"] is not None


def test_wrong_code_rejected(env):
    enroll(env["tf"])
    c = build(env).test_client()
    password(c)
    r = post(c, "/login/totp", code="000000")
    assert r.status_code in (200, 401)
    assert not authed(c)


def test_replayed_code_rejected(env):
    enroll(env["tf"])
    app = build(env)
    c1, c2 = app.test_client(), app.test_client()
    code = now_code()
    password(c1); post(c1, "/login/totp", code=code)
    assert authed(c1)
    password(c2)
    post(c2, "/login/totp", code=code)
    assert not authed(c2)


def test_totp_failures_rate_limited(env):
    enroll(env["tf"])
    c = build(env).test_client()
    password(c)
    for _ in range(5):
        assert post(c, "/login/totp", code="000000").status_code != 429
    assert post(c, "/login/totp", code=now_code()).status_code == 429
    assert not authed(c)


def test_totp_post_requires_csrf(env):
    enroll(env["tf"])
    c = build(env).test_client()
    password(c)
    assert c.post("/login/totp", data={"code": now_code()}, base_url=HTTPS).status_code in (400, 403)
    assert not authed(c)


def test_recovery_code_works_once_and_is_removed(env):
    enroll(env["tf"], recovery=["abcd-1234", "wxyz-9876"])
    app = build(env)
    c = app.test_client()
    password(c); post(c, "/login/totp", code="abcd-1234")
    assert authed(c)
    st = totp.load(env["tf"])
    assert st["recovery"] == [hashlib.sha256(b"wxyz-9876").hexdigest()]
    c2 = app.test_client()
    password(c2); post(c2, "/login/totp", code="abcd-1234")
    assert not authed(c2)


def test_pending_expires_after_300s(env, monkeypatch):
    enroll(env["tf"])
    c = build(env).test_client()
    password(c)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 301)
    r = c.get("/login/totp", base_url=HTTPS)
    assert r.status_code in (302, 303) and not r.headers["Location"].endswith("/login/totp")
    t = csrf_of(c.get("/login", base_url=HTTPS).get_data(as_text=True))
    post_r = c.post("/login/totp", data={"code": totp.code_at(TOTP_SECRET, real() + 301), "csrf_token": t},
                    base_url=HTTPS)
    assert not authed(c)


# --- setup ----------------------------------------------------------------

def setup_page(c):
    html = c.get("/login/setup", base_url=HTTPS).get_data(as_text=True)
    secret = re.search(r"\b([A-Z2-7]{32})\b", html)
    assert secret, "base32 secret must be shown as text"
    return html, secret.group(1)


def test_no_state_leads_to_setup(env):
    c = build(env).test_client()
    r = password(c)
    assert r.headers["Location"].endswith("/login/setup")
    assert not authed(c)


def test_setup_shows_secret_uri_and_10_recovery_codes(env):
    c = build(env).test_client()
    password(c)
    html, secret = setup_page(c)
    assert "otpauth://totp/" in html and f"secret={secret}" in html
    assert len(re.findall(r"<code[^>]*>[^<]+</code>", html)) >= 10
    assert not env["tf"].exists()  # nothing saved before a valid code


def test_setup_saves_only_after_valid_code(env):
    app = build(env)
    c = app.test_client()
    password(c)
    html, secret = setup_page(c)
    r = post(c, "/login/setup", code="000000")
    assert r.status_code in (200, 401) and not env["tf"].exists() and not authed(c)
    r = post(c, "/login/setup", code=totp.code_at(secret, time.time()))
    assert r.status_code in (302, 303)
    st = totp.load(env["tf"])
    assert st["secret"] == secret and len(st["recovery"]) == 10
    assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in st["recovery"])
    assert stat.S_IMODE(env["tf"].stat().st_mode) == 0o600
    assert authed(c)


def test_recovery_codes_stored_only_hashed_and_shown_once(env):
    c = build(env).test_client()
    password(c)
    html, secret = setup_page(c)
    shown = re.findall(r"<code[^>]*>([^<]+)</code>", html)
    post(c, "/login/setup", code=totp.code_at(secret, time.time()))
    raw = env["tf"].read_text()
    assert all(code.strip() not in raw for code in shown if len(code.strip()) > 6)
    # a fresh password login goes to the code page, never setup again
    c2 = build(env).test_client()
    r = password(c2)
    assert r.headers["Location"].endswith("/login/totp")
    page = c2.get("/login/totp", base_url=HTTPS).get_data(as_text=True)
    assert not any(code.strip() in page for code in shown if len(code.strip()) > 6)


def setup_file(env):
    return env["tf"].with_name("totp-setup.json")


def test_setup_state_is_server_side_not_in_cookie(env):
    app = build(env)
    c = app.test_client()
    password(c)
    html, secret = setup_page(c)
    shown = [x.strip() for x in re.findall(r"<code[^>]*>([^<]+)</code>", html) if len(x.strip()) > 6]
    raw = c.get_cookie(app.config["SESSION_COOKIE_NAME"]).value
    sess = app.session_interface.get_signing_serializer(app).loads(raw)
    assert isinstance(sess["setup"], str)
    blob = json.dumps(sess)
    assert secret not in blob and not any(x in blob for x in shown)
    st = json.loads(setup_file(env).read_text())
    assert st["id"] == sess["setup"] and st["secret"] == secret and len(st["codes"]) == 10
    assert stat.S_IMODE(setup_file(env).stat().st_mode) == 0o600


def test_setup_secret_stable_across_get_and_post(env):
    c = build(env).test_client()
    password(c)
    _, secret = setup_page(c)
    r = post(c, "/login/setup", code="000000")
    assert r.status_code == 401 and secret in r.get_data(as_text=True)
    assert setup_page(c)[1] == secret


def test_enrollment_deletes_setup_file(env):
    c = build(env).test_client()
    password(c)
    _, secret = setup_page(c)
    assert setup_file(env).exists()
    post(c, "/login/setup", code=totp.code_at(secret, time.time()))
    assert env["tf"].exists() and not setup_file(env).exists()


@pytest.mark.parametrize("junk", ["{not json", None])
def test_missing_or_corrupt_setup_file_starts_fresh(env, junk):
    c = build(env).test_client()
    password(c)
    _, secret = setup_page(c)
    if junk is None:
        setup_file(env).unlink()
    else:
        setup_file(env).write_text(junk)
    _, new = setup_page(c)
    assert new != secret
    post(c, "/login/setup", code=totp.code_at(new, time.time()))
    assert totp.load(env["tf"])["secret"] == new and authed(c)


def test_expired_setup_file_is_replaced(env):
    c = build(env).test_client()
    password(c)
    _, secret = setup_page(c)
    st = json.loads(setup_file(env).read_text())
    st["t"] = time.time() - 301
    setup_file(env).write_text(json.dumps(st))
    assert setup_page(c)[1] != secret


def test_setup_unreachable_once_enrolled(env):
    enroll(env["tf"])
    c = build(env).test_client()
    password(c)
    r = c.get("/login/setup", base_url=HTTPS)
    assert r.status_code in (302, 303, 403, 404) and "setup" not in r.headers.get("Location", "")
    t = csrf_of(c.get("/login/totp", base_url=HTTPS).get_data(as_text=True))
    c.post("/login/setup", data={"code": now_code(), "csrf_token": t}, base_url=HTTPS)
    assert json.loads(env["tf"].read_text())["secret"] == TOTP_SECRET and not authed(c)


def test_setup_not_reachable_after_login_complete(env):
    enroll(env["tf"])
    c = build(env).test_client()
    password(c); post(c, "/login/totp", code=now_code())
    r = c.get("/login/setup", base_url=HTTPS)
    assert r.status_code != 200


def test_setup_requires_csrf(env):
    c = build(env).test_client()
    password(c)
    html, secret = setup_page(c)
    r = c.post("/login/setup", data={"code": totp.code_at(secret, time.time())}, base_url=HTTPS)
    assert r.status_code in (400, 403) and not env["tf"].exists()


# --- audit ----------------------------------------------------------------

def audit_lines(env):
    return [json.loads(x) for x in env["audit"].read_text().splitlines()] if env["audit"].exists() else []


def test_events_audited_without_secrets(env):
    enroll(env["tf"], recovery=["abcd-1234"])
    c = build(env).test_client()
    password(c); post(c, "/login/totp", code="123456")
    password(c); post(c, "/login/totp", code="abcd-1234")
    lines = audit_lines(env)
    assert any(not e["ok"] for e in lines) and any(e["ok"] for e in lines)
    raw = env["audit"].read_text()
    assert "abcd-1234" not in raw and TOTP_SECRET not in raw and "123456" not in raw


def test_enrollment_audited_without_secrets(env):
    c = build(env).test_client()
    password(c)
    html, secret = setup_page(c)
    shown = re.findall(r"<code[^>]*>([^<]+)</code>", html)
    post(c, "/login/setup", code=totp.code_at(secret, time.time()))
    raw = env["audit"].read_text()
    assert audit_lines(env) and secret not in raw
    assert not any(s.strip() in raw for s in shown if len(s.strip()) > 6)


# --- repo hygiene ---------------------------------------------------------

def test_no_new_dependency_and_forms_have_csrf_no_inline():
    reqs = (ROOT / "monitor/requirements.txt").read_text().lower()
    assert "pyotp" not in reqs and "qrcode" not in reqs
    for name in ("login_totp.html", "totp_setup.html"):
        t = (ROOT / "monitor/app/templates" / name).read_text()
        assert 'name="csrf_token"' in t or "csrf_token()" in t
        assert "<script" not in t and "style=" not in t and "<style" not in t


def test_state_file_gitignored():
    assert "monitor/data/totp.json" in (ROOT / ".gitignore").read_text().split()


def test_recovery_wiki_explains_reset():
    t = (ROOT / "monitor/wiki/recovery.md").read_text().lower()
    assert "totp" in t and "totp.json" in t and "delete" in t


def test_corrupt_state_fails_closed(tmp_path):
    import pytest
    from app import totp
    p = tmp_path / "totp.json"
    p.write_text("{oops")
    with pytest.raises(ValueError):
        totp.load(p)
    assert totp.load(tmp_path / "missing.json") is None
