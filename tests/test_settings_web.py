import json
import re
from pathlib import Path

import pytest

from app import settings, web
from app.web import create_app
from conftest import login, totp_cfg

ROOT = Path(__file__).resolve().parent.parent
HTTPS = "https://localhost"
NOW = 1700000300  # peer aaaaaaaa handshake 200 s ago, bbbbbbbb 100 s ago


def make(prom, path):
    return create_app({"ADMIN_PASSWORD": "pw", "SECRET_KEY": "k", "WIKI_DIR": str(ROOT / "monitor/wiki"),
                       "DEVICES_FILE": str(ROOT / "monitor/config/devices.toml"),
                       "SETTINGS_FILE": str(path), **totp_cfg(Path(path).parent)}, prom_client=prom)


def token(html):
    t = re.search(r'name="csrf_token"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*name="csrf_token"', html)
    return t.group(1) or t.group(2)


@pytest.fixture
def sfile(tmp_path):
    return tmp_path / "settings.json"


@pytest.fixture
def client(fake, sfile):
    return login(make(fake, sfile).test_client())


def put(sfile, **values):
    sfile.write_text(json.dumps(values))


def get(c, path):
    return c.get(path, base_url=HTTPS)


def form(**over):
    d = {"default_range": "24h", "refresh_s": "0", "byte_units": "binary",
         "handshake_good_s": "180", "panels": list(settings.PANELS)}
    d.update(over)
    return d


def post(c, data, csrf=True):
    if csrf:
        data = dict(data, csrf_token=token(get(c, "/settings").get_data(as_text=True)))
    return c.post("/settings", data=data, base_url=HTTPS)


def test_requires_login(fake, sfile):
    c = make(fake, sfile).test_client()
    r = get(c, "/settings")
    assert r.status_code in (302, 303) and "/login" in r.headers["Location"]
    r = c.post("/settings", data=form(), base_url=HTTPS)
    assert r.status_code in (302, 303, 401, 403)
    assert not sfile.exists()


def test_get_renders_current_values(fake, sfile):
    put(sfile, refresh_s=60, byte_units="decimal", handshake_good_s=240, default_range="7d")
    c = login(make(fake, sfile).test_client())
    r = get(c, "/settings")
    h = r.get_data(as_text=True)
    assert r.status_code == 200
    assert "240" in h and "decimal" in h and "7d" in h
    for name in ("default_range", "refresh_s", "byte_units", "handshake_good_s", "panels", "csrf_token"):
        assert f'name="{name}"' in h, name
    assert 'action="/logout"' in h


def test_settings_link_in_nav(client):
    assert 'href="/settings"' in get(client, "/").get_data(as_text=True)


def test_post_without_csrf_rejected(client, sfile):
    r = post(client, form(refresh_s="60"), csrf=False)
    assert r.status_code in (400, 403)
    assert not sfile.exists()


def test_post_bad_csrf_rejected(client, sfile):
    r = post(client, dict(form(refresh_s="60"), csrf_token="nope"), csrf=False)
    assert r.status_code in (400, 403)
    assert not sfile.exists()


def test_valid_post_persists_and_redirects(client, sfile):
    r = post(client, form(default_range="7d", refresh_s="300", byte_units="decimal",
                          handshake_good_s="600", panels=["traffic", "peers"]))
    assert r.status_code == 303
    assert r.headers["Location"].endswith("/settings?saved=1")
    assert json.loads(sfile.read_text()) == {"default_range": "7d", "refresh_s": 300, "byte_units": "decimal",
                                             "handshake_good_s": 600, "panels": ["traffic", "peers"], "thresholds": {}}
    assert get(client, "/settings?saved=1").status_code == 200


def test_unknown_keys_ignored(client, sfile):
    r = post(client, dict(form(), evil="1", PROM_URL="http://x"))
    assert r.status_code == 303
    assert set(json.loads(sfile.read_text())) == set(settings.DEFAULTS)


def test_invalid_post_400_file_unchanged(fake, sfile):
    put(sfile, refresh_s=60)
    before = sfile.read_text()
    c = login(make(fake, sfile).test_client())
    r = post(c, form(refresh_s="7", handshake_good_s="5"))
    assert r.status_code == 400
    assert "refresh_s" in r.get_data(as_text=True)
    assert sfile.read_text() == before


def test_default_range_applies(fake, sfile):
    put(sfile, default_range="7d")
    c = login(make(fake, sfile).test_client())
    for path in ("/", "/detail/peer/aaaaaaaa"):
        h = get(c, path).get_data(as_text=True)
        assert re.search(r'<a href="[^"]*range=7d"[^>]*aria-current="true"', h), path
    h = get(c, "/?range=24h").get_data(as_text=True)
    assert re.search(r'<a href="[^"]*range=24h"[^>]*aria-current="true"', h)
    h = get(c, "/?range=bogus").get_data(as_text=True)
    assert re.search(r'<a href="[^"]*range=7d"[^>]*aria-current="true"', h)


def test_default_range_default_is_24h(client):
    h = get(client, "/").get_data(as_text=True)
    assert re.search(r'<a href="[^"]*range=24h"[^>]*aria-current="true"', h)


def test_refresh_header(fake, sfile):
    put(sfile, refresh_s=60)
    c = login(make(fake, sfile).test_client())
    assert get(c, "/").headers.get("Refresh") == "60"
    assert get(c, "/detail/peer/aaaaaaaa").headers.get("Refresh") == "60"
    assert "Refresh" not in get(c, "/settings").headers
    assert "<script" not in get(c, "/").get_data(as_text=True).lower().replace("<script src=", "")
    put(sfile, refresh_s=0)
    assert "Refresh" not in get(c, "/").headers


def test_byte_units(fake, sfile):
    c = login(make(fake, sfile).test_client())
    h = get(c, "/detail/peer/aaaaaaaa").get_data(as_text=True)
    assert "2.9 KiB" in h
    put(sfile, byte_units="decimal")
    h = get(c, "/detail/peer/aaaaaaaa").get_data(as_text=True)
    assert "3.0 kB" in h and "2.9 KiB" not in h


def test_bytes_function_units():
    assert web._bytes(2048) == "2.0 KiB"
    assert web._bytes(2048, units="binary") == "2.0 KiB"
    assert web._bytes(2000, units="decimal") == "2.0 kB"
    assert web._bytes(5_000_000, units="decimal") == "5.0 MB"
    assert web._bytes(None, units="decimal") == "n/a"
    assert web._bytes(12, units="decimal") == "12 B"


def test_handshake_good_s(fake, sfile, monkeypatch):
    monkeypatch.setattr(web.time, "time", lambda: NOW)
    c = login(make(fake, sfile).test_client())
    default = get(c, "/").get_data(as_text=True)
    put(sfile, handshake_good_s=300)
    wide = get(c, "/").get_data(as_text=True)
    put(sfile, handshake_good_s=60)
    narrow = get(c, "/").get_data(as_text=True)
    good = lambda h: len(re.findall(r'dot good', h))
    assert good(wide) == good(default) + 1
    assert good(narrow) == good(default) - 1


def test_hide_traffic_panel(fake, sfile):
    c = login(make(fake, sfile).test_client())
    assert 'id="h-traffic"' in get(c, "/").get_data(as_text=True)
    put(sfile, panels=["peers", "interfaces", "services", "checks"])
    h = get(c, "/").get_data(as_text=True)
    assert 'id="h-traffic"' not in h
    assert 'id="h-host"' in h


def test_hide_all_panels_still_renders(fake, sfile):
    put(sfile, panels=[])
    c = login(make(fake, sfile).test_client())
    r = get(c, "/")
    assert r.status_code == 200
    assert 'id="h-traffic"' not in r.get_data(as_text=True)


def test_untick_all_panels_saves_empty_selection(client, sfile):
    r = post(client, {k: v for k, v in form().items() if k != "panels"} | {"panels": ""})
    assert r.status_code == 303
    assert json.loads(sfile.read_text())["panels"] == []


# --- T5: thresholds form, device names, backup settings ----------------------

import json as _json  # noqa: E402

from app import audit, config  # noqa: E402
from conftest import FakeNetctl  # noqa: E402
from test_alerts_web import CFG, entries as audit_entries, make as make_full  # noqa: E402


@pytest.fixture
def tdir(tmp_path):
    return tmp_path


@pytest.fixture
def full(fake, tdir):
    return login(make_full(fake, tdir, FakeNetctl()).test_client())


def page_token(c, path="/settings"):
    return token(get(c, path).get_data(as_text=True))


def merged(tdir):
    return config.merged_backups(CFG / "backups.toml", tdir / "backup-overrides.json")


def test_threshold_form_saves_and_shows_errors_and_reset(full, tdir):
    sf = tdir / "settings.json"
    r = full.post("/settings", data=form(disk_pct="70", handshake_stale_s="3600", backup_age_h="", csrf_token=page_token(full)),
                  base_url=HTTPS)
    assert r.status_code in (302, 303)
    assert _json.loads(sf.read_text())["thresholds"] == {"disk_pct": 70, "handshake_stale_s": 3600}
    assert 'name="disk_pct"' in get(full, "/settings").get_data(as_text=True)
    r = full.post("/settings", data=form(disk_pct="3", csrf_token=page_token(full)), base_url=HTTPS)
    assert r.status_code == 400 and "disk_pct" in r.get_data(as_text=True)
    assert _json.loads(sf.read_text())["thresholds"]["disk_pct"] == 70
    full.post("/settings", data=form(reset_thresholds="1", csrf_token=page_token(full)), base_url=HTTPS)
    assert _json.loads(sf.read_text())["thresholds"] == {}


def test_device_rename_saves_override_and_audits(full, tdir):
    key = "aaaaaaaaXYZ" + "=" * 3
    r = full.post("/settings/devices", data={"public_key": key, "name": "Anna's phone", "csrf_token": page_token(full)},
                  base_url=HTTPS)
    assert r.status_code in (302, 303)
    assert _json.loads((tdir / "device_names.json").read_text()) == {"aaaaaaaa": "Anna's phone"}
    e = audit_entries(tdir)
    assert len(e) == 1 and e[0]["ok"] is True
    assert "Anna&#39;s phone" in get(full, "/").get_data(as_text=True)  # autoescaped


def test_device_rename_needs_csrf(full, tdir):
    r = full.post("/settings/devices", data={"public_key": "aaaaaaaa", "name": "x"}, base_url=HTTPS)
    assert r.status_code == 400 and not (tdir / "device_names.json").exists()


def bform(**over):
    """Backup form as the page would submit it: unchanged defaults, then overrides by field name.

    Field names: destination_root; per target <field>_<name> for enabled ("1" = ticked), interval_h,
    categories (list), include, exclude (one path per line), retention_daily/weekly/monthly."""
    cfg = config.load_backups(CFG / "backups.toml")
    d = {"destination_root": cfg["destination_root"]}
    for t in cfg["targets"]:
        n = t["name"]
        d.update({f"enabled_{n}": "1", f"interval_h_{n}": str(t["interval_h"]), f"categories_{n}": t["categories"],
                  f"include_{n}": "\n".join(t["include"]), f"exclude_{n}": "\n".join(t["exclude"]),
                  **{f"retention_{k}_{n}": str(v) for k, v in t["retention"].items()}})
    d.update(over)
    return d


def bpost(c, **over):
    over["csrf_token"] = over.get("csrf_token") or page_token(c)
    return c.post("/settings/backups", data=bform(**over), base_url=HTTPS)


def test_backup_settings_confirm_then_save(full, tdir):
    ov = tdir / "backup-overrides.json"
    edit = dict(interval_h_pc="12", categories_pc=["home", "packages"], exclude_pc="/home/*/.cache\n/home/*/Downloads",
                retention_daily_pc="3", destination_root="/srv/new-disk/")
    edit["enabled_laptop"] = ""  # unticked box
    r = bpost(full, **edit)
    assert r.status_code == 200 and not ov.exists()  # confirm page summarises, nothing saved yet
    assert "12" in r.get_data(as_text=True)
    r = bpost(full, confirm="1", **edit)
    assert r.status_code in (302, 303) and ov.exists()
    cfg = merged(tdir)
    pc = next(t for t in cfg["targets"] if t["name"] == "pc")
    assert cfg["destination_root"] == "/srv/new-disk"
    assert pc["interval_h"] == 12 and pc["categories"] == ["home", "packages"]
    assert pc["exclude"] == ["/home/*/.cache", "/home/*/Downloads"] and pc["retention"]["daily"] == 3
    assert next(t for t in cfg["targets"] if t["name"] == "laptop")["enabled"] is False
    e = audit_entries(tdir)
    assert len(e) == 1 and e[0]["ok"] is True
    assert not list(tdir.glob("backup-overrides.json.*.tmp"))


@pytest.mark.parametrize("bad", [
    {"interval_h_pc": "0"}, {"interval_h_pc": "abc"}, {"interval_h_pc": "9999"},
    {"include_pc": "relative/path"}, {"exclude_pc": "/a/../etc"},
    {"categories_pc": ["home", "nas-data"]},  # local-only category on an ssh target
    {"categories_pc": []}, {"destination_root": "not-absolute"},
    {"retention_daily_pc": "-1"},
])
def test_backup_settings_invalid_rejected_with_messages(full, tdir, bad):
    for confirm in ({}, {"confirm": "1"}):
        r = bpost(full, **bad, **confirm)
        assert r.status_code == 400
        assert re.search(r"error|invalid|not ", r.get_data(as_text=True), re.I)
    assert not (tdir / "backup-overrides.json").exists()


@pytest.mark.parametrize("field,value", [("mac_pc", "11:22:33:44:55:66"), ("hosts_pc", "evil.example"),
                                         ("user_pc", "root")])
def test_backup_settings_cannot_set_read_only_keys(full, tdir, field, value):
    r = bpost(full, confirm="1", **{field: value})
    assert r.status_code == 400 and not (tdir / "backup-overrides.json").exists()
    assert merged(tdir)["targets"][1]["mac"] == "02:00:00:00:00:01"


def test_backup_settings_need_csrf(full, tdir):
    r = full.post("/settings/backups", data=bform(confirm="1"), base_url=HTTPS)
    assert r.status_code == 400 and not (tdir / "backup-overrides.json").exists()


def test_sidebar_register_and_reset_placement(client):
    h = get(client, "/settings").get_data(as_text=True)
    aside = re.search(r"<aside.*?</aside>", h, re.S).group(0)
    for a in ("h-set-view", "h-set-panels", "h-set-th", "h-set-dev", "h-set-bk"):
        assert f'href="#{a}"' in aside
    assert 'href="/backups/targets/pc#h-bk-set"' in aside
    th = re.search(r'<section aria-labelledby="h-set-th">.*?</section>', h, re.S).group(0)
    assert 'name="reset_thresholds"' in th


def test_device_label_name_and_key(client):
    h = get(client, "/settings").get_data(as_text=True)
    m = re.search(r'<label class="ln" for="f-dev-([^"]+)">(.*?)</label>', h, re.S)
    assert f'<span class="ls">{m.group(1)}</span>' in m.group(2)
    assert m.group(2).split("<")[0].strip()
