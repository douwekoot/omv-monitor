"""T5 web pages: config validation at startup, alerts, dashboard backups/updates, thresholds, Run now."""
import json
import re
import time
from pathlib import Path

import pytest

from app import audit, config
from app.config import ConfigError
from app.netctl import NetctlError
from app.web import create_app
from conftest import FakeNetctl, FakeProm, login, totp_cfg, vec

ROOT = Path(__file__).resolve().parent.parent
HTTPS = "https://localhost"
CFG = ROOT / "monitor/config"


def make(prom, tmp_path, netctl=None, **over):
    return create_app({"ADMIN_PASSWORD": "pw", "SECRET_KEY": "k", "WIKI_DIR": str(ROOT / "monitor/wiki"),
                       "DEVICES_FILE": str(CFG / "devices.toml"),
                       "SETTINGS_FILE": str(tmp_path / "settings.json"),
                       "AUDIT_FILE": str(tmp_path / "audit.jsonl"),
                       "DEVICE_NAMES_FILE": str(tmp_path / "device_names.json"),
                       "MONITOR_CONFIG": str(CFG / "monitor.toml"), "BACKUPS_CONFIG": str(CFG / "backups.toml"),
                       "BACKUP_OVERRIDES_FILE": str(tmp_path / "backup-overrides.json"),
                       "ALERT_HISTORY_FILE": str(tmp_path / "alert-history.jsonl"),
                       "BACKUP_RUNS_FILE": str(tmp_path / "backup-runs.jsonl"),
                       **totp_cfg(tmp_path), **over}, prom_client=prom, netctl=netctl)


def token(html):
    t = re.search(r'name="csrf_token"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*name="csrf_token"', html)
    return t.group(1) or t.group(2)


def get(c, path):
    return c.get(path, base_url=HTTPS)


def body(c, path):
    return get(c, path).get_data(as_text=True)


def entries(tmp_path):
    return [e for e in audit.recent(str(tmp_path / "audit.jsonl")) if e["action"] != "login"]


# --- startup validation ------------------------------------------------------

def test_broken_monitor_toml_refuses_to_start(fake, tmp_path):
    bad = tmp_path / "monitor.toml"
    bad.write_text("[thresholds]\ndisk_pct = 3\nhandshake_stale_s = 86400\nbackup_age_h = 36\n"
                   "[retention]\nalert_history_days = 90\nprometheus = \"7d\"\n"
                   '[[services]]\nunit = "ssh"\nlabel = "SSH"\nrestart = false\n')
    with pytest.raises(ConfigError, match=r"monitor\.toml.*thresholds\.disk_pct"):
        make(fake, tmp_path, MONITOR_CONFIG=str(bad))


def test_broken_backups_toml_refuses_to_start(fake, tmp_path):
    bad = tmp_path / "backups.toml"
    bad.write_text('[[targets]]\nname = "x"\n')
    with pytest.raises(ConfigError, match=r"backups\.toml.*destination_root"):
        make(fake, tmp_path, BACKUPS_CONFIG=str(bad))


def test_broken_overrides_refuse_to_start(fake, tmp_path):
    (tmp_path / "backup-overrides.json").write_text(json.dumps({"targets": {"pc": {"interval_h": 0}}}))
    with pytest.raises(ConfigError, match=r"backup-overrides\.json.*interval_h"):
        make(fake, tmp_path)


# --- alerts page --------------------------------------------------------------

def ev(ts, title, sev="finding", event="raised", rule="disk-usage"):
    return {"ts": ts, "event": event, "sev": sev, "rule": rule, "title": title}


def write_history(tmp_path, *events):
    (tmp_path / "alert-history.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))


@pytest.fixture
def client(fake, tmp_path):
    return login(make(fake, tmp_path, FakeNetctl()).test_client())


def test_alerts_requires_login(fake, tmp_path):
    r = get(make(fake, tmp_path).test_client(), "/alerts")
    assert r.status_code in (302, 303) and "/login" in r.headers["Location"]


def test_alerts_newest_first_with_timestamps(client, tmp_path):
    t0 = 1761800000  # 2025-10-30
    write_history(tmp_path, ev(t0, "Old thing"), ev(t0 + 5000, "Middle thing", sev="advisory"), ev(t0 + 9000, "Newest thing"))
    h = body(client, "/alerts")
    assert h.index("Newest thing") < h.index("Middle thing") < h.index("Old thing")
    day = time.localtime(t0)
    assert time.strftime("%Y-%m-%d", day) in h or time.strftime("%-d %b", day) in h


def test_alerts_sev_filter(client, tmp_path):
    write_history(tmp_path, ev(1761800000, "Bad disk"), ev(1761800100, "Odd cert", sev="advisory"))
    f = body(client, "/alerts?sev=finding")
    assert "Bad disk" in f and "Odd cert" not in f
    a = body(client, "/alerts?sev=advisory")
    assert "Odd cert" in a and "Bad disk" not in a


def test_alerts_empty_state(client):
    h = body(client, "/alerts")
    assert get(client, "/alerts").status_code == 200
    assert re.search(r"no (alerts|events|history)", h, re.I)


# --- dashboard: thresholds, handshake, backups, updates ----------------------

def prom_with(fake, **metrics):
    fake.data.update(metrics)
    return fake


def test_stale_peer_raises_handshake_age_on_dashboard(client):
    # fixture peers last shook hands in 2023, far beyond the default 24 h threshold
    assert "has had no recent handshake" in body(client, "/")


def test_fresh_peer_not_raised_by_default_but_by_lower_threshold(fake, tmp_path):
    p = {"interface": "wgnet1", "peer": "aaaaaaaa", "allowed_ips": "10.8.0.2/32"}
    fake.data["omv_wg_latest_handshake_timestamp_seconds"] = [vec(time.time() - 1000, **p)]
    c = login(make(fake, tmp_path).test_client())
    assert "has had no recent handshake" not in body(c, "/")
    (tmp_path / "settings.json").write_text(json.dumps({"thresholds": {"handshake_stale_s": 60}}))
    assert "has had no recent handshake" in body(c, "/")


def test_disk_threshold_override_changes_dashboard(fake, tmp_path):
    prom_with(fake, node_filesystem_size_bytes=[vec(1000, mountpoint="/srv", fstype="ext4")],
              node_filesystem_avail_bytes=[vec(400, mountpoint="/srv", fstype="ext4")])  # 60% used
    c = login(make(fake, tmp_path).test_client())
    assert "/srv is nearly full" not in body(c, "/")
    (tmp_path / "settings.json").write_text(json.dumps({"thresholds": {"disk_pct": 50}}))
    assert "/srv is nearly full" in body(c, "/")


def test_dashboard_backup_rows_and_na(fake, tmp_path):
    prom_with(fake, **{"omv_device_backup_last_success_timestamp_seconds": [vec(time.time() - 7200, target="omv")],
                       "omv_device_backup_size_bytes": [vec(2048, target="omv")]})
    (tmp_path / "settings.json").write_text(json.dumps({"panels": ["backups"]}))
    h = body(login(make(fake, tmp_path).test_client()), "/")
    for label in ("Server (OMV)", "Desktop PC (Fedora)", "Laptop (Fedora)"):
        assert label in h
    assert "2.0 KiB" in h and "2 h ago" in h
    assert h.count("n/a") >= 2  # pc and laptop report nothing


def test_dashboard_updates_panel(fake, tmp_path):
    (tmp_path / "settings.json").write_text(json.dumps({"panels": ["updates"]}))
    prom_with(fake, omv_apt_upgrades_pending=[vec(7)], omv_reboot_required=[vec(1)])
    h = body(login(make(fake, tmp_path).test_client()), "/")
    assert re.search(r"\b7\b", h) and re.search(r"reboot", h, re.I)
    fake.data.pop("omv_apt_upgrades_pending"), fake.data.pop("omv_reboot_required")
    assert "n/a" in body(login(make(fake, tmp_path).test_client()), "/")


# --- backup target page and Run now --------------------------------------------

def run_post(c, name="pc", csrf=True, **data):
    if csrf:
        data["csrf_token"] = token(body(c, f"/backups/targets/{name}"))
    return c.post(f"/backups/targets/{name}/run", data=data, base_url=HTTPS)


def boxes(html):
    """{value: checked} for the category checkboxes of a page."""
    out = {}
    for m in re.finditer(r'<input[^>]*name="categories"[^>]*>', html):
        v = re.search(r'value="([^"]+)"', m.group(0))
        out[v.group(1)] = " checked" in m.group(0) or m.group(0).rstrip("/> ").endswith("checked")
    return out


@pytest.fixture
def nc():
    return FakeNetctl({"backup-run": {"detail": "backup of pc started"}})


@pytest.fixture
def rclient(fake, tmp_path, nc):
    return login(make(fake, tmp_path, nc).test_client())


def runs(nc):
    return [c for c in nc.calls if c[0] == "backup-run"]


def test_target_page(fake, tmp_path, nc):
    (tmp_path / "backup-runs.jsonl").write_text(json.dumps(
        {"ts": 1761800000, "target": "pc", "step": "backup", "ok": False, "detail": "Destination not writable"}) + "\n")
    c = login(make(fake, tmp_path, nc).test_client())
    h = body(c, "/backups/targets/pc")
    assert "Desktop PC (Fedora)" in h and "Destination not writable" in h
    assert get(c, "/backups/targets/nope").status_code == 404


def test_run_requires_login(fake, tmp_path, nc):
    r = make(fake, tmp_path, nc).test_client().post("/backups/targets/pc/run", data={"confirm": "1"}, base_url=HTTPS)
    assert r.status_code in (302, 303, 401, 403) and runs(nc) == []


def test_run_first_post_shows_confirm_with_saved_selection(fake, tmp_path, nc):
    (tmp_path / "backup-overrides.json").write_text(json.dumps({"targets": {"pc": {"categories": ["home", "packages"]}}}))
    c = login(make(fake, tmp_path, nc).test_client())
    r = run_post(c)
    assert r.status_code == 200 and runs(nc) == []
    got = boxes(r.get_data(as_text=True))
    assert set(got) == config.CATEGORIES["ssh"]
    assert {k for k, v in got.items() if v} == {"home", "packages"}


def test_run_confirmed_subset_calls_netctl_once_and_audits(rclient, nc, tmp_path):
    r = run_post(rclient, confirm="1", categories=["home", "users"])
    assert r.status_code in (302, 303)
    assert len(runs(nc)) == 1
    action, args = runs(nc)[0]
    assert args["target"] == "pc" and sorted(args["categories"]) == ["home", "users"]
    e = entries(tmp_path)
    assert len(e) == 1 and e[0]["ok"] is True and "pc" in json.dumps(e[0])


@pytest.mark.parametrize("cats", [["home", "nas-data"], ["bogus"], []])
def test_run_rejects_bad_categories(rclient, nc, cats):
    assert run_post(rclient, confirm="1", categories=cats).status_code == 400
    assert runs(nc) == []


def test_run_bad_csrf(rclient, nc):
    assert run_post(rclient, csrf=False, confirm="1", categories=["home"]).status_code == 400
    assert runs(nc) == []


def test_run_unknown_target(rclient, nc):
    r = rclient.post("/backups/targets/nope/run", data={"confirm": "1", "categories": ["home"], "csrf_token": token(body(rclient, "/backups"))},
                     base_url=HTTPS)
    assert r.status_code == 404 and runs(nc) == []


def test_run_netctl_error_is_audited_and_shown(fake, tmp_path):
    nc = FakeNetctl({"backup-run": NetctlError("could not start backup (exit 1)")})
    c = login(make(fake, tmp_path, nc).test_client())
    r = run_post(c, confirm="1", categories=["home"], )
    page = r.get_data(as_text=True)
    if r.status_code in (302, 303):
        page = body(c, r.headers["Location"])
    assert "could not start backup" in page
    e = entries(tmp_path)
    assert len(e) == 1 and e[0]["ok"] is False


def test_run_without_netctl_is_a_clear_error(fake, tmp_path):
    c = login(make(fake, tmp_path, None).test_client())
    r = run_post(c, confirm="1", categories=["home"])
    assert r.status_code < 500


@pytest.mark.parametrize("q,cur", [("", "All"), ("?sev=bogus", "All"), ("?sev=finding", "Findings"), ("?sev=advisory", "Advisories")])
def test_alerts_filter_marks_current(client, q, cur):
    nav = re.search(r'<nav class="segm" aria-label="Filter">.*?</nav>', body(client, "/alerts" + q), re.S).group(0)
    assert re.findall(r'aria-current="true">([^<]+)<', nav) == [cur]


def test_alerts_sidebar_recent_and_empty(client, tmp_path):
    side = lambda: re.search(r"<aside.*?</aside>", body(client, "/alerts"), re.S).group(0)
    assert "No alerts yet." in side()
    write_history(tmp_path, *[ev(1761800000 + i, f"Thing {i}") for i in range(7)])
    s = side()
    assert "Thing 6" in s and "Thing 2" in s and "Thing 1<" not in s


def test_backups_list_shows_health_not_schedule(fake, tmp_path):
    prom_with(fake, **{"omv_device_backup_last_success_timestamp_seconds": [vec(time.time() - 7200, target="pc")],
                       "omv_device_backup_last_ok": [vec(0, target="pc")]})
    h = body(login(make(fake, tmp_path).test_client()), "/backups")
    pc = re.search(r'href="/backups/targets/pc">Desktop PC \(Fedora\)</a>.*?</li>', h, re.S).group(0)
    assert '<span class="cap bad">failed</span>' in pc
    assert re.search(r'href="/backups/targets/laptop".*?<span class="dot idle"', h, re.S)


def test_run_now_disabled_without_helper(fake, tmp_path):
    h = body(login(make(fake, tmp_path, None).test_client()), "/backups/targets/pc")
    assert re.search(r'<button class="btn" type="submit" disabled aria-describedby="run-note">Run now', h)
    assert 'aria-current="page"' in re.search(r'href="/backups/targets/pc"[^>]*>', h).group(0)


def test_target_settings_save_keeps_other_overrides(fake, tmp_path):
    ov = tmp_path / "backup-overrides.json"
    ov.write_text(json.dumps({"targets": {"omv": {"interval_h": 6}}, "destination_root": "/srv/other"}))
    c = login(make(fake, tmp_path).test_client())
    form = {"csrf_token": token(body(c, "/backups/targets/pc")), "confirm": "1", "enabled_pc": "1", "interval_h_pc": "12",
            "categories_pc": ["home"], "include_pc": "", "exclude_pc": "", "retention_daily_pc": "7",
            "retention_weekly_pc": "4", "retention_monthly_pc": "6"}
    r = c.post("/settings/backups", data=form, base_url="https://localhost")
    assert r.status_code == 303 and r.headers["Location"].endswith("/backups/targets/pc?saved=1")
    saved = json.loads(ov.read_text())
    assert saved["targets"]["omv"] == {"interval_h": 6} and saved["destination_root"] == "/srv/other"
    assert saved["targets"]["pc"]["interval_h"] == 12 and saved["targets"]["pc"]["categories"] == ["home"]
