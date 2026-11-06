import json
import re
from pathlib import Path

import pytest

from app import audit
from app.netctl import NetctlError
from app.web import create_app
from conftest import FakeNetctl, login, totp_cfg

ROOT = Path(__file__).resolve().parent.parent
HTTPS = "https://localhost"


def make(prom, tmp_path, netctl):
    return create_app({"ADMIN_PASSWORD": "pw", "SECRET_KEY": "k", "WIKI_DIR": str(ROOT / "monitor/wiki"),
                       "DEVICES_FILE": str(ROOT / "monitor/config/devices.toml"),
                       "SETTINGS_FILE": str(tmp_path / "settings.json"),
                       "AUDIT_FILE": str(tmp_path / "audit.jsonl"), **totp_cfg(tmp_path)}, prom_client=prom, netctl=netctl)


def token(html):
    t = re.search(r'name="csrf_token"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*name="csrf_token"', html)
    return t.group(1) or t.group(2)


def get(c, path):
    return c.get(path, base_url=HTTPS)


def restart(c, unit="minidlna", confirm=True, csrf=True):
    data = {"unit": unit}
    if confirm:
        data["confirm"] = "1"
    if csrf:
        data["csrf_token"] = token(get(c, "/network").get_data(as_text=True))
    return c.post("/network/restart", data=data, base_url=HTTPS)


@pytest.fixture
def nc():
    return FakeNetctl({"restart": {"unit": "minidlna", "active": True}})


@pytest.fixture
def client(fake, tmp_path, nc):
    return login(make(fake, tmp_path, nc).test_client())


def restarts(nc):
    """Restart calls only: GET /network also makes read-only helper calls (peers, pending, snapshots)."""
    return [c for c in nc.calls if c[0] == "restart"]


def entries(tmp_path):
    return [e for e in audit.recent(str(tmp_path / "audit.jsonl")) if e["action"] != "login"]


def test_requires_login(fake, tmp_path, nc):
    c = make(fake, tmp_path, nc).test_client()
    r = get(c, "/network")
    assert r.status_code in (302, 303) and "/login" in r.headers["Location"]
    r = c.post("/network/restart", data={"unit": "minidlna", "confirm": "1"}, base_url=HTTPS)
    assert r.status_code in (302, 303, 401, 403)
    assert restarts(nc) == []


def test_csrf_missing(client, nc):
    assert restart(client, csrf=False).status_code == 400
    assert restarts(nc) == []


def test_unit_not_on_allowlist(client, nc, tmp_path):
    assert restart(client, unit="cron").status_code == 400
    assert restarts(nc) == []
    e = entries(tmp_path)
    assert e and e[0]["ok"] is False


def test_allowlist_matches_helper(client, nc):
    from app import data
    from app.network import _units
    t = (Path(__file__).parent.parent / "monitor/host/omv-netctl.py").read_text()
    # the helper derives its allowlist from the same file and function, for the same interface
    assert "config.restart_units(config.load_monitor(MONITOR_TOML)[\"services\"], IFACE)" in t
    assert re.search(r'^IFACE = "(.+)"$', t, re.M).group(1) == data.WG_IF
    with client.application.app_context():
        units = _units()
    assert set(units) == {"wg-quick@wgnet1", "smbd", "minidlna", "nginx", "tailscaled", "omv-monitor"}
    assert restart(client, unit="wg-quick@wgnet1").status_code == 303
    assert restarts(nc) == [("restart", {"unit": "wg-quick@wgnet1"})]
    assert restart(client, unit="ssh").status_code == 400


@pytest.mark.parametrize("unit", ["minidlna;rm", "", "../x", "minidlna\nssh"])
def test_invalid_unit(client, nc, unit):
    assert restart(client, unit=unit).status_code == 400
    assert restarts(nc) == []


def test_confirm_step_skipped(client, nc):
    r = restart(client, confirm=False)
    h = r.get_data(as_text=True)
    assert r.status_code == 200 and restarts(nc) == []
    assert "minidlna" in h and 'name="confirm"' in h and 'value="1"' in h
    assert 'name="csrf_token"' in h and 'name="unit"' in h


def test_confirmed_restart(client, nc, tmp_path):
    r = restart(client)
    assert r.status_code == 303 and "/network" in r.headers["Location"]
    assert restarts(nc) == [("restart", {"unit": "minidlna"})]
    e = entries(tmp_path)
    assert len(e) == 1 and e[0]["ok"] is True and e[0]["action"] == "restart"
    assert e[0]["args"] == {"unit": "minidlna"}
    h = get(client, r.headers["Location"]).get_data(as_text=True)
    assert "restart" in h and "minidlna" in h
    assert "csrf_token" not in json.dumps(e[0])


def test_netctl_error_shown_and_audited(fake, tmp_path):
    nc = FakeNetctl({"restart": NetctlError("unit failed to start")})
    c = login(make(fake, tmp_path, nc).test_client())
    r = restart(c)
    h = r.get_data(as_text=True)
    if r.status_code in (302, 303):
        h = get(c, r.headers["Location"]).get_data(as_text=True)
    assert "unit failed to start" in h
    e = entries(tmp_path)
    assert e and e[0]["ok"] is False and "unit failed to start" in e[0]["detail"]


def test_actions_disabled(fake, tmp_path):
    c = login(make(fake, tmp_path, None).test_client())
    h = get(c, "/network").get_data(as_text=True)
    assert "/network/restart" not in h and 'name="unit"' not in h
    assert restart(c).status_code == 503


def test_network_page_na_and_csp(client, nc):
    r = get(client, "/network")
    h = r.get_data(as_text=True)
    assert r.status_code == 200 and "n/a" in h  # minidlna has no sample in the fake
    assert "/network/restart" in h
    assert "chart.js" not in h.lower()
    assert not re.search(r"<script(?![^>]*\bsrc=)", h) and "style=" not in h and "<style" not in h


def test_audit_roundtrip_order_and_garbage(tmp_path):
    p = tmp_path / "sub" / "audit.jsonl"
    assert audit.recent(str(p)) == []
    audit.record(str(p), "restart", {"unit": "a"}, True, "one", "1.2.3.4")
    audit.record(str(p), "restart", {"unit": "b"}, False, "two", None)
    with open(p, "a") as f:
        f.write("not json\n{\"half\": \n")
    audit.record(str(p), "restart", {"unit": "c"}, True, "three", None)
    got = audit.recent(str(p))
    assert [e["args"]["unit"] for e in got] == ["c", "b", "a"]
    assert got[2]["user"] == "admin" and got[2]["remote_addr"] == "1.2.3.4" and "time" in got[2]
    assert len(audit.recent(str(p), n=2)) == 2


# --- sidebar register, state capsules, readable log, restart warnings ---
K1, K2 = "a" * 43 + "=", "B" * 43 + "="
PEERS = {"peers": [{"public_key": K1, "allowed_ips": ["10.8.0.2/32"], "enabled": True},
                   {"public_key": K2, "allowed_ips": ["10.8.0.1/32"], "enabled": False}]}


def page(c):
    return get(c, "/network").get_data(as_text=True)


def aside(h):
    return re.search(r"<aside.*?</aside>", h, re.S).group(0)


def section(h, hid):
    return re.search(r'<section aria-labelledby="%s">.*?</section>' % hid, h, re.S).group(0)


@pytest.fixture
def pclient(fake, tmp_path):
    nc = FakeNetctl({"peers": PEERS, "pending": {"pending": None}, "snapshots": {"snapshots": []}})
    return login(make(fake, tmp_path, nc).test_client())


def test_sidebar_register(pclient):
    h = page(pclient)
    assert "is-detail" in h
    a = aside(h)
    assert 'aria-labelledby="s-' in a and "Peers" in a and "Services" in a
    for k, ip in ((K1, "10.8.0.2/32"), (K2, "10.8.0.1/32")):
        assert re.search(r'<a class="row" href="/network/peer/[^"]+">', a) and ip in a
    assert a.count('href="/network/peer/') == 2
    assert "Samba" in a and "running" in a and "stopped" in a and "n/a" in a  # minidlna unknown


def test_sidebar_na_without_peers(client):
    a = aside(page(client))  # FakeNetctl has no peers answer -> unknown
    assert "Peers" in a and "n/a" in a and "/network/peer/" not in a


def test_state_capsules(pclient):
    h = page(pclient)
    svc = section(h, "h-net-svc")
    assert re.search(r'<span class="cap good">\s*running', svc)
    assert re.search(r'<span class="cap bad">\s*stopped', svc)
    assert re.search(r'<span class="cap idle">\s*n/a', svc)
    peers = section(h, "h-net-peers")
    assert re.search(r'<span class="cap good">\s*enabled', peers)
    assert re.search(r'<span class="cap (idle|warn)">\s*disabled', peers)


def test_peer_links_not_ln_anchor(pclient):
    h = page(pclient)
    assert not re.search(r'<a class="ln"[^>]*href="/network/peer/', h)
    assert re.search(r'href="/network/peer/', section(h, "h-net-peers"))


def test_audit_log_readable(pclient, tmp_path):
    p = str(tmp_path / "audit.jsonl")
    audit.record(p, "restart", {"unit": "omv-monitor"}, True, "active", "10.0.0.1")
    audit.record(p, "rename", {"public_key": K1, "old": "Old", "new": "Laptop"}, True, "ok", "10.0.0.1")
    audit.record(p, "restore", {"snapshot": "0123456789ab"}, True, "ok", "10.0.0.1")
    log = section(page(pclient), "h-net-log")
    assert "restart omv-monitor" in log
    assert re.search(r"rename peer \S+ to Laptop", log) and K1 not in log
    assert "0123456789ab" in log
    assert "{" not in log and "&#34;" not in log and '"unit"' not in log


@pytest.mark.parametrize("unit,text", [("wg-quick@wgnet1", "Restarting WireGuard may cut your VPN session"),
                                       ("omv-monitor", "Restarting the monitor takes this page down briefly")])
def test_restart_warning_banner(client, nc, unit, text):
    r = restart(client, unit=unit, confirm=False)
    h = r.get_data(as_text=True)
    assert r.status_code == 200 and text in h and 'class="banner"' in h and 'name="confirm"' in h
    assert "This is the connection you are using" not in h
    assert restart(client, unit=unit).status_code == 303 and ("restart", {"unit": unit}) in nc.calls


def test_restart_no_banner_for_ordinary_unit(client):
    h = restart(client, unit="nginx", confirm=False).get_data(as_text=True)
    assert 'class="banner"' not in h and "Restarting WireGuard" not in h and "Restarting the monitor" not in h
