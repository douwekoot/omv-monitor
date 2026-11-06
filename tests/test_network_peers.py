"""Peer editing UI. FakeNetctl result shapes mirror monitor/host/omv-netctl.py (checked against T3):
peers -> {"peers": [{public_key, allowed_ips: [..], enabled, latest_handshake}]},
snapshots -> {"snapshots": [{id, time, action, summary}]},
pending -> {"pending": {id, action, summary, expires_at} | None}."""
import html as htmllib
import json
import os
import re
import time
from pathlib import Path

import pytest

from app import audit
from app.devices import peer_label
from app.netctl import NetctlError
from app.web import create_app
from conftest import FakeNetctl, login, totp_cfg

ROOT = Path(__file__).resolve().parent.parent
HTTPS = "https://localhost"
K1, K2 = "a" * 43 + "=", "B" * 43 + "="  # Laptop 10.8.0.2/32 (the caller), Phone 10.8.0.1/32
PID, SNAP = "0123456789abcdef", "0123456789ab"
EXPIRES = 1700000400
PEERS = {"peers": [{"public_key": K1, "allowed_ips": ["10.8.0.2/32"], "enabled": True},
                   {"public_key": K2, "allowed_ips": ["10.8.0.1/32"], "enabled": False}]}
PENDING = {"id": PID, "action": "peer-set", "summary": "Change allowed IPs of Laptop", "expires_at": EXPIRES}
MUTATING = ("peer-set", "peer-disable", "peer-enable", "restore", "confirm", "revert")


def make(prom, tmp_path, netctl, names=True):
    cfg = {"ADMIN_PASSWORD": "pw", "SECRET_KEY": "k", "WIKI_DIR": str(ROOT / "monitor/wiki"),
           "DEVICES_FILE": str(ROOT / "monitor/config/devices.toml"),
           "SETTINGS_FILE": str(tmp_path / "settings.json"), "AUDIT_FILE": str(tmp_path / "audit.jsonl"), **totp_cfg(tmp_path)}
    if names:
        cfg["DEVICE_NAMES_FILE"] = str(tmp_path / "device_names.json")
    return create_app(cfg, prom_client=prom, netctl=netctl)


def token(page):
    t = re.search(r'name="csrf_token"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*name="csrf_token"', page)
    return t.group(1) or t.group(2)


def get(c, path):
    return c.get(path, base_url=HTTPS, environ_overrides={"REMOTE_ADDR": "10.8.0.2"})


def post(c, path, csrf=True, confirm=True, **form):
    if confirm:
        form["confirm"] = "1"
    if csrf:
        form["csrf_token"] = token(get(c, "/network").get_data(as_text=True))
    return c.post(path, data=form, base_url=HTTPS, environ_overrides={"REMOTE_ADDR": "10.8.0.2"})


def forms(page, action):
    """[(body, {name: value})] for each <form action=action> on the page."""
    out = []
    for m in re.finditer(r'<form[^>]*action="%s"[^>]*>(.*?)</form>' % re.escape(action), page, re.S):
        fields = {}
        for i in re.findall(r"<input[^>]*>", m.group(1)):
            n, v = re.search(r'name="([^"]*)"', i), re.search(r'value="([^"]*)"', i)
            if n:
                fields[n.group(1)] = htmllib.unescape(v.group(1)) if v else ""
        out.append((m.group(1), fields))
    return out


def submit(c, page, action, contains=""):
    """Click the first matching form on page; if a confirm page comes back, confirm it."""
    body, fields = next(f for f in forms(page, action) if contains in f[0] or contains in f[1].values())
    r = c.post(action, data=fields, base_url=HTTPS, environ_overrides={"REMOTE_ADDR": "10.8.0.2"})
    if r.status_code == 200 and "confirm" not in fields:
        _, fields = forms(r.get_data(as_text=True), action)[0]
        r = c.post(action, data=fields, base_url=HTTPS, environ_overrides={"REMOTE_ADDR": "10.8.0.2"})
    return r


@pytest.fixture
def nc():
    return FakeNetctl({"peers": PEERS, "pending": {"pending": None}, "snapshots": {"snapshots": [
        {"id": SNAP, "time": 1761818400.123456}, {"id": "fedcba987654", "time": 1761728400.5}]},
        "peer-set": {"id": PID, "expires_at": EXPIRES}, "peer-disable": {"id": PID, "expires_at": EXPIRES},
        "peer-enable": {"id": PID, "expires_at": EXPIRES}, "restore": {"id": PID, "expires_at": EXPIRES},
        "confirm": {}, "revert": {}})


@pytest.fixture
def client(fake, tmp_path, nc):
    return login(make(fake, tmp_path, nc).test_client())


def entries(tmp_path):
    return [e for e in audit.recent(str(tmp_path / "audit.jsonl")) if e["action"] != "login"]


def changes(nc):
    return [c for c in nc.calls if c[0] in MUTATING]


# (path, form) for every route that changes something
ROUTES = [("/network/peer/rename", {"public_key": K1, "name": "Work laptop"}),
          ("/network/peer/allowed-ips", {"public_key": K1, "allowed_ips": "10.8.0.5/32"}),
          ("/network/peer/disable", {"public_key": K1}), ("/network/peer/enable", {"public_key": K2}),
          ("/network/pending/confirm", {"id": PID}), ("/network/pending/revert", {"id": PID}),
          ("/network/restore", {"snapshot": SNAP})]
IDS = [p.rsplit("/", 1)[-1] for p, _ in ROUTES]


@pytest.mark.parametrize("path,form", ROUTES, ids=IDS)
def test_requires_login(fake, tmp_path, nc, path, form):
    c = make(fake, tmp_path, nc).test_client()
    r = c.post(path, data={**form, "confirm": "1"}, base_url=HTTPS)
    assert r.status_code in (302, 303, 401, 403)
    assert changes(nc) == [] and not (tmp_path / "device_names.json").exists()
    r = get(c, "/network/peer/" + K1)
    assert r.status_code in (302, 303) and "/login" in r.headers["Location"]


@pytest.mark.parametrize("path,form", ROUTES, ids=IDS)
def test_csrf_missing(client, tmp_path, nc, path, form):
    assert post(client, path, csrf=False, **form).status_code in (400, 403)
    assert changes(nc) == [] and not (tmp_path / "device_names.json").exists() and entries(tmp_path) == []


@pytest.mark.parametrize("path,form", ROUTES, ids=IDS)
def test_confirm_skipped_shows_diff_and_changes_nothing(client, tmp_path, nc, path, form):
    r = post(client, path, confirm=False, **form)
    page = r.get_data(as_text=True)
    assert r.status_code == 200 and f'action="{path}"' in page and 'name="confirm"' in page
    assert changes(nc) == [] and not (tmp_path / "device_names.json").exists() and entries(tmp_path) == []


def test_confirm_page_diffs(client):
    page = post(client, "/network/peer/rename", confirm=False, public_key=K1, name="Work laptop").get_data(as_text=True)
    assert "Laptop" in page and "Work laptop" in page
    page = post(client, "/network/peer/allowed-ips", confirm=False, public_key=K1,
                allowed_ips="10.8.0.5/32").get_data(as_text=True)
    assert "10.8.0.2/32" in page and "10.8.0.5/32" in page


def test_confirm_page_warns_only_for_own_connection(client):
    mine = post(client, "/network/peer/disable", confirm=False, public_key=K1).get_data(as_text=True)
    other = post(client, "/network/peer/enable", confirm=False, public_key=K2).get_data(as_text=True)
    assert "this is the connection you are using" in mine.lower()
    assert "this is the connection you are using" not in other.lower()


BAD_KEYS = ["bad", "", "a" * 43, "a" * 44, "a" * 42 + "!=", "../etc/passwd", "a" * 43 + "=\n"]


@pytest.mark.parametrize("key", BAD_KEYS)
@pytest.mark.parametrize("path,extra", [("/network/peer/rename", {"name": "x"}),
                                        ("/network/peer/allowed-ips", {"allowed_ips": "10.8.0.5/32"}),
                                        ("/network/peer/disable", {}), ("/network/peer/enable", {})])
def test_invalid_public_key(client, tmp_path, nc, key, path, extra):
    assert post(client, path, public_key=key, **extra).status_code in (400, 404)
    assert changes(nc) == [] and not (tmp_path / "device_names.json").exists()


def test_peer_detail(client):
    page = get(client, "/network/peer/" + K1).get_data(as_text=True)
    assert "Laptop" in page and "10.8.0.2/32" in page
    for action in ("rename", "allowed-ips", "disable"):
        assert forms(page, "/network/peer/" + action)
    assert forms(get(client, "/network/peer/" + K2).get_data(as_text=True), "/network/peer/enable")


@pytest.mark.parametrize("key", BAD_KEYS[:2] + ["a" * 43, "../x"] + ["c" * 43 + "="])
def test_peer_detail_unknown_is_404(client, key):
    assert get(client, "/network/peer/" + key).status_code == 404


@pytest.mark.parametrize("ips", ["banana", "10.0.0.1/33", "10.0.0.0/8, nonsense", "", "  ", "300.1.1.1/32"])
def test_invalid_allowed_ips(client, tmp_path, nc, ips):
    assert post(client, "/network/peer/allowed-ips", public_key=K1, allowed_ips=ips).status_code == 400
    assert changes(nc) == [] and entries(tmp_path) == []


def last(tmp_path):
    return entries(tmp_path)[0]


@pytest.mark.parametrize("raw", ["10.8.0.5/32, 10.8.0.6/32", "10.8.0.5/32 10.8.0.6/32",
                                 "10.8.0.5/32,10.8.0.6/32"])
def test_allowed_ips_call(client, tmp_path, nc, raw):
    r = post(client, "/network/peer/allowed-ips", public_key=K1, allowed_ips=raw)
    assert r.status_code == 303 and r.headers["Location"].split("?")[0].endswith("/network")
    assert changes(nc) == [("peer-set", {"public_key": K1, "allowed_ips": ["10.8.0.5/32", "10.8.0.6/32"]})]
    assert last(tmp_path)["action"] == "peer-set" and last(tmp_path)["ok"] is True


@pytest.mark.parametrize("path,key,action", [("disable", K1, "peer-disable"), ("enable", K2, "peer-enable")])
def test_enable_disable_call(client, tmp_path, nc, path, key, action):
    r = post(client, "/network/peer/" + path, public_key=key)
    assert r.status_code == 303 and r.headers["Location"].split("?")[0].endswith("/network")
    assert changes(nc) == [(action, {"public_key": key})]
    assert last(tmp_path)["action"] == action and last(tmp_path)["ok"] is True


@pytest.mark.parametrize("path,form,action", [
    ("/network/peer/allowed-ips", {"public_key": K1, "allowed_ips": "10.8.0.5/32"}, "peer-set"),
    ("/network/peer/disable", {"public_key": K1}, "peer-disable"),
    ("/network/peer/enable", {"public_key": K2}, "peer-enable"),
    ("/network/pending/confirm", {"id": PID}, "confirm"),
    ("/network/pending/revert", {"id": PID}, "revert"),
    ("/network/restore", {"snapshot": SNAP}, "restore")])
def test_helper_error_is_shown_and_audited(client, tmp_path, nc, path, form, action):
    nc.responses[action] = NetctlError("another change is pending: confirm or revert it first")
    r = post(client, path, **form)
    assert r.status_code == 303
    e = last(tmp_path)
    assert e["action"] == action and e["ok"] is False and "another change is pending" in e["detail"]
    assert "another change is pending" in get(client, "/network").get_data(as_text=True)


def test_pending_banner(client, nc):
    assert not forms(get(client, "/network").get_data(as_text=True), "/network/pending/revert")
    nc.responses["pending"] = {"pending": PENDING}
    page = get(client, "/network").get_data(as_text=True)
    assert "Change allowed IPs of Laptop" in page
    assert time.strftime("%H:%M:%S", time.localtime(EXPIRES)) in page
    assert forms(page, "/network/pending/confirm")[0][1]["id"] == PID
    assert forms(page, "/network/pending/revert")[0][1]["id"] == PID


def test_keep_and_undo(client, tmp_path, nc):
    nc.responses["pending"] = {"pending": PENDING}
    page = get(client, "/network").get_data(as_text=True)
    assert submit(client, page, "/network/pending/confirm").status_code == 303
    assert changes(nc) == [("confirm", {"id": PID})] and last(tmp_path)["action"] == "confirm"
    nc.calls.clear()
    assert submit(client, page, "/network/pending/revert").status_code == 303
    assert changes(nc) == [("revert", {"id": PID})] and last(tmp_path)["action"] == "revert"


def test_network_lists_peers_with_names_and_snapshots(client):
    page = get(client, "/network").get_data(as_text=True)
    assert "Laptop" in page and "Phone" in page and "/network/peer/" + K1 in page
    assert SNAP in page and "fedcba987654" in page
    assert forms(page, "/network/restore")[0][1]["snapshot"] in (SNAP, "fedcba987654")


def test_network_snapshot_time_is_readable(client):
    # helper sends an epoch float (time.time()); the page must not show it raw
    page = get(client, "/network").get_data(as_text=True)
    assert "1761818400" not in page and "1761728400" not in page
    # same local-time conversion as the app, so the check holds in any timezone
    for t in (1761818400, 1761728400):
        assert time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) in page


def test_network_without_helper_data(client, nc):
    nc.responses["peers"] = NetctlError("host helper unavailable")
    nc.responses["snapshots"] = NetctlError("host helper unavailable")
    nc.responses["pending"] = NetctlError("host helper unavailable")
    r = get(client, "/network")
    assert r.status_code == 200 and "n/a" in r.get_data(as_text=True)


def test_restore_call(client, tmp_path, nc):
    r = post(client, "/network/restore", snapshot=SNAP)
    assert r.status_code == 303 and r.headers["Location"].split("?")[0].endswith("/network")
    [(action, args)] = changes(nc)
    assert action == "restore" and list(args.values()) == [SNAP]
    assert last(tmp_path)["action"] == "restore" and last(tmp_path)["ok"] is True


@pytest.mark.parametrize("snap", ["", "0123456789a", "0123456789abc", "0123456789AB", "../../etc", "0123456789ag",
                                  "0123456789ab\n"])
def test_restore_invalid_id(client, nc, snap):
    assert post(client, "/network/restore", snapshot=snap).status_code == 400
    assert changes(nc) == []


# --- rename (never touches the helper nor devices.toml) ---

def names(tmp_path):
    return json.loads((tmp_path / "device_names.json").read_text())


def test_rename_writes_override_atomically(fake, tmp_path, nc, monkeypatch):
    c = login(make(fake, tmp_path, nc).test_client())
    toml = ROOT / "monitor/config/devices.toml"
    before = toml.read_bytes()
    replaced = []
    real = os.replace
    monkeypatch.setattr(os, "replace", lambda a, b: (replaced.append(str(b)), real(a, b))[1])
    r = post(c, "/network/peer/rename", public_key=K1, name="  Work laptop  ")
    assert r.status_code == 303 and r.headers["Location"].split("?")[0].endswith("/network")
    assert names(tmp_path) == {peer_label(K1): "Work laptop"}
    assert str(tmp_path / "device_names.json") in replaced
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith("device_names")) == ["device_names.json"]
    assert toml.read_bytes() == before and changes(nc) == []
    assert "Work laptop" in get(c, "/network").get_data(as_text=True)
    e = last(tmp_path)
    assert e["action"] == "rename" and e["ok"] is True and "Laptop" in json.dumps(e) and "Work laptop" in json.dumps(e)


def test_rename_default_file_is_next_to_settings(fake, tmp_path, nc):
    c = login(make(fake, tmp_path, nc, names=False).test_client())
    assert post(c, "/network/peer/rename", public_key=K2, name="Mobile").status_code == 303
    assert names(tmp_path) == {peer_label(K2): "Mobile"}


def test_rename_keeps_other_names(client, tmp_path):
    post(client, "/network/peer/rename", public_key=K1, name="One")
    post(client, "/network/peer/rename", public_key=K2, name="Two")
    assert names(tmp_path) == {peer_label(K1): "One", peer_label(K2): "Two"}


@pytest.mark.parametrize("name", ["", "   ", "x" * 41, "bad\x00name", "bad\nname", "tab\there", "\x7f"])
def test_rename_invalid_name(client, tmp_path, name):
    assert post(client, "/network/peer/rename", public_key=K1, name=name).status_code == 400
    assert not (tmp_path / "device_names.json").exists() and entries(tmp_path) == []


def test_rename_max_length_ok(client, tmp_path):
    assert post(client, "/network/peer/rename", public_key=K1, name="x" * 40).status_code == 303
    assert names(tmp_path)[peer_label(K1)] == "x" * 40


def test_restore_name(client, tmp_path):
    post(client, "/network/peer/rename", public_key=K1, name="Work laptop")
    page = get(client, "/network").get_data(as_text=True)
    assert submit(client, page, "/network/peer/rename", contains="Laptop").status_code == 303
    assert names(tmp_path)[peer_label(K1)] == "Laptop"
    assert "Laptop" in get(client, "/").get_data(as_text=True)


# --- pages stay free of inline code and chart.js ---

def test_no_inline_script_or_style(client, nc):
    nc.responses["pending"] = {"pending": PENDING}
    pages = [get(client, "/network"), get(client, "/network/peer/" + K1),
             post(client, "/network/peer/disable", confirm=False, public_key=K1),
             post(client, "/network/peer/rename", confirm=False, public_key=K1, name="Z")]
    for r in pages:
        page = r.get_data(as_text=True)
        assert r.status_code == 200 and "chart.js" not in page.lower()
        assert not re.search(r"<script(?![^>]*\bsrc=)", page) and "<style" not in page
        assert not re.search(r"<[^>]+\sstyle=", page) and not re.search(r"<[^>]+\son\w+=", page)


# --- keys with "/" and "+" (about half of real WireGuard keys) ---
K3 = "gN/2+Kx9Qe7Vt0uLwzR3cPq/1mYhJbA8dFs+oEiXk4M="


def test_peer_page_key_with_slash_and_plus(fake, tmp_path):
    nc = FakeNetctl({"peers": {"peers": [{"public_key": K3, "allowed_ips": ["10.8.0.7/32"], "enabled": True}]},
                     "pending": {"pending": None}, "snapshots": {"snapshots": []}})
    c = login(make(fake, tmp_path, nc).test_client())
    link = re.search(r'href="(/network/peer/[^"]+)"', get(c, "/network").get_data(as_text=True)).group(1)
    r = get(c, htmllib.unescape(link))
    assert r.status_code == 200 and K3 in r.get_data(as_text=True)
    assert post(c, "/network/peer/rename", public_key=K3, name="Slashy").status_code == 303
    assert names(tmp_path) == {peer_label(K3): "Slashy"} and peer_label(K3) == "gN_2-Kx9"
    # the Prometheus label is the 8-char form; the new name must show on the dashboard
    lab = peer_label(K3)
    for m in ("omv_wg_latest_handshake_timestamp_seconds", "omv_wg_received_bytes_total", "omv_wg_sent_bytes_total"):
        fake.data[m] = [{"metric": {"interface": "wgnet1", "peer": lab, "allowed_ips": "10.8.0.7/32"},
                         "value": [1700000000, "1700000100" if "handshake" in m else "5"]}]
    assert "Slashy" in get(c, "/").get_data(as_text=True)


def test_name_survives_allowed_ips_change(client, tmp_path, nc):
    post(client, "/network/peer/rename", public_key=K1, name="Work laptop")
    nc.responses["peers"] = {"peers": [{"public_key": K1, "allowed_ips": ["10.8.0.99/32"], "enabled": True},
                                     PEERS["peers"][1]]}
    assert "Work laptop" in get(client, "/network").get_data(as_text=True)


def test_no_pending_says_so_and_bad_snapshot_time_does_not_500(fake, tmp_path, nc):
    nc.responses["snapshots"] = {"snapshots": [{"id": SNAP, "time": None}, {"id": "fedcba987654", "time": "x"}]}
    page = login(make(fake, tmp_path, nc).test_client()).get("/network", base_url=HTTPS)
    assert page.status_code == 200
    assert "No change is waiting." in page.get_data(as_text=True)
