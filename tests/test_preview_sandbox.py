import importlib.util
import re
import subprocess
import urllib.request
from pathlib import Path

import pytest

from conftest import login

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "tools" / "preview_sandbox.py"
HTTPS = "https://localhost"


def load():
    spec = importlib.util.spec_from_file_location("preview_sandbox", SRC)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def boom(*a, **k):
    raise AssertionError("network/subprocess call attempted")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    app = load().build_app(str(tmp_path / "settings.json"))
    c = app.test_client()
    # the sandbox enrolls TOTP in a totp.json next to its settings file
    from app import totp
    return login(c, "preview", totp.load(tmp_path / "totp.json")["secret"])


def test_no_app_created_at_import():
    assert not hasattr(load(), "app")


def test_dashboard_shows_canned_names(client):
    r = client.get("/", base_url=HTTPS)
    assert r.status_code == 200
    h = r.get_data(as_text=True)
    for s in ("Laptop", "Phone", "wgnet1", "enp2s0"):
        assert s in h, s
    assert "data unavailable" not in h.lower()


def test_canned_prom_is_offline(tmp_path, monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    prom = load().CannedProm()
    assert prom.query("omv_wg_received_bytes_total")
    assert prom.query_range("probe_success", 0, 60, 15)


def test_pages_render_without_network(client):
    for path in ("/", "/wiki"):
        assert client.get(path, base_url=HTTPS).status_code == 200


def test_source_is_hermetic():
    src = SRC.read_text()
    for bad in ("192.168.1.10", "ssh", "subprocess", "socket", "urllib"):
        assert bad not in src, bad
    assert "127.0.0.1" in src
    assert "0.0.0.0" not in src
    hosts = re.findall(r'host\s*=\s*"([^"]+)"', src)
    assert hosts and set(hosts) == {"127.0.0.1"}


def test_preview_actions_disabled(client):
    html = client.get("/network", base_url=HTTPS).get_data(as_text=True)
    t = re.search(r'name="csrf_token"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*name="csrf_token"', html)
    t = t.group(1) or t.group(2)
    assert "/network/restart" not in html
    r = client.post("/network/restart", data={"unit": "minidlna", "confirm": "1", "csrf_token": t}, base_url=HTTPS)
    assert r.status_code == 503
