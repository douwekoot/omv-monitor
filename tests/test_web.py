import re
from pathlib import Path

import pytest

from app.prom import PromError
from app.web import create_app
from app.charts import line_chart
from conftest import FakeProm, login, totp_cfg

ROOT = Path(__file__).resolve().parent.parent
HTTPS = "https://localhost"


def make(prom):
    return create_app({"ADMIN_PASSWORD": "pw", "SECRET_KEY": "k", "WIKI_DIR": str(ROOT / "monitor/wiki"),
                       "DEVICES_FILE": str(ROOT / "monitor/config/devices.toml"),
                       **totp_cfg()}, prom_client=prom)


def logged_in(prom):
    c = make(prom).test_client()
    return login(c)


def get(c, path):
    return c.get(path, base_url=HTTPS)


@pytest.fixture
def client(fake):
    return logged_in(fake)


def test_dashboard_content(client):
    r = get(client, "/")
    assert r.status_code == 200
    h = r.get_data(as_text=True)
    for s in ("Laptop", "Phone", "wgnet1", "enp2s0", "smbd", "minidlna", "nginx", "tailscaled", "ssh",
              "1.1.1.1", "192.168.1.1", "24h", "7d", "<svg"):
        assert s in h, s
    assert "data unavailable" not in h.lower()


def test_dashboard_links_to_network(client):
    assert 'href="/network" >Network<' in get(client, "/").get_data(as_text=True)


def test_dashboard_links_to_details(client):
    h = get(client, "/").get_data(as_text=True)
    for href in ("/detail/peer/aaaaaaaa", "/detail/interface/enp2s0", "/detail/service/smbd",
                 "/detail/check/ping:1.1.1.1"):
        assert f'href="{href}"' in h, href


def test_main_nav_links(client):
    h = get(client, "/").get_data(as_text=True)
    nav = re.search(r'<nav class="seg".*?</nav>', h, re.S).group(0)
    assert set(re.findall(r'href="([^"]+)"', nav)) == {"/", "/advisories", "/alerts", "/network", "/backups", "/wiki"}
    assert 'action="/logout"' in h
    assert re.search(r'<a class="pill-btn icon-btn" href="/settings" aria-label="Settings"[^>]*>\s*<svg', h)
    assert 'href="/settings"' not in nav


def test_settings_gear_marks_current(client):
    h = get(client, "/settings").get_data(as_text=True)
    assert re.search(r'href="/settings" aria-label="Settings" aria-current="page"', h)


def test_no_external_assets(client):
    h = get(client, "/").get_data(as_text=True)
    assert not re.search(r'(src|href)="(https?:)?//', h)
    assert "prefers-color-scheme" in h or "prefers-color-scheme" in (
        get(client, re.search(r'href="(/static/[^"]+\.css)"', h).group(1)).get_data(as_text=True))


@pytest.mark.parametrize("path", ["/detail/peer/aaaaaaaa", "/detail/interface/enp2s0",
                                  "/detail/service/smbd", "/detail/check/ping:1.1.1.1"])
@pytest.mark.parametrize("rng", ["", "?range=24h", "?range=7d"])
def test_detail_ok(client, path, rng):
    r = get(client, path + rng)
    assert r.status_code == 200
    assert "<svg" in r.get_data(as_text=True)


def test_detail_shows_labels(client):
    h = get(client, "/detail/peer/aaaaaaaa").get_data(as_text=True)
    assert "Laptop" in h and "10.8.0.2/32" in h


@pytest.mark.parametrize("path", ["/detail/bogus/x", "/detail/peer/nope", "/detail/service/nope",
                                  "/detail/interface/nope", "/detail/check/nocolon", "/detail/peer/a%22b"])
def test_detail_404(fake, path):
    fake.ranges = {}
    assert get(logged_in(fake), path).status_code == 404


class Down:
    def query(self, e):
        raise PromError("down")

    query_range = lambda self, *a: self.query(a[0])


@pytest.mark.parametrize("path", ["/", "/detail/peer/aaaaaaaa"])
def test_prom_error_renders_unavailable(path):
    r = get(logged_in(Down()), path)
    assert r.status_code == 200
    assert "data unavailable" in r.get_data(as_text=True).lower()


def test_wiki(client):
    r = get(client, "/wiki")
    assert r.status_code == 200 and "/wiki/monitoring" in r.get_data(as_text=True)
    assert get(client, "/wiki/monitoring").status_code == 200
    assert get(client, "/wiki/does-not-exist").status_code == 404
    assert get(client, "/wiki/..%2Fsecret").status_code == 404


# ---- charts ----
def test_chart_basic():
    svg = line_chart({"rx": [(0, 1), (10, 5)], "tx": [(0, 2), (10, 3)]}, unit="B/s")
    assert svg.startswith("<figure") and svg.endswith("</figure>") and "<svg" in svg
    assert "rx" in svg and "tx" in svg


def test_chart_escapes_labels():
    svg = line_chart({"<script>x</script>": [(0, 1), (1, 2)]})
    assert "<script>" not in svg and "&lt;script&gt;" in svg


@pytest.mark.parametrize("series", [{}, {"a": []}, {"a": [(1, 1)]}, {"a": [(0, 3), (5, 3)]}])
def test_chart_degenerate(series):
    assert "<figure" in line_chart(series)


def test_chart_label_names_latest_values():
    svg = line_chart({"Received": [(0, 1), (10, 2048)]}, unit="B/s")
    assert 'aria-label="Received: latest 2 KiB/s"' in svg
    assert 'aria-label="No data"' in line_chart({})


def test_dashboard_a11y(client):
    h = get(client, "/").get_data(as_text=True)
    assert '<h1 class="large bad">4 findings, 6 advisories</h1>' in h and "Inspected at " in h  # laptop target is disabled in backups.toml
    assert 'aria-current="page"' in h and "aria-pressed" not in h
    assert re.search(r'href="/\?range=24h" aria-current="true"', h)


def test_findings_ordered_and_linked(client):
    h = get(client, "/").get_data(as_text=True)
    main = h[h.index('<main class="inspector'):]
    att = main[main.index("Needs attention"):main.index("Traffic on wgnet1")]
    # Findings come before advisories; each item finding links to its page.
    assert att.index("is down") < att.index("is not running") < att.index("not reported")
    assert 'href="/advisories/connectivity-checks">ping 192.168.1.1 is down' in att
    assert 'href="/advisories/services-running">nginx is not running' in att
    assert "MiniDLNA is not reported" in att and "tailscaled is not reported" in att
    side = h[h.index('<aside'):h.index('</aside>')]
    for href in ("/detail/peer/aaaaaaaa", "/detail/interface/enp2s0", "/detail/service/smbd", "/detail/check/ping:1.1.1.1"):
        assert f'href="{href}"' in side, href


def test_detail_selects_item_in_sidebar(client):
    h = get(client, "/detail/service/smbd").get_data(as_text=True)
    assert '<a class="row" href="/detail/service/smbd" aria-current="page">' in h
    assert 'class="verdict-pill bad" href="/">' in h  # not current on an item page


def test_detail_heading_is_name_with_state(client):
    h = get(client, "/detail/peer/aaaaaaaa").get_data(as_text=True)
    assert re.search(r'<h1 class="title">(Laptop|Phone)</h1>', h) and 'class="cap idle">idle<' in h
    h = get(client, "/detail/check/ping:1.1.1.1").get_data(as_text=True)
    assert '<h1 class="title">ping 1.1.1.1</h1>' in h and 'class="cap good">up<' in h


def test_service_detail_strip(client):
    h = get(client, "/detail/service/smbd").get_data(as_text=True)
    assert 'class="strip k-service"' in h and "running" in h


def test_state_strip_classes_and_label():
    from app.charts import state_strip
    svg = state_strip([1, None, 0.5, 0], "running", "k-service")
    assert 'class="strip k-service"' in svg and 'aria-label="running 50% of the time"' in svg
    assert [c for c in ("s-up", "s-none", "s-part", "s-down") if f'class="{c}"' in svg] == ["s-up", "s-none", "s-part", "s-down"]


def test_findings_quiet_for_idle_peer_and_unused_interface():
    from app.web import findings, _host
    peers = [{"code": "P1", "last_handshake": None}]
    ifs = [{"code": "I1", "device": "wlp3s0", "up": False, "state": "down", "cls": "idle"},
           {"code": "I2", "device": "wgnet1", "up": False, "state": "down", "cls": "bad"}]
    rows, n = findings(peers, ifs, [], [], _host({"ip_forward": True, "nat_masquerade": True,
                                                   "input_policy_accept": False, "ssh_password_auth": False}), False)
    assert n == {"finding": 1, "advisory": 0} and rows[0]["title"] == "wgnet1 is down"


def test_chart_axis_spans_selected_range():
    import time as t
    svg = line_chart({"a": [(5000, 1), (6000, 2)]}, span=(0, 86400))
    assert t.strftime("%d %b %H:%M", t.localtime(0)) in svg and t.strftime("%d %b %H:%M", t.localtime(86400)) in svg


def test_advisories_index_lists_every_rule(client):
    from app.advisories import RULES
    h = get(client, "/advisories").get_data(as_text=True)
    for rid in RULES:
        assert f'href="/advisories/{rid}"' in h, rid
    assert '<a href="/advisories/connectivity-checks">Connectivity checks</a>' in h
    assert "How advisories are raised" in h


@pytest.mark.parametrize("rid", ["ipv4-forwarding", "nat-masquerade", "input-policy", "ssh-password-login",
                                 "connectivity-checks", "services-running", "required-interfaces", "monitoring-data"])
def test_advisory_page(client, rid):
    r = get(client, f"/advisories/{rid}")
    h = r.get_data(as_text=True)
    assert r.status_code == 200 and "How to fix" in h and "What is measured" in h
    assert f'<a class="row" href="/advisories/{rid}" aria-current="page">' in h


def test_advisory_page_shows_raised_items(client):
    h = get(client, "/advisories/services-running").get_data(as_text=True)
    assert "Raised now" in h and "nginx is not running" in h and 'href="/detail/service/smbd"' in h
    assert get(client, "/advisories/nope").status_code == 404


def test_wiki_docs_layout(client):
    h = get(client, "/wiki/monitoring").get_data(as_text=True)
    assert 'aria-label="On this page"' in h and 'href="#components"' in h
    assert "<dt>Section</dt><dd>Operations</dd>" in h and "<dt>About</dt><dd>Monitoring stack</dd>" in h
    idx = get(client, "/wiki").get_data(as_text=True)
    assert '<a href="/wiki/alerts">Alerts</a>' in idx and "Email alerts and SMTP setup" in idx


def test_chart_embeds_exact_points():
    import json, html as H
    svg = line_chart({"Sent": [(100, 1.5), (200, 2.25)]}, unit="ms", span=(0, 300))
    raw = json.loads(H.unescape(re.search(r'data-chart="([^"]+)"', svg).group(1)))
    assert raw["series"] == [{"name": "Sent", "c": 0, "pts": [[100, 1.5], [200, 2.25]]}]
    assert raw["x0"] == 0 and raw["x1"] == 300 and raw["unit"] == "ms" and '<div class="area">' in svg


def test_dashboard_disks_and_containers_panels(client):
    h = get(client, "/").get_data(as_text=True)
    assert 'id="h-disks"' in h and 'id="h-containers"' in h
    for s in ("sda", "sdb", "minidlna", "pihole", "running", "stopped"):
        assert s in h, s


def test_failing_disk_raises_finding_on_dashboard(fake):
    from conftest import vec
    fake.data["omv_smart_healthy"] = [vec(1, device="sda"), vec(0, device="sdb")]
    h = get(logged_in(fake), "/").get_data(as_text=True)
    assert "sdb SMART health check failed" in h


def test_missing_metrics_show_na_and_advisories(fake):
    for k in ("omv_smart_healthy", "omv_container_running", "omv_cert_expiry_timestamp_seconds"):
        fake.data[k] = []
    r = get(logged_in(fake), "/")
    h = r.get_data(as_text=True)
    assert r.status_code == 200
    assert "Disk health not reported" in h and "Certificate expiry not reported" in h
    assert 'id="h-disks"' in h and 'id="h-containers"' in h
    assert "n/a" in h


def test_panels_hidden_when_deselected(fake, tmp_path):
    import json
    (tmp_path / "s.json").write_text(json.dumps({"panels": ["peers"]}))
    c = create_app({"ADMIN_PASSWORD": "pw", "SECRET_KEY": "k", "WIKI_DIR": str(ROOT / "monitor/wiki"),
                    "DEVICES_FILE": str(ROOT / "monitor/config/devices.toml"),
                    "SETTINGS_FILE": str(tmp_path / "s.json"), **totp_cfg(tmp_path)}, prom_client=fake).test_client()
    h = get(login(c), "/").get_data(as_text=True)
    assert 'id="h-disks"' not in h and 'id="h-containers"' not in h


def _backup_client(fake, root):
    return login(create_app({"ADMIN_PASSWORD": "pw", "SECRET_KEY": "k", "WIKI_DIR": str(ROOT / "monitor/wiki"),
                             "DEVICES_FILE": str(ROOT / "monitor/config/devices.toml"),
                             "BACKUP_DIR": str(root), **totp_cfg()}, prom_client=fake).test_client())


def test_dashboard_last_backup_shown(fake, tmp_path):
    d = tmp_path / "files" / "config"
    d.mkdir(parents=True)
    (d / "config-2020-01-01_0330.tar.gz").write_bytes(b"x")
    h = get(_backup_client(fake, tmp_path / "files"), "/").get_data(as_text=True)
    assert 'id="h-backup"' in h and "2020-01-01 03:30" in h and "ago" in h


@pytest.mark.parametrize("sub", ["empty", "missing"])
def test_dashboard_last_backup_na(fake, tmp_path, sub):
    root = tmp_path / sub
    if sub == "empty":
        root.mkdir()
    h = get(_backup_client(fake, root), "/").get_data(as_text=True)
    assert 'id="h-backup"' in h and "n/a" in h


def test_dashboard_traffic_axis_follows_visible_peak(fake):
    from conftest import mat
    import time
    now = time.time()
    s = [mat([(now - 120, 1024), (now - 60, 3 * 1024)])]
    fake.ranges["rate(node_network_receive_bytes_total"] = fake.ranges["rate(node_network_transmit_bytes_total"] = s
    h = get(logged_in(fake), "/").get_data(as_text=True)
    assert "Peak 3 KiB/s" in h and "<span>5 KiB/s</span>" in h
