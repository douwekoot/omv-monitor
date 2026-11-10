import io
import json
import time
import urllib.error
from pathlib import Path

import pytest

from app import config, data
from app.prom import PromClient, PromError
from conftest import FakeProm, mat, vec

SVCS = config.load_monitor(Path(__file__).parent.parent / "monitor/config/monitor.toml")["services"]

DEVICES = {"10.8.0.2/32": "Laptop", "10.8.0.1/32": "Phone"}


# ---- PromClient with mocked urlopen ----
class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def patch_urlopen(monkeypatch, fn):
    monkeypatch.setattr("urllib.request.urlopen", fn)
    import app.prom as p
    monkeypatch.setattr(p, "urlopen", fn, raising=False)


def test_query_success(monkeypatch):
    body = {"status": "success", "data": {"resultType": "vector", "result": [{"metric": {"a": "b"}, "value": [1, "2"]}]}}
    seen = []

    def fake_open(req, *a, **kw):
        seen.append(req.full_url if hasattr(req, "full_url") else req)
        return Resp(json.dumps(body).encode())

    patch_urlopen(monkeypatch, fake_open)
    out = PromClient("http://x:9090").query("up")
    assert out == body["data"]["result"]
    assert seen[0].startswith("http://x:9090/api/v1/query")


def test_query_range_success(monkeypatch):
    res = [{"metric": {}, "values": [[1, "2"]]}]
    body = {"status": "success", "data": {"resultType": "matrix", "result": res}}
    patch_urlopen(monkeypatch, lambda *a, **k: Resp(json.dumps(body).encode()))
    assert PromClient().query_range("up", 0, 10, 5) == res


def test_status_error(monkeypatch):
    body = {"status": "error", "errorType": "bad_data", "error": "boom"}
    patch_urlopen(monkeypatch, lambda *a, **k: Resp(json.dumps(body).encode()))
    with pytest.raises(PromError):
        PromClient().query("up")


def test_network_error(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.URLError("down")

    patch_urlopen(monkeypatch, boom)
    with pytest.raises(PromError):
        PromClient().query("up")


def test_http_error(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.HTTPError("http://x", 500, "err", {}, io.BytesIO(b"{}"))

    patch_urlopen(monkeypatch, boom)
    with pytest.raises(PromError):
        PromClient().query_range("up", 0, 10, 5)


# ---- data layer ----
def test_peers_merge_one_row_each(fake):
    rows = data.peers(fake, DEVICES)
    assert len(rows) == 2
    assert [r["device"] for r in rows] == ["Laptop", "Phone"]
    laptop = rows[0]
    assert laptop["id"] == "aaaaaaaa"
    assert laptop["allowed_ips"] == "10.8.0.2/32"
    assert laptop["interface"] == "wgnet1"
    assert laptop["last_handshake"] == 1700000100
    assert laptop["received"] == 1000 and laptop["sent"] == 3000


def test_peers_fallback_name(fake):
    rows = data.peers(fake, {})
    assert sorted(r["device"] for r in rows) == ["10.8.0.1/32", "10.8.0.2/32"]


def test_peers_missing_handshake_is_none(fake):
    fake.data["omv_wg_latest_handshake_timestamp_seconds"] = []
    assert all(r["last_handshake"] is None for r in data.peers(fake, DEVICES))


def test_interfaces_one_row_each_and_filtered(fake):
    rows = data.interfaces(fake)
    assert sorted(r["device"] for r in rows) == ["enp2s0", "eth9", "wgnet1"]
    e = next(r for r in rows if r["device"] == "enp2s0")
    w = next(r for r in rows if r["device"] == "wgnet1")
    # wgnet1 has node_network_up=0 but carrier=1: must show as up
    assert e["up"] is True and w["up"] is True
    assert next(r for r in rows if r["device"] == "eth9")["up"] is False
    assert e["rx_bps"] == 10 and e["tx_bps"] == 20
    assert e["rx_total"] == 111 and e["tx_total"] == 222


def test_services_always_five(fake):
    rows = data.services(fake, SVCS)
    assert [r["name"] for r in rows] == ["smbd", "minidlna", "nginx", "tailscaled", "ssh"]
    assert [r["label"] for r in rows] == ["Samba", "MiniDLNA", "nginx", "tailscaled", "SSH"]
    assert [r["active"] for r in rows] == [True, None, False, None, True]


def test_services_all_missing(fake):
    fake.data["omv_service_active"] = []
    rows = data.services(fake, SVCS)
    assert len(rows) == 5 and all(r["active"] is None for r in rows)


def test_checks_one_row_per_job_instance(fake):
    rows = data.checks(fake)
    assert sorted(r["id"] for r in rows) == ["dns:1.1.1.1", "ping:1.1.1.1", "ping:192.168.1.1"]
    r = next(r for r in rows if r["id"] == "ping:192.168.1.1")
    assert r["job"] == "ping" and r["instance"] == "192.168.1.1"
    assert r["success"] is False and r["duration_s"] == 0.5


def test_posture(fake):
    assert data.posture(fake) == {
        "ip_forward": True, "nat_masquerade": True,
        "input_policy_accept": False, "ssh_password_auth": False,
    }


def test_posture_missing_is_none(fake):
    fake.data["omv_ip_forward"] = []
    assert data.posture(fake)["ip_forward"] is None


def test_wg_traffic(fake):
    out = data.wg_traffic(fake, 3600)
    assert out["rx"] == [(1700000000, 5.0), (1700000015, 6.0)]
    assert out["tx"] == [(1700000000, 5.0), (1700000015, 6.0)]


@pytest.mark.parametrize("kind,id", [
    ("peer", "aaaaaaaa"), ("interface", "enp2s0"), ("service", "smbd"), ("check", "ping:1.1.1.1"),
])
def test_history_known(fake, kind, id):
    out = data.history(fake, kind, id, 3600, SVCS)
    assert out and all(isinstance(k, str) for k in out)
    for pts in out.values():
        assert pts and all(len(p) == 2 for p in pts)


def test_history_unknown_kind(fake):
    with pytest.raises(KeyError):
        data.history(fake, "bogus", "x", 3600)


@pytest.mark.parametrize("bad", ['a"b', "a{b", "a}b", 'x"} or vector(1) #', "a\\b", "a\nb"])
@pytest.mark.parametrize("kind", ["peer", "interface", "service", "check"])
def test_history_rejects_injection(fake, kind, bad):
    with pytest.raises(KeyError):
        data.history(fake, kind, bad, 3600)
    assert not any(bad in c for c in fake.calls)


def test_history_unknown_id_without_data(fake):
    fake.ranges = {}
    with pytest.raises(KeyError):
        data.history(fake, "peer", "zzzzzzzz", 3600)


def test_strips_align_slots_and_mark_gaps():
    from app.data import SLOTS, strips
    step = 86400 // SLOTS
    end = time.time() // step * step
    start = end - step * (SLOTS - 1)
    fake = FakeProm(ranges={"probe_success": [mat([(start, 1), (start + 2 * step, 0.5), (end, 0)], job="ping", instance="1.1.1.1")]})
    s = strips(fake, "check", 86400)["ping:1.1.1.1"]
    assert len(s) == SLOTS and s[0] == 1 and s[1] is None and s[2] == 0.5 and s[-1] == 0


def test_scale_is_max_across_items():
    from app.data import scale
    fake = FakeProm(ranges={"max(probe_duration_seconds)": [mat([(0, 0.2), (15, 0.7)])]})
    assert scale(fake, "check", 3600) == 0.7 and scale(fake, "service", 3600) is None


def test_disks_sorted_with_health_flag():
    from conftest import vec
    f = FakeProm({"omv_smart_healthy": [vec(0, device="sdb"), vec(1, device="sda")]})
    assert data.disks(f) == [{"device": "sda", "healthy": True}, {"device": "sdb", "healthy": False}]
    assert data.disks(FakeProm()) == []


def test_containers_sorted_with_running_flag():
    from conftest import vec
    f = FakeProm({"omv_container_running": [vec(1, name="web"), vec(0, name="db")]})
    assert data.containers(f) == [{"name": "db", "running": False}, {"name": "web", "running": True}]
    assert data.containers(FakeProm()) == []


def test_cert_expiry_value_or_none():
    from conftest import vec
    f = FakeProm({"omv_cert_expiry_timestamp_seconds": [vec(1800000000)]})
    assert data.cert_expiry(f) == 1800000000
    assert data.cert_expiry(FakeProm()) is None


# ---- updates, device backups, filesystems ----
def test_updates(fake):
    fake.data["omv_apt_upgrades_pending"] = [vec(4)]
    fake.data["omv_reboot_required"] = [vec(1)]
    assert data.updates(fake) == {"pending": 4, "reboot": True}
    fake.data["omv_apt_upgrades_pending"] = [vec(0)]
    fake.data["omv_reboot_required"] = [vec(0)]
    r = data.updates(fake)
    assert r == {"pending": 0, "reboot": False} and r["pending"] is not None


def test_updates_missing_is_none(fake):
    assert data.updates(fake) == {"pending": None, "reboot": None}
    fake.data["omv_reboot_required"] = [vec(1)]
    assert data.updates(fake) == {"pending": None, "reboot": True}


def backup_metrics(fake, **targets):
    names = {"last_success": "omv_device_backup_last_success_timestamp_seconds",
             "last_run": "omv_device_backup_last_run_timestamp_seconds", "ok": "omv_device_backup_last_ok",
             "size": "omv_device_backup_size_bytes", "interval_s": "omv_device_backup_interval_seconds"}
    for field, metric in names.items():
        fake.data[metric] = [vec(v[field], target=t) for t, v in targets.items() if field in v]


def test_device_backups_sorted_rows(fake):
    backup_metrics(fake,
                   zed={"last_success": 1700000000, "last_run": 1700000100, "ok": 0, "size": 5e9, "interval_s": 86400},
                   alpha={"last_success": 1699990000, "last_run": 1699990000, "ok": 1, "size": 1e9, "interval_s": 129600})
    rows = data.device_backups(fake)
    assert [r["target"] for r in rows] == ["alpha", "zed"]
    assert rows[0] == {"target": "alpha", "last_success": 1699990000, "last_run": 1699990000, "ok": True,
                       "size": 1e9, "interval_s": 129600}
    assert rows[1]["ok"] is False and rows[1]["last_run"] == 1700000100


def test_device_backups_missing_fields_are_none(fake):
    backup_metrics(fake, alpha={"last_run": 1700000000, "ok": 0})
    (r,) = data.device_backups(fake)
    assert r["target"] == "alpha" and r["ok"] is False
    assert r["last_success"] is None and r["size"] is None and r["interval_s"] is None


def test_device_backups_none_reported(fake):
    assert data.device_backups(fake) == []


def fs(fake, rows):
    fake.data["node_filesystem_size_bytes"] = [vec(s, mountpoint=m, fstype=t, device="d") for m, t, s, a in rows]
    fake.data["node_filesystem_avail_bytes"] = [vec(a, mountpoint=m, fstype=t, device="d") for m, t, s, a in rows]


def test_filesystems_used_pct_and_excludes_virtual(fake):
    fs(fake, [("/", "ext4", 1000, 250), ("/srv/data", "ext4", 2000, 1900), ("/run", "tmpfs", 100, 99),
              ("/var/lib/docker/overlay2/x/merged", "overlay", 500, 100)])
    rows = data.filesystems(fake)
    assert [r["mount"] for r in rows] == ["/", "/srv/data"]
    assert rows[0]["used_pct"] == pytest.approx(75.0)
    assert rows[1]["used_pct"] == pytest.approx(5.0)


def test_filesystems_missing_is_none_or_empty(fake):
    assert data.filesystems(fake) == []
    fake.data["node_filesystem_size_bytes"] = [vec(1000, mountpoint="/", fstype="ext4")]  # no avail
    assert data.filesystems(fake) == [{"mount": "/", "used_pct": None}]


@pytest.mark.parametrize("kind,id", [
    ("peer", 'a"} or vector(1) #'), ("peer", "a{b}"), ("peer", "a\\"), ("peer", "a\n"), ("peer", ""),
    ("interface", 'eth0"}[5m] or {job=~".+'), ("interface", "a b"),
    ("check", 'j",instance="x"} or up{a="'), ("check", 'blackbox:x"}'), ("check", "j:i\n"),
])
def test_history_never_sends_unsafe_ids_to_prometheus(kind, id):
    c = FakeProm(ranges={"": []})
    with pytest.raises(KeyError):
        data.history(c, kind, id, 3600, SVCS)
    assert c.calls == []


def test_history_service_must_be_configured(tmp_path):
    c = FakeProm()
    with pytest.raises(KeyError):
        data.history(c, "service", 'x"} or up{a="', 3600, SVCS)
    assert c.calls == []
