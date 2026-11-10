"""Device backup downloads: host export/snapshots, the omv-netctl actions and the web routes."""
import json
import os

import pytest

from app import backups
from conftest import FakeNetctl, login
from test_alerts_web import HTTPS, body, entries, get, make, token
from test_device_backup import NOW, Env, Fake, target
from test_netctl_helper import BK_CFG, Clock, FakeRunner, load as load_netctl

SNAP = "a1b2c3d4"
READY = f"pc-{SNAP}-home_user_Documents-20261102-2015.tar"


# --- host: omv-device-backup.py snapshots / export ------------------------------

class DumpFake(Fake):
    def __init__(self, rc=0, out=""):
        super().__init__()
        self.dumps, self.rc, self.out = [], rc, out

    def run(self, argv, input=None):
        self.calls.append((list(argv), input))
        return 0, 'warning: x\n[{"short_id": "a1b2c3d4", "time": "2026-11-01T03:00:00+01:00", "paths": ["/home"], "hostname": "pc"},' \
                  ' {"short_id": "ffff0000", "time": "2026-11-02T03:00:00+01:00", "paths": ["/home"]}]'

    def dump(self, argv, path):
        self.dumps.append(list(argv))
        if self.rc == 0:
            path.write_bytes(b"tar")
        return self.rc, self.out


@pytest.fixture
def owned(monkeypatch):
    calls = []
    monkeypatch.setattr(os, "chown", lambda p, u, g: calls.append((str(p), u, g)))
    return calls


def env(tmp_path, fake, **kw):
    return Env(tmp_path, [target("pc")], fake, dest=str(tmp_path / "nas"), **kw)


def test_snapshots_newest_first_runs_restic_locally(tmp_path):
    e = env(tmp_path, DumpFake())
    rows = e.b.snapshots("pc")
    assert [r["id"] for r in rows] == ["ffff0000", "a1b2c3d4"] and rows[1]["host"] == "pc"
    argv = e.fake.calls[0][0]
    assert argv[:3] == ["restic", "-r", str(tmp_path / "nas" / "pc")] and "ssh" not in argv
    with pytest.raises(ValueError):
        e.b.snapshots("nope")


def test_export_writes_tar_for_the_web_user(tmp_path, owned):
    (tmp_path / "nas").mkdir()
    e = env(tmp_path, DumpFake())
    assert e.b.export("pc", SNAP, "/home/user/Documents") is True
    assert e.fake.dumps[0][-5:] == ["dump", "--archive", "tar", SNAP, "/home/user/Documents"]
    files = [p.name for p in (tmp_path / "nas" / ".exports").iterdir()]
    assert len(files) == 1 and files[0].startswith(f"pc-{SNAP}-home_user_Documents-") and files[0].endswith(".tar")
    assert backups._EXPORT.fullmatch(files[0])
    assert any(u == 10001 for _, u, _ in owned)


def test_export_failure_leaves_err_not_tar(tmp_path, owned):
    (tmp_path / "nas").mkdir()
    e = env(tmp_path, DumpFake(rc=1, out="no such path"))
    assert e.b.export("pc", SNAP, "/nope") is False
    files = [p.name for p in (tmp_path / "nas" / ".exports").iterdir()]
    assert len(files) == 1 and files[0].endswith(".tar.err")
    assert "no such path" in (tmp_path / "nas" / ".exports" / files[0]).read_text()


def test_export_refuses_system_disk(tmp_path, owned):
    e = env(tmp_path, DumpFake(), dev=lambda p: 1)
    assert e.b.export("pc", SNAP, "/home") is False
    assert e.fake.dumps == [] and not (tmp_path / "nas" / ".exports").exists()


def test_due_expires_old_exports(tmp_path):
    d = tmp_path / "nas" / ".exports"
    d.mkdir(parents=True)
    old, fresh, stuck = d / READY, d / READY.replace("2015", "2016"), d / (READY + ".part")
    for f in (old, fresh, stuck):
        f.write_bytes(b"x")
    os.utime(old, (NOW - 3700, NOW - 3700))
    os.utime(fresh, (NOW - 60, NOW - 60))
    os.utime(stuck, (NOW - 3700, NOW - 3700))  # a running dump keeps its .part for 6 h
    env(tmp_path, DumpFake()).b.expire_exports()
    assert not old.exists() and fresh.exists() and stuck.exists()


# --- omv-netctl backup-snapshots / backup-export --------------------------------

@pytest.fixture
def helper(tmp_path):
    runner = FakeRunner()
    return load_netctl().Helper(runner, tmp_path / "state", clock=Clock(), backup_config=lambda: BK_CFG), runner, tmp_path / "state"


def test_netctl_export_writes_request_and_starts_unit(helper):
    h, runner, state = helper
    r = h.handle({"action": "backup-export", "args": {"target": "pc", "snapshot": SNAP, "path": "/home/user"}})
    assert r["ok"] is True
    assert runner.calls == [["systemctl", "start", "--no-block", "omv-device-export@pc.service"]]
    assert json.loads((state / "backup-requests" / "export-pc.json").read_text()) == {"snapshot": SNAP, "path": "/home/user"}


@pytest.mark.parametrize("args", [
    {"target": "nope", "snapshot": SNAP, "path": "/home"},
    {"target": "pc", "snapshot": "latest", "path": "/home"},
    {"target": "pc", "snapshot": SNAP + ";x", "path": "/home"},
    {"target": "pc", "snapshot": SNAP, "path": "home"},
    {"target": "pc", "snapshot": SNAP, "path": "--help"},
    {"target": "pc", "snapshot": SNAP, "path": "/home/../etc/shadow"},
    {"target": "pc", "snapshot": SNAP, "path": "/home\n/etc"},
    {"target": "pc", "snapshot": SNAP, "path": ["/home"]},
    {"target": "pc", "snapshot": SNAP},
])
def test_netctl_export_rejected(helper, args):
    h, runner, _ = helper
    assert h.handle({"action": "backup-export", "args": args})["ok"] is False
    assert runner.calls == []


def test_netctl_snapshots_runs_the_backup_script(helper):
    h, runner, _ = helper
    runner.run = lambda argv, input=None: (runner.calls.append(list(argv)), (0, '[{"id": "a1b2c3d4"}]'))[1]
    assert h.handle({"action": "backup-snapshots", "args": {"target": "omv"}})["result"]["snapshots"] == [{"id": "a1b2c3d4"}]
    assert runner.calls[0][-2:] == ["snapshots", "omv"]
    assert h.handle({"action": "backup-snapshots", "args": {"target": "../x"}})["ok"] is False


# --- web ------------------------------------------------------------------------

SNAPS = [{"id": SNAP, "time": "2026-11-02T03:00:00+01:00", "paths": ["/home"], "host": "pc"}]


@pytest.fixture
def exports(tmp_path):
    d = tmp_path / "exports"
    d.mkdir()
    (d / READY).write_bytes(b"tarbytes")
    (d / (READY.replace("2015", "2016") + ".part")).write_bytes(b"")
    (d / (READY.replace("2015", "2017") + ".err")).write_text("restic dump failed (exit 1): path not found")
    (d / READY.replace("pc-", "omv-")).write_bytes(b"other target")
    return d


@pytest.fixture
def nc():
    return FakeNetctl({"backup-snapshots": {"snapshots": SNAPS}, "backup-export": {"detail": "export started"}})


@pytest.fixture
def c(fake, tmp_path, nc, exports):
    return login(make(fake, tmp_path, nc, EXPORT_DIR=str(exports)).test_client())


def export_post(c, **data):
    data["csrf_token"] = token(body(c, "/backups/targets/pc"))
    return c.post("/backups/targets/pc/export", data=data, base_url=HTTPS)


def calls(nc):
    return [a for a in nc.calls if a[0] == "backup-export"]


def test_list_exports_states(exports):
    rows = {e["state"]: e for e in backups.list_exports(exports, "pc")}
    assert set(rows) == {"ready", "running", "failed"} and "path not found" in rows["failed"]["error"]
    assert backups.resolve_export(exports, READY) == exports / READY
    assert backups.resolve_export(exports, READY + ".part") is None
    assert backups.resolve_export(exports, "../" + READY) is None


def test_target_page_has_download_section(c):
    h = body(c, "/backups/targets/pc")
    assert f'value="{SNAP}"' in h and 'name="path"' in h
    assert f"/backups/exports/{READY}" in h and "preparing" in h and "path not found" in h
    assert READY.replace("pc-", "omv-") not in h


def test_target_page_without_helper_says_so(fake, tmp_path, exports):
    c = login(make(fake, tmp_path, None, EXPORT_DIR=str(exports)).test_client())
    assert "host helper is not connected" in body(c, "/backups/targets/pc")


def test_first_post_confirms_then_calls_netctl_and_audits(c, nc, tmp_path):
    r = export_post(c, snapshot=SNAP, path="/home/user/Documents")
    assert r.status_code == 200 and "Prepare download" in r.get_data(as_text=True) and calls(nc) == []
    r = export_post(c, snapshot=SNAP, path="/home/user/Documents", confirm="1")
    assert r.status_code == 303 and "exporting=1" in r.headers["Location"]
    assert calls(nc) == [("backup-export", {"target": "pc", "snapshot": SNAP, "path": "/home/user/Documents"})]
    assert [e["action"] for e in entries(tmp_path)] == ["backup-export"]


def test_full_snapshot_exports_root(c, nc):
    assert "whole snapshot" in export_post(c, snapshot=SNAP, path="", full="1").get_data(as_text=True)
    export_post(c, snapshot=SNAP, path="", full="1", confirm="1")
    assert calls(nc) == [("backup-export", {"target": "pc", "snapshot": SNAP, "path": "/"})]


@pytest.mark.parametrize("snap, path", [("latest", "/home"), (SNAP, "home"), (SNAP, "/home/../etc"), (SNAP, "")])
def test_bad_input_is_400_without_call(c, nc, snap, path):
    assert export_post(c, snapshot=snap, path=path, confirm="1").status_code == 400
    assert calls(nc) == []


def test_post_needs_csrf(c, nc):
    r = c.post("/backups/targets/pc/export", data={"snapshot": SNAP, "path": "/home", "confirm": "1"}, base_url=HTTPS)
    assert r.status_code == 400 and calls(nc) == []


def test_download_ready_only(c, tmp_path):
    r = get(c, f"/backups/exports/{READY}")
    assert r.status_code == 200 and r.data == b"tarbytes" and r.headers["Content-Disposition"].startswith("attachment")
    assert "backup-download" in [e["action"] for e in entries(tmp_path)]
    assert get(c, f"/backups/exports/{READY.replace('2015', '2016')}.part").status_code == 404
    assert get(c, "/backups/exports/..%2Fsecrets").status_code == 404


def test_download_needs_login(fake, tmp_path, nc, exports):
    c = make(fake, tmp_path, nc, EXPORT_DIR=str(exports)).test_client()
    assert get(c, f"/backups/exports/{READY}").status_code == 302


_OK = "nas-0123abcd-Documents-20261030-0330.tar"


@pytest.mark.parametrize("name", [
    "../" + _OK, "/etc/passwd", "sub/" + _OK, _OK + "/../x", _OK + "\n", _OK + "\0", "%2e%2e%2f" + _OK, ".." ])
def test_resolve_export_rejects_traversal(tmp_path, name):
    (tmp_path / _OK).write_bytes(b"x")
    assert backups.resolve_export(tmp_path, name) is None


def test_resolve_export_refuses_symlink_and_symlinked_dir(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("x")
    d = tmp_path / "exports"
    d.mkdir()
    (d / _OK).symlink_to(secret)
    assert backups.resolve_export(d, _OK) is None
    link = tmp_path / "link"
    link.symlink_to(d)
    (d / _OK).unlink()
    (d / _OK).write_bytes(b"x")
    assert backups.resolve_export(link, _OK) is None  # base dir itself must not be a symlink


@pytest.mark.parametrize("p", ["/a/../b", "/a/\nb", "rel", "/a\0b", "/" + "a" * 1100, None, 5])
def test_valid_export_path_rejects(p):
    assert not backups.valid_export_path(p)
