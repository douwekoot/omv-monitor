"""Contract (coder must implement) for monitor/host/omv-device-backup.py:

DeviceBackup(cfg, runner, clock=time.time, sleep=time.sleep, send_wol=None, ismount=os.path.ismount,
             st_dev=lambda p: os.stat(p).st_dev, log_file=, metrics_file=, secrets_dir=, lock_dir=)
  .run_target(name, categories=None) and .due(); runner.run(argv, input=None) -> (rc, out);
  send_wol(mac) is called to wake. Lock file: <lock_dir>/<name>.lock (fcntl.flock).
  due() reads last_run from the previous metrics file.
"""
import fcntl
import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "monitor/host/omv-device-backup.py"
PASSWORD = "s3cretpw-xyz"
NOW = 1_000_000.0
DEST = "/mnt/nasbackup"


def load():
    spec = importlib.util.spec_from_file_location("omv_device_backup", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def target(name, kind="ssh", **kw):
    t = {"name": name, "label": name, "kind": kind, "hosts": [], "user": "", "mac": None,
         "shutdown_after_wol": False, "enabled": True, "interval_h": 24, "include": [], "exclude": [],
         "categories": ["home"], "retention": {"daily": 7, "weekly": 4, "monthly": 6}}
    if kind == "ssh":
        t.update(hosts=["pc.lan"], user="bk")
    t.update(kw)
    return t


class Fake:
    """Fake ssh/ping/restic/systemctl: a host answers any argv naming it while in `up`."""

    def __init__(self, up=(), fail_restic=False):
        self.up, self.fail_restic, self.calls = set(up), fail_restic, []
        self.conn = "192.168.1.10 51234 192.168.1.50 22"  # client ip, port, server ip, port

    def run(self, argv, input=None):
        self.calls.append((list(argv), input))
        j = " ".join(argv)
        if "SSH_CONNECTION" in j:
            return (0, self.conn) if any(h in self.up for h in ("pc.lan", "laptop.lan", "10.8.0.2")) else (255, "unreachable")
        if "restic" in j and "backup" in j and self.fail_restic:
            return 1, "restic failed"
        names = [h for h in ("pc.lan", "laptop.lan", "10.8.0.2") if h in j]
        if names and not any(h in self.up for h in names):
            return 255, "unreachable"
        return 0, "ok"

    def joined(self):
        return [" ".join(a) for a, _ in self.calls]

    def has(self, *words):
        return any(all(w in j for w in words) for j in self.joined())


class Env:
    def __init__(self, tmp, targets, fake, mounted=True, dev=lambda p: 2 if p != "/" else 1, dest=DEST):
        self.mod = load()
        self.tmp, self.fake, self.wols = tmp, fake, []
        (tmp / "secrets").mkdir()
        for t in targets:
            (tmp / "secrets" / f"restic-{t['name']}.pass").write_text(PASSWORD)
        self.log, self.prom = tmp / "runs.jsonl", tmp / "omv_device_backup.prom"
        self.cfg = {"destination_root": dest, "targets": targets}

        def wol(mac):
            self.wols.append(mac)
            fake.up.add("pc.lan")  # the machine boots after the magic packet

        self.b = self.mod.DeviceBackup(
            self.cfg, fake, clock=lambda: NOW, sleep=lambda s: None, send_wol=wol,
            ismount=lambda p: mounted, st_dev=dev, log_file=self.log, metrics_file=self.prom,
            secrets_dir=tmp / "secrets", lock_dir=tmp)

    def steps(self, t=None):
        rows = [json.loads(x) for x in self.log.read_text().splitlines()] if self.log.exists() else []
        return [r for r in rows if t is None or r["target"] == t]

    def names(self, t=None):
        return [r["step"] for r in self.steps(t)]


@pytest.fixture(autouse=True)
def no_real_subprocess(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("real subprocess used")
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)


def pc(**kw):
    return target("pc", mac="aa:bb:cc:dd:ee:ff", shutdown_after_wol=True, **kw)


def test_pc_already_on_no_wol_no_shutdown(tmp_path):
    e = Env(tmp_path, [pc()], Fake(up={"pc.lan"}))
    e.b.run_target("pc")
    assert e.wols == [] and not e.fake.has("shutdown") and not e.fake.has("poweroff")
    assert e.fake.has("restic", "backup") and e.fake.has("restic", "forget", "--prune")
    assert "wake" not in e.names() and "shutdown" not in e.names() and e.names()[-1] == "done"


def test_pc_down_wol_run_shutdown(tmp_path):
    e = Env(tmp_path, [pc()], Fake())
    e.b.run_target("pc")
    assert e.wols == ["aa:bb:cc:dd:ee:ff"]
    last = [j for j in e.fake.joined() if "restic" in j or "shutdown" in j or "poweroff" in j]
    assert "shutdown" in last[-1] or "poweroff" in last[-1]
    assert e.names() == ["check", "wake", "check", "run", "forget", "shutdown", "done"] or \
        {"check", "wake", "run", "forget", "shutdown", "done"} <= set(e.names())


def test_pc_wol_fails_no_shutdown(tmp_path):
    f = Fake()
    e = Env(tmp_path, [pc()], f)
    e.b.send_wol = lambda mac: None  # never comes up
    e.b.run_target("pc")
    assert "fail" in e.names() and not f.has("restic") and not f.has("shutdown") and not f.has("poweroff")
    assert [s for s in e.steps() if s["step"] == "fail"][0]["ok"] is False


def test_run_fails_after_wol_still_shuts_down(tmp_path):
    e = Env(tmp_path, [pc()], Fake(fail_restic=True))
    e.b.run_target("pc")
    assert e.fake.has("shutdown") or e.fake.has("poweroff")
    assert "fail" in e.names() and "done" not in e.names()
    assert 'omv_device_backup_last_ok{target="pc"} 0' in e.prom.read_text()


def test_no_shutdown_when_flag_off(tmp_path):
    e = Env(tmp_path, [target("pc", mac="aa:bb:cc:dd:ee:ff", shutdown_after_wol=False)], Fake())
    e.b.run_target("pc")
    assert e.wols and not e.fake.has("shutdown") and not e.fake.has("poweroff")


def test_laptop_second_host_vpn(tmp_path):
    f = Fake(up={"10.8.0.2"})
    e = Env(tmp_path, [target("laptop", hosts=["laptop.lan", "10.8.0.2"])], f)
    e.b.run_target("laptop")
    assert e.wols == []
    assert any("restic" in j and "10.8.0.2" in j for j in f.joined())
    assert "done" in e.names()


def test_laptop_unreachable_skipped(tmp_path):
    f = Fake()
    e = Env(tmp_path, [target("laptop", hosts=["laptop.lan", "10.8.0.2"])], f)
    e.b.run_target("laptop")
    assert "skip" in e.names() and e.wols == []
    assert not f.has("restic") and not f.has("shutdown") and not f.has("poweroff")


def test_local_target(tmp_path):
    f = Fake()
    e = Env(tmp_path, [target("omv", "local", categories=["host-config"])], f)
    e.b.run_target("omv")
    restic = [a for a, _ in f.calls if a[0] == "restic"]
    assert restic and "/etc" in " ".join(restic[0]) and f"{DEST}/omv" in " ".join(restic[0])
    assert not f.has("ssh") and "done" in e.names()


def test_due(tmp_path):
    ts = [pc(), target("laptop", hosts=["pc.lan"], enabled=False), target("old", hosts=["pc.lan"])]
    ts.append(target("fresh", hosts=["pc.lan"]))
    e = Env(tmp_path, ts, Fake(up={"pc.lan"}))
    e.prom.write_text(
        f'omv_device_backup_last_run_timestamp_seconds{{target="old"}} {NOW - 25 * 3600}\n'
        f'omv_device_backup_last_run_timestamp_seconds{{target="fresh"}} {NOW - 3600}\n')
    e.b.due()
    ran = {x["target"] for x in e.steps() if x["step"] == "run"}
    assert ran == {"pc", "old"}


def test_busy_lock_skips(tmp_path):
    e = Env(tmp_path, [target("omv", "local")], Fake())
    with open(tmp_path / "omv.lock", "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        e.b.run_target("omv")
    assert "skip" in e.names() and not e.fake.has("restic")


@pytest.mark.parametrize("dest,mounted,dev", [
    ("/", True, lambda p: 1),
    (DEST, True, lambda p: 1),          # same filesystem as /
    (DEST, False, lambda p: 2),         # not a mount point (nor under one)
])
def test_destination_unsafe_refuses(tmp_path, dest, mounted, dev):
    e = Env(tmp_path, [target("omv", "local")], Fake(), mounted=mounted, dev=dev, dest=dest)
    e.b.run_target("omv")
    assert "fail" in e.names() and e.fake.calls == []


def test_repo_path_no_double_slash(tmp_path):
    e = Env(tmp_path, [target("omv", "local")], Fake(), dest=DEST)
    e.cfg["destination_root"] = DEST
    e.b.run_target("omv")
    assert not any("//" in a for argv, _ in e.fake.calls for a in argv if a.startswith("/"))


def test_only_selected_categories_reach_restic(tmp_path):
    f = Fake(up={"pc.lan"})
    e = Env(tmp_path, [target("pc", categories=["home", "system-settings", "users"])], f)
    e.b.run_target("pc", ["system-settings"])
    j = " ".join(x for x in f.joined() if "restic" in x and "backup" in x)
    assert "/etc" in j and "/home" not in j
    assert next(s for s in e.steps() if s["step"] == "run")["categories"] == ["system-settings"]


def test_default_categories_are_saved_ones(tmp_path):
    f = Fake(up={"pc.lan"})
    e = Env(tmp_path, [target("pc", categories=["home"])], f)
    e.b.run_target("pc")
    j = " ".join(x for x in f.joined() if "restic" in x and "backup" in x)
    assert "/home" in j and "/etc" not in j


def test_unknown_category_rejected(tmp_path):
    f = Fake(up={"pc.lan"})
    e = Env(tmp_path, [target("pc")], f)
    with pytest.raises(ValueError):
        e.b.run_target("pc", ["omv-config"])
    assert f.calls == []


def test_secret_never_in_argv_or_log(tmp_path):
    e = Env(tmp_path, [pc()], Fake())
    e.b.run_target("pc")
    assert not any(PASSWORD in j for j in e.fake.joined())
    assert PASSWORD not in e.log.read_text() and PASSWORD not in e.prom.read_text()


def test_log_lines_and_metrics(tmp_path):
    e = Env(tmp_path, [target("pc", mac="aa:bb:cc:dd:ee:ff")], Fake(up={"pc.lan"}))
    e.b.run_target("pc")
    for s in e.steps():
        assert {"ts", "target", "step", "ok", "detail"} <= set(s) and s["ts"] == NOW
    m = e.prom.read_text()
    assert f'omv_device_backup_last_success_timestamp_seconds{{target="pc"}} {int(NOW)}' in m
    assert f'omv_device_backup_last_run_timestamp_seconds{{target="pc"}} {int(NOW)}' in m
    assert 'omv_device_backup_last_ok{target="pc"} 1' in m
    assert 'omv_device_backup_interval_seconds{target="pc"} 86400' in m
    assert "omv_device_backup_size_bytes" not in m  # unknown size is omitted


def test_metrics_keep_other_targets(tmp_path):
    e = Env(tmp_path, [target("pc"), target("omv", "local")], Fake(up={"pc.lan"}))
    e.b.run_target("pc")
    e.b.run_target("omv")
    m = e.prom.read_text()
    assert 'last_ok{target="pc"}' in m and 'last_ok{target="omv"}' in m


def test_restic_exit_3_is_success_with_warning(tmp_path):
    class F3(Fake):
        def run(self, argv, input=None):
            if " backup --tag" in " ".join(argv):
                self.calls.append((list(argv), input))
                return 3, "could not read x"
            return super().run(argv, input)

    f = F3(up={"pc.lan"})
    e = Env(tmp_path, [target("pc")], f)
    assert e.b.run_target("pc") is True
    assert f.has("forget", "--prune") and "done" in e.names()
    run = next(r for r in e.steps() if r["step"] == "run")
    assert run["ok"] and "warning" in run["detail"]
    assert f"omv_device_backup_last_success_timestamp_seconds{{target=\"pc\"}} {int(NOW)}" in e.prom.read_text()


def test_local_categories_cover_confdb_prometheus_opt(tmp_path, monkeypatch):
    f = Fake()
    e = Env(tmp_path, [target("omv", "local", categories=["omv-config", "monitor-data", "compose"])], f)
    monkeypatch.setattr(e.mod.glob, "glob", lambda x: [x.replace("*", "v_")])
    e.b.run_target("omv")
    assert f.has("omv-confdbadm", "dump")
    restic = next(" ".join(a) for a, _ in f.calls if a[0] == "restic" and "--tag" in a)
    assert "v_prom-data" in restic and "/opt/v_" in restic and e.mod.STAGE in restic


@pytest.mark.parametrize("conn,host,want", [
    ("192.168.1.10 5 192.168.1.50 22", "pc.lan", "bk@192.168.1.10:"),
    ("10.8.0.254 5 10.8.0.2 22", "10.8.0.2", "bk@10.8.0.254:"),
])
def test_sftp_host_from_ssh_connection(tmp_path, conn, host, want):
    f = Fake(up={host})
    f.conn = conn
    e = Env(tmp_path, [target("pc", hosts=[host])], f)
    e.b.run_target("pc")
    assert any("sftp:" + want in j for j in f.joined() if "restic" in j) and "done" in e.names()


@pytest.mark.parametrize("conn", ["", "garbage", "not-an-ip 5 1.2.3.4 22"])
def test_bad_ssh_connection_fails_without_restic(tmp_path, conn):
    f = Fake(up={"pc.lan"})
    f.conn = conn
    e = Env(tmp_path, [target("pc")], f)
    assert e.b.run_target("pc") is False
    assert not f.has("restic") and any(s["step"] == "fail" and "NAS address" in s["detail"] for s in e.steps())


def test_metrics_concurrent_targets_keep_both(tmp_path):
    import threading
    e = Env(tmp_path, [target("a"), target("b")], Fake())
    (tmp_path / "x").mkdir()
    e2 = Env(tmp_path / "x", [target("a"), target("b")], Fake())
    e2.b.metrics_file = e.b.metrics_file
    ts = [threading.Thread(target=lambda b=b, n=n: [b._write_metrics(n, True, 5) for _ in range(30)])
          for b, n in ((e.b, "a"), (e2.b, "b"))]
    [t.start() for t in ts]
    [t.join() for t in ts]
    m = e.prom.read_text()
    assert 'last_ok{target="a"}' in m and 'last_ok{target="b"}' in m
    assert not list(tmp_path.glob("*.tmp")) and not list(tmp_path.glob(".omv*"))
    assert e.prom.stat().st_mode & 0o777 == 0o644


def test_compose_excludes_secrets(tmp_path, monkeypatch):
    f = Fake()
    e = Env(tmp_path, [target("omv", "local", categories=["compose"])], f)
    monkeypatch.setattr(e.mod.glob, "glob", lambda x: ["/opt/omv-monitor"])
    e.b.run_target("omv")
    argv = next(a for a, _ in f.calls if a[0] == "restic" and "--tag" in a)
    ex = [argv[i + 1] for i, a in enumerate(argv) if a == "--exclude"]
    assert "/opt/omv-monitor/secrets" in ex and "/opt/**/secrets" in ex


PRIVATE_STAGE = re.compile(r"umask 0?77|mkdir -m 0?700|install -d -m 0?700")


def test_local_staging_dir_is_private(tmp_path):
    f = Fake()
    e = Env(tmp_path, [target("omv", "local", categories=["omv-config"])], f)
    e.b.run_target("omv")
    script = next(a[-1] for a, _ in f.calls if a[:2] == ["sh", "-c"] and "confdb" in a[-1])
    assert PRIVATE_STAGE.search(script)  # confdb dump holds password hashes


def test_device_staging_dir_is_private(tmp_path):
    f = Fake(up={"pc.lan"})
    e = Env(tmp_path, [target("pc", categories=["packages", "gnome-settings"])], f)
    e.b.run_target("pc")
    assert any(PRIVATE_STAGE.search(j) for j in f.joined() if "mkdir" in j)


def test_dump_file_is_created_private(tmp_path, monkeypatch):
    import os
    import types
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=0, stderr=b""))
    old = os.umask(0o022)
    try:
        out = tmp_path / "x.tar.part"
        load().Runner().dump(["true"], out)
    finally:
        os.umask(old)
    assert out.stat().st_mode & 0o077 == 0


class DumpFake(Fake):
    def dump(self, argv, path):
        self.calls.append((list(argv), None))
        Path(path).write_bytes(b"tar")
        return 0, ""


@pytest.mark.parametrize("snapshot,path", [
    ("--password-command=id", "/etc"), ("-o", "/etc"), ("latest", "--option=x"), ("abc123", "etc"), ("abc 123", "/etc")])
def test_export_rejects_option_like_snapshot_or_path(tmp_path, monkeypatch, snapshot, path):
    import os
    monkeypatch.setattr(os, "chown", lambda *a, **k: None)
    f = DumpFake()
    e = Env(tmp_path, [target("omv", "local")], f, dest=str(tmp_path / "nas"))
    (tmp_path / "nas").mkdir()
    try:
        e.b.export("omv", snapshot, path)
    except ValueError:
        pass
    assert not f.has("dump")
