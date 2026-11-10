import importlib.util
import json
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "monitor/host/omv-netctl.py"
SERVICE = ROOT / "monitor/host/omv-netctl.service"


def load():
    spec = importlib.util.spec_from_file_location("omv_netctl", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.MONITOR_TOML = str(ROOT / "monitor/config/monitor.toml")
    return mod


class FakeRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv, input=None):
        self.calls.append(list(argv))
        return 0, "active"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture(autouse=True)
def no_real_subprocess(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("real subprocess used")
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)


@pytest.fixture
def env(tmp_path):
    mod = load()
    runner, clock = FakeRunner(), Clock()
    helper = mod.Helper(runner, tmp_path / "state", clock=clock)
    return mod, helper, runner, clock, tmp_path / "state"


SYSTEMCTL = ["wg-quick@wgnet1", "minidlna", "nginx", "smbd", "tailscaled"]


@pytest.mark.parametrize("unit", SYSTEMCTL)
def test_restart_allowlisted_unit(env, unit):
    _, helper, runner, _, _ = env
    r = helper.handle({"action": "restart", "args": {"unit": unit}})
    assert r["ok"] is True
    assert r["result"]["unit"] == unit
    assert "active" in r["result"]["before"] and "active" in r["result"]["after"]
    assert runner.calls == [["systemctl", "is-active", unit],
                            ["systemctl", "restart", unit],
                            ["systemctl", "is-active", unit]]


def test_restart_allowlist_follows_monitor_toml(env, tmp_path):
    mod, helper, runner, _, _ = env
    toml = (Path(mod.MONITOR_TOML).read_text()
            .replace('unit = "nginx"\nlabel = "nginx"\nrestart = true', 'unit = "nginx"\nlabel = "nginx"\nrestart = false'))
    (tmp_path / "m.toml").write_text(toml)
    mod.MONITOR_TOML = str(tmp_path / "m.toml")
    assert helper.handle({"action": "restart", "args": {"unit": "nginx"}})["ok"] is False
    assert helper.handle({"action": "restart", "args": {"unit": "smbd"}})["ok"] is True


def test_restart_refused_when_monitor_toml_unusable(env, tmp_path):
    mod, helper, runner, _, _ = env
    mod.MONITOR_TOML = str(tmp_path / "missing.toml")
    r = helper.handle({"action": "restart", "args": {"unit": "smbd"}})
    assert r["ok"] is False and "service list unusable" in r["error"] and runner.calls == []


def test_restart_omv_monitor_is_detached_compose_restart(env):
    _, helper, runner, _, _ = env
    r = helper.handle({"action": "restart", "args": {"unit": "omv-monitor"}})
    assert r["ok"] is True
    assert r["result"] == {"unit": "omv-monitor", "before": "n/a", "after": "n/a"}
    # detached: the restart may run after the reply, so wait briefly for it
    cmd = ["docker", "compose", "--project-directory", "/opt/omv-monitor", "restart"]
    for _ in range(100):
        if cmd in runner.calls:
            break
        time.sleep(0.02)
    assert runner.calls == [cmd]


@pytest.mark.parametrize("unit", ["sshd", "../x", "minidlna;rm", "", None, 5, ["nginx"]])
def test_restart_rejects_other_units(env, unit):
    _, helper, runner, _, _ = env
    r = helper.handle({"action": "restart", "args": {"unit": unit}})
    assert r["ok"] is False and isinstance(r["error"], str)
    assert runner.calls == []


@pytest.mark.parametrize("req", [
    {"action": "rm-rf", "args": {}},
    {"action": "restart"},
    {"action": "restart", "args": {}},
    {"action": "restart", "args": "nginx"},
    {"args": {}},
    {"action": 5},
    [], "restart", None, 3,
])
def test_bad_requests_never_raise(env, req):
    _, helper, runner, _, _ = env
    r = helper.handle(req)
    assert r["ok"] is False and isinstance(r["error"], str)
    assert runner.calls == []


def test_pending_empty(env):
    _, helper, _, _, _ = env
    assert helper.handle({"action": "pending", "args": {}}) == {"ok": True, "result": {"pending": None}}


def begin_dummy(helper, undone):
    return helper._begin("dummy", "dummy change", lambda: undone.append(1))


def test_framework_auto_revert_after_deadline(env):
    mod, helper, _, clock, state = env
    undone = []
    begin_dummy(helper, undone)
    assert (state / "pending.json").exists()
    assert (state / "pending.json").stat().st_mode & 0o777 == 0o600
    p = helper.handle({"action": "pending"})["result"]["pending"]
    assert p["action"] == "dummy" and p["summary"] == "dummy change"
    assert p["expires_at"] == pytest.approx(clock.t + 60)
    clock.t += 59
    helper.expire()
    assert undone == []
    clock.t += 2
    helper.expire()
    assert undone == [1]
    assert helper.handle({"action": "pending"})["result"]["pending"] is None
    assert not (state / "pending.json").exists()


def test_framework_confirm_keeps_change(env):
    _, helper, _, clock, state = env
    undone = []
    begin_dummy(helper, undone)
    pid = helper.handle({"action": "pending"})["result"]["pending"]["id"]
    assert helper.handle({"action": "confirm", "args": {"id": "wrong"}})["ok"] is False
    assert helper.handle({"action": "confirm", "args": {}})["ok"] is False
    assert helper.handle({"action": "confirm", "args": {"id": pid}})["ok"] is True
    clock.t += 600
    helper.expire()
    assert undone == []
    assert helper.handle({"action": "pending"})["result"]["pending"] is None
    assert not (state / "pending.json").exists()
    assert helper.handle({"action": "confirm", "args": {"id": pid}})["ok"] is False


def test_framework_revert_undoes_now(env):
    _, helper, _, _, _ = env
    undone = []
    begin_dummy(helper, undone)
    pid = helper.handle({"action": "pending"})["result"]["pending"]["id"]
    assert helper.handle({"action": "revert", "args": {"id": "wrong"}})["ok"] is False
    assert undone == []
    assert helper.handle({"action": "revert", "args": {"id": pid}})["ok"] is True
    assert undone == [1]
    assert helper.handle({"action": "pending"})["result"]["pending"] is None


def test_framework_refuses_second_pending(env):
    _, helper, _, _, _ = env
    undone = []
    begin_dummy(helper, undone)
    r = helper._begin("other", "second", lambda: undone.append(2))
    msg = "another change is pending: confirm or revert it first"
    # _begin may return the error dict or raise; accept either, but it must refuse
    if isinstance(r, dict):
        assert r == {"ok": False, "error": msg}
    assert undone == []
    assert helper.handle({"action": "pending"})["result"]["pending"]["action"] == "dummy"


def test_framework_undo_argv_list_runs_through_runner(env):
    _, helper, runner, clock, _ = env
    helper._begin("dummy", "argv undo", ["wg", "set", "wgnet1", "peer", "X", "remove"])
    clock.t += 61
    helper.expire()
    assert runner.calls == [["wg", "set", "wgnet1", "peer", "X", "remove"]]


def test_leftover_pending_json_reverted_on_start(tmp_path):
    mod = load()
    state = tmp_path / "state"
    r1, clock = FakeRunner(), Clock()
    h1 = mod.Helper(r1, state, clock=clock)
    h1._begin("dummy", "argv undo", ["wg", "set", "wgnet1", "peer", "X", "remove"])
    assert (state / "pending.json").exists()
    r2 = FakeRunner()
    h2 = mod.Helper(r2, state, clock=clock)  # simulated restart mid-change
    assert r2.calls == [["wg", "set", "wgnet1", "peer", "X", "remove"]]
    assert not (state / "pending.json").exists()
    assert h2.handle({"action": "pending"})["result"]["pending"] is None


# --- socket server -------------------------------------------------------

@pytest.fixture
def server(tmp_path, monkeypatch):
    mod = load()
    runner = FakeRunner()
    monkeypatch.setattr(mod, "Runner", lambda: runner)  # main() must build its runner via Runner()
    monkeypatch.delenv("OMV_NETCTL_GID", raising=False)
    sock = tmp_path / "run" / "netctl.sock"
    sock.parent.mkdir()
    argv = ["serve", "--socket", str(sock), "--state", str(tmp_path / "state")]
    monkeypatch.setattr("sys.argv", ["omv-netctl.py"] + argv)
    t = threading.Thread(target=lambda: mod.main(argv), daemon=True)
    t.start()
    for _ in range(200):
        # The file appears at bind(), before listen(): wait until it really accepts.
        probe = socket.socket(socket.AF_UNIX)
        try:
            probe.connect(str(sock))
            break
        except OSError:
            time.sleep(0.02)
        finally:
            probe.close()
    assert sock.exists()
    return sock, runner


def ask(sock, payload):
    if not isinstance(payload, bytes):
        payload = json.dumps(payload).encode() + b"\n"
    c = socket.socket(socket.AF_UNIX)
    c.settimeout(5)
    c.connect(str(sock))
    try:
        c.sendall(payload)
    except (BrokenPipeError, ConnectionResetError):
        pass
    buf = b""
    try:
        while not buf.endswith(b"\n"):
            d = c.recv(65536)
            if not d:
                break
            buf += d
    except ConnectionResetError:
        pass
    c.close()
    return json.loads(buf)


def test_socket_restart_and_pending(server):
    sock, runner = server
    r = ask(sock, {"action": "restart", "args": {"unit": "nginx"}})
    assert r["ok"] is True and r["result"]["unit"] == "nginx"
    assert ["systemctl", "restart", "nginx"] in runner.calls
    assert ask(sock, {"action": "pending", "args": {}}) == {"ok": True, "result": {"pending": None}}


@pytest.mark.parametrize("payload", [
    {"action": "nope", "args": {}},
    {"action": "restart"},
    [1, 2],
    b"not json\n",
    b'{"action": "pending"\n',
    b"\xff\xfe\n",
])
def test_socket_bad_requests(server, payload):
    sock, runner = server
    r = ask(sock, payload)
    assert r["ok"] is False and isinstance(r["error"], str)
    assert runner.calls == []


def test_socket_oversized_request(server):
    sock, runner = server
    big = b'{"action":"pending","args":{"x":"' + b"a" * 70000 + b'"}}\n'
    r = ask(sock, big)
    assert r["ok"] is False
    assert runner.calls == []
    # server still alive afterwards
    assert ask(sock, {"action": "pending"})["ok"] is True


def test_trickling_client_gets_cut_off(server, monkeypatch):
    sock, runner = server
    t0 = time.monotonic()
    c = socket.socket(socket.AF_UNIX)
    c.settimeout(10)
    c.connect(str(sock))
    for _ in range(12):  # one byte per second, never a newline
        try:
            c.send(b" ")
        except OSError:
            break
        time.sleep(1)
    c.close()
    assert time.monotonic() - t0 < 12
    assert ask(sock, {"action": "pending"})["ok"] is True


def test_callable_undo_lost_on_restart_is_logged(tmp_path, capsys):
    mod = load()
    state = tmp_path / "state"
    h1 = mod.Helper(FakeRunner(), state, clock=Clock())
    h1._begin("dummy", "callable undo", lambda: None)
    r2 = FakeRunner()
    mod.Helper(r2, state, clock=Clock())
    assert r2.calls == []
    assert "cannot undo dummy" in capsys.readouterr().err


# --- service unit --------------------------------------------------------

def test_service_unit():
    text = SERVICE.read_text()
    for needle in ("Type=simple", "User=root", "RuntimeDirectory=omv-netctl", "StateDirectory=omv-netctl", "StateDirectoryMode=0700",
                   "Restart=on-failure", "NoNewPrivileges", "ProtectHome", "PrivateTmp",
                   "ExecStart=/usr/bin/python3 /opt/omv-monitor/host/omv-netctl.py serve"):
        assert needle in text


class FlakyRunner(FakeRunner):
    def __init__(self):
        super().__init__()
        self.fail = True

    def run(self, argv, input=None):
        self.calls.append(list(argv))
        if self.fail:
            raise subprocess.TimeoutExpired(argv, 60)
        return 0, ""


def test_failing_undo_is_kept_logged_and_retried(tmp_path):
    mod = load()
    state = tmp_path / "state"
    runner, clock = FlakyRunner(), Clock()
    h = mod.Helper(runner, state, clock=clock)
    h._begin("dummy", "s", ["wg", "set", "wgnet1", "peer", "X", "remove"])
    clock.t += 61
    h.expire()  # must not raise
    assert (state / "pending.json").exists() and h.pending
    h.expire()  # backoff: not retried yet
    assert len(runner.calls) == 1
    clock.t += mod.UNDO_RETRY
    runner.fail = False
    h.expire()
    assert len(runner.calls) == 2 and h.pending is None
    assert not (state / "pending.json").exists()


def test_failing_undo_on_start_and_manual_revert(tmp_path):
    mod = load()
    state = tmp_path / "state"
    runner, clock = FlakyRunner(), Clock()
    mod.Helper(runner, state, clock=clock)._begin("dummy", "s", ["wg", "set", "wgnet1", "peer", "X", "remove"])
    h = mod.Helper(runner, state, clock=clock)  # restart with failing undo must not raise
    assert (state / "pending.json").exists()
    pid = h.pending["id"]
    assert h.handle({"action": "revert", "args": {"id": pid}})["ok"] is False
    assert h.pending
    runner.fail = False
    assert h.handle({"action": "revert", "args": {"id": pid}})["ok"] is True
    assert h.pending is None


# --- backup-run / backup-targets (T3) ---------------------------------------
# Contract: Helper(..., backup_config=callable returning the merged backups cfg dict);
# categories travel via a JSON request file somewhere under the state dir, never argv.
BK_CFG = {"destination_root": "/mnt/nas", "targets": [
    {"name": "pc", "kind": "ssh"}, {"name": "omv", "kind": "local"}]}


@pytest.fixture
def bk(tmp_path):
    mod = load()
    runner = FakeRunner()
    helper = mod.Helper(runner, tmp_path / "state", clock=Clock(), backup_config=lambda: BK_CFG)
    return helper, runner, tmp_path / "state"


def test_backup_run_starts_template_unit(bk):
    helper, runner, state = bk
    r = helper.handle({"action": "backup-run", "args": {"target": "pc", "categories": ["home", "users"]}})
    assert r["ok"] is True
    assert runner.calls == [["systemctl", "start", "--no-block", "omv-device-backup@pc.service"]]
    reqs = [json.loads(p.read_text()) for p in state.rglob("*") if p.is_file() and p.suffix == ".json"
            and "categories" in p.read_text()]
    assert any(q["categories"] == ["home", "users"] for q in reqs)
    assert helper.handle({"action": "pending"})["result"]["pending"] is None


def test_backup_run_without_categories(bk):
    helper, runner, _ = bk
    assert helper.handle({"action": "backup-run", "args": {"target": "omv"}})["ok"] is True
    assert runner.calls == [["systemctl", "start", "--no-block", "omv-device-backup@omv.service"]]


@pytest.mark.parametrize("args", [
    {"target": "nope", "categories": ["home"]},
    {"target": "../pc", "categories": ["home"]},
    {"target": "pc@x.service", "categories": ["home"]},
    {"target": "PC"},
    {"target": "pc", "categories": ["omv-config"]},      # local-only category on an ssh target
    {"target": "pc", "categories": ["home; rm -rf /"]},
    {"target": "pc", "categories": "home"},
    {"target": "pc", "categories": [1]},
    {},
])
def test_backup_run_rejected(bk, args):
    helper, runner, _ = bk
    r = helper.handle({"action": "backup-run", "args": args})
    assert r["ok"] is False and isinstance(r["error"], str)
    assert runner.calls == []


def test_backup_targets_lists_allowlist(bk):
    helper, _, _ = bk
    t = helper.handle({"action": "backup-targets"})["result"]["targets"]
    assert t["pc"] == sorted({"home", "system-settings", "gnome-settings", "packages", "users", "full-system"})
    assert t["omv"] == sorted({"omv-config", "host-config", "compose", "monitor-data", "nas-data"})


# --- privilege-boundary audit (T3) -----------------------------------------

def test_deeply_nested_json_does_not_kill_server(server):
    sock, runner = server
    r = ask(sock, b"[" * 30000 + b"\n")
    assert r["ok"] is False and runner.calls == []
    assert ask(sock, {"action": "pending"})["ok"] is True


@pytest.mark.parametrize("payload", [b"\n", b"", b'{"action":"pending"}'])  # empty line, empty, no newline
def test_socket_degenerate_requests_keep_server_alive(server, payload):
    sock, runner = server
    c = socket.socket(socket.AF_UNIX)
    c.settimeout(5)
    c.connect(str(sock))
    c.sendall(payload)
    c.shutdown(socket.SHUT_WR)
    try:
        c.recv(65536)
    except OSError:
        pass
    c.close()
    assert runner.calls == []
    assert ask(sock, {"action": "pending"})["ok"] is True


def test_socket_not_reachable_by_others(tmp_path, monkeypatch):
    import os
    mod = load()
    monkeypatch.setattr(mod, "Runner", FakeRunner)
    monkeypatch.setenv("OMV_NETCTL_GID", str(os.getgid()))
    sock = tmp_path / "run" / "netctl.sock"
    argv = ["serve", "--socket", str(sock), "--state", str(tmp_path / "state")]
    threading.Thread(target=lambda: mod.main(argv), daemon=True).start()
    for _ in range(200):
        if sock.exists():
            break
        time.sleep(0.02)
    assert sock.stat().st_mode & 0o007 == 0
    assert sock.parent.stat().st_mode & 0o007 == 0
    assert sock.stat().st_gid == os.getgid()


def test_pending_json_symlink_not_followed(tmp_path):
    mod = load()
    state, victim = tmp_path / "state", tmp_path / "victim"
    victim.write_text("precious")
    state.mkdir()
    (state / "pending.json").symlink_to(victim)
    h = mod.Helper(FakeRunner(), state, clock=Clock())  # a leftover symlink must not be read as state either
    h._begin("dummy", "s", ["wg", "set", "wgnet1", "peer", "X", "remove"])
    assert victim.read_text() == "precious"
    p = state / "pending.json"
    assert not p.is_symlink() and json.loads(p.read_text())["action"] == "dummy"
    assert p.stat().st_mode & 0o077 == 0
    assert [f.name for f in state.iterdir() if f.name.endswith((".tmp", ".part"))] == []


def test_backup_request_symlink_not_followed(bk):
    helper, runner, state = bk
    victim = state.parent / "victim"
    victim.write_text("precious")
    (state / "backup-requests").mkdir()
    (state / "backup-requests" / "pc.json").symlink_to(victim)
    r = helper.handle({"action": "backup-run", "args": {"target": "pc", "categories": ["home"]}})
    assert victim.read_text() == "precious"
    assert r["ok"] is True or r["ok"] is False  # refusing is as acceptable as replacing the link


@pytest.mark.parametrize("undo", [
    ["touch", "/tmp/pwned"],
    ["sh", "-c", "id"],
    ["wg", "syncconf", "wgnet1", "/etc/shadow"],
    ["wg", "syncconf", "wgnet1", "../../../etc/shadow"],
    ["wg", "set", "othernet", "peer", "X", "remove"],
    ["wg", "--version"],
    "wg set wgnet1 peer X remove",
])
def test_tampered_pending_undo_is_not_executed(tmp_path, undo):
    mod = load()
    state = tmp_path / "state"
    state.mkdir()
    (state / "pending.json").write_text(json.dumps({"id": "a", "action": "x", "summary": "s", "expires_at": 0, "undo": undo}))
    r = FakeRunner()
    h = mod.Helper(r, state, clock=Clock())
    assert r.calls == []
    assert h.pending is None or h.pending.get("undo") in (None, [])


@pytest.mark.parametrize("raw", ["[]", "null", '"x"', "5", "{", '{"id": 1}'])
def test_malformed_pending_json_does_not_crash_start_or_expire(tmp_path, raw):
    mod = load()
    state = tmp_path / "state"
    state.mkdir()
    (state / "pending.json").write_text(raw)
    h = mod.Helper(FakeRunner(), state, clock=Clock())
    h.expire()
    assert h.handle({"action": "pending"})["ok"] is True


def test_non_numeric_expiry_cannot_stall_the_revert_loop(tmp_path):
    mod = load()
    state = tmp_path / "state"
    state.mkdir()
    (state / "pending.json").write_text(json.dumps(
        {"id": "a", "action": "x", "expires_at": "never", "undo": ["wg", "set", "wgnet1", "peer", "X", "remove"]}))
    clock = Clock()
    h = mod.Helper(FlakyRunner(), state, clock=clock)  # undo fails on start, so pending is kept
    clock.t += 3600
    h.expire()  # must not raise (it runs in the server loop)
    h.expire()


@pytest.mark.parametrize("bad", [None, "", "wrong", 5, ["x"], {"a": 1}])
@pytest.mark.parametrize("action", ["confirm", "revert"])
def test_confirm_revert_need_exact_id(env, action, bad):
    _, helper, runner, clock, state = env
    begun = helper._begin("dummy", "s", ["wg", "set", "wgnet1", "peer", "X", "remove"])
    args = {} if bad is None else {"id": bad}
    r = helper.handle({"action": action, "args": args})
    assert r["ok"] is False
    assert helper.pending is not None and (state / "pending.json").exists()
    assert runner.calls == []
    clock.t += 61
    helper.expire()  # the revert is still armed
    assert runner.calls == [["wg", "set", "wgnet1", "peer", "X", "remove"]]
    assert begun["ok"]


@pytest.mark.parametrize("args", [
    {"target": "--help"}, {"target": "-x"}, {"target": "pc\n"}, {"target": "pc "}, {"target": ["pc"]}, {"target": None}, {},
])
def test_backup_snapshots_target_never_reaches_argv_unvalidated(bk, args):
    helper, runner, _ = bk
    r = helper.handle({"action": "backup-snapshots", "args": args})
    assert r["ok"] is False and runner.calls == []


@pytest.mark.parametrize("target", ["-pc", "--pc"])
def test_option_like_target_names_rejected_even_if_configured(tmp_path, target):
    mod = load()
    runner = FakeRunner()
    cfg = {"destination_root": "/mnt/nas", "targets": [{"name": target, "kind": "ssh"}]}
    h = mod.Helper(runner, tmp_path / "state", clock=Clock(), backup_config=lambda: cfg)
    for action in ("backup-snapshots", "backup-run"):
        r = h.handle({"action": action, "args": {"target": target}})
        assert r["ok"] is False
    assert runner.calls == []


@pytest.mark.parametrize("pub", ["-" + "A" * 42 + "A=", "A" * 43 + "A=\n", " " + "A" * 43 + "A="])
@pytest.mark.parametrize("action", ["peer-disable", "peer-enable", "peer-remove", "peer-set"])
def test_wg_keys_with_dash_or_whitespace_rejected(env, action, pub):
    _, helper, runner, _, _ = env
    r = helper.handle({"action": action, "args": {"public_key": pub, "allowed_ips": ["10.8.0.9/32"]}})
    assert r["ok"] is False and runner.calls == []


@pytest.mark.parametrize("path", ["/home/x\n--delete", "/a/../b", "relative", "-rf", "/" + "a" * 1100, "/a\x00b", 5, None])
def test_backup_export_path_rejected(bk, path):
    helper, runner, _ = bk
    r = helper.handle({"action": "backup-export", "args": {"target": "pc", "snapshot": "a1b2c3d4", "path": path}})
    assert r["ok"] is False and runner.calls == []


@pytest.mark.parametrize("snap", ["--all", "-a1b2c3d4", "a1b2c3d\n", "latest", "a1b2c3d", "g" * 8, None, 5])
def test_backup_export_snapshot_rejected(bk, snap):
    helper, runner, _ = bk
    r = helper.handle({"action": "backup-export", "args": {"target": "pc", "snapshot": snap, "path": "/home"}})
    assert r["ok"] is False and runner.calls == []


def test_service_unit_hardening():
    text = SERVICE.read_text()
    for needle in ("ProtectSystem=", "ProtectKernelModules=yes", "ProtectKernelTunables=yes", "ProtectControlGroups=yes",
                   "RestrictSUIDSGID=yes", "LockPersonality=yes"):
        assert needle in text
    if "ProtectSystem=strict" in text:  # then everything the helper writes must be listed, or actions break
        rw = " ".join(line for line in text.splitlines() if line.startswith("ReadWritePaths="))
        assert "/etc/wireguard" in rw  # wg-quick save
    assert "ProtectSystem=no" not in text
