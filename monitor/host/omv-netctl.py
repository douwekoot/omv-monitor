#!/usr/bin/env python3
"""Privileged host helper: fixed-allowlist JSON actions over a Unix socket (stdlib only, runs as root)."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from app import config  # noqa: E402

SOCKET = "/run/omv-netctl/netctl.sock"
STATE = "/var/lib/omv-netctl"
MAX_REQUEST = 64 * 1024
MONITOR_RESTART = ["docker", "compose", "--project-directory", "/opt/omv-monitor", "restart"]
IFACE = "wgnet1"
WG_SAVE = ["wg-quick", "save", IFACE]
KEEP_SNAPSHOTS = 10
KEY_RE = re.compile(r"[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=")
IP_RE = re.compile(r"10\.8\.0\.(0|[1-9][0-9]{0,2})/32")
SNAP_RE = re.compile(r"[0-9a-f]{12}")
MONITOR_TOML = "/opt/omv-monitor/config/monitor.toml"  # the web container mounts config/ read-only
UNDO_RETRY = 5
BACKUP_CFG = ("/opt/omv-monitor/config/backups.toml", "/opt/omv-monitor/data/backup-overrides.json")
NAME_RE = re.compile(r"[a-z0-9-]+")
RESTIC_ID_RE = re.compile(r"[0-9a-f]{8,64}")
DEVICE_BACKUP = ["/usr/bin/python3", "/opt/omv-monitor/host/omv-device-backup.py"]
PENDING_BUSY = "another change is pending: confirm or revert it first"


def log(msg):
    print(msg, file=sys.stderr, flush=True)


class Runner:
    def run(self, argv, input=None):
        p = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout


class Helper:
    def __init__(self, runner, state_dir, clock=time.time, revert_after=60, backup_config=None):
        self.runner, self.clock, self.revert_after = runner, clock, revert_after
        self.backup_config = backup_config or (lambda: config.merged_backups(*BACKUP_CFG))
        self.state_dir = pathlib.Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.pfile = self.state_dir / "pending.json"
        self.lock = threading.RLock()
        self.pending = None
        self.confirm_fn = None  # runs on confirm only (e.g. delete a stash); lost on restart = stash kept, safe
        self.undo_fn = None  # in-memory only; a leftover pending.json can only replay an argv
        if self.pfile.exists():
            try:
                self.pending = json.loads(self.pfile.read_text())
            except ValueError:
                self.pending = {"id": "", "undo": None, "action": "corrupt"}
            self._undo("leftover pending change reverted on start")

    # --- pending/confirm/revert framework -------------------------------
    def _begin(self, action, summary, undo):
        # undo: argv list (persisted, survives a helper restart) or a callable (in-memory only:
        # NOT reverted after a restart, only logged). Lockout-critical changes must pass an argv list.
        with self.lock:
            if self.pending:
                return {"ok": False, "error": PENDING_BUSY}
            argv = undo if isinstance(undo, list) else None
            self.pending = {"id": secrets.token_hex(8), "action": action, "summary": summary,
                            "expires_at": self.clock() + self.revert_after, "undo": argv}
            self.undo_fn = None if argv else undo
            fd = os.open(self.pfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(self.pending, f)
            return {"ok": True, "result": {"id": self.pending["id"], "expires_at": self.pending["expires_at"]}}

    def _undo(self, why):
        """Run the undo; True when done. On failure keep pending (and pending.json) so expire() retries."""
        p, fn = self.pending, self.undo_fn
        try:
            if p.get("undo"):
                rc, _ = self.runner.run(p["undo"])
                if rc != 0:
                    raise RuntimeError(f"undo exited {rc}")
                if p["undo"][:2] == ["wg", "syncconf"]:  # keep wgnet1.conf equal to runtime after an undo too
                    if self.runner.run(WG_SAVE)[0] != 0:
                        raise RuntimeError("wg-quick save failed")
            elif fn:
                fn()
            else:
                log(f"WARNING cannot undo {p.get('action')}: callable undo lost on restart, manual check needed")
        except Exception as e:
            log(f"ERROR undo of {p.get('action')} failed ({type(e).__name__}: {e}), retrying in {UNDO_RETRY}s")
            if isinstance(p.get("expires_at"), (int, float)):
                p["expires_at"] = self.clock() + UNDO_RETRY
            return False
        self.pending, self.undo_fn, self.confirm_fn = None, None, None
        self.pfile.unlink(missing_ok=True)
        log(f"{why}: {p.get('action')}")
        return True

    def expire(self):
        with self.lock:
            if self.pending and self.clock() >= self.pending.get("expires_at", 0):
                self._undo("auto-revert")

    def _check_id(self, args):
        pid = args.get("id")
        if not self.pending or not isinstance(pid, str) or pid != self.pending["id"]:
            raise ValueError("no matching pending change")

    def _pending(self, args):
        p = self.pending
        return {"pending": {k: p[k] for k in ("id", "action", "summary", "expires_at")} if p else None}

    def _confirm(self, args):
        self._check_id(args)
        fn, self.confirm_fn = self.confirm_fn, None
        self.pending, self.undo_fn = None, None
        self.pfile.unlink(missing_ok=True)
        if fn:
            fn()
        return {}

    def _revert(self, args):
        self._check_id(args)
        if not self._undo("reverted"):
            raise RuntimeError("undo failed, will retry automatically")
        return {}

    # --- actions ---------------------------------------------------------
    def _active(self, unit):
        return self.runner.run(["systemctl", "is-active", unit])[1].strip()

    def _restart(self, args):
        unit = args.get("unit")
        try:  # re-read per request, so an edited service list needs no helper restart
            units = config.restart_units(config.load_monitor(MONITOR_TOML)["services"], IFACE)
        except config.ConfigError as e:
            raise ValueError(f"service list unusable: {e}") from None
        if not isinstance(unit, str) or unit not in units:
            raise ValueError("unit not allowed")
        if unit == "omv-monitor":
            # restarts this very web app: run after the reply has been sent
            t = threading.Timer(0.5, self.runner.run, [MONITOR_RESTART])
            t.daemon = True
            t.start()
            return {"unit": unit, "before": "n/a", "after": "n/a"}
        before = self._active(unit)
        self.runner.run(["systemctl", "restart", unit])
        return {"unit": unit, "before": before, "after": self._active(unit)}

    # --- wireguard -------------------------------------------------------
    def _wg(self, *argv, input=None):
        rc, out = self.runner.run(list(argv), input=input) if input is not None else self.runner.run(list(argv))
        if rc != 0:  # never include output: it may hold key material
            raise RuntimeError(f"{' '.join(argv[:2])} failed (exit {rc})")
        return out

    def _runtime_peers(self):
        peers = {}
        for line in self._wg("wg", "show", IFACE, "dump").splitlines()[1:]:
            f = line.split("\t")
            if len(f) < 8:
                continue
            ips = [] if f[3] == "(none)" else f[3].split(",")
            peers[f[0]] = {"public_key": f[0], "allowed_ips": ips, "enabled": True,
                           "psk": None if f[1] == "(none)" else f[1],
                           "latest_handshake": int(f[4]) or None}
        return peers

    def _stash_path(self, pub):
        return self.state_dir / "disabled" / (hashlib.sha256(pub.encode()).hexdigest() + ".json")

    def _stashed(self, runtime):
        out = {}  # entries whose key is live again (stale after an auto-revert) are ignored
        for f in sorted((self.state_dir / "disabled").glob("*.json")):
            try:
                d = json.loads(f.read_text())
                if d["public_key"] not in runtime:
                    out[d["public_key"]] = dict(d, enabled=False, latest_handshake=None)
            except (ValueError, KeyError, TypeError):
                log(f"ignoring unreadable stash {f.name}")
        return out

    @staticmethod
    def _key(args):
        k = args.get("public_key")
        if not isinstance(k, str) or not KEY_RE.fullmatch(k):
            raise ValueError("invalid public_key")
        return k

    @staticmethod
    def _ip(v):
        if not isinstance(v, str) or not IP_RE.fullmatch(v) or not 1 <= int(v.split(".")[3].split("/")[0]) <= 253:
            raise ValueError("allowed IP must be a /32 in 10.8.0.1-253")
        return v

    def _used(self, runtime, stash, skip=None):
        return {ip for k, p in {**runtime, **stash}.items() if k != skip for ip in p["allowed_ips"]}

    def _write_private(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)

    def _snapshot(self, action, summary, protect=None):
        sid = secrets.token_hex(6)
        meta = json.dumps({"id": sid, "time": self.clock(), "action": action, "summary": summary})
        path = self.state_dir / "snapshots" / (sid + ".conf")
        self._write_private(path, "# omv-netctl " + meta + "\n" + self._wg("wg", "showconf", IFACE))
        old = sorted(path.parent.glob("*.conf"), key=lambda f: f.stat().st_mtime_ns)[:-KEEP_SNAPSHOTS]
        for f in old:
            if f != protect:  # a restore target must outlive the pre-restore snapshot's prune
                f.unlink(missing_ok=True)
        return sid, path

    def _wg_change(self, action, summary, apply, protect=None, on_confirm=None):
        """snapshot -> pending with argv undo (restore snapshot) -> apply -> persist; undo at once if apply fails."""
        if self.pending:
            return {"ok": False, "error": PENDING_BUSY}
        sid, path = self._snapshot(action, summary, protect)
        begun = self._begin(action, summary, ["wg", "syncconf", IFACE, str(path)])
        if not begun["ok"]:
            return begun
        try:
            extra = apply() or {}
            self._wg(*WG_SAVE)
        except Exception:
            self._undo("apply failed")
            raise
        self.confirm_fn = on_confirm
        return {"pending": begun["result"], "snapshot": sid, **extra}

    def _peers(self, args):
        runtime = self._runtime_peers()
        keep = ("public_key", "allowed_ips", "enabled", "latest_handshake")
        return {"peers": [{k: p[k] for k in keep} for p in [*runtime.values(), *self._stashed(runtime).values()]]}

    def _peer_set(self, args):
        pub, ips = self._key(args), args.get("allowed_ips")
        if not isinstance(ips, list) or not 1 <= len(ips) <= 8 or len(set(map(str, ips))) != len(ips):
            raise ValueError("allowed_ips must be a list of 1..8 distinct CIDRs")
        for ip in ips:
            self._ip(ip)
        runtime = self._runtime_peers()
        if pub not in runtime:
            raise ValueError("unknown peer")
        if set(ips) & self._used(runtime, self._stashed(runtime), skip=pub):
            raise ValueError("allowed IP already used by another peer")
        return self._wg_change("peer-set", f"set allowed IPs of {pub[:8]}",
                               lambda: self._wg("wg", "set", IFACE, "peer", pub, "allowed-ips", ",".join(ips)))

    def _peer_disable(self, args):
        pub = self._key(args)
        peer = self._runtime_peers().get(pub)
        if not peer:
            raise ValueError("unknown peer")

        def apply():
            d = {"public_key": pub, "allowed_ips": peer["allowed_ips"]}
            if peer["psk"]:
                d["preshared_key"] = peer["psk"]
            self._write_private(self._stash_path(pub), json.dumps(d))
            self._wg("wg", "set", IFACE, "peer", pub, "remove")
        return self._wg_change("peer-disable", f"disable peer {pub[:8]}", apply)

    def _set_peer(self, pub, ips, psk=None):
        argv = ["wg", "set", IFACE, "peer", pub, "allowed-ips", ",".join(ips)]
        tmp = pathlib.Path(tempfile.mkdtemp())  # 0700
        try:
            if psk:
                self._write_private(tmp / "psk", psk + "\n")
                argv += ["preshared-key", str(tmp / "psk")]
            self._wg(*argv)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _peer_enable(self, args):
        pub = self._key(args)
        runtime = self._runtime_peers()
        d = self._stashed(runtime).get(pub)
        if not d:
            raise ValueError("peer is not disabled")
        if set(d["allowed_ips"]) & self._used(runtime, {}):
            raise ValueError("allowed IP already used by another peer")
        # stash stays until the peer is removed: an auto-revert of this enable must not lose it
        return self._wg_change("peer-enable", f"enable peer {pub[:8]}",
                               lambda: self._set_peer(pub, d["allowed_ips"], d.get("preshared_key")))

    def _peer_remove(self, args):
        pub = self._key(args)
        stashed = self._stash_path(pub).exists()
        if pub not in (runtime := self._runtime_peers()) and not (stashed and pub in self._stashed(runtime)):
            raise ValueError("unknown peer")

        def apply():
            if pub in runtime:
                self._wg("wg", "set", IFACE, "peer", pub, "remove")
        return self._wg_change("peer-remove", f"remove peer {pub[:8]}", apply,
                               on_confirm=lambda: self._stash_path(pub).unlink(missing_ok=True))

    def _peer_add(self, args):
        endpoint = os.environ.get("OMV_NETCTL_ENDPOINT")
        if not endpoint:
            raise ValueError("endpoint not configured")
        runtime = self._runtime_peers()
        used = self._used(runtime, self._stashed(runtime))
        ip = args.get("allowed_ip")
        if ip is None:
            ip = next((c for i in range(1, 254) if (c := f"10.8.0.{i}/32") not in used), None)
            if not ip:
                raise ValueError("no free address")
        elif self._ip(ip) in used:
            raise ValueError("allowed IP already used by another peer")
        priv = self._wg("wg", "genkey").strip()
        pub = self._wg("wg", "pubkey", input=priv + "\n").strip()
        psk = self._wg("wg", "genpsk").strip()
        server = self._wg("wg", "show", IFACE, "public-key").strip()
        cfg = (f"[Interface]\nPrivateKey = {priv}\nAddress = {ip}\n\n[Peer]\nPublicKey = {server}\n"
               f"PresharedKey = {psk}\nEndpoint = {endpoint}\nAllowedIPs = 10.8.0.0/24, 192.168.1.0/24\n"
               "PersistentKeepalive = 25\n")
        res = self._wg_change("peer-add", f"add peer {pub[:8]}", lambda: self._set_peer(pub, [ip], psk))
        if res.get("ok") is False:
            return res
        return {**res, "public_key": pub, "allowed_ips": [ip], "client_config": cfg}

    def _snapshots(self, args):
        out = []
        files = sorted((self.state_dir / "snapshots").glob("*.conf"), key=lambda f: f.stat().st_mtime_ns, reverse=True)
        for f in files:
            try:
                out.append(json.loads(f.read_text().split("\n", 1)[0][len("# omv-netctl "):]))
            except ValueError:
                pass
        return {"snapshots": out}

    def _restore(self, args):
        sid = args.get("snapshot")
        if not isinstance(sid, str) or not SNAP_RE.fullmatch(sid):
            raise ValueError("invalid snapshot id")
        target = self.state_dir / "snapshots" / (sid + ".conf")
        if not target.is_file():
            raise ValueError("unknown snapshot")
        return self._wg_change("restore", f"restore snapshot {sid}", lambda: self._wg("wg", "syncconf", IFACE, str(target)), protect=target)

    # --- device backups ----------------------------------------------------
    def _backup_targets(self, args):
        return {"targets": {t["name"]: sorted(config.CATEGORIES[t["kind"]]) for t in self.backup_config()["targets"]}}

    def _backup_run(self, args):
        name, cats = args.get("target"), args.get("categories")
        kinds = {t["name"]: t["kind"] for t in self.backup_config()["targets"]}
        if not isinstance(name, str) or not NAME_RE.fullmatch(name) or name not in kinds:
            raise ValueError("unknown backup target")
        if cats is not None and (not isinstance(cats, list) or not cats or any(
                not isinstance(c, str) or c not in config.CATEGORIES[kinds[name]] for c in cats)):
            raise ValueError("categories not allowed for this target")
        req = self.state_dir / "backup-requests" / (name + ".json")
        if cats:
            self._write_private(req, json.dumps({"categories": list(dict.fromkeys(cats))}))
        else:
            req.unlink(missing_ok=True)  # a stale request must not narrow this run
        rc, _ = self.runner.run(["systemctl", "start", "--no-block", f"omv-device-backup@{name}.service"])
        if rc != 0:
            raise RuntimeError(f"could not start backup (exit {rc})")
        return {"detail": f"backup of {name} started"}

    def _target(self, args):
        name = args.get("target")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name) or name not in {t["name"] for t in self.backup_config()["targets"]}:
            raise ValueError("unknown backup target")
        return name

    def _backup_snapshots(self, args):
        rc, out = self.runner.run([*DEVICE_BACKUP, "snapshots", self._target(args)])
        if rc != 0:
            raise RuntimeError(f"could not list snapshots (exit {rc})")
        return {"snapshots": json.loads(out)}

    def _backup_export(self, args):
        name, snap, path = self._target(args), args.get("snapshot"), args.get("path")
        if not isinstance(snap, str) or not RESTIC_ID_RE.fullmatch(snap):
            raise ValueError("invalid snapshot id")
        if (not isinstance(path, str) or not path.startswith("/") or len(path) > 1024
                or any(c in path for c in "\0\n\r") or ".." in path.split("/")):
            raise ValueError("path must be an absolute folder path without ..")
        self._write_private(self.state_dir / "backup-requests" / f"export-{name}.json", json.dumps({"snapshot": snap, "path": path}))
        rc, _ = self.runner.run(["systemctl", "start", "--no-block", f"omv-device-export@{name}.service"])
        if rc != 0:
            raise RuntimeError(f"could not start export (exit {rc})")
        return {"detail": f"export of {path} from {name} snapshot {snap} started"}

    ACTIONS = {"backup-run": "_backup_run", "backup-targets": "_backup_targets", "backup-snapshots": "_backup_snapshots",
               "backup-export": "_backup_export", "restart": "_restart", "pending": "_pending", "confirm": "_confirm", "revert": "_revert",
               "peers": "_peers", "peer-set": "_peer_set", "peer-disable": "_peer_disable",
               "peer-enable": "_peer_enable", "peer-remove": "_peer_remove", "peer-add": "_peer_add",
               "snapshots": "_snapshots", "restore": "_restore"}

    def handle(self, req):
        try:
            if not isinstance(req, dict):
                raise ValueError("request must be an object")
            action, args = req.get("action"), req.get("args", {})
            if not isinstance(action, str) or action not in self.ACTIONS:
                raise ValueError("unknown action")
            if not isinstance(args, dict):
                raise ValueError("args must be an object")
            log(f"action {action}")
            with self.lock:
                res = getattr(self, self.ACTIONS[action])(args)
            if res.get("ok") is False:  # a mutating action may return _begin's refusal
                return res
            return {"ok": True, "result": res}
        except Exception as e:  # never raise to the server loop
            log(f"error {type(e).__name__}: {e}")
            return {"ok": False, "error": str(e) or type(e).__name__}


def recv_by(conn, deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise socket.timeout("deadline")
    conn.settimeout(left)
    return conn.recv(65536)


def read_request(conn, deadline):
    buf = b""
    while b"\n" not in buf:
        d = recv_by(conn, deadline)
        if not d:
            break
        buf += d
        if len(buf) > MAX_REQUEST:
            return None
    return buf


def serve_one(conn, helper):
    deadline = time.monotonic() + 5  # whole exchange, so a slow client cannot stall expire()
    try:
        buf = read_request(conn, deadline)
        if buf is None:
            reply = {"ok": False, "error": "request too large"}
        else:
            try:
                reply = helper.handle(json.loads(buf.split(b"\n", 1)[0].decode()))
            except ValueError:  # includes UnicodeDecodeError and JSONDecodeError
                reply = {"ok": False, "error": "invalid JSON"}
        conn.sendall(json.dumps(reply).encode() + b"\n")
        if buf is None:  # drain so closing does not reset the client before it reads the reply
            conn.shutdown(socket.SHUT_WR)
            while recv_by(conn, deadline):
                pass
    except OSError:
        pass
    finally:
        conn.close()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["serve"])
    ap.add_argument("--socket", default=SOCKET)
    ap.add_argument("--state", default=STATE)
    a = ap.parse_args(argv)
    helper = Helper(Runner(), a.state)
    sock = pathlib.Path(a.socket)
    sock.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(sock.parent, 0o750)
    sock.unlink(missing_ok=True)
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(str(sock))
    os.chmod(sock, 0o660)
    gid = os.environ.get("OMV_NETCTL_GID")
    if gid:
        os.chown(sock, -1, int(gid))
        os.chown(sock.parent, -1, int(gid))
    srv.listen(8)
    srv.settimeout(1)
    while True:
        helper.expire()
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        serve_one(conn, helper)


if __name__ == "__main__":
    main()
