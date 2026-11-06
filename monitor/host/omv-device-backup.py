#!/usr/bin/env python3
"""Restic backups of the configured targets (stdlib only, runs as root).

  omv-device-backup.py due                      run every enabled target whose interval has passed
  omv-device-backup.py run NAME [--categories a,b]   run one target now
  omv-device-backup.py snapshots NAME           print the target's snapshots as JSON
  omv-device-backup.py export NAME              dump the folder named in omv-netctl's request to a tar

Repos live under destination_root (a separate NAS disk). Passwords come from
secrets/restic-<name>.pass and reach restic on stdin, never argv or the log.
"""
import argparse
import fcntl
import glob
import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import config  # noqa: E402

BASE = "/opt/omv-monitor"
CFG = (f"{BASE}/config/backups.toml", f"{BASE}/data/backup-overrides.json")
LOG_FILE = f"{BASE}/data/backup-runs.jsonl"
METRICS_FILE = "/var/lib/node_exporter/textfile/omv_device_backup.prom"
SECRETS = f"{BASE}/secrets"
LOCK_DIR = "/run/omv-device-backup"
REQUESTS = "/var/lib/omv-netctl/backup-requests"
STAGE = "/var/lib/omv-device-backup-staging"
EXPORTS = ".exports"  # under destination_root; the dot keeps it apart from repo names ([a-z0-9-]+)
EXPORT_TTL, PART_TTL = 3600, 6 * 3600  # a ready export lives 1 h; a stuck .part is dropped after 6 h
WEB_UID = 10001  # the web container's user (monitor/Dockerfile): it reads exports, nothing else does
WAKE_POLLS, WAKE_WAIT = 18, 10  # ~3 min
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]
METRICS = ("last_success_timestamp_seconds", "last_run_timestamp_seconds", "last_ok", "size_bytes", "interval_seconds")
_LINE = re.compile(r'omv_device_backup_(\w+)\{target="([a-z0-9-]+)"\} (\S+)')

FULL_EXCLUDES = ["/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", "/var/cache", "/home/*/.cache", "/swapfile"]
# Fixed allowlist: category -> restic paths. No free text ever reaches a command.
SSH_PATHS = {"home": ["/home"], "system-settings": ["/etc"], "full-system": ["/"]}
SSH_STAGED = {  # shell run on the device, writing into $S; fixed strings
    "gnome-settings": 'for h in /home/*; do u=${h##*/}; runuser -u "$u" -- dconf dump / > "$S/dconf-$u.ini" 2>/dev/null; done',
    "packages": 'rpm -qa > "$S/rpm.txt"; dnf repolist > "$S/dnf-repos.txt"; flatpak list > "$S/flatpak.txt"',
    "users": 'getent passwd > "$S/passwd"; getent group > "$S/group"',  # getent only: no shadow hashes
}
LOCAL_PATHS = {  # shortcut: Prometheus TSDB dir is copied live (admin snapshot API is off), restore may drop the newest WAL
    "omv-config": ["/etc/openmediavault"],
    "host-config": ["/etc"],
    "compose": ["/opt/*"],  # whole stack dirs, .env files included
    "monitor-data": [f"{BASE}/config", f"{BASE}/wiki", f"{BASE}/data", "/var/lib/docker/volumes/*prom-data/_data"],
    "nas-data": ["/srv/dev-disk-by-*"],  # destination_root is excluded below
}
LOCAL_STAGED = {"omv-config": 'omv-confdbadm dump > "$S/confdb-dump.txt"'}  # best effort, fixed string


class Runner:
    def run(self, argv, input=None):
        try:
            p = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=6 * 3600)
        except subprocess.TimeoutExpired:
            return 124, "timed out"
        return p.returncode, p.stdout + p.stderr

    def dump(self, argv, path):
        """Run argv with stdout streamed into path (binary, too big for memory)."""
        with open(path, "wb") as f:
            try:
                p = subprocess.run(argv, stdout=f, stderr=subprocess.PIPE, timeout=6 * 3600)
            except subprocess.TimeoutExpired:
                return 124, "timed out"
        return p.returncode, p.stderr.decode(errors="replace")


def send_wol(mac):
    raw = bytes.fromhex(mac.replace(":", ""))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(b"\xff" * 6 + raw * 16, ("255.255.255.255", 9))


class DeviceBackup:
    def __init__(self, cfg, runner, clock=time.time, sleep=time.sleep, send_wol=send_wol,
                 ismount=os.path.ismount, st_dev=lambda p: os.stat(p).st_dev, log_file=LOG_FILE,
                 metrics_file=METRICS_FILE, secrets_dir=SECRETS, lock_dir=LOCK_DIR):
        self.cfg, self.runner, self.clock, self.sleep, self.send_wol = cfg, runner, clock, sleep, send_wol
        self.ismount, self.st_dev, self.nas = ismount, st_dev, None
        self.log_file, self.metrics_file = Path(log_file), Path(metrics_file)
        self.secrets, self.lock_dir = Path(secrets_dir), Path(lock_dir)
        self.lock_dir.mkdir(parents=True, exist_ok=True)

    # --- log and metrics ----------------------------------------------------
    def _log(self, name, step, ok, detail="", **extra):
        row = {"ts": self.clock(), "target": name, "step": step, "ok": ok, "detail": str(detail)[:300], **extra}
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        return ok

    def _read_metrics(self):
        vals = {}
        try:
            for m, t, v in _LINE.findall(self.metrics_file.read_text()):
                vals.setdefault(t, {})[m] = v
        except OSError:
            pass
        return vals

    def _write_metrics(self, name, ok, size=None):
        with open(self.metrics_file.with_name(self.metrics_file.name + ".lock"), "a") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)  # other targets may be writing at the same time
            self._write_metrics_locked(name, ok, size)

    def _write_metrics_locked(self, name, ok, size):
        vals, now = self._read_metrics(), int(self.clock())
        for t in self.cfg["targets"]:
            vals.setdefault(t["name"], {})["interval_seconds"] = str(t["interval_h"] * 3600)
        v = vals.setdefault(name, {})
        v["last_run_timestamp_seconds"], v["last_ok"] = str(now), "1" if ok else "0"
        if ok:
            v["last_success_timestamp_seconds"] = str(now)
        if size is not None:
            v["size_bytes"] = str(size)
        lines = [f'omv_device_backup_{m}{{target="{t}"}} {vals[t][m]}'
                 for m in METRICS for t in sorted(vals) if m in vals[t]]
        fd, tmp = tempfile.mkstemp(dir=self.metrics_file.parent, prefix=".omv_device_backup.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(lines) + "\n")
            os.chmod(tmp, 0o644)
            os.replace(tmp, self.metrics_file)  # atomic for node-exporter
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    # --- helpers ------------------------------------------------------------
    def _dest_ok(self):
        root = self.cfg["destination_root"]
        if root == "/":
            return "destination_root is /"
        try:
            if self.st_dev(root) == self.st_dev("/"):
                return f"{root} is on the system disk"
        except OSError as e:
            return f"{root}: {e.strerror or e}"
        p = root
        while p != "/":
            if self.ismount(p):
                return None
            p = os.path.dirname(p) or "/"
        return f"{root} is not on a mounted filesystem"

    def _ssh(self, t, host, cmd, input=None):
        key = self.secrets / f"ssh-{t['name']}"
        ident = ["-i", str(key)] if key.exists() else []
        return self.runner.run([*SSH, *ident, f"{t['user']}@{host}", cmd], input=input)

    def _alive(self, t, host):
        return self._ssh(t, host, "true")[0] == 0

    def _find_host(self, t):
        return next((h for h in t["hosts"] if self._alive(t, h)), None)

    def _wake(self, t):
        """Return (host, woke). host None = unreachable (reason already logged)."""
        n = t["name"]
        host = self._find_host(t)
        self._log(n, "check", host is not None, host or "no host answers")
        if host:
            return host, False
        if not t["mac"]:
            self._log(n, "skip", True, "unreachable and no MAC for Wake-on-LAN")
            return None, False
        try:
            self.send_wol(t["mac"])
        except OSError as e:
            self._log(n, "fail", False, f"wake-on-LAN failed: {e}")
            return None, False
        self._log(n, "wake", True, "magic packet sent")
        for _ in range(WAKE_POLLS):
            self.sleep(WAKE_WAIT)
            if host := self._find_host(t):
                self._log(n, "check", True, f"{host} is up")
                return host, True
        self._log(n, "fail", False, "did not come up after Wake-on-LAN")
        return None, False

    def _paths(self, t, cats):
        table = SSH_PATHS if t["kind"] == "ssh" else LOCAL_PATHS
        paths = [p for c in cats for p in table.get(c, [])]
        if any(c in (SSH_STAGED if t["kind"] == "ssh" else LOCAL_STAGED) for c in cats):
            paths.append(STAGE)
        paths = list(dict.fromkeys(paths + t["include"]))
        ex = list(t["exclude"]) + (FULL_EXCLUDES if "full-system" in cats else [])
        if t["kind"] == "local":
            ex += [self.cfg["destination_root"], f"{BASE}/secrets", "/opt/**/secrets"]  # never back up the keys
        return paths, ex

    def _restic(self, t, host, args, pw):
        """Run restic locally or on the device; the password goes in on stdin."""
        repo = config.repo_path(self.cfg, t["name"])
        if t["kind"] == "local":
            return self.runner.run(["restic", "-r", repo, "--password-file", str(self.secrets / f"restic-{t['name']}.pass"), *args])
        nas = f"[{self.nas}]" if ":" in self.nas else self.nas
        remote = ["sudo", "-n", "restic", "-r", f"sftp:{t['user']}@{nas}:{repo}", "--password-file", "/dev/stdin", *args]
        return self._ssh(t, host, shlex.join(remote), input=pw)

    def _nas_host(self, t, host):
        """The server's address as the device sees it (1st field of $SSH_CONNECTION: the NAS is the ssh client): LAN or WireGuard IP."""
        rc, out = self._ssh(t, host, 'echo "$SSH_CONNECTION"')
        try:
            if rc != 0:
                raise ValueError
            self.nas = str(ipaddress.ip_address(out.split()[0]))
        except (ValueError, IndexError):
            self.nas = None
            self._log(t["name"], "fail", False, "cannot determine the NAS address from the device's SSH_CONNECTION")
        return self.nas

    def _ssh_sh(self, t, host, script):
        return self._ssh(t, host, f"sudo -n sh -c {shlex.quote(script)}")

    def _backup(self, t, host, cats, pw):
        n = t["name"]
        paths, ex = self._paths(t, cats)
        if not paths:
            return self._log(n, "run", False, "nothing selected to back up", categories=cats)
        if t["kind"] == "ssh":
            staged = [SSH_STAGED[c] for c in cats if c in SSH_STAGED]
            if staged:
                script = f'S={STAGE}; rm -rf "$S"; mkdir -p "$S"; ' + "; ".join(staged)
                self._ssh_sh(t, host, script)  # best effort: a missing tool leaves an empty file
        else:
            staged = [LOCAL_STAGED[c] for c in cats if c in LOCAL_STAGED]
            if staged:
                self.runner.run(["sh", "-c", f'S={STAGE}; rm -rf "$S"; mkdir -p "$S"; ' + "; ".join(staged)])
            paths = [p for x in paths for p in (sorted(glob.glob(x)) or ([x] if "*" not in x else []))]
        args = ["backup", "--tag", "omv-device-backup"]
        args += [a for e in ex for a in ("--exclude", e)] + ["--", *paths]
        rc, out = self._restic(t, host, args, pw)
        if rc not in (0, 3) and self._restic(t, host, ["cat", "config"], pw)[0] != 0:  # repo missing: create, retry once
            if self._restic(t, host, ["init"], pw)[0] == 0:
                rc, out = self._restic(t, host, args, pw)
        if t["kind"] == "ssh" and any(c in SSH_STAGED for c in cats):
            self._ssh_sh(t, host, f"rm -rf {STAGE}")
        elif t["kind"] == "local":
            self.runner.run(["rm", "-rf", STAGE])
        if rc == 3:  # restic: snapshot written, some files unreadable
            return self._log(n, "run", True, "warning: some files unreadable (restic exit 3): " + out.strip()[-150:], categories=cats)
        return self._log(n, "run", rc == 0, out.strip()[-200:] if rc else "backup complete", categories=cats)

    def _forget(self, t, host, pw):
        r = t["retention"]
        args = ["forget", "--prune", "--keep-daily", str(r["daily"]), "--keep-weekly", str(r["weekly"]),
                "--keep-monthly", str(r["monthly"])]
        rc, out = self._restic(t, host, args, pw)
        return self._log(t["name"], "forget", rc == 0, out.strip()[-200:] if rc else "retention applied")

    def _size(self, t, host, pw):
        rc, out = self._restic(t, host, ["stats", "--json", "--mode", "raw-data"], pw)
        try:
            return int(json.loads(out)["total_size"]) if rc == 0 else None
        except (ValueError, KeyError, TypeError):
            return None

    # --- entry points -------------------------------------------------------
    def run_target(self, name, categories=None):
        t = next((x for x in self.cfg["targets"] if x["name"] == name), None)
        if t is None:
            raise ValueError(f"unknown target {name}")
        cats = list(categories) if categories else list(t["categories"])  # saved ones were validated by config
        bad = [c for c in categories or () if c not in config.CATEGORIES[t["kind"]]]
        if bad:
            raise ValueError(f"categories not allowed for {name}: {bad}")
        with open(self.lock_dir / f"{name}.lock", "w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return self._log(name, "skip", True, "another run of this target is in progress")
            return self._locked(t, cats)

    def _locked(self, t, cats):
        n, host, woke, ok, size = t["name"], None, False, False, None
        try:
            if reason := self._dest_ok():
                self._log(n, "fail", False, reason)
            else:
                try:
                    pw = (self.secrets / f"restic-{n}.pass").read_text()
                except OSError as e:
                    self._log(n, "fail", False, f"restic password file: {e.strerror or e}")
                    pw = None
                if pw is not None:
                    if t["kind"] == "ssh":
                        host, woke = self._wake(t)
                        if host is None:
                            if not t["mac"]:
                                return False  # skipped: not a failed run
                            pw = None
                    else:
                        self._log(n, "check", True, "local")
                if pw is not None:
                    try:
                        ok = bool((t["kind"] == "local" or self._nas_host(t, host)) and
                                  self._backup(t, host, cats, pw) and self._forget(t, host, pw))
                        size = self._size(t, host, pw) if ok else None
                    finally:
                        if woke and t["shutdown_after_wol"]:
                            rc, out = self._ssh(t, host, "sudo -n shutdown -h now")
                            self._log(n, "shutdown", rc in (0, 255), "shutdown sent")  # 255: ssh dropped as it went down
            self._log(n, "done", True, "finished") if ok else self._log(n, "fail", False, "backup did not complete")
        except Exception as e:  # never leave the run unlogged
            self._log(n, "fail", False, f"{type(e).__name__}: {e}")
        self._write_metrics(n, ok, size)
        return ok

    # --- downloads: restic runs on the server, the repo is on its disk for every kind of target ---
    def _local_restic(self, name, args):
        return ["restic", "-r", config.repo_path(self.cfg, name), "--password-file", str(self.secrets / f"restic-{name}.pass"), *args]

    def exports_dir(self):
        return Path(self.cfg["destination_root"]) / EXPORTS

    def snapshots(self, name):
        """Newest-first [{id, time, paths, host}] of a target's repo; raises on a restic error."""
        if name not in {t["name"] for t in self.cfg["targets"]}:
            raise ValueError(f"unknown target {name}")
        rc, out = self.runner.run(self._local_restic(name, ["snapshots", "--json", "--no-lock"]))
        if rc != 0:
            raise RuntimeError(f"restic snapshots failed (exit {rc}): {out.strip()[-200:]}")
        snaps = json.JSONDecoder().raw_decode(out[out.index("["):])[0]  # stderr warnings may precede the JSON
        rows = [{"id": s["short_id"], "time": s["time"], "paths": s.get("paths", []), "host": s.get("hostname", "")}
                for s in snaps if isinstance(s, dict) and "short_id" in s]
        return sorted(rows, key=lambda r: r["time"], reverse=True)

    def export(self, name, snapshot, path):
        """restic dump of one folder into <destination_root>/.exports/<file>.tar (.part while running, .err on failure)."""
        if name not in {t["name"] for t in self.cfg["targets"]}:
            raise ValueError(f"unknown target {name}")
        if reason := self._dest_ok():  # an unmounted NAS disk would fill the system disk
            return self._log(name, "export", False, reason)
        d = self.exports_dir()
        d.mkdir(mode=0o750, exist_ok=True)
        os.chown(d, 0, WEB_UID)
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", path.strip("/"))[:60] or "full"
        base = d / f"{name}-{snapshot}-{slug}-{time.strftime('%Y%m%d-%H%M', time.localtime(self.clock()))}.tar"
        part, err = base.with_name(base.name + ".part"), base.with_name(base.name + ".err")
        with open(self.lock_dir / f"export-{name}.lock", "w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return self._log(name, "export", False, "another export of this target is in progress")
            try:
                rc, out = self.runner.dump(self._local_restic(name, ["dump", "--archive", "tar", snapshot, path]), part)
            except OSError as e:  # e.g. disk full: never leave half an archive that looks finished
                rc, out = 1, e.strerror or str(e)
            if rc != 0:
                part.unlink(missing_ok=True)
                err.write_text(f"restic dump failed (exit {rc}): {out.strip()[-300:]}\n")
                os.chown(err, WEB_UID, WEB_UID)
                return self._log(name, "export", False, f"{path} from {snapshot}: exit {rc}")
            os.chown(part, WEB_UID, WEB_UID)
            os.chmod(part, 0o400)
            part.rename(base)
            return self._log(name, "export", True, f"{path} from {snapshot} ready as {base.name}")

    def expire_exports(self):
        d = self.exports_dir()
        for f in d.iterdir() if d.is_dir() else ():
            ttl = PART_TTL if f.name.endswith(".part") else EXPORT_TTL
            if f.is_file() and self.clock() - f.stat().st_mtime > ttl:
                f.unlink(missing_ok=True)

    def due(self):
        self.expire_exports()
        last = self._read_metrics()
        for t in self.cfg["targets"]:
            prev = float(last.get(t["name"], {}).get("last_run_timestamp_seconds", 0))
            if t["enabled"] and self.clock() - prev >= t["interval_h"] * 3600:
                self.run_target(t["name"])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("due")
    r = sub.add_parser("run")
    r.add_argument("name")
    r.add_argument("--categories")
    sub.add_parser("snapshots").add_argument("name")
    sub.add_parser("export").add_argument("name")
    a = ap.parse_args(argv)
    b = DeviceBackup(config.merged_backups(*CFG), Runner())
    if a.cmd == "due":
        b.due()
        return 0
    if a.cmd == "snapshots":
        print(json.dumps(b.snapshots(a.name)))
        return 0
    if a.cmd == "export":
        req = Path(REQUESTS) / f"export-{a.name}.json"
        try:
            q = json.loads(req.read_text())
            snapshot, path = q["snapshot"], q["path"]
        except (OSError, ValueError, KeyError):
            print("no export request", file=sys.stderr)
            return 1
        finally:
            req.unlink(missing_ok=True)
        return 0 if b.export(a.name, snapshot, path) else 1
    cats = a.categories.split(",") if a.categories else None
    req = Path(REQUESTS) / f"{a.name}.json"
    if cats is None and req.is_file():  # written by omv-netctl for "Run now"
        try:
            cats = json.loads(req.read_text())["categories"]
        except (OSError, ValueError, KeyError):
            cats = None
        req.unlink(missing_ok=True)
    return 0 if b.run_target(a.name, cats) else 1


if __name__ == "__main__":
    sys.exit(main())
