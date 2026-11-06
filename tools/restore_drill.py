"""Restore drill: unpack the newest omv-backup archives into a scratch dir and check the app starts from them.

Usage: python tools/restore_drill.py BACKUP_FILES_DIR [--scratch DIR]
       python tools/restore_drill.py --target NAME [--scratch DIR]   (restic repo of a device-backup target)
Read-only on the archives; writes only inside the scratch dir; no network.
"""
import argparse
import json
import os
import shutil
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "monitor"))
from app import backups, settings, wiki  # noqa: E402
from app.web import create_app  # noqa: E402


class _StubProm:
    def query(self, expr):
        return []

    def query_range(self, expr, start, end, step):
        return []


def _ok(msg):
    print(f"OK {msg}")


def _check(scratch):
    devices = scratch / "config" / "devices.toml"
    with open(devices, "rb") as f:
        n = len(tomllib.load(f).get("devices", {}))
    _ok(f"config/devices.toml loads ({n} devices)")

    sfile = scratch / "data" / "settings.json"
    if sfile.is_file():
        _, errors = settings.validate(json.loads(sfile.read_text(encoding="utf-8")))
        if errors:
            raise ValueError("settings.json invalid: " + "; ".join(errors))
        _ok("data/settings.json valid")

    pages = wiki.list_pages(scratch / "wiki")
    if not pages:
        raise ValueError("wiki has no pages")
    for slug, _ in pages:
        wiki.render_page(scratch / "wiki", slug)
    _ok(f"wiki renders {len(pages)} pages")

    app = create_app({
        "ADMIN_PASSWORD": "drill", "SECRET_KEY": "drill", "WIKI_DIR": str(scratch / "wiki"),
        "DEVICES_FILE": str(devices), "SETTINGS_FILE": str(sfile),
        "AUDIT_FILE": str(scratch / "data" / "audit.jsonl"), "TOTP_FILE": str(scratch / "data" / "totp.json"),
        "DEVICE_NAMES_FILE": str(scratch / "data" / "device_names.json"), "BACKUP_DIR": str(scratch / "backups"),
    }, prom_client=_StubProm())
    status = app.test_client().get("/login", base_url="https://localhost").status_code
    if status != 200:
        raise ValueError(f"GET /login returned {status}")
    _ok("app starts, GET /login 200")


def drill_target(repo, runner, password_file, scratch):
    """Restore the latest restic snapshot of one target into scratch; return the file count."""
    scratch = Path(scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    rc, out = runner.run(["restic", "-r", str(repo), "--password-file", str(password_file),
                          "restore", "latest", "--target", str(scratch)])
    if rc != 0:
        raise ValueError(f"restic restore failed (exit {rc}): {out.strip()[-200:]}")
    n = sum(1 for p in scratch.rglob("*") if p.is_file())
    if not n:
        raise ValueError("restore produced no files")
    return n


def _dev(path):
    return os.stat(path).st_dev


def drill_in(parent, name, repo, runner, password_file):
    """Restore into a fresh scratch dir under parent (never on the root filesystem); always remove it."""
    parent = Path(parent)
    anc = parent
    while not anc.exists():  # check before any mkdir so nothing is created on "/"
        anc = anc.parent
    if _dev(anc) == _dev("/"):
        raise ValueError(f"scratch location {parent} is on the root filesystem")
    parent.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix=f".drill-{name}-", dir=parent))
    try:
        return drill_target(repo, runner, password_file, scratch), scratch
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


class _Runner:
    def run(self, argv):
        import subprocess
        p = subprocess.run(argv, capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr


def _target_main(args, runner=None):
    """Restore the newest snapshot of one device-backup target (run as root on the host)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "monitor"))
    from app import config
    base = Path("/opt/omv-monitor")
    try:
        cfg = config.merged_backups(base / "config/backups.toml", base / "data/backup-overrides.json")
        if not any(t["name"] == args.target for t in cfg["targets"]):
            raise ValueError(f"unknown target {args.target}")
        n, scratch = drill_in(args.scratch or cfg["destination_root"], args.target,
                              config.repo_path(cfg, args.target), runner or _Runner(),
                              base / "secrets" / f"restic-{args.target}.pass")
        _ok(f"{args.target}: restored {n} files into {scratch} (removed)")
    except (ValueError, OSError) as e:
        print(f"FAIL {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    return 0


def main(argv=None, runner=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("backup_dir", type=Path, nargs="?")
    ap.add_argument("--target", help="drill one device-backup target's restic repo instead")
    ap.add_argument("--scratch", type=Path)
    args = ap.parse_args(argv)
    if args.target:
        return _target_main(args, runner)
    if args.backup_dir is None:
        ap.error("backup_dir or --target is required")
    try:
        newest = {k: v[0]["name"] for k, v in backups.list_backups(args.backup_dir).items() if v}
        missing = [k for k in backups.KINDS if k not in newest]
        if missing:
            raise ValueError("no archive for: " + ", ".join(missing))
        scratch = args.scratch or Path(tempfile.mkdtemp(prefix="restore-drill-"))
        scratch.mkdir(parents=True, exist_ok=True)
        print(f"scratch: {scratch}")
        for kind, name in newest.items():
            dest = scratch / ("prometheus" if kind == "prometheus" else ".")
            with tarfile.open(args.backup_dir / kind / name) as t:
                t.extractall(dest, filter="data")
            _ok(f"{kind}: extracted {name}")
        _check(scratch)
    except (ValueError, OSError, tarfile.TarError, tomllib.TOMLDecodeError, KeyError) as e:
        print(f"FAIL {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
