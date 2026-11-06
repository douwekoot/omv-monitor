"""Read-only view of the NAS backups written by host/omv-backup.sh (secrets are never mounted here)."""
import json
import re
from pathlib import Path

KINDS = ("config", "wiki", "settings", "prometheus")
_NAME = re.compile(r"(?P<kind>[a-z]+)-(?P<date>\d{4}-\d{2}-\d{2})_(?P<hm>\d{4})\.tar\.gz")


def _entry(p):
    m = _NAME.fullmatch(p.name)
    if not m or not p.is_file() or p.is_symlink():
        return None
    hm = m["hm"]
    return {"name": p.name, "size": p.stat().st_size, "when": f"{m['date']} {hm[:2]}:{hm[2:]}"}


def list_backups(root):
    """Kind -> archives, newest first. A missing folder is an empty list."""
    out = {}
    for kind in KINDS:
        d = Path(root) / kind
        found = [e for p in (d.iterdir() if d.is_dir() else ()) if (e := _entry(p))]
        out[kind] = sorted((e for e in found if e["name"].startswith(kind + "-")), key=lambda e: e["name"],
                           reverse=True)
    return out


def resolve(root, kind, name):
    """The archive path for a download, or None for anything not listed."""
    if kind not in KINDS or not name.startswith(kind + "-") or not _NAME.fullmatch(name):
        return None
    p = Path(root) / kind / name
    return p if _entry(p) else None


def read_runs(path, target=None, n=50):
    """Newest-first rows of the backup runs jsonl (optionally one target); corrupt lines and a missing file are skipped."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    rows = []
    for ln in lines:
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if isinstance(r, dict) and (target is None or r.get("target") == target):
            rows.append(r)
    rows.sort(key=lambda r: r.get("ts") if isinstance(r.get("ts"), (int, float)) else 0, reverse=True)
    return rows[:n]


# Device backup exports: written by host/omv-device-backup.py export into <destination_root>/.exports.
_EXPORT = re.compile(r"(?P<target>[a-z0-9-]+)-(?P<snap>[0-9a-f]{8,64})-(?P<slug>[A-Za-z0-9._-]{1,60})-"
                     r"(?P<date>\d{8})-(?P<hm>\d{4})\.tar(?P<state>\.part|\.err)?")
SNAPSHOT_RE = re.compile(r"[0-9a-f]{8,64}")


def valid_export_path(path):
    """The same rule omv-netctl enforces: an absolute folder path without .. or control characters."""
    return (isinstance(path, str) and path.startswith("/") and len(path) <= 1024
            and not any(c in path for c in "\0\n\r") and ".." not in path.split("/"))


def list_exports(root, target):
    """Newest-first exports of one target: {name, state (ready|running|failed), size, when, error}."""
    d = Path(root)
    out = []
    for p in d.iterdir() if d.is_dir() else ():
        m = _EXPORT.fullmatch(p.name)
        if not m or m["target"] != target or not p.is_file() or p.is_symlink():
            continue
        state = {".part": "running", ".err": "failed"}.get(m["state"], "ready")
        try:
            error = p.read_text(errors="replace").strip()[:300] if state == "failed" else None
        except OSError:
            error = "n/a"
        d8, hm = m["date"], m["hm"]
        out.append({"name": p.name, "state": state, "size": p.stat().st_size, "snapshot": m["snap"],
                    "when": f"{d8[:4]}-{d8[4:6]}-{d8[6:]} {hm[:2]}:{hm[2:]}", "error": error, "mtime": p.stat().st_mtime})
    return sorted(out, key=lambda e: e["mtime"], reverse=True)


def resolve_export(root, name):
    """A ready export's path for download, or None for anything else."""
    m = _EXPORT.fullmatch(name)
    if not m or m["state"]:
        return None
    p = Path(root) / name
    return p if p.is_file() and not p.is_symlink() else None
