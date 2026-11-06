import os
import subprocess
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "monitor/host/omv-backup.sh"


def run(tmp_path, **env):
    src, prom, dest = tmp_path / "src", tmp_path / "prom", tmp_path / "nas"
    for d in ("config", "wiki", "data", "certs"):
        (src / d).mkdir(parents=True, exist_ok=True)
        (src / d / "f.txt").write_text(d)
    (src / ".env").write_text("APP_SECRET_KEY=x\n")
    prom.mkdir(exist_ok=True)
    (prom / "wal").write_text("tsdb")
    e = dict(os.environ, OMV_MONITOR_DIR=str(src), OMV_BACKUP_DIR=str(dest), OMV_PROM_DIR=str(prom), **env)
    subprocess.run(["sh", str(SCRIPT)], env=e, check=True, capture_output=True)
    return dest


def archives(dest):
    return sorted(p.relative_to(dest).parts[:2] for p in dest.rglob("*.tar.gz"))


def test_one_archive_per_kind_in_ordered_folders(tmp_path):
    dest = run(tmp_path)
    assert archives(dest) == [("files", "config"), ("files", "prometheus"), ("files", "settings"),
                              ("files", "wiki"), ("secrets", "certs"), ("secrets", "env")]
    with tarfile.open(next((dest / "secrets/env").glob("*.tar.gz"))) as t:
        assert t.getnames() == [".env"]
    with tarfile.open(next((dest / "files/settings").glob("*.tar.gz"))) as t:
        assert "data/f.txt" in t.getnames()


def test_totp_state_goes_to_secrets_not_files(tmp_path):
    (tmp_path / "src/data").mkdir(parents=True)
    (tmp_path / "src/data/totp.json").write_text("{}")
    dest = run(tmp_path)
    names = lambda d: [n for p in (dest / d).rglob("*.tar.gz") for n in tarfile.open(p).getnames()]
    assert any(n.endswith("totp.json") for n in names("secrets"))
    assert not any(n.endswith("totp.json") for n in names("files"))


def test_totp_setup_file_not_backed_up(tmp_path):
    (tmp_path / "src/data").mkdir(parents=True)
    (tmp_path / "src/data/totp-setup.json").write_text("{}")
    dest = run(tmp_path)
    for p in (dest / "files/settings").glob("*.tar.gz"):
        assert not any(n.endswith("totp-setup.json") for n in tarfile.open(p).getnames())


def test_secrets_are_private_and_files_readable(tmp_path):
    dest = run(tmp_path)
    assert (dest / "secrets").stat().st_mode & 0o777 == 0o700
    for p in (dest / "secrets").rglob("*.tar.gz"):
        assert p.stat().st_mode & 0o077 == 0
    for p in (dest / "files").rglob("*.tar.gz"):
        assert p.stat().st_mode & 0o004


def test_old_archives_are_pruned(tmp_path):
    dest = run(tmp_path)
    old = dest / "files/config/config-2000-01-01_0000.tar.gz"
    old.write_bytes(b"")
    past = time.time() - 30 * 86400
    os.utime(old, (past, past))
    run(tmp_path, OMV_BACKUP_KEEP_DAYS="14")
    assert not old.exists()
    assert list((dest / "files/config").glob("*.tar.gz"))


def test_missing_source_fails_without_leftovers(tmp_path):
    dest = run(tmp_path)
    (tmp_path / "src/wiki/f.txt").unlink()
    (tmp_path / "src/wiki").rmdir()
    e = dict(os.environ, OMV_MONITOR_DIR=str(tmp_path / "src"), OMV_BACKUP_DIR=str(dest),
             OMV_PROM_DIR=str(tmp_path / "prom"))
    r = subprocess.run(["sh", str(SCRIPT)], env=e, capture_output=True)
    assert r.returncode != 0
    assert not list(dest.rglob("*.tmp"))
