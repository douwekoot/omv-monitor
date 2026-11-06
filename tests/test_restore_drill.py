import sys

from test_backup_script import ROOT, run

sys.path.insert(0, str(ROOT / "tools"))
from restore_drill import main  # noqa: E402


def make(tmp_path):
    """Back up a minimal install (as the real script does) and return the NAS files/ dir."""
    (tmp_path / "src/wiki").mkdir(parents=True)
    (tmp_path / "src/wiki/index.md").write_text("# Home\n\nhello\n")
    (tmp_path / "src/config").mkdir(parents=True)
    (tmp_path / "src/config/devices.toml").write_text('[devices]\n"10.0.0.2/32" = "Phone"\n')
    return run(tmp_path) / "files"


def test_drill_passes(tmp_path, capsys):
    files = make(tmp_path)
    assert main([str(files), "--scratch", str(tmp_path / "scratch")]) == 0
    assert "GET /login 200" in capsys.readouterr().out


def test_missing_kind_fails(tmp_path, capsys):
    files = make(tmp_path)
    for p in (files / "wiki").glob("*.tar.gz"):
        p.unlink()
    assert main([str(files), "--scratch", str(tmp_path / "scratch")]) != 0
    assert "wiki" in capsys.readouterr().err


def test_corrupt_archive_fails(tmp_path):
    files = make(tmp_path)
    next((files / "config").glob("*.tar.gz")).write_bytes(b"not a tar")
    assert main([str(files), "--scratch", str(tmp_path / "scratch")]) != 0


# --- per-target restic drill (T3) -------------------------------------------
# Contract: restore_drill.drill_target(repo, runner, password_file, scratch) runs
# `restic ... restore latest --target <scratch>` via runner.run(argv, input=None) -> (rc, out),
# then raises ValueError unless files exist in scratch; returns the number of files.
import pytest  # noqa: E402
from pathlib import Path  # noqa: E402

import restore_drill  # noqa: E402


class ResticFake:
    def __init__(self, files=("home/u/a.txt",), rc=0):
        self.files, self.rc, self.calls = files, rc, []

    def run(self, argv, input=None):
        self.calls.append(list(argv))
        if "restore" in argv and self.rc == 0:
            dest = Path(argv[argv.index("--target") + 1])
            for f in self.files:
                (dest / f).parent.mkdir(parents=True, exist_ok=True)
                (dest / f).write_text("x")
        return self.rc, ""


def test_target_drill_ok(tmp_path):
    r = ResticFake()
    assert restore_drill.drill_target("/mnt/nas/pc", r, "/s/pass", tmp_path / "scratch") == 1
    argv = r.calls[0]
    assert "restore" in argv and "latest" in argv and "/mnt/nas/pc" in " ".join(argv)
    assert "--password-file" in argv and "/s/pass" in argv


def test_target_drill_no_files_fails(tmp_path):
    with pytest.raises(ValueError):
        restore_drill.drill_target("/mnt/nas/pc", ResticFake(files=()), "/s/pass", tmp_path / "scratch")


def test_target_drill_restic_error_fails(tmp_path):
    with pytest.raises(ValueError):
        restore_drill.drill_target("/mnt/nas/pc", ResticFake(rc=1), "/s/pass", tmp_path / "scratch")


def test_cli_target_unknown_fails(capsys):
    assert restore_drill.main(["--target", "no-such-target"], runner=ResticFake()) == 1
    assert "FAIL" in capsys.readouterr().err


def _fake_fs(monkeypatch, root_dev=1):
    monkeypatch.setattr(restore_drill, "_dev", lambda p: root_dev if str(p) == "/" else 2)


def test_drill_in_scratch_under_dest_removed_after_success(tmp_path, monkeypatch):
    _fake_fs(monkeypatch)
    n, scratch = restore_drill.drill_in(tmp_path, "pc", "/r", ResticFake(), "/p")
    assert n == 1 and scratch.parent == tmp_path and scratch.name.startswith(".drill-pc-")
    assert not scratch.exists() and not list(tmp_path.iterdir())


def test_drill_in_scratch_removed_after_restic_failure(tmp_path, monkeypatch):
    _fake_fs(monkeypatch)
    with pytest.raises(ValueError):
        restore_drill.drill_in(tmp_path, "pc", "/r", ResticFake(rc=1), "/p")
    assert not list(tmp_path.iterdir())


def test_drill_in_refuses_root_filesystem(tmp_path, monkeypatch):
    _fake_fs(monkeypatch, root_dev=2)
    r = ResticFake()
    with pytest.raises(ValueError, match="root filesystem"):
        restore_drill.drill_in(tmp_path, "pc", "/r", r, "/p")
    assert r.calls == [] and not list(tmp_path.iterdir())


def test_cli_target_uses_destination_root(tmp_path, monkeypatch):
    from app import config
    _fake_fs(monkeypatch)
    monkeypatch.setattr(config, "merged_backups", lambda *a: {"destination_root": str(tmp_path), "targets": [{"name": "pc"}]})
    assert restore_drill.main(["--target", "pc"], runner=ResticFake()) == 0
    assert not list(tmp_path.iterdir())


def test_drill_in_refuses_before_mkdir(tmp_path, monkeypatch):
    _fake_fs(monkeypatch, root_dev=2)
    with pytest.raises(ValueError, match="root filesystem"):
        restore_drill.drill_in(tmp_path / "new" / "deep", "pc", "/r", ResticFake(), "/p")
    assert not (tmp_path / "new").exists()
