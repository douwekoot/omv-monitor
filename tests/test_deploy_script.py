import os
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools/deploy-remote.sh"


def write(base, files):
    for rel, body in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)


def setup(tmp_path):
    live, stage, units, snaps = (tmp_path / d for d in ("live", "stage", "units", "snaps"))
    write(live, {"app/web.py": "old", "wiki/a.md": "same", ".env": "SECRET=1", "data/s.json": "{}",
                 "host/omv-backup.timer": "old timer", "host/omv-new.timer": "never installed"})
    write(units, {"omv-backup.timer": "old timer"})
    snaps.mkdir()
    return live, stage, units, snaps


def run(tmp_path, mode, stage_files=None):
    live, stage, units, snaps = (tmp_path / d for d in ("live", "stage", "units", "snaps"))
    if stage_files is not None:
        write(stage, stage_files)
    env = dict(os.environ, OMV_DIR=str(live), OMV_STAGE=str(stage), OMV_UNIT_DIR=str(units),
               OMV_SNAP_DIR=str(snaps), OMV_SKIP_SERVICES="1")
    return subprocess.run(["bash", str(SCRIPT), mode], env=env, capture_output=True, text=True)


STAGED = {"app/web.py": "new", "wiki/a.md": "same", "app/extra.py": "added", ".env": "FROM-GIT",
          "host/omv-backup.timer": "new timer", "host/omv-new.timer": "changed but not installed"}


def test_plan_lists_changes_and_touches_nothing(tmp_path):
    live, *_ = setup(tmp_path)
    r = run(tmp_path, "plan", STAGED)
    assert r.returncode == 0, r.stderr
    listed = {l.strip() for l in r.stdout.splitlines()[1:]}
    assert listed == {"app/web.py", "app/extra.py", "host/omv-backup.timer", "host/omv-new.timer"}
    assert (live / "app/web.py").read_text() == "old"


def test_apply_copies_snapshots_and_updates_installed_units(tmp_path):
    live, stage, units, snaps = setup(tmp_path)
    r = run(tmp_path, "apply", STAGED)
    assert r.returncode == 0, r.stderr
    assert (live / "app/web.py").read_text() == "new" and (live / "app/extra.py").exists()
    assert (live / ".env").read_text() == "SECRET=1"
    assert (units / "omv-backup.timer").read_text() == "new timer"
    assert (units / "omv-backup.timer").stat().st_mode & 0o777 == 0o600
    assert not (units / "omv-new.timer").exists()
    assert not stage.exists()
    [snap] = snaps.glob("omv-monitor-pre-deploy-*.tar.gz")
    with tarfile.open(snap) as t:
        names = t.getnames()
    assert "./app/web.py" in names and not any(n.startswith(("./.env", "./data")) for n in names)


def test_up_to_date_does_nothing(tmp_path):
    live, stage, units, snaps = setup(tmp_path)
    r = run(tmp_path, "apply", {"app/web.py": "old", "wiki/a.md": "same"})
    assert "up to date" in r.stdout
    assert not list(snaps.iterdir())


def test_rollback_restores_previous_state(tmp_path):
    live, stage, units, snaps = setup(tmp_path)
    run(tmp_path, "apply", STAGED)
    r = run(tmp_path, "rollback")
    assert r.returncode == 0, r.stderr
    assert (live / "app/web.py").read_text() == "old"
    assert (units / "omv-backup.timer").read_text() == "old timer"
    assert (live / ".env").read_text() == "SECRET=1"


def test_snapshots_are_capped(tmp_path):
    live, stage, units, snaps = setup(tmp_path)
    for i in range(7):
        (snaps / f"omv-monitor-pre-deploy-2026-01-0{i}_000000.tar.gz").write_bytes(b"")
    run(tmp_path, "apply", STAGED)
    assert len(list(snaps.glob("omv-monitor-pre-deploy-*"))) == 5
