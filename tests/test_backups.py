import os
import re

import pytest

from app import backups
from app.web import create_app
from conftest import totp_cfg
from test_settings_web import HTTPS, ROOT, get, login


def archive(root, kind, name, body=b"tgz"):
    d = root / kind
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(body)
    return d / name


@pytest.fixture
def broot(tmp_path):
    r = tmp_path / "files"
    archive(r, "config", "config-2026-10-29_0330.tar.gz")
    archive(r, "config", "config-2026-10-30_0330.tar.gz", b"newer")
    archive(r, "prometheus", "prometheus-2026-10-30_0330.tar.gz")
    return r


def test_list_newest_first_and_empty_kinds(broot):
    got = backups.list_backups(broot)
    assert list(got) == list(backups.KINDS)
    assert [e["name"] for e in got["config"]] == ["config-2026-10-30_0330.tar.gz", "config-2026-10-29_0330.tar.gz"]
    assert got["config"][0] == {"name": "config-2026-10-30_0330.tar.gz", "size": 5, "when": "2026-10-30 03:30"}
    assert got["wiki"] == [] and got["settings"] == []


def test_missing_root_is_empty(tmp_path):
    assert backups.list_backups(tmp_path / "nope") == {k: [] for k in backups.KINDS}


def test_unlisted_files_are_ignored(broot, tmp_path):
    archive(broot, "config", "notes.txt")
    archive(broot, "config", ".config-2026-10-30_0400.tmp")
    archive(broot, "config", "wiki-2026-10-30_0330.tar.gz")
    secret = archive(tmp_path, "secrets", "env-2026-10-30_0330.tar.gz")
    os.symlink(secret, broot / "config" / "config-2026-10-31_0330.tar.gz")
    assert len(backups.list_backups(broot)["config"]) == 2


@pytest.mark.parametrize("kind,name", [
    ("env", "env-2026-10-30_0330.tar.gz"),
    ("certs", "certs-2026-10-30_0330.tar.gz"),
    ("config", "../secrets/env-2026-10-30_0330.tar.gz"),
    ("config", "wiki-2026-10-30_0330.tar.gz"),
    ("config", "config-2026-10-30_0330.tar.gz/.."),
    ("config", "config-2099-01-01_0000.tar.gz"),
    ("..", "config-2026-10-30_0330.tar.gz"),
])
def test_resolve_refuses_anything_not_listed(broot, kind, name):
    assert backups.resolve(broot, kind, name) is None


def test_resolve_listed_archive(broot):
    assert backups.resolve(broot, "config", "config-2026-10-30_0330.tar.gz") == \
        broot / "config" / "config-2026-10-30_0330.tar.gz"


def app_with(fake, tmp_path, broot):
    return create_app({"ADMIN_PASSWORD": "pw", "SECRET_KEY": "k", "WIKI_DIR": str(ROOT / "monitor/wiki"),
                       "DEVICES_FILE": str(ROOT / "monitor/config/devices.toml"),
                       "SETTINGS_FILE": str(tmp_path / "s.json"), "BACKUP_DIR": str(broot), **totp_cfg(tmp_path)}, prom_client=fake)


def test_pages_need_login(fake, tmp_path, broot):
    c = app_with(fake, tmp_path, broot).test_client()
    assert get(c, "/backups").status_code == 302
    assert get(c, "/backups/config/config-2026-10-30_0330.tar.gz").status_code == 302


def test_page_lists_archives_and_names_the_device(fake, tmp_path, broot):
    c = login(app_with(fake, tmp_path, broot).test_client())
    h = c.get("/backups", base_url=HTTPS, environ_base={"REMOTE_ADDR": "10.8.0.1"}).get_data(as_text=True)
    assert "/backups/config/config-2026-10-30_0330.tar.gz" in h
    assert "No backups yet." in h
    assert "<strong>Phone</strong>" in h
    assert "env-" not in h


def test_download_is_an_attachment(fake, tmp_path, broot):
    c = login(app_with(fake, tmp_path, broot).test_client())
    r = get(c, "/backups/config/config-2026-10-30_0330.tar.gz")
    assert r.status_code == 200 and r.data == b"newer"
    assert r.headers["Content-Disposition"].startswith("attachment")
    assert r.headers["Content-Type"] == "application/gzip"


def test_download_of_unlisted_file_is_404(fake, tmp_path, broot):
    c = login(app_with(fake, tmp_path, broot).test_client())
    assert get(c, "/backups/env/env-2026-10-30_0330.tar.gz").status_code == 404
    assert get(c, "/backups/config/..%2F..%2Fsecrets").status_code == 404


def test_backups_link_on_dashboard(fake, tmp_path, broot):
    c = login(app_with(fake, tmp_path, broot).test_client())
    h = get(c, "/").get_data(as_text=True)
    assert 'href="/backups"' in h
    side_nav = re.search(r'<aside class="side.*?<nav class="seg".*?</nav>', h, re.S).group(0)
    assert 'href="/backups"' in side_nav



def _runs(tmp_path, *lines):
    p = tmp_path / "runs.jsonl"
    p.write_text("\n".join(lines) + "\n")
    return p


def test_read_runs_newest_first_filter_limit_and_corrupt(tmp_path):
    import json
    row = lambda ts, t, ok=True: json.dumps({"ts": ts, "target": t, "step": "backup", "ok": ok, "detail": f"d{ts}"})
    p = _runs(tmp_path, row(1, "pc"), "{not json", row(3, "omv"), "", row(2, "pc", False), "[1]")
    assert [r["ts"] for r in backups.read_runs(p)] == [3, 2, 1]
    assert [r["ts"] for r in backups.read_runs(p, target="pc")] == [2, 1]
    assert [r["ts"] for r in backups.read_runs(p, n=2)] == [3, 2]
    assert backups.read_runs(p, target="nope") == []


def test_read_runs_missing_file(tmp_path):
    assert backups.read_runs(tmp_path / "nope.jsonl") == []


def test_sidebar_lists_targets_and_archive_kinds(fake, tmp_path, broot):
    c = login(app_with(fake, tmp_path, broot).test_client())
    side = re.search(r"<aside.*?</aside>", get(c, "/backups").get_data(as_text=True), re.S).group(0)
    assert re.search(r'href="/backups/targets/[^"]+"', side)
    assert 'href="/backups#h-bk-config"' in side and 'href="/backups#h-bk-prometheus"' in side


@pytest.mark.parametrize("name", [
    "../config/config-2026-10-30_0330.tar.gz", "/etc/passwd", "config/../config/config-2026-10-30_0330.tar.gz",
    "config-2026-10-30_0330.tar.gz/", "config-2026-10-30_0330.tar.gz\n", "config-2026-10-30_0330.tar.gz\0",
    "config%2F..%2Fx-2026-10-30_0330.tar.gz", "config-2026-10-30_0330.tar.gz/../../x",
])
def test_resolve_rejects_traversal_names(broot, name):
    assert backups.resolve(broot, "config", name) is None


@pytest.mark.parametrize("kind", ["..", "config/..", "/etc", "", "config\0", "CONFIG"])
def test_resolve_rejects_bad_kinds(broot, kind):
    assert backups.resolve(broot, kind, "config-2026-10-30_0330.tar.gz") is None


def test_resolve_refuses_symlinked_archive_and_kind_dir(broot, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("x")
    (broot / "config" / "config-2026-11-01_0330.tar.gz").symlink_to(secret)
    assert backups.resolve(broot, "config", "config-2026-11-01_0330.tar.gz") is None
    out = tmp_path / "outside"
    archive(out, "wiki", "wiki-2026-10-30_0330.tar.gz")
    (broot / "wiki").symlink_to(out / "wiki")
    assert backups.resolve(broot, "wiki", "wiki-2026-10-30_0330.tar.gz") is None
    assert backups.list_backups(broot)["wiki"] == []
