import json
import os
from pathlib import Path

import pytest

from app import config
from app.config import ConfigError

REPO_CFG = Path(__file__).resolve().parent.parent / "monitor" / "config"

MONITOR = """
[thresholds]
disk_pct = 80
handshake_stale_s = 3600
backup_age_h = 48

[retention]
alert_history_days = 90
prometheus = "7d"

[[services]]
unit = "smbd"
label = "Samba"
restart = true

[[services]]
unit = "ssh"
label = "SSH"
restart = false
"""

BACKUPS = """
destination_root = "/srv/nas2/backups"

[[targets]]
name = "omv"
label = "Server"
kind = "local"
enabled = true
interval_h = 24
categories = ["omv-config", "compose"]
include = []
exclude = ["/var/tmp/*"]
retention = {daily = 7, weekly = 4, monthly = 6}

[[targets]]
name = "pc"
label = "Desktop"
kind = "ssh"
hosts = ["pc.lan", "10.0.0.2"]
user = "backup"
mac = "aa:bb:cc:dd:ee:ff"
shutdown_after_wol = true
enabled = true
interval_h = 24
categories = ["home", "packages"]
include = ["/home/me"]
exclude = []
retention = {daily = 7, weekly = 4, monthly = 6}
"""


def write(tmp_path, text, name="x.toml"):
    p = tmp_path / name
    p.write_text(text)
    return p


def bad(tmp_path, text, *needles, loader=config.load_backups, name="backups.toml"):
    with pytest.raises(ConfigError) as e:
        loader(write(tmp_path, text, name))
    for n in (name, *needles):
        assert n in str(e.value)


def tweak(old, new, text=BACKUPS):
    assert old in text
    return text.replace(old, new, 1)


# ---- monitor.toml

def test_threshold_defaults():
    assert config.THRESHOLD_DEFAULTS == {"disk_pct": 85, "handshake_stale_s": 604800, "backup_age_h": 36}


def test_load_monitor(tmp_path):
    c = config.load_monitor(write(tmp_path, MONITOR, "monitor.toml"))
    assert c["thresholds"] == {"disk_pct": 80, "handshake_stale_s": 3600, "backup_age_h": 48}
    assert c["retention"] == {"alert_history_days": 90, "prometheus": "7d"}


def test_repo_monitor_toml():
    c = config.load_monitor(REPO_CFG / "monitor.toml")
    assert c["thresholds"] == config.THRESHOLD_DEFAULTS
    assert c["retention"] == {"alert_history_days": 90, "prometheus": "7d"}
    assert [s["unit"] for s in c["services"]] == ["smbd", "minidlna", "nginx", "tailscaled", "ssh"]


def test_services_and_restart_units(tmp_path):
    c = config.load_monitor(write(tmp_path, MONITOR, "monitor.toml"))
    assert c["services"] == [{"unit": "smbd", "label": "Samba", "restart": True},
                             {"unit": "ssh", "label": "SSH", "restart": False}]
    assert config.restart_units(c["services"], "wg0") == {
        "wg-quick@wg0": "WireGuard", "smbd": "Samba", "omv-monitor": "Monitor (this page)"}


def test_monitor_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="monitor.toml"):
        config.load_monitor(tmp_path / "monitor.toml")


@pytest.mark.parametrize("old,new,key", [
    ("[thresholds]", "[thresholds\n", None),
    ("disk_pct = 80", "disk_pct = 80\nbogus = 1", "bogus"),
    ("disk_pct = 80", 'disk_pct = "80"', "thresholds.disk_pct"),
    ("disk_pct = 80", "disk_pct = true", "thresholds.disk_pct"),
    ("disk_pct = 80", "disk_pct = 49", "thresholds.disk_pct"),
    ("disk_pct = 80", "disk_pct = 100", "thresholds.disk_pct"),
    ("handshake_stale_s = 3600", "handshake_stale_s = 59", "thresholds.handshake_stale_s"),
    ("backup_age_h = 48", "backup_age_h = 721", "thresholds.backup_age_h"),
    ("alert_history_days = 90", "alert_history_days = 0", "retention.alert_history_days"),
    ("alert_history_days = 90", "alert_history_days = 3651", "retention.alert_history_days"),
    ('prometheus = "7d"', "prometheus = 7", "retention.prometheus"),
    ('prometheus = "7d"', 'prometheus = "soon"', "retention.prometheus"),
    ('unit = "smbd"', 'unit = "-x"', "services[0].unit"),
    ('unit = "smbd"', 'unit = "a;b"', "services[0].unit"),
    ('unit = "smbd"', 'unit = "ssh"', "services[1].unit"),
    ('unit = "smbd"', 'unit = "omv-monitor"', "services[0].unit"),
    ('unit = "smbd"', 'unit = "wg-quick@wgnet1"', "services[0].unit"),
    ('label = "Samba"', 'label = "<b>"', "services[0].label"),
    ("restart = true", 'restart = "yes"', "services[0].restart"),
    ("restart = true", "restart = true\nextra = 1", "services[0].extra"),
    ('label = "Samba"\nrestart = true', 'label = "Samba"', "services[0].restart"),
])
def test_monitor_invalid(tmp_path, old, new, key):
    bad(tmp_path, tweak(old, new, MONITOR), *([key] if key else []),
        loader=config.load_monitor, name="monitor.toml")


# ---- backups.toml

def test_load_backups(tmp_path):
    c = config.load_backups(write(tmp_path, BACKUPS, "backups.toml"))
    assert c["destination_root"] == "/srv/nas2/backups"
    assert [t["name"] for t in c["targets"]] == ["omv", "pc"]
    omv, pc = c["targets"]
    assert omv["kind"] == "local" and omv["mac"] is None and omv["shutdown_after_wol"] is False
    assert omv["retention"] == {"daily": 7, "weekly": 4, "monthly": 6}
    assert pc["hosts"] == ["pc.lan", "10.0.0.2"] and pc["user"] == "backup"
    assert pc["mac"] == "aa:bb:cc:dd:ee:ff" and pc["shutdown_after_wol"] is True
    assert config.repo_path(c, "pc") == "/srv/nas2/backups/pc"


def test_categories_allowlist():
    assert config.CATEGORIES == {
        "ssh": {"home", "system-settings", "gnome-settings", "packages", "users", "full-system"},
        "local": {"omv-config", "host-config", "compose", "monitor-data", "nas-data"}}
    assert set(config.CATEGORY_LABELS) >= config.CATEGORIES["ssh"] | config.CATEGORIES["local"]


def test_repo_backups_toml():
    c = config.load_backups(REPO_CFG / "backups.toml")
    t = {x["name"]: x for x in c["targets"]}
    assert set(t) == {"omv", "pc", "laptop"}
    assert t["omv"]["kind"] == "local"
    assert t["pc"]["kind"] == "ssh" and t["pc"]["mac"] and t["pc"]["shutdown_after_wol"] is True
    assert t["laptop"]["kind"] == "ssh" and t["laptop"]["mac"] is None and t["laptop"]["hosts"]


def test_backups_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="backups.toml"):
        config.load_backups(tmp_path / "backups.toml")


@pytest.mark.parametrize("old,new,key", [
    ('interval_h = 24\ncategories = ["omv', 'interval_h = 24\nbogus = 1\ncategories = ["omv', "bogus"),
    ('label = "Server"', "label = 5", "targets.omv.label"),
    ("interval_h = 24\ncategories = [\"omv", "interval_h = 0\ncategories = [\"omv", "targets.omv.interval_h"),
    ("interval_h = 24\ncategories = [\"omv", "interval_h = 721\ncategories = [\"omv", "targets.omv.interval_h"),
    ("daily = 7, weekly = 4, monthly = 6}\n\n[[", "daily = 366, weekly = 4, monthly = 6}\n\n[[", "targets.omv.retention.daily"),
    ("weekly = 4, monthly = 6}\n\n[[", "weekly = 105, monthly = 6}\n\n[[", "targets.omv.retention.weekly"),
    ("monthly = 6}\n\n[[", "monthly = 121}\n\n[[", "targets.omv.retention.monthly"),
    ("enabled = true\ninterval_h = 24\ncategories = [\"omv", 'enabled = "yes"\ninterval_h = 24\ncategories = ["omv', "targets.omv.enabled"),
    ('name = "omv"', 'name = "Bad Name"', "targets.Bad Name.name"),
    ('name = "pc"', 'name = "omv"', "omv"),  # duplicate
    ('mac = "aa:bb:cc:dd:ee:ff"', 'mac = "nonsense"', "targets.pc.mac"),
    ('kind = "local"', 'kind = "local"\nmac = "aa:bb:cc:dd:ee:ff"', "targets.omv.mac"),
    ('categories = ["home", "packages"]', 'categories = ["home", "omv-config"]', "targets.pc.categories"),
    ('categories = ["omv-config", "compose"]', 'categories = ["home"]', "targets.omv.categories"),
    ('categories = ["home", "packages"]', "categories = []", "targets.pc.categories"),
    ('include = ["/home/me"]', 'include = ["home/me"]', "targets.pc.include"),
    ('include = ["/home/me"]', 'include = ["/home/../etc"]', "targets.pc.include"),
    ('exclude = ["/var/tmp/*"]', 'exclude = ["tmp/*"]', "targets.omv.exclude"),
    ('destination_root = "/srv/nas2/backups"', 'destination_root = "backups"', "destination_root"),
    ('destination_root = "/srv/nas2/backups"', 'destination_root = "/srv/../etc"', "destination_root"),
    ('destination_root = "/srv/nas2/backups"', "destination_root = 3", "destination_root"),
    ('hosts = ["pc.lan", "10.0.0.2"]', "hosts = []", "targets.pc.hosts"),
])
def test_backups_invalid(tmp_path, old, new, key):
    bad(tmp_path, tweak(old, new), key)


def test_backups_bad_toml_and_missing_user(tmp_path):
    bad(tmp_path, "destination_root = ", "")
    bad(tmp_path, tweak('user = "backup"\n', ""), "targets.pc.user")


# ---- overrides

@pytest.fixture
def cfg(tmp_path):
    return config.load_backups(write(tmp_path, BACKUPS, "backups.toml"))


def test_validate_overrides_ok(cfg):
    ov = {"destination_root": "/mnt/other",
          "targets": {"pc": {"enabled": False, "interval_h": 12, "categories": ["home"],
                             "include": ["/home/me/docs"], "exclude": ["*.iso"],
                             "retention": {"daily": 3, "weekly": 2, "monthly": 1}}}}
    clean, errors = config.validate_backup_overrides(cfg, ov)
    assert errors == [] and clean == ov


@pytest.mark.parametrize("target,key,value", [
    ("pc", "interval_h", 0),
    ("pc", "interval_h", "12"),
    ("pc", "enabled", "yes"),
    ("pc", "categories", ["omv-config"]),
    ("pc", "categories", []),
    ("pc", "include", ["relative"]),
    ("pc", "include", ["/a/../b"]),
    ("pc", "include", ["/a\nb"]),
    ("pc", "include", ["/a\0b"]),
    ("pc", "include", ["/a"] * 51),
    ("pc", "exclude", ["rel/path"]),
    ("pc", "retention", {"daily": 400, "weekly": 1, "monthly": 1}),
    ("omv", "categories", ["home"]),
    ("pc", "hosts", ["evil"]),
    ("pc", "mac", "aa:bb:cc:dd:ee:00"),
    ("pc", "user", "root"),
    ("pc", "kind", "local"),
    ("pc", "label", "x"),
])
def test_validate_overrides_rejects(cfg, target, key, value):
    clean, errors = config.validate_backup_overrides(cfg, {"targets": {target: {key: value}}})
    assert len(errors) == 1 and errors[0].startswith(f"targets.{target}.{key}")
    assert key not in clean.get("targets", {}).get(target, {})


def test_validate_overrides_unknown_target_and_root(cfg):
    _, errors = config.validate_backup_overrides(cfg, {"targets": {"nope": {"enabled": True}}})
    assert errors and "targets.nope" in errors[0]
    _, errors = config.validate_backup_overrides(cfg, {"destination_root": "rel"})
    assert errors and errors[0].startswith("destination_root")
    _, errors = config.validate_backup_overrides(cfg, {"destination_root": "/a/../b"})
    assert errors


def test_merged_backups(tmp_path):
    base = write(tmp_path, BACKUPS, "backups.toml")
    ovp = tmp_path / "backup-overrides.json"
    # missing overrides file -> plain defaults
    assert config.merged_backups(base, ovp) == config.load_backups(base)
    ovp.write_text(json.dumps({"destination_root": "/mnt/other",
                               "targets": {"pc": {"interval_h": 6, "categories": ["users"]}}}))
    m = config.merged_backups(base, ovp)
    pc = {t["name"]: t for t in m["targets"]}["pc"]
    assert m["destination_root"] == "/mnt/other" and config.repo_path(m, "pc") == "/mnt/other/pc"
    assert pc["interval_h"] == 6 and pc["categories"] == ["users"]
    assert pc["hosts"] == ["pc.lan", "10.0.0.2"] and pc["include"] == ["/home/me"]  # untouched keys keep defaults
    assert [t["name"] for t in m["targets"]] == ["omv", "pc"]


@pytest.mark.parametrize("content,key", [
    ("{not json", None),
    (json.dumps({"targets": {"pc": {"mac": "aa:bb:cc:dd:ee:00"}}}), "targets.pc.mac"),
    (json.dumps({"targets": {"pc": {"interval_h": 0}}}), "targets.pc.interval_h"),
])
def test_merged_backups_bad_overrides(tmp_path, content, key):
    base = write(tmp_path, BACKUPS, "backups.toml")
    ovp = tmp_path / "backup-overrides.json"
    ovp.write_text(content)
    with pytest.raises(ConfigError) as e:
        config.merged_backups(base, ovp)
    assert "backup-overrides.json" in str(e.value) and (key is None or key in str(e.value))


def test_save_backup_overrides(tmp_path, monkeypatch):
    p = tmp_path / "data" / "backup-overrides.json"
    p.parent.mkdir()
    ov = {"targets": {"pc": {"interval_h": 6}}}
    config.save_backup_overrides(p, ov)
    assert json.loads(p.read_text()) == ov
    assert (p.stat().st_mode & 0o777) == 0o640
    assert [f.name for f in p.parent.iterdir()] == ["backup-overrides.json"]
    # a failure while replacing leaves the old file intact and no tmp behind
    def boom(*a, **k):
        raise OSError("disk")
    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        config.save_backup_overrides(p, {"targets": {"pc": {"interval_h": 9}}})
    assert json.loads(p.read_text()) == ov
    assert [f.name for f in p.parent.iterdir()] == ["backup-overrides.json"]
