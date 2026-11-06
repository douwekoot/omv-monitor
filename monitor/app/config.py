"""Strict loaders for config/monitor.toml and config/backups.toml plus backup overrides.

Stdlib only: host scripts import this file too. Nothing here falls back silently;
every problem raises ConfigError (or is listed by validate_backup_overrides).
"""
import json
import os
import re
import tempfile
import tomllib
from pathlib import Path

THRESHOLD_DEFAULTS = {"disk_pct": 85, "handshake_stale_s": 604800, "backup_age_h": 36}
THRESHOLD_RANGES = {"disk_pct": (50, 99), "handshake_stale_s": (60, 604800), "backup_age_h": (1, 720)}
_RETENTION_RANGES = {"daily": (0, 365), "weekly": (0, 104), "monthly": (0, 120)}

CATEGORY_LABELS = {
    "home": "Home files",
    "system-settings": "System settings (/etc)",
    "gnome-settings": "GNOME settings (dconf dump)",
    "packages": "Installed packages (dnf/flatpak lists)",
    "users": "Users and groups",
    "full-system": "Full system",
    "omv-config": "OMV config",
    "host-config": "Host config",
    "compose": "Compose stacks",
    "monitor-data": "Wiki, settings and Prometheus",
    "nas-data": "NAS data",
}
CATEGORIES = {
    "ssh": {"home", "system-settings", "gnome-settings", "packages", "users", "full-system"},
    "local": {"omv-config", "host-config", "compose", "monitor-data", "nas-data"},
}
OVERRIDABLE = ("enabled", "interval_h", "categories", "include", "exclude", "retention")

_NAME = re.compile(r"[a-z0-9-]+")
_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*")  # no leading '-': never an ssh option
_USER = re.compile(r"[a-z_][a-z0-9_-]*")
_MAC = re.compile(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}")
_PROM = re.compile(r"[1-9][0-9]*[smhdwy]")
_UNIT = re.compile(r"[a-z0-9][a-z0-9@._-]{0,63}")  # systemd unit or container name; no leading '-'
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()-]{0,39}")
RESERVED_UNITS = ("omv-monitor",)  # the helper restarts it with docker compose, not from this list


class ConfigError(ValueError):
    pass


class _Bad(ValueError):
    """A value problem; .key is the dotted key relative to the section."""

    def __init__(self, key, msg):
        super().__init__(msg)
        self.key, self.msg = key, msg


def _int(key, v, lo, hi):
    if type(v) is not int or not lo <= v <= hi:
        raise _Bad(key, f"not an integer from {lo} to {hi}")
    return v


def _bool(key, v):
    if type(v) is not bool:
        raise _Bad(key, "not true or false")
    return v


def _str(key, v, rx=None):
    if not isinstance(v, str) or not v or (rx and not rx.fullmatch(v)):
        raise _Bad(key, "not a valid value")
    return v


def _path(key, v, glob=False):
    ok = isinstance(v, str) and v and not re.search(r"[\n\r\0]", v) and ".." not in v.split("/")
    if not ok or not (v.startswith("/") or (glob and "/" not in v)):
        raise _Bad(key, "not an absolute path without '..'")
    return v


def _paths(key, v, glob=False):
    if not isinstance(v, list) or len(v) > 50:
        raise _Bad(key, "not a list of at most 50 paths")
    return [_path(key, p, glob) for p in v]


def _target_field(key, v, kind, partial=False):
    """Validate one overridable target key; partial allows a subset of retention keys."""
    if key == "enabled":
        return _bool(key, v)
    if key == "interval_h":
        return _int(key, v, 1, 720)
    if key == "categories":
        if (not isinstance(v, list) or not v
                or any(not isinstance(c, str) or c not in CATEGORIES[kind] for c in v)):
            raise _Bad(key, f"must be a non-empty list from {sorted(CATEGORIES[kind])}")
        return list(dict.fromkeys(v))
    if key == "include":
        return _paths(key, v)
    if key == "exclude":
        return _paths(key, v, glob=True)
    if key == "retention":
        if not isinstance(v, dict) or set(v) - set(_RETENTION_RANGES) or (
                not partial and set(v) != set(_RETENTION_RANGES)):
            raise _Bad(key, "must have keys daily, weekly, monthly")
        return {k: _int(f"retention.{k}", n, *_RETENTION_RANGES[k]) for k, n in v.items()}
    raise _Bad(key, "not overridable")


def _root(v):
    v = _path("destination_root", v)
    return v.rstrip("/") or "/"


def _read_toml(path):
    path = Path(path)
    try:
        with open(path, "rb") as f:
            return path.name, tomllib.load(f)
    except OSError as e:
        raise ConfigError(f"{path.name}: cannot read: {e.strerror or e}") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path.name}: bad TOML: {e}") from None


def _table(name, d, allowed, prefix=""):
    if not isinstance(d, dict):
        raise ConfigError(f"{name}: {prefix.rstrip('.') or 'top level'}: not a table")
    for k in d:
        if k not in allowed:
            raise ConfigError(f"{name}: {prefix}{k}: unknown key")
    for k in allowed:
        if k not in d:
            raise ConfigError(f"{name}: {prefix}{k}: missing")


def _services(name, v):
    """[[services]]: unit, label, restart. The root helper's restart allowlist comes from here."""
    if not isinstance(v, list) or not 1 <= len(v) <= 20:
        raise ConfigError(f"{name}: services: must be a list of 1 to 20 [[services]] tables")
    out = []
    for i, s in enumerate(v):
        pre = f"services[{i}]."
        _table(name, s, ("unit", "label", "restart"), pre)
        try:
            unit = _str("unit", s["unit"], _UNIT)
            if unit in RESERVED_UNITS or unit.startswith("wg-quick@") or unit in (o["unit"] for o in out):
                raise _Bad("unit", "duplicate or reserved")
            label = _str("label", s["label"], _LABEL)
            out.append({"unit": unit, "label": label, "restart": _bool("restart", s["restart"])})
        except _Bad as e:
            raise ConfigError(f"{name}: {pre}{e.key}: {e.msg}") from None
    return out


def restart_units(svcs, iface):
    """unit -> label of every restartable unit. The Network page offers these and omv-netctl allows exactly these."""
    return {f"wg-quick@{iface}": "WireGuard", **{s["unit"]: s["label"] for s in svcs if s["restart"]},
            "omv-monitor": "Monitor (this page)"}


def load_monitor(path):
    name, raw = _read_toml(path)
    _table(name, raw, ("thresholds", "retention", "services"))
    _table(name, raw["thresholds"], THRESHOLD_DEFAULTS, "thresholds.")
    _table(name, raw["retention"], ("alert_history_days", "prometheus"), "retention.")
    try:
        th = {k: _int(f"thresholds.{k}", raw["thresholds"][k], *THRESHOLD_RANGES[k]) for k in THRESHOLD_DEFAULTS}
        r = raw["retention"]
        ret = {"alert_history_days": _int("retention.alert_history_days", r["alert_history_days"], 1, 3650),
               "prometheus": _str("retention.prometheus", r["prometheus"], _PROM)}
    except _Bad as e:
        raise ConfigError(f"{name}: {e.key}: {e.msg}") from None
    return {"thresholds": th, "retention": ret, "services": _services(name, raw["services"])}


_TARGET_KEYS = ("name", "label", "kind", "hosts", "user", "mac", "shutdown_after_wol", *OVERRIDABLE)
_TARGET_REQUIRED = ("name", "label", "kind", "interval_h", "categories", "retention")
_SSH_ONLY = ("hosts", "user", "mac", "shutdown_after_wol")


def _target(t):
    if not isinstance(t, dict):
        raise _Bad("targets", "not a table")
    n = t.get("name")
    pre = f"targets.{n if isinstance(n, str) else '?'}"
    try:
        for k in t:
            if k not in _TARGET_KEYS:
                raise _Bad(k, "unknown key")
        for k in _TARGET_REQUIRED:
            if k not in t:
                raise _Bad(k, "missing")
        _str("name", n, _NAME)
        _str("label", t["label"])
        kind = t["kind"]
        if kind not in CATEGORIES:
            raise _Bad("kind", "must be local or ssh")
        out = {"name": n, "label": t["label"], "kind": kind, "hosts": [], "user": "", "mac": None,
               "shutdown_after_wol": False, "enabled": True, "include": [], "exclude": []}
        for k in _SSH_ONLY:
            if k in t and kind != "ssh":
                raise _Bad(k, "only allowed for ssh targets")
        if kind == "ssh":
            hosts = t.get("hosts")
            if not isinstance(hosts, list) or not hosts:
                raise _Bad("hosts", "must be a non-empty list")
            out["hosts"] = [_str("hosts", h, _HOST) for h in hosts]
            out["user"] = _str("user", t.get("user"), _USER)
            if t.get("mac") is not None:
                out["mac"] = _str("mac", t["mac"], _MAC)
            out["shutdown_after_wol"] = _bool("shutdown_after_wol", t.get("shutdown_after_wol", False))
        for k in OVERRIDABLE:
            if k in t:
                out[k] = _target_field(k, t[k], kind)
        return out
    except _Bad as e:
        raise _Bad(f"{pre}.{e.key}" if e.key != "targets" else pre, e.msg) from None


def load_backups(path):
    name, raw = _read_toml(path)
    try:
        for k in raw:
            if k not in ("destination_root", "targets"):
                raise _Bad(k, "unknown key")
        if "destination_root" not in raw:
            raise _Bad("destination_root", "missing")
        root = _root(raw["destination_root"])
        if not isinstance(raw.get("targets"), list) or not raw["targets"]:
            raise _Bad("targets", "must be a non-empty list of [[targets]]")
        targets, seen = [], set()
        for t in raw["targets"]:
            t = _target(t)
            if t["name"] in seen:
                raise _Bad(f"targets.{t['name']}", "duplicate target name")
            seen.add(t["name"])
            targets.append(t)
    except _Bad as e:
        raise ConfigError(f"{name}: {e.key}: {e.msg}") from None
    return {"destination_root": root, "targets": targets}


def repo_path(cfg, name):
    return f"{cfg['destination_root']}/{name}"


def validate_backup_overrides(cfg, overrides):
    """Return (clean, errors); invalid values are dropped from clean."""
    clean, errors = {}, []
    if not isinstance(overrides, dict):
        return clean, ["overrides: not an object"]
    kinds = {t["name"]: t["kind"] for t in cfg["targets"]}
    for k, v in overrides.items():
        if k == "destination_root":
            try:
                clean[k] = _root(v)
            except _Bad as e:
                errors.append(f"{k}: {e.msg}")
        elif k == "targets" and isinstance(v, dict):
            for n, fields in v.items():
                if n not in kinds or not isinstance(fields, dict):
                    errors.append(f"targets.{n}: unknown target or not an object")
                    continue
                for fk, fv in fields.items():
                    try:
                        if fk not in OVERRIDABLE:
                            raise _Bad(fk, "not overridable")
                        val = _target_field(fk, fv, kinds[n], partial=True)
                        clean.setdefault("targets", {}).setdefault(n, {})[fk] = val
                    except _Bad as e:
                        errors.append(f"targets.{n}.{e.key}: {e.msg}")
        else:
            errors.append(f"{k}: unknown key")
    return clean, errors


def merged_backups(path, overrides_path):
    cfg = load_backups(path)
    overrides_path = Path(overrides_path)
    try:
        raw = json.loads(overrides_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return cfg
    except (OSError, ValueError) as e:
        raise ConfigError(f"{overrides_path.name}: unreadable: {e}") from None
    clean, errors = validate_backup_overrides(cfg, raw)
    if errors:
        raise ConfigError(f"{overrides_path.name}: " + "; ".join(errors))
    cfg["destination_root"] = clean.get("destination_root", cfg["destination_root"])
    for t in cfg["targets"]:
        for k, v in clean.get("targets", {}).get(t["name"], {}).items():
            t[k] = {**t[k], **v} if k == "retention" else v
    return cfg


def save_backup_overrides(path, overrides):
    """Atomic write; callers validate first with validate_backup_overrides."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(overrides, f, indent=2)
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
