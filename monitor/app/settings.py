"""Local, dashboard-only display settings (never touches host configuration)."""
import json
import os
import tempfile
from pathlib import Path

from .config import THRESHOLD_DEFAULTS, THRESHOLD_RANGES

PANELS = ("traffic", "peers", "interfaces", "services", "checks", "disks", "containers", "backups", "updates")

DEFAULTS = {
    "default_range": "24h",
    "refresh_s": 0,
    "byte_units": "binary",
    "handshake_good_s": 180,
    "panels": list(PANELS),
    "thresholds": {},  # overrides of config.THRESHOLD_DEFAULTS
}

_RANGES = ("24h", "7d")
_REFRESH = (0, 30, 60, 300)
_UNITS = ("binary", "decimal")


def _int(value):
    if isinstance(value, bool):
        raise ValueError
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        digits = value.strip()
        if not (digits.isascii() and digits.isdigit()):
            raise ValueError
        return int(digits)
    raise ValueError


def _check(key, value):
    """Return the clean value for key or raise ValueError."""
    if key == "default_range":
        if value in _RANGES:
            return value
    elif key == "refresh_s":
        if _int(value) in _REFRESH:
            return _int(value)
    elif key == "byte_units":
        if value in _UNITS:
            return value
    elif key == "handshake_good_s":
        n = _int(value)
        if 30 <= n <= 3600:
            return n
    elif key == "panels":
        if isinstance(value, (list, tuple)) and all(
            isinstance(p, str) and p in PANELS for p in value
        ):
            return list(dict.fromkeys(value))
    raise ValueError(key)


def _thresholds(value):
    if not isinstance(value, dict):
        return {}, ["invalid value for thresholds"]
    out, errors = {}, []
    for k, v in value.items():
        if k not in THRESHOLD_DEFAULTS:
            continue
        try:
            n = _int(v)
            if not THRESHOLD_RANGES[k][0] <= n <= THRESHOLD_RANGES[k][1]:
                raise ValueError
            out[k] = n
        except ValueError:
            errors.append(f"invalid value for thresholds.{k}: {v!r}")
    return out, errors


def thresholds(values, defaults):
    return {**defaults, **values.get("thresholds", {})}


def validate(raw):
    clean = {k: (v.copy() if isinstance(v, (list, dict)) else v) for k, v in DEFAULTS.items()}
    errors = []
    if not isinstance(raw, dict):
        return clean, ["settings must be an object"]
    for key, value in raw.items():
        if key not in DEFAULTS:
            continue
        if key == "thresholds":
            clean[key], errs = _thresholds(value)
            errors += errs
            continue
        try:
            clean[key] = _check(key, value)
        except (ValueError, TypeError):
            errors.append(f"invalid value for {key}: {value!r}")
    return clean, errors


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        raw = {}
    return validate(raw)[0]


def save(path, values):
    clean, errors = validate(values)
    if errors:
        raise ValueError("; ".join(errors))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=2)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return clean


def from_form(form):
    raw = {}
    for key in ("default_range", "refresh_s", "byte_units", "handshake_good_s"):
        if key in form:
            raw[key] = form[key]
    if "reset_thresholds" in form:
        raw["thresholds"] = {}
    else:
        t = {k: str(form[k]).strip() for k in THRESHOLD_DEFAULTS if k in form}
        if t:  # an empty field means no override
            raw["thresholds"] = {k: v for k, v in t.items() if v}
    # The form sends a hidden empty "panels" value so that unticking every box
    # is still submitted; drop that marker before validating.
    if hasattr(form, "getlist"):
        panels = form.getlist("panels")
    elif "panels" in form:
        p = form["panels"]
        panels = [p] if isinstance(p, str) else list(p)
    else:
        return raw
    raw["panels"] = [p for p in panels if p]
    return raw
