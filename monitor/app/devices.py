import json
import os
import tempfile
import tomllib
from pathlib import Path


def peer_label(public_key):
    """The `peer` label omv-wg-metrics.sh puts on each series: first 8 key chars, "/" -> "_", "+" -> "-" (idempotent)."""
    return public_key[:8].replace("/", "_").replace("+", "-")


def read_overrides(path):
    """{public_key or allowed_ips: name} from the JSON override file; missing or garbled -> {}."""
    if not path:
        return {}
    try:
        d = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in d.items() if isinstance(k, str) and isinstance(v, str)} if isinstance(d, dict) else {}


def save_override(path, public_key, name):
    """Set one name (keyed by peer_label, the dashboard label; survives allowed_ips changes) in the override file, atomically (tempfile + os.replace, like settings.save)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    names = {**read_overrides(path), peer_label(public_key): name}
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(names, f, indent=2)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_devices(path, overrides=None):
    try:
        with open(path, "rb") as f:
            devices = dict(tomllib.load(f).get("devices", {}))
    except FileNotFoundError:
        devices = {}
    return {**devices, **read_overrides(overrides)}


def device_name(allowed_ips, devices, public_key=None):
    # label first (also given a bare label by the dashboard); full key = legacy entries
    return (public_key and (devices.get(peer_label(public_key)) or devices.get(public_key))) or devices.get(allowed_ips, allowed_ips)
