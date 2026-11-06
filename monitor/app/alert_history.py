"""Alert history: one JSON object per line, raised/cleared events (stdlib only; host scripts import it)."""
import json
import os
import tempfile
import time
from pathlib import Path

DAY = 86400


def record(path, events):
    if not events:
        return
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.writelines(json.dumps(e) + "\n" for e in events)


def _events(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            e = json.loads(ln)
        except ValueError:
            continue
        if isinstance(e, dict):
            out.append(e)
    return out


def read(path, sev=None, limit=500):
    """Newest first; shortcut: whole file is read, fine for 90 days of events."""
    rows = [e for e in _events(path) if sev is None or e.get("sev") == sev]
    return sorted(rows, key=lambda e: e.get("ts", 0), reverse=True)[:limit]


def prune(path, keep_days, now=None):
    if not Path(path).exists():
        return
    cutoff = (time.time() if now is None else now) - keep_days * DAY
    keep = [e for e in _events(path) if isinstance(e.get("ts"), (int, float)) and e["ts"] >= cutoff]
    fd, tmp = tempfile.mkstemp(dir=Path(path).parent, prefix=".alert-history.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.writelines(json.dumps(e) + "\n" for e in keep)
        os.chmod(tmp, 0o644)  # mkstemp makes it 0600; the web user must read it
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def active(path):
    """{(rule, title): sev} still raised: the latest event for each item is a 'raised'."""
    state = {}
    for e in _events(path):
        k = (e.get("rule"), e.get("title"))
        if e.get("event") == "raised":
            state[k] = e.get("sev")
        else:
            state.pop(k, None)
    return state
