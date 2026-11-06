import json
import time
from pathlib import Path


def record(path, action, args, ok, detail, remote_addr):
    """Append one audit line. Callers must never pass private keys or client configs."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    line = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "user": "admin", "remote_addr": remote_addr,
            "action": action, "args": args, "ok": ok, "detail": detail}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")


CHUNK = 8192


def recent(path, n=50):
    out = []
    try:
        with open(path, "rb") as f:
            pos = f.seek(0, 2)
            buf = b""
            while pos > 0 and len(out) < n:
                size = min(CHUNK, pos)
                pos -= size
                f.seek(pos)
                buf = f.read(size) + buf
                lines = buf.split(b"\n")
                # the first piece may be cut by the chunk boundary; keep it until the start is reached
                buf = lines[0] if pos > 0 else b""
                for ln in reversed(lines[1:] if pos > 0 else lines):
                    if len(out) == n:
                        break
                    try:
                        e = json.loads(ln.decode("utf-8", errors="replace"))
                    except ValueError:
                        continue
                    if isinstance(e, dict):
                        out.append(e)
    except OSError:
        return []
    return out
