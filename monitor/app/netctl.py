import json
import socket


class NetctlError(Exception):
    pass


class NetctlClient:
    """Talks to the host helper over a unix socket: one json line out, one json line back."""

    def __init__(self, path):
        self.path = path

    def call(self, action, **args):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(70)
                s.connect(self.path)
                s.sendall(json.dumps({"action": action, "args": args}).encode() + b"\n")
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
            reply = json.loads(buf)
            ok = reply["ok"]
        except (OSError, ValueError, KeyError, TypeError):
            raise NetctlError("host helper unavailable") from None
        if not ok:
            raise NetctlError(str(reply.get("error", "failed")))
        return reply.get("result")
