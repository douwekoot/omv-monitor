"""TOTP (RFC 6238, SHA1, 6 digits, 30 s) and one-time recovery codes, stdlib only."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

STEP = 30


def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode()


def code_at(secret, t):
    key = base64.b32decode(secret.upper())
    mac = hmac.new(key, struct.pack(">Q", int(t // STEP)), hashlib.sha1).digest()
    o = mac[-1] & 15
    return f"{(struct.unpack('>I', mac[o:o + 4])[0] & 0x7FFFFFFF) % 10**6:06d}"


def verify(secret, code, now, last_step):
    """Matched step for a code within +-1 step, or None; steps <= last_step are replays."""
    code = (code or "").strip().replace(" ", "")
    step = int(now // STEP)
    for s in (step, step - 1, step + 1):
        if (last_step is None or s > last_step) and hmac.compare_digest(code_at(secret, s * STEP).encode(), code.encode()):
            return s
    return None


def otpauth_uri(secret, account="admin", issuer="omv-monitor"):
    return f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}"


def new_recovery_codes(n=10):
    return [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(n)]


def load(path):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return None  # a corrupt file raises on purpose: fail closed rather than re-offer setup


def save(path, state):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".totp-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
