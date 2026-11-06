import json
import re
import tempfile
import time
from pathlib import Path

import pytest

TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
HTTPS = "https://localhost"


def enroll(path, secret=TOTP_SECRET, recovery=(), last_step=None):
    """Write an enrolled TOTP state file (recovery = plaintext codes, stored as sha256)."""
    import hashlib
    Path(path).write_text(json.dumps({"secret": secret, "last_step": last_step,
                                      "recovery": [hashlib.sha256(c.encode()).hexdigest() for c in recovery]}))
    Path(path).chmod(0o600)


def totp_cfg(tmp_path=None):
    """Config fragment with an enrolled TOTP_FILE (fresh temp dir if no tmp_path given)."""
    d = Path(tmp_path) if tmp_path else Path(tempfile.mkdtemp())
    enroll(d / "totp.json")
    return {"TOTP_FILE": str(d / "totp.json")}


@pytest.fixture(autouse=True)
def _tmp_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_AUDIT_FILE", str(tmp_path / "audit.jsonl"))  # never write the repo's audit log


def csrf_of(html):
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*name="csrf_token"', html)
    return m.group(1) or m.group(2)


def login(client, pw="pw", secret=TOTP_SECRET, now=None):
    """Finish password + TOTP login against an app built with an enrolled TOTP_FILE."""
    from app import totp
    t = csrf_of(client.get("/login", base_url=HTTPS).get_data(as_text=True))
    client.post("/login", data={"password": pw, "csrf_token": t}, base_url=HTTPS)
    t = csrf_of(client.get("/login/totp", base_url=HTTPS).get_data(as_text=True))
    code = totp.code_at(secret, time.time() if now is None else now)
    client.post("/login/totp", data={"code": code, "csrf_token": t}, base_url=HTTPS)
    return client


class FakeProm:
    """Fake client: an expr is answered by the longest registered key it contains."""

    def __init__(self, data=None, ranges=None):
        self.data = data or {}
        self.ranges = ranges or {}
        self.calls = []

    def _match(self, table, expr):
        keys = [k for k in table if k in expr]
        return table[max(keys, key=len)] if keys else []

    def query(self, expr):
        self.calls.append(expr)
        return self._match(self.data, expr)

    def query_range(self, expr, start, end, step):
        self.calls.append(expr)
        return self._match(self.ranges, expr)


class FakeNetctl:
    """Fake host-helper client: records calls; responses maps action -> dict result or Exception."""

    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def call(self, action, **args):
        self.calls.append((action, args))
        r = self.responses.get(action, {})
        if isinstance(r, Exception):
            raise r
        if action in ("peer-set", "peer-disable", "peer-enable", "restore") and "pending" not in r:
            # real helper shape (omv-netctl _wg_change): {"pending": {id, expires_at}, "snapshot": sid}
            return {"pending": r, "snapshot": "0123456789ab"}
        return r


def vec(value, **labels):
    return {"metric": labels, "value": [1700000000, str(value)]}


def mat(values, **labels):
    return {"metric": labels, "values": [[t, str(v)] for t, v in values]}


@pytest.fixture
def fake():
    wg = lambda peer, ips: {"interface": "wgnet1", "peer": peer, "allowed_ips": ips}
    p1, p2 = wg("aaaaaaaa", "10.8.0.2/32"), wg("bbbbbbbb", "10.8.0.1/32")
    data = {
        "omv_wg_latest_handshake_timestamp_seconds": [vec(1700000100, **p1), vec(1700000200, **p2)],
        "omv_wg_received_bytes_total": [vec(1000, **p1), vec(2000, **p2)],
        "omv_wg_sent_bytes_total": [vec(3000, **p1), vec(4000, **p2)],
        # Real host: wgnet1 has operstate "unknown", so node_network_up is 0 while carrier is 1.
        "node_network_up": [vec(1, device="enp2s0"), vec(0, device="wgnet1"), vec(1, device="lo"),
                            vec(1, device="veth1a2b"), vec(1, device="docker0"), vec(1, device="br-abc123")],
        "node_network_carrier": [vec(1, device="enp2s0"), vec(1, device="wgnet1"), vec(1, device="lo"),
                                 vec(1, device="veth1a2b"), vec(1, device="docker0"),
                                 vec(1, device="br-abc123"), vec(0, device="eth9")],
        "node_network_receive_bytes_total": [vec(111, device=d) for d in
                                             ("enp2s0", "wgnet1", "lo", "veth1a2b", "docker0", "br-abc123")],
        "node_network_transmit_bytes_total": [vec(222, device=d) for d in
                                              ("enp2s0", "wgnet1", "lo", "veth1a2b", "docker0", "br-abc123")],
        "rate(node_network_receive_bytes_total": [vec(10, device=d) for d in
                                                  ("enp2s0", "wgnet1", "lo", "veth1a2b", "docker0", "br-abc123")],
        "rate(node_network_transmit_bytes_total": [vec(20, device=d) for d in
                                                   ("enp2s0", "wgnet1", "lo", "veth1a2b", "docker0", "br-abc123")],
        "omv_service_active": [vec(1, service="smbd"), vec(0, service="nginx"), vec(1, service="ssh")],
        "probe_success": [vec(1, job="ping", instance="1.1.1.1"), vec(0, job="ping", instance="192.168.1.1"),
                          vec(1, job="dns", instance="1.1.1.1")],
        "probe_duration_seconds": [vec(0.02, job="ping", instance="1.1.1.1"),
                                   vec(0.5, job="ping", instance="192.168.1.1"),
                                   vec(0.03, job="dns", instance="1.1.1.1")],
        "omv_ip_forward": [vec(1)],
        "omv_nat_masquerade": [vec(1)],
        "omv_input_policy_accept": [vec(0)],
        "omv_ssh_password_auth": [vec(0)],
        "omv_smart_healthy": [vec(1, device="sda"), vec(1, device="sdb")],
        "omv_container_running": [vec(1, name="minidlna"), vec(0, name="pihole")],
        "omv_cert_expiry_timestamp_seconds": [vec(4102444800)],  # year 2100
    }
    series = [mat([(1700000000, 5), (1700000015, 6)])]
    ranges = {
        "rate(node_network_receive_bytes_total": series,
        "rate(node_network_transmit_bytes_total": series,
        "omv_wg_received_bytes_total": series,
        "omv_wg_sent_bytes_total": series,
        "omv_service_active": series,
        "probe_success": series,
        "probe_duration_seconds": series,
        "avg_over_time(omv_service_active": [mat([(1700000000, 1), (1700000900, 0.5)], service="smbd")],
    }
    return FakeProm(data, ranges)
