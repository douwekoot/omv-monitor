"""Offline preview of the monitor app with canned data. Makes no network or process calls.

Run: .venv/bin/python tools/preview_sandbox.py  ->  http://127.0.0.1:8100, password "preview".
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "monitor"))
from app.prom import PromClient  # noqa: E402
from app import totp  # noqa: E402
from app.web import create_app  # noqa: E402


def vec(value, **labels):
    return {"metric": labels, "value": [1700000000, str(value)]}


def mat(values, **labels):
    return {"metric": labels, "values": [[t, str(v)] for t, v in values]}


_WG = lambda peer, ips: {"interface": "wgnet1", "peer": peer, "allowed_ips": ips}  # noqa: E731
_P1, _P2 = _WG("aaaaaaaa", "10.8.0.2/32"), _WG("bbbbbbbb", "10.8.0.1/32")
_DEVS = ("enp2s0", "wgnet1", "lo", "veth1a2b", "docker0", "br-abc123")
_SERIES = [mat([(1700000000, 5), (1700000015, 6)])]

DATA = {
    "omv_wg_latest_handshake_timestamp_seconds": [vec(1700000100, **_P1), vec(1700000200, **_P2)],
    "omv_wg_received_bytes_total": [vec(1000, **_P1), vec(2000, **_P2)],
    "omv_wg_sent_bytes_total": [vec(3000, **_P1), vec(4000, **_P2)],
    "node_network_up": [vec(1, device="enp2s0"), vec(0, device="wgnet1"), vec(1, device="lo"),
                        vec(1, device="veth1a2b"), vec(1, device="docker0"), vec(1, device="br-abc123")],
    "node_network_carrier": [vec(1, device=d) for d in _DEVS] + [vec(0, device="eth9")],
    "node_network_receive_bytes_total": [vec(111, device=d) for d in _DEVS],
    "node_network_transmit_bytes_total": [vec(222, device=d) for d in _DEVS],
    "rate(node_network_receive_bytes_total": [vec(10, device=d) for d in _DEVS],
    "rate(node_network_transmit_bytes_total": [vec(20, device=d) for d in _DEVS],
    "omv_service_active": [vec(1, service="smbd"), vec(0, service="nginx"), vec(1, service="cron")],
    "probe_success": [vec(1, job="ping", instance="1.1.1.1"), vec(0, job="ping", instance="192.168.1.1"),
                      vec(1, job="dns", instance="1.1.1.1")],
    "probe_duration_seconds": [vec(0.02, job="ping", instance="1.1.1.1"),
                               vec(0.5, job="ping", instance="192.168.1.1"),
                               vec(0.03, job="dns", instance="1.1.1.1")],
    "omv_ip_forward": [vec(1)],
    "omv_nat_masquerade": [vec(1)],
    "omv_input_policy_accept": [vec(0)],
}
RANGES = {
    "rate(node_network_receive_bytes_total": _SERIES,
    "rate(node_network_transmit_bytes_total": _SERIES,
    "omv_wg_received_bytes_total": _SERIES,
    "omv_wg_sent_bytes_total": _SERIES,
    "omv_service_active": _SERIES,
    "probe_success": _SERIES,
    "probe_duration_seconds": _SERIES,
    "avg_over_time(omv_service_active": [mat([(1700000000, 1), (1700000900, 0.5)], service="smbd")],
}


def _match(table, expr):
    keys = [k for k in table if k in expr]
    return table[max(keys, key=len)] if keys else []


class CannedProm(PromClient):
    """Answers every query from the canned tables above; never touches the network."""

    def _get(self, path, params):
        expr = params.get("query", "")
        return _match(RANGES if path.endswith("query_range") else DATA, expr)


def build_app(settings_file=None):
    settings = settings_file or str(Path(tempfile.gettempdir()) / "omv-preview-settings.json")
    totp_file = Path(settings).parent / "totp.json"
    if not totp_file.exists():  # fixed secret so the sandbox login is scriptable
        totp.save(totp_file, {"secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "last_step": None, "recovery": []})
    return create_app({"ADMIN_PASSWORD": "preview", "SECRET_KEY": "preview", "TOTP_FILE": str(totp_file),
                       "WIKI_DIR": str(ROOT / "monitor/wiki"),
                       "DEVICES_FILE": str(ROOT / "monitor/config/devices.toml"),
                       "SETTINGS_FILE": settings, "NETCTL_SOCKET": None},  # actions disabled
                      prom_client=CannedProm())


if __name__ == "__main__":
    build_app().run(host="127.0.0.1", port=8100)
