import re
import time

from .devices import device_name

WG_IF = "wgnet1"
POSTURE = {"ip_forward": "omv_ip_forward", "nat_masquerade": "omv_nat_masquerade",
           "input_policy_accept": "omv_input_policy_accept", "ssh_password_auth": "omv_ssh_password_auth"}
_HIDDEN = re.compile(r"lo|veth.*|docker.*|br-.*")
_SAFE = re.compile(r"[A-Za-z0-9_.:/+=-]+")  # wg peer labels are base64 prefixes, so + / = are allowed


def _num(item):
    return float(item["value"][1])


def _by(items, label):
    return {i["metric"].get(label): _num(i) for i in items}


def _flag(v):
    return None if v is None else v == 1


def _safe(v):
    if not _SAFE.fullmatch(v):
        raise KeyError(v)
    return v


def peers(client, devices):
    rows = {}
    for field, metric in (("last_handshake", "omv_wg_latest_handshake_timestamp_seconds"),
                          ("received", "omv_wg_received_bytes_total"), ("sent", "omv_wg_sent_bytes_total")):
        for i in client.query(metric):
            m = i["metric"]
            r = rows.setdefault(m["peer"], {"id": m["peer"], "device": None, "allowed_ips": m.get("allowed_ips", ""),
                                            "interface": m.get("interface", WG_IF), "last_handshake": None,
                                            "received": 0.0, "sent": 0.0})
            r[field] = _num(i)
    for r in rows.values():
        r["device"] = device_name(r["allowed_ips"], devices, r["id"])
        if not r["last_handshake"]:  # 0 = never handshaken
            r["last_handshake"] = None
    return sorted(rows.values(), key=lambda r: r["device"])


def interfaces(client):
    # carrier, not node_network_up: wgnet1 reports operstate "unknown", so up is 0 there
    carrier = _by(client.query("node_network_carrier"), "device")
    cols = {k: _by(client.query(q), "device") for k, q in (
        ("rx_total", "node_network_receive_bytes_total"), ("tx_total", "node_network_transmit_bytes_total"),
        ("rx_bps", "rate(node_network_receive_bytes_total[1m])"),
        ("tx_bps", "rate(node_network_transmit_bytes_total[1m])"))}
    devs = {d for d in carrier if d} | {d for c in cols.values() for d in c if d}
    return [{"device": d, "up": _flag(carrier.get(d)), **{k: c.get(d) for k, c in cols.items()}}
            for d in sorted(devs) if not _HIDDEN.fullmatch(d)]


def services(client, svcs):
    """One row per [[services]] entry of monitor.toml."""
    got = _by(client.query("omv_service_active"), "service")
    return [{"name": s["unit"], "label": s["label"], "active": _flag(got.get(s["unit"]))} for s in svcs]


def disks(client):
    got = _by(client.query("omv_smart_healthy"), "device")
    return [{"device": d, "healthy": _flag(got[d])} for d in sorted(k for k in got if k)]


def containers(client):
    got = _by(client.query("omv_container_running"), "name")
    return [{"name": n, "running": _flag(got[n])} for n in sorted(k for k in got if k)]


def cert_expiry(client):
    r = client.query("omv_cert_expiry_timestamp_seconds")
    return _num(r[0]) if r else None


def updates(client):
    pending, reboot = client.query("omv_apt_upgrades_pending"), client.query("omv_reboot_required")
    return {"pending": int(_num(pending[0])) if pending else None, "reboot": _flag(_num(reboot[0])) if reboot else None}


_BACKUP_FIELDS = (("last_success", "omv_device_backup_last_success_timestamp_seconds"),
                  ("last_run", "omv_device_backup_last_run_timestamp_seconds"), ("ok", "omv_device_backup_last_ok"),
                  ("size", "omv_device_backup_size_bytes"), ("interval_s", "omv_device_backup_interval_seconds"))


def device_backups(client):
    cols = {f: _by(client.query(m), "target") for f, m in _BACKUP_FIELDS}
    names = sorted({t for c in cols.values() for t in c if t})
    return [{"target": t, **{f: (_flag(c.get(t)) if f == "ok" else c.get(t)) for f, c in cols.items()}} for t in names]


_VIRTUAL_FS = {"tmpfs", "devtmpfs", "overlay", "squashfs", "ramfs", "proc", "sysfs", "cgroup", "cgroup2"}


def filesystems(client):
    def by_mount(metric):
        return {i["metric"].get("mountpoint"): _num(i) for i in client.query(metric)
                if i["metric"].get("fstype") not in _VIRTUAL_FS}
    size, avail = by_mount("node_filesystem_size_bytes"), by_mount("node_filesystem_avail_bytes")
    return [{"mount": m, "used_pct": (s - avail[m]) / s * 100 if s and m in avail else None}
            for m, s in sorted(size.items())]


def checks(client):
    ok = {(i["metric"].get("job"), i["metric"].get("instance")): _num(i) for i in client.query("probe_success")}
    dur = {(i["metric"].get("job"), i["metric"].get("instance")): _num(i) for i in client.query("probe_duration_seconds")}
    return [{"id": f"{j}:{inst}", "job": j, "instance": inst, "success": _flag(ok.get(k)), "duration_s": dur.get(k)}
            for k in sorted(ok.keys() | dur.keys(), key=str) for j, inst in [k]]


def posture(client):
    out = {}
    for k, metric in POSTURE.items():
        r = client.query(metric)
        out[k] = _flag(_num(r[0])) if r else None
    return out


def _range(client, expr, range_s):
    end = time.time()
    return [[(float(t), float(v)) for t, v in s["values"]]
            for s in client.query_range(expr, end - range_s, end, max(15, range_s // 240))]


def _first(client, expr, range_s):
    s = _range(client, expr, range_s)
    return s[0] if s else []


def wg_traffic(client, range_s):
    d = f'device="{WG_IF}"'
    return {"rx": _first(client, f"rate(node_network_receive_bytes_total{{{d}}}[1m])", range_s),
            "tx": _first(client, f"rate(node_network_transmit_bytes_total{{{d}}}[1m])", range_s)}


def history(client, kind, id, range_s, svcs=()):
    if kind not in ("peer", "interface", "service", "check"):
        raise KeyError(kind)
    _safe(id)
    if kind == "peer":
        q = {"received": f'rate(omv_wg_received_bytes_total{{peer="{id}"}}[1m])',
             "sent": f'rate(omv_wg_sent_bytes_total{{peer="{id}"}}[1m])'}
    elif kind == "interface":
        q = {"rx": f'rate(node_network_receive_bytes_total{{device="{id}"}}[1m])',
             "tx": f'rate(node_network_transmit_bytes_total{{device="{id}"}}[1m])'}
    elif kind == "service":
        if id not in {s["unit"] for s in svcs}:
            raise KeyError(id)
        q = {"active": f'omv_service_active{{service="{id}"}}'}
    else:
        job, sep, inst = id.partition(":")  # instance may itself contain ':'
        if not sep:
            raise KeyError(id)
        sel = f'{{job="{job}",instance="{inst}"}}'
        q = {"success": "probe_success" + sel, "duration_s": "probe_duration_seconds" + sel}
    out = {name: _first(client, expr, range_s) for name, expr in q.items()}
    if not any(out.values()):
        raise KeyError(id)
    return out


# State strips: one slot per 1/96 of the range, valued by the fraction of that slot the item was up.
STRIPS = {
    "peer": ("peer", "avg_over_time(((time() - omv_wg_latest_handshake_timestamp_seconds{{interface=\"%s\"}}) < bool 180)[{w}:1m])" % WG_IF),
    "check": (None, "avg_over_time(probe_success[{w}])"),
    "service": ("service", "avg_over_time(omv_service_active[{w}])"),
    "interface": ("device", "avg_over_time(node_network_carrier[{w}])"),
}
SLOTS = 96


def _slotted(client, expr, range_s):
    """[(labels, [fraction or None per slot])] for an expression with a {w} window placeholder."""
    step = range_s // SLOTS
    end = time.time() // step * step
    start = end - step * (SLOTS - 1)
    out = []
    for s in client.query_range(expr.format(w=f"{step}s"), start, end, step):
        slots = [None] * SLOTS
        for t, v in s["values"]:
            i = round((float(t) - start) / step)
            if 0 <= i < SLOTS:
                slots[i] = float(v)
        out.append((s["metric"], slots))
    return out


def strips(client, kind, range_s):
    """{item id: [fraction up or None per slot]} for one kind; None marks a slot without data."""
    label, expr = STRIPS[kind]
    return {(f"{m.get('job')}:{m.get('instance')}" if label is None else m.get(label)): slots
            for m, slots in _slotted(client, expr, range_s)}


# Posture history: each expression is 1 when healthy, so a full strip always means "fine".
POSTURE_STRIPS = {
    "ip_forward": "avg_over_time(omv_ip_forward[{w}])",
    "nat_masquerade": "avg_over_time((omv_nat_masquerade > bool 0)[{w}:1m])",
    "input_policy_accept": "1 - avg_over_time(omv_input_policy_accept[{w}])",
    "ssh_password_auth": "1 - avg_over_time(omv_ssh_password_auth[{w}])",
}


def posture_strip(client, key, range_s):
    got = _slotted(client, POSTURE_STRIPS[key], range_s)
    return got[0][1] if got else None


# Fixed y-scale shared by every check, so response-time charts compare directly (traffic scales to its own peak).
SCALES = {
    "check": ["probe_duration_seconds"],
}


def scale(client, kind, range_s):
    """Largest value of the kind's charted metric across all items in the range, or None."""
    vals = [v for expr in SCALES.get(kind, []) for s in _range(client, f"max({expr})", range_s) for _, v in s]
    return max(vals) if vals else None
