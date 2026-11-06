"""Advisory rules: what the app raises from the register data, and how serious it is.

Every rule is evaluated on each page load from the latest values in Prometheus. A failing rule
raises a "finding" (something is broken or unsafe) or an "advisory" (worth a look, not broken).
The explanation of each rule lives in advisories/<id>.md beside this file.
"""
import time
from pathlib import Path

from .config import THRESHOLD_DEFAULTS

DOCS = Path(__file__).resolve().parent / "advisories"
CRITICAL_IFS = {"enp2s0", "wgnet1"}  # wlp3s0 is down by design, so it is never raised
CERT_WARN_DAYS = 30
CERT_FINDING_DAYS = 7
DISK_FINDING_PCT = 95  # at or above this (and the disk_pct threshold) a full disk is a finding, not just worth a look

# id, title, posture key, healthy value, healthy text, unhealthy text, severity, raised title, short note
POSTURE = [
    ("ipv4-forwarding", "IPv4 forwarding", "ip_forward", True, "on", "off", "finding",
     "IPv4 forwarding is off", "WireGuard clients cannot reach the LAN."),
    ("nat-masquerade", "NAT masquerade", "nat_masquerade", True, "on", "off", "finding",
     "NAT masquerade on enp2s0 is missing", "VPN traffic to the LAN will not find its way back."),
    ("input-policy", "Default deny", "input_policy_accept", False, "on", "off", "advisory",
     "No default-deny firewall", "Every listening port is reachable from anywhere that can reach the server."),
    ("ssh-password-login", "SSH password login", "ssh_password_auth", False, "disabled", "enabled", "finding",
     "SSH accepts password login", "Turn off password authentication in OMV: Services, SSH."),
]
# Rule groups in display order: (group, [(rule id, title, one-line description)])
GROUPS = [
    ("Host posture", [
        ("ipv4-forwarding", "IPv4 forwarding", "Forwarding between interfaces, needed for VPN access to the LAN."),
        ("nat-masquerade", "NAT masquerade", "Address translation for VPN traffic leaving through enp2s0."),
        ("input-policy", "Default deny", "Whether the firewall refuses traffic to this host that no rule allows."),
        ("ssh-password-login", "SSH password login", "Whether SSH accepts passwords as well as keys.")]),
    ("Connectivity", [
        ("connectivity-checks", "Connectivity checks", "Ping and DNS probes from this host."),
        ("handshake-age", "WireGuard handshake age", "Time since each VPN device last connected.")]),
    ("Services", [("services-running", "Services running", "Each service listed in config/monitor.toml.")]),
    ("Interfaces", [("required-interfaces", "Required interfaces", "Carrier on enp2s0 and wgnet1.")]),
    ("Disks", [("disk-health", "Disk health", "SMART overall health of each disk."),
               ("disk-usage", "Disk usage", "How full each filesystem is.")]),
    ("Maintenance", [
        ("os-updates", "OS updates", "Pending package upgrades."),
        ("reboot-required", "Reboot required", "Whether an update needs a restart to take effect."),
        ("backup-overdue", "Backup overdue", "Age of the last successful backup of each device.")]),
    ("Certificate", [("certificate-expiry", "Certificate expiry", "Days left on the TLS certificate.")]),
    ("Monitoring", [("monitoring-data", "Monitoring data", "Whether Prometheus answered for this page.")]),
]
RULES = {rid: (title, group, about) for group, rules in GROUPS for rid, title, about in rules}
POSTURE_KEY = {r[0]: r[2] for r in POSTURE}


def host_rows(post):
    """Host posture rows: (code, label, state text, class, raised tuple or None, rule id)."""
    rows = []
    for n, (rid, label, key, ok, ok_txt, bad_txt, sev, title, note) in enumerate(POSTURE, 1):
        v, code = post.get(key), f"H{n}"
        if v is None:
            rows.append((code, label, "n/a", "warn", ("advisory", code, f"{label} not reported",
                                                     "The metrics script did not report it."), rid))
        elif v == ok:
            rows.append((code, label, ok_txt, "good", None, rid))
        else:
            rows.append((code, label, bad_txt, "bad" if sev == "finding" else "warn", (sev, code, title, note), rid))
    return rows


def _item(out, rid, name, state, cls, kind, id=None):
    out[rid]["items"].append({"name": name, "state": state, "cls": cls, "href": None, "kind": kind, "id": id or name})


def _ago(s):
    return f"{int(s // 86400)} d ago" if s >= 2 * 86400 else f"{int(s // 3600)} h ago" if s >= 3600 else f"{int(s // 60)} min ago"


def _maintenance(out, updates, backups, backup_targets, th, now):
    if updates is not None:
        for rid, key, label, state, title, note in (
                ("os-updates", "pending", "Pending upgrades", "{} pending", "Package upgrades pending",
                 "{} upgrades are waiting. Install them in OMV: System, Update Management."),
                ("reboot-required", "reboot", "Reboot", "required", "Reboot required", "Restart the server when it suits you.")):
            v = updates.get(key)
            if v is None:
                _item(out, rid, label, "n/a", "warn", "maintenance", rid)
                out[rid]["raised"].append(("advisory", None, f"{label} not reported", "The metrics script did not report it."))
            elif v:
                _item(out, rid, label, state.format(v), "warn", "maintenance", rid)
                out[rid]["raised"].append(("advisory", None, title, note.format(v)))
            else:
                _item(out, rid, label, "none" if rid == "os-updates" else "not needed", "good", "maintenance", rid)
    if backups is None and backup_targets is None:
        return
    limit = th["backup_age_h"] * 3600
    labels = backup_targets if isinstance(backup_targets, dict) else {}  # {name: label} names the device as the app does
    for b in backups or []:
        n, last = b["target"], b.get("last_success")
        if backup_targets is not None and n not in backup_targets:
            continue  # disabled target: its old metrics are not a problem
        t = labels.get(n, n)
        if last is None:
            _item(out, "backup-overdue", t, "n/a", "warn", "backup", n)
            out["backup-overdue"]["raised"].append(("advisory", None, f"Backup of {t} has no successful run reported", "Check the backup log."))
            continue
        age = now - last
        late = age > limit
        sev = "finding" if late and (b.get("ok") is False or age > 2 * limit) else "advisory"
        _item(out, "backup-overdue", t, _ago(age), ("bad" if sev == "finding" else "warn") if late else "good", "backup", n)
        if late:
            out["backup-overdue"]["raised"].append((sev, None, f"Backup of {t} is overdue",
                                                    f"The last successful backup was {_ago(age)}, older than the threshold."))
    reported = {b["target"] for b in backups or []}
    for n in backup_targets or []:
        if n not in reported:
            t = labels.get(n, n)
            _item(out, "backup-overdue", t, "n/a", "warn", "backup", n)
            out["backup-overdue"]["raised"].append(("advisory", None, f"Backup of {t} not reported", "No backup metrics exist for this target."))


def evaluate(peers, ifs, svcs, checks, host, unavailable, disks=None, cert_expiry=None, now=None, cert_reported=False,
             thresholds=None, updates=None, backups=None, filesystems=None, backup_targets=None):
    """{rule id: {"status": pass|advisory|finding, "raised": [...], "items": [...]}} for every rule.

    The keyword arguments after cert_reported are optional: a rule whose data is None is not evaluated."""
    th = {**THRESHOLD_DEFAULTS, **(thresholds or {})}
    judge_peers = now is not None  # shortcut: callers that pass no clock (the web app today) keep not judging peers; wire it there with now=
    now = time.time() if now is None else now
    out = {rid: {"raised": [], "items": []} for rid in RULES}
    for code, label, text, cls, raised, rid in host:
        out[rid]["items"].append({"name": label, "state": text, "cls": cls, "href": None, "kind": "posture", "id": rid})
        if raised:
            out[rid]["raised"].append(raised)
    for c in checks:
        out["connectivity-checks"]["items"].append({"name": f"{c['job']} {c['instance']}", "state": c["state"], "cls": c["cls"],
                                                    "href": f"/detail/check/{c['id']}", "kind": "check", "id": c["id"]})
        if not c["success"]:
            down = c["success"] is False
            out["connectivity-checks"]["raised"].append(("finding" if down else "advisory", c["code"],
                f"{c['job']} {c['instance']} is " + ("down" if down else "not reported"), "Connectivity check failing."))
    for s in svcs:
        out["services-running"]["items"].append({"name": s["label"], "state": s["state"], "cls": s["cls"],
                                                 "href": f"/detail/service/{s['name']}", "kind": "service", "id": s["name"]})
        if not s["active"]:
            stopped = s["active"] is False
            out["services-running"]["raised"].append(("finding" if stopped else "advisory", s["code"],
                f"{s['label']} is " + ("not running" if stopped else "not reported"), "Service check failing."))
    for i in ifs:
        if i["device"] not in CRITICAL_IFS:
            continue
        out["required-interfaces"]["items"].append({"name": i["device"], "state": i["state"], "cls": i["cls"],
                                                    "href": f"/detail/interface/{i['device']}", "kind": "interface", "id": i["device"]})
        if i["up"] is False:
            out["required-interfaces"]["raised"].append(("finding", i["code"], f"{i['device']} is down",
                                                         "A required interface has no carrier."))
    for d in disks or []:
        ok = d["healthy"]
        out["disk-health"]["items"].append({"name": d["device"], "state": d.get("state") or ("healthy" if ok else "failed" if ok is False else "n/a"),
                                            "cls": d.get("cls") or ("good" if ok else "bad" if ok is False else "warn"),
                                            "href": None, "kind": "disk", "id": d["device"]})
        if not ok:
            out["disk-health"]["raised"].append(("finding" if ok is False else "advisory", d.get("code"),
                f"{d['device']} SMART " + ("health check failed" if ok is False else "not reported"), "Disk health check failing."))
    if disks == []:
        out["disk-health"]["raised"].append(("advisory", None, "Disk health not reported", "The metrics script did not report any disk."))
    for f in filesystems or []:
        p = f["used_pct"]
        if p is None:
            _item(out, "disk-usage", f["mount"], "n/a", "warn", "filesystem")
            out["disk-usage"]["raised"].append(("advisory", None, f"{f['mount']} usage not reported", "The metrics did not report its size."))
            continue
        full = p >= th["disk_pct"]
        sev = "finding" if full and p >= DISK_FINDING_PCT else "advisory"
        _item(out, "disk-usage", f["mount"], f"{p:.0f}% used", ("bad" if sev == "finding" else "warn") if full else "good", "filesystem")
        if full:
            out["disk-usage"]["raised"].append((sev, None, f"{f['mount']} is nearly full", f"{p:.0f}% used. Free space or add storage."))
    for p in (peers or []) if judge_peers else []:
        h, name = p["last_handshake"], p["device"]
        if h is None:
            _item(out, "handshake-age", name, "n/a", "warn", "peer")
            out["handshake-age"]["raised"].append(("advisory", None, f"{name} has never connected", "No WireGuard handshake is recorded."))
            continue
        stale = now - h > th["handshake_stale_s"]
        _item(out, "handshake-age", name, _ago(now - h), "bad" if stale else "good", "peer")
        if stale:
            out["handshake-age"]["raised"].append(("finding", None, f"{name} has had no recent handshake",
                                                   f"Last WireGuard handshake was {_ago(now - h)}, older than the threshold."))
    _maintenance(out, updates, backups, backup_targets, th, now)
    if cert_expiry is not None:
        left = (cert_expiry - now) / 86400
        if left < CERT_WARN_DAYS:
            sev, title = (("finding", "Certificate has expired") if left < 0 else
                          ("finding", f"Certificate expires within {CERT_FINDING_DAYS} days") if left < CERT_FINDING_DAYS else
                          ("advisory", f"Certificate expires within {CERT_WARN_DAYS} days"))
            out["certificate-expiry"]["raised"].append((sev, None, title, "Renew the certificate before it lapses."))
        out["certificate-expiry"]["items"].append({"name": "TLS certificate", "state": f"{int(left)} days left" if left >= 0 else "expired",
                                                   "cls": "bad" if left < CERT_FINDING_DAYS else "warn" if left < CERT_WARN_DAYS else "good",
                                                   "href": None, "kind": "certificate", "id": "certificate"})
    elif cert_reported:  # queried fine but the metric is absent
        out["certificate-expiry"]["raised"].append(("advisory", None, "Certificate expiry not reported", "The metrics script did not report the certificate."))
    out["monitoring-data"]["items"].append({"name": "Prometheus", "state": "unavailable" if unavailable else "answering",
                                            "cls": "bad" if unavailable else "good", "href": None, "kind": "data", "id": "prometheus"})
    if unavailable:
        out["monitoring-data"]["raised"].append(("finding", None, "Prometheus data unavailable", "Some values could not be loaded."))
    for r in out.values():
        sevs = {x[0] for x in r["raised"]}
        r["status"] = "finding" if "finding" in sevs else "advisory" if sevs else "pass"
    return out


def findings(results):
    """Raised items, findings before advisories, numbered F1.. and A1.., each linking to its rule page."""
    raised = [(sev, code, title, note, rid) for rid, r in results.items() for sev, code, title, note in r["raised"]]
    raised.sort(key=lambda f: f[0] != "finding")
    n = {"finding": 0, "advisory": 0}
    rows = []
    for sev, code, title, note, rid in raised:
        n[sev] += 1
        rows.append({"no": f"{sev[0].upper()}{n[sev]}", "sev": sev, "code": code, "title": title, "note": note,
                     "rule": rid, "href": f"/advisories/{rid}"})
    return rows, n
