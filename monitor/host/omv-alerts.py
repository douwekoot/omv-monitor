#!/usr/bin/python3
"""Log raised/cleared findings and advisories, and mail new findings. Run every 60 s by omv-alerts.timer (stdlib only)."""
import json
import os
import smtplib
import ssl
import sys
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import advisories, alert_history, audit, config, data, settings  # noqa: E402
from app.devices import load_devices  # noqa: E402
from app.prom import PromClient  # noqa: E402

ADDR = "you@example.com"
STATE_FILE = Path("/var/lib/omv-alerts/state.json")
AUDIT_FILE = Path("/opt/omv-monitor/data/audit.jsonl")
WEB_URL = "https://192.168.1.10:8443/login"
HISTORY_FILE = Path("/opt/omv-monitor/data/alert-history.jsonl")
SECRETS_FILE = Path("/opt/omv-monitor/secrets/smtp.env")  # root-only, key=value: OMV_SMTP_HOST/USER/PASSWORD
MONITOR_TOML = Path("/opt/omv-monitor/config/monitor.toml")
BACKUPS_TOML = Path("/opt/omv-monitor/config/backups.toml")
SETTINGS_FILE = Path("/opt/omv-monitor/data/settings.json")
BACKUP_OVERRIDES_FILE = Path("/opt/omv-monitor/data/backup-overrides.json")
DEVICES = ("/opt/omv-monitor/config/devices.toml", "/opt/omv-monitor/data/device-names.json")


def _fetch(fn, default):
    try:
        return fn(), False
    except Exception:  # any failure means "data unavailable", as in the web app
        return default, True


def _decorate(rows, prefix, up, on, off, off_cls="bad"):
    for n, r in enumerate(rows, 1):
        v = r[up]
        r["code"] = f"{prefix}{n}"
        r["state"], r["cls"] = ("n/a", "warn") if v is None else (on, "good") if v else (off, off_cls)
    return rows


def web_probe():
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # self-signed cert
    try:
        urllib.request.urlopen(WEB_URL, timeout=10, context=ctx).close()
    except urllib.error.HTTPError:
        pass  # any HTTP response means the app is up
    except OSError:  # URLError and timeouts
        return False
    return True


def _config():
    """(thresholds, alert_history_days, services); an unreadable config falls back to the defaults
    (and no service checks) and is logged."""
    th, days, svcs = dict(config.THRESHOLD_DEFAULTS), 90, []
    try:
        cfg = config.load_monitor(MONITOR_TOML)
        th, days, svcs = cfg["thresholds"], cfg["retention"]["alert_history_days"], cfg["services"]
    except Exception as e:
        print(f"omv-alerts: monitor.toml unusable, using defaults ({type(e).__name__})", file=sys.stderr)
    return settings.thresholds(settings.load(SETTINGS_FILE), th), days, svcs


def _backup_targets():
    try:
        return {t["name"]: t["label"] for t in config.merged_backups(BACKUPS_TOML, BACKUP_OVERRIDES_FILE)["targets"] if t["enabled"]}
    except Exception:  # no backups configured here
        return None


def current_findings(client, devices, now=None, probe=None):
    """Raised findings and advisories, each with sev, rule, title, note and key."""
    now = time.time() if now is None else now
    th, _, svcs_cfg = _config()
    ifs, d1 = _fetch(lambda: data.interfaces(client), [])
    svcs, d2 = _fetch(lambda: data.services(client, svcs_cfg), [])
    checks, d3 = _fetch(lambda: data.checks(client), [])
    post, d4 = _fetch(lambda: data.posture(client), {})
    disks, d5 = _fetch(lambda: data.disks(client), [])
    cert, d6 = _fetch(lambda: data.cert_expiry(client), None)
    peers, d7 = _fetch(lambda: data.peers(client, devices), [])
    upd, d8 = _fetch(lambda: data.updates(client), {"pending": None, "reboot": None})
    bks, d9 = _fetch(lambda: data.device_backups(client), None)
    fss, d10 = _fetch(lambda: data.filesystems(client), None)
    _decorate(ifs, "I", "up", "up", "down", "bad")
    _decorate(svcs, "S", "active", "running", "stopped")
    _decorate(checks, "C", "success", "up", "down")
    rules = advisories.evaluate(peers, ifs, svcs, checks, advisories.host_rows(post), any((d1, d2, d3, d4, d5, d6, d7, d8, d9, d10)),
                              disks=disks, cert_expiry=cert, now=now, thresholds=th, updates=upd, backups=bks,
                              filesystems=fss,
                              backup_targets=None if bks is None else _backup_targets())
    out = [f for f in advisories.findings(rules)[0]]
    if not (probe or web_probe)():
        out.append({"sev": "finding", "rule": "monitoring-data", "title": "Web app unreachable",
                    "note": f"{WEB_URL} does not answer."})
    return [{**f, "key": f"{f['rule']}:{f['title']}"} for f in out]


def new_findings(current, state):
    return [f for f in current if f["key"] not in state]


def send(msg, host, user, password, smtp_factory=smtplib.SMTP_SSL):
    with smtp_factory(host, 465, timeout=20) as s:
        s.login(user, password)
        s.send_message(msg)


def _smtp_secrets():
    """(host, user, password) from SECRETS_FILE; raises OSError/KeyError when unreadable or incomplete."""
    kv = {}
    for ln in SECRETS_FILE.read_text(encoding="utf-8").splitlines():
        k, sep, v = ln.partition("=")
        if sep and not k.lstrip().startswith("#"):
            kv[k.strip()] = v.strip()
    return kv["OMV_SMTP_HOST"], kv["OMV_SMTP_USER"], kv["OMV_SMTP_PASSWORD"]


def _load_state():
    try:
        return set(json.loads(STATE_FILE.read_text()))
    except (OSError, ValueError):
        return set()


def _log_history(cur, days):
    """Append raised/cleared events for items that appeared or went away since the last run."""
    try:
        now = time.time()
        alert_history.prune(HISTORY_FILE, days, now)  # first: an item raised before the cutoff is simply raised anew
        before = alert_history.active(HISTORY_FILE)
        now_items = {(f["rule"], f["title"]): f["sev"] for f in cur}
        ev = [{"ts": now, "event": "raised", "sev": sev, "rule": r, "title": t} for (r, t), sev in now_items.items() if (r, t) not in before]
        if ("monitoring-data", "Prometheus data unavailable") not in now_items:  # an outage hides items; do not call them cleared
            ev += [{"ts": now, "event": "cleared", "sev": sev, "rule": r, "title": t} for (r, t), sev in before.items() if (r, t) not in now_items]
        alert_history.record(HISTORY_FILE, ev)
    except OSError as e:
        print(f"omv-alerts: history write failed ({type(e).__name__})", file=sys.stderr)


def main(argv=None, env=os.environ, client=None, smtp_factory=smtplib.SMTP_SSL):
    client = client or PromClient("http://127.0.0.1:9090")
    cur = current_findings(client, load_devices(*DEVICES))
    _log_history(cur, _config()[1])
    cur_f = [f for f in cur if f["sev"] == "finding"]
    old = _load_state()
    fresh = new_findings(cur_f, old)
    if fresh:
        try:
            host, user, password = _smtp_secrets()
        except (OSError, KeyError) as e:
            print(f"omv-alerts: cannot read SMTP settings from {SECRETS_FILE} ({type(e).__name__})", file=sys.stderr)
            return 2
        msg = EmailMessage()
        msg["Subject"] = "OMV alert: " + "; ".join(" ".join(f["title"].split()) for f in fresh)  # no CR/LF: header injection
        msg["From"], msg["To"] = user, env.get("OMV_ALERT_TO") or ADDR
        msg.set_content("\n".join(f"{f['title']}\n  {f['note']}\n  rule: {f['rule']}\n" for f in fresh))
        try:
            send(msg, host, user, password, smtp_factory)
        except Exception as e:  # never print e: it could echo credentials
            print(f"omv-alerts: send failed ({type(e).__name__})", file=sys.stderr)
            return 1
        # state first: a mail already sent must never be repeated because auditing failed
        keys = {f["key"] for f in cur_f}
        if any(k.endswith(":Prometheus data unavailable") for k in keys):
            keys |= old  # outage hides other findings; keep them so recovery does not re-mail
        try:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            STATE_FILE.write_text(json.dumps(sorted(keys)))
            if AUDIT_FILE.parent.exists():
                audit.record(AUDIT_FILE, "alert-email", {"findings": [f["key"] for f in fresh]}, True, "sent", None)
        except Exception as e:
            print(f"omv-alerts: bookkeeping failed ({type(e).__name__})", file=sys.stderr)
            return 1
        return 0
    keys = {f["key"] for f in cur_f}
    if any(k.endswith(":Prometheus data unavailable") for k in keys):
        keys |= old
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(sorted(keys)))
    except OSError as e:
        print(f"omv-alerts: state write failed ({type(e).__name__})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
