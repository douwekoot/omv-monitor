import ipaddress
import re
import time

from flask import Blueprint, abort, current_app, redirect, render_template, request, url_for

from . import audit, config, data
from .devices import device_name, load_devices, save_override
from .auth import check_csrf, login_required
from .netctl import NetctlError

bp = Blueprint("network", __name__)
_UNIT = re.compile(r"[a-z0-9@._-]+")  # same charset as config._UNIT
_KEY = re.compile(r"[A-Za-z0-9+/]{43}=")  # same shape as the helper's WireGuard public key check
_PID, _SNAP = re.compile(r"[0-9a-f]{16}"), re.compile(r"[0-9a-f]{12}")


WARN = {"wg-quick@wgnet1": "Restarting WireGuard may cut your VPN session. If you are connected through it, "
                           "this page stops responding until the tunnel is back.",
        "omv-monitor": "Restarting the monitor takes this page down briefly. Reload it after a few seconds."}


def _what(e):
    """One readable line for an audit entry (never raw JSON)."""
    a, act = e["args"] or {}, e["action"]
    key = f"{a['public_key'][:8]}…" if a.get("public_key") else ""
    if act == "rename":
        return f"rename peer {key} to {a.get('new', 'n/a')}"
    if act == "restart":
        return f"restart {a.get('unit', 'n/a')}"
    if act == "restore":
        return f"restore snapshot {a.get('snapshot', 'n/a')}"
    return " ".join(str(x) for x in (act, "peer" if key else "", key, a.get("id") and f"change {a['id']}") if x)


def _units():
    """Restartable units from monitor.toml; omv-netctl derives its allowlist the same way."""
    return config.restart_units(current_app.config["SERVICES"], data.WG_IF)


def _states():
    """Current state per restartable service, re-read from Prometheus (n/a when unknown)."""
    svcs, failed = current_app.config["FETCH"](data.services, [], current_app.config["SERVICES"])
    act = {s["name"]: s["active"] for s in svcs}  # Prometheus only knows some of the units -> n/a
    return [{"name": n, "label": label, "state": "n/a" if act.get(n) is None else "running" if act[n] else "stopped"}
            for n, label in _units().items()], failed


@bp.get("/network")
@login_required
def network_page():
    cfg = current_app.config
    services, failed = _states()
    log = [{**e, "what": _what(e), "when": _when_iso(e.get("time"))} for e in audit.recent(cfg["AUDIT_FILE"])]
    done = next((e for e in log if e["time"] == request.args.get("done")), None)
    nc = cfg["NETCTL"]
    peers, pending, snaps = (_ask(a, k) if nc else None for a, k in (("peers", "peers"), ("pending", "pending"),
                                                                       ("snapshots", "snapshots")))
    devices = _devices()
    rows = None if peers is None else [{**p, "name": _name(p, devices)} for p in peers]
    if pending:
        pending = {**pending, "at": _when(pending.get("expires_at"), "%H:%M:%S")}
    snaps = snaps and [{**sn, "time": _when(sn.get("time"))} for sn in snaps if isinstance(sn, dict)]
    names = {r["public_key"]: r["name"] for r in rows or []}
    restorable = [e for e in log if e["action"] == "rename" and e["ok"] and e["args"].get("public_key") in names
                  and names[e["args"]["public_key"]] == e["args"].get("new")][:5]
    return render_template("network.html", services=services, log=log, done=done, unavailable=failed,
                           enabled=nc is not None, peers=rows, pending=pending, snapshots=snaps, restorable=restorable)


def _side(current=None):
    """Context for the Network sidebar on the peer and confirm pages."""
    services, _ = _states()
    peers = _ask("peers", "peers") if current_app.config["NETCTL"] else None
    devices = _devices()
    return {"services": services, "peers": None if peers is None else [{**p, "name": _name(p, devices)} for p in peers],
            "pcurrent": current}


def _confirm_page(title, lines, fields, button, rows=(), warn=False):
    return render_template("network_confirm.html", title=title, lines=lines, fields=fields, button=button, rows=rows,
                           warn=warn, action=request.path, **_side(fields.get("public_key") if isinstance(fields, dict) else None))


def _when_iso(s):
    """Audit time (ISO with offset) in the app's own format."""
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.strptime(s, "%Y-%m-%dT%H:%M:%S%z"))
    except (TypeError, ValueError):
        return s or "unknown time"


def _when(ts, fmt="%Y-%m-%d %H:%M:%S"):
    try:
        return time.strftime(fmt, time.localtime(ts))
    except (TypeError, ValueError, OverflowError, OSError):
        return "unknown time"


def _ask(action, key):
    """One read-only helper call; None when the helper cannot answer (page shows n/a), {} when it says null."""
    try:
        r = current_app.config["NETCTL"].call(action)
    except NetctlError:
        return None
    r = r.get(key, 0) if isinstance(r, dict) else 0
    return {} if r is None else r if isinstance(r, (list, dict)) else None  # {} = answered "nothing"


def _devices():
    cfg = current_app.config
    return load_devices(cfg["DEVICES_FILE"], cfg["DEVICE_NAMES_FILE"])


def _ips(p):
    return ",".join(p.get("allowed_ips", []))


def _name(p, devices):
    return device_name(_ips(p), devices, p.get("public_key"))


def _is_me(p):
    try:
        me = ipaddress.ip_address(request.remote_addr)
        return any(me in ipaddress.ip_network(a, strict=False) for a in p.get("allowed_ips", []))
    except ValueError:
        return False


def _peer(key):
    """The helper's record for a valid public key; 400 bad key, 404 unknown, 503 helper unavailable."""
    if not _KEY.fullmatch(key):
        abort(400)
    peers = _ask("peers", "peers")
    if peers is None:
        abort(503)
    return next((p for p in peers if p.get("public_key") == key), None) or abort(404)


def _apply(action, audit_args, run):
    """Run one confirmed change, audit it (errors too), and go back to /network."""
    cfg = current_app.config
    try:
        run()
        ok, detail = True, "done"
    except (NetctlError, OSError) as e:
        ok, detail = False, str(e)
    audit.record(cfg["AUDIT_FILE"], action, audit_args, ok, detail, request.remote_addr)
    return redirect(url_for("network.network_page", done=audit.recent(cfg["AUDIT_FILE"], 1)[0]["time"]), 303)


def _guard():
    check_csrf()
    if current_app.config["NETCTL"] is None:
        abort(503)


@bp.get("/network/peer/<path:public_key>")  # keys may contain "/"
@login_required
def peer_page(public_key):
    p = _peer(public_key) if _KEY.fullmatch(public_key) else abort(404)
    return render_template("network_peer.html", p=p, name=_name(p, _devices()), ips=", ".join(p.get("allowed_ips", [])),
                           **_side(public_key))


@bp.post("/network/peer/rename")
@login_required
def peer_rename():
    _guard()
    p = _peer(request.form.get("public_key", ""))
    new = request.form.get("name", "").strip()
    if not 1 <= len(new) <= 40 or not new.isprintable():
        abort(400)
    old = _name(p, _devices())
    if request.form.get("confirm") != "1":
        return _confirm_page("Rename this device?", ["Only the name shown in this app changes, not the WireGuard peer."],
                             {"public_key": p["public_key"], "name": new}, "Rename", [("Name", old, new)])
    return _apply("rename", {"public_key": p["public_key"], "old": old, "new": new},
                  lambda: save_override(current_app.config["DEVICE_NAMES_FILE"], p["public_key"], new))


@bp.post("/network/peer/allowed-ips")
@login_required
def peer_allowed_ips():
    _guard()
    p = _peer(request.form.get("public_key", ""))
    new = [x for x in re.split(r"[,\s]+", request.form.get("allowed_ips", "")) if x]
    try:
        for x in new:
            ipaddress.ip_network(x, strict=False)
    except ValueError:
        abort(400)
    if not new:
        abort(400)
    if request.form.get("confirm") != "1":
        return _confirm_page("Change allowed IPs?", _lines(p, "Changing the addresses of this peer"),
                             {"public_key": p["public_key"], "allowed_ips": ", ".join(new)}, "Change allowed IPs",
                             [("Allowed IPs", ", ".join(p.get("allowed_ips", [])), ", ".join(new))], _is_me(p))
    args = {"public_key": p["public_key"], "allowed_ips": new}
    return _apply("peer-set", args, lambda: current_app.config["NETCTL"].call("peer-set", **args))


def _lines(p, what):
    msg = f"{what} takes effect now and reverts by itself after 60 seconds unless you press Keep on the Network page."
    return ["This is the connection you are using. If it stops working, wait for the automatic revert. " + msg
            if _is_me(p) else msg]


def _toggle(action, verb):
    _guard()
    p = _peer(request.form.get("public_key", ""))
    if request.form.get("confirm") != "1":
        return _confirm_page(f"{verb} this peer?", _lines(p, f"{verb} the peer"), {"public_key": p["public_key"]}, verb,
                             warn=_is_me(p))
    args = {"public_key": p["public_key"]}
    return _apply(action, args, lambda: current_app.config["NETCTL"].call(action, **args))


@bp.post("/network/peer/disable")
@login_required
def peer_disable():
    return _toggle("peer-disable", "Disable")


@bp.post("/network/peer/enable")
@login_required
def peer_enable():
    return _toggle("peer-enable", "Enable")


def _pending(action, title, lines):
    _guard()
    pid = request.form.get("id", "")
    if not _PID.fullmatch(pid):
        abort(400)
    if request.form.get("confirm") != "1":
        return _confirm_page(title, lines, {"id": pid}, title.rstrip("?"))
    return _apply(action, {"id": pid}, lambda: current_app.config["NETCTL"].call(action, id=pid))


@bp.post("/network/pending/confirm")
@login_required
def pending_confirm():
    return _pending("confirm", "Keep this change?", ["The change becomes permanent and will not revert."])


@bp.post("/network/pending/revert")
@login_required
def pending_revert():
    return _pending("revert", "Undo this change?", ["The previous configuration is restored now."])


@bp.post("/network/restore")
@login_required
def restore():
    _guard()
    snap = request.form.get("snapshot", "")
    if not _SNAP.fullmatch(snap):
        abort(400)
    if request.form.get("confirm") != "1":
        return _confirm_page("Restore this snapshot?", [
            "The WireGuard configuration is replaced by the snapshot. The change reverts by itself after 60 seconds "
            "unless you press Keep on the Network page."], {"snapshot": snap}, "Restore", [("Snapshot", "", snap)])
    return _apply("restore", {"snapshot": snap}, lambda: current_app.config["NETCTL"].call("restore", snapshot=snap))


@bp.post("/network/restart")
@login_required
def restart():
    cfg = current_app.config
    check_csrf()
    nc = cfg["NETCTL"]
    if nc is None:
        abort(503)
    unit = request.form.get("unit", "")
    if not _UNIT.fullmatch(unit) or unit not in _units():
        audit.record(cfg["AUDIT_FILE"], "restart", {"unit": unit[:64]}, False, "unit not allowed", request.remote_addr)
        abort(400)
    if request.form.get("confirm") != "1":
        state = next((s for s in _states()[0] if s["name"] == unit), {"label": unit, "state": "n/a"})
        return _confirm_page(f"Restart {state['label']}?", [
            f"The service {unit} is now {state['state']}. It will be stopped and started again, which drops its "
            f"connections for a few seconds. If it does not come back, log in to the server over SSH and run "
            f"systemctl status {unit}."], {"unit": unit}, f"Restart {unit}", warn=WARN.get(unit, False))
    args = {"unit": unit}
    try:
        res = nc.call("restart", **args)
        ok, detail = True, "active" if isinstance(res, dict) and res.get("active") else "restarted"
    except NetctlError as e:
        ok, detail = False, str(e)
    audit.record(cfg["AUDIT_FILE"], "restart", args, ok, detail, request.remote_addr)
    return redirect(url_for("network.network_page", done=audit.recent(cfg["AUDIT_FILE"], 1)[0]["time"]), 303)
