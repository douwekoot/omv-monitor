import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

from flask import Flask, abort, g, make_response, redirect, render_template, request, send_file, session, url_for

from . import advisories, alert_history, audit, backups, data, devices as devmod, network, settings, totp, wiki
from . import config as cfgmod
from .auth import RateLimiter, check_csrf, csrf_token, login_required, password_ok
from .charts import line_chart, state_strip
from .devices import load_devices
from .netctl import NetctlClient, NetctlError
from .prom import PromClient, PromError

PKG = Path(__file__).resolve().parent.parent
PENDING_S = 300  # password accepted, waiting for the second factor
RANGES = {"24h": 86400, "7d": 604800}


def _bytes(v, units="binary"):
    if v is None:
        return "n/a"
    base, names = (1000, ("B", "kB", "MB", "GB", "TB")) if units == "decimal" else (1024, ("B", "KiB", "MiB", "GiB", "TiB"))
    for u in names:
        if abs(v) < base or u == names[-1]:
            return f"{v:.0f} {u}" if u == "B" else f"{v:.1f} {u}"
        v /= base


def _ago(ts, good_s=180):
    """Handshake age text and state class; an idle peer is normal (the phone is often off the VPN)."""
    if not ts:
        return "never", "idle"
    s = max(0, int(time.time() - ts))
    txt = f"{s} s ago" if s < 120 else f"{s // 60} min ago" if s < 7200 else f"{s // 3600} h ago"
    return txt, "good" if s < good_s else "idle"


def _state(v, on="up", off="down", off_cls="bad"):
    return ("n/a", "warn") if v is None else (on, "good") if v else (off, off_cls)


CODES = {"peer": "P", "interface": "I", "service": "S", "check": "C"}
CRITICAL_IFS = advisories.CRITICAL_IFS
STRIP_WORD = {"peer": "connected", "service": "running", "check": "up", "interface": "up"}


def _strip_cls(kind, id):
    """Down time is neutral where it is normal: idle peers and unused interfaces."""
    return f"k-{kind}" + (" k-idle" if kind == "peer" or (kind == "interface" and id not in CRITICAL_IFS) else "")


def _coded(kind, rows):
    for n, r in enumerate(rows, 1):
        r["code"] = f"{CODES[kind]}{n}"
    return rows


def _host(post):
    return advisories.host_rows(post)


def findings(peers, ifs, svcs, checks, host, unavailable):
    """What needs attention: findings before advisories, numbered, each linking to its rule page."""
    return advisories.findings(advisories.evaluate(peers, ifs, svcs, checks, host, unavailable))


def _dur(s):
    return f"{max(1, round(s / 60))} min" if s < 7200 else f"{round(s / 3600)} h" if s < 172800 else f"{round(s / 86400)} days"


def _since(slots, range_s):
    """How long the latest state has held, read from a strip; "at least" when the run reaches the data's start."""
    if not slots or slots[-1] is None:
        return None
    ok, n = slots[-1] >= .5, 0
    for v in reversed(slots):
        if v is None or (v >= .5) != ok:
            break
        n += 1
    at_least = n == len(slots) or slots[-n - 1] is None
    return ("for at least " if at_least else "for about ") + _dur(n * range_s / len(slots))


def verdict(n):
    words = {"finding": "findings", "advisory": "advisories"}
    text = ", ".join(f"{v} {k if v == 1 else words[k]}" for k, v in n.items() if v) or "Passed"
    return text, "bad" if n["finding"] else "warn" if n["advisory"] else "good"


def create_app(config=None, prom_client=None, netctl=None):
    env = os.environ.get
    cfg = {"ADMIN_PASSWORD": env("APP_ADMIN_PASSWORD", ""), "SECRET_KEY": env("APP_SECRET_KEY", ""),
           "PROM_URL": env("PROM_URL", "http://127.0.0.1:9090"),
           "DEVICES_FILE": env("APP_DEVICES_FILE", str(PKG / "config" / "devices.toml")),
           "SETTINGS_FILE": env("APP_SETTINGS_FILE", str(PKG / "config" / "settings.json")),
           "DEVICE_NAMES_FILE": env("APP_DEVICE_NAMES_FILE"),
           "BACKUP_DIR": env("APP_BACKUP_DIR", str(PKG / "backups")),
           "EXPORT_DIR": env("APP_EXPORT_DIR", str(PKG / "exports")),
           "NETCTL_SOCKET": env("APP_NETCTL_SOCKET"), "AUDIT_FILE": env("APP_AUDIT_FILE"), "TOTP_FILE": env("APP_TOTP_FILE"),
           "WIKI_DIR": env("APP_WIKI_DIR", str(PKG / "wiki")),
           "MONITOR_CONFIG": env("APP_MONITOR_CONFIG", str(PKG / "config" / "monitor.toml")),
           "BACKUPS_CONFIG": env("APP_BACKUPS_CONFIG", str(PKG / "config" / "backups.toml")),
           "BACKUP_OVERRIDES_FILE": env("APP_BACKUP_OVERRIDES_FILE"), "ALERT_HISTORY_FILE": env("APP_ALERT_HISTORY_FILE"),
           "BACKUP_RUNS_FILE": env("APP_BACKUP_RUNS_FILE"), "LOGIN_MAX_ATTEMPTS": 5, "LOGIN_WINDOW_S": 300,
           **(config or {})}
    if not cfg["ADMIN_PASSWORD"]:
        raise RuntimeError("APP_ADMIN_PASSWORD must be set")
    if not cfg["SECRET_KEY"]:
        raise RuntimeError("APP_SECRET_KEY must be set")
    # shortcut: length enforced only for deployment (env) values; code-supplied test configs may be short
    if "SECRET_KEY" not in (config or {}) and len(cfg["SECRET_KEY"]) < 16:
        raise RuntimeError("APP_SECRET_KEY must be at least 16 characters")
    if "ADMIN_PASSWORD" not in (config or {}) and len(cfg["ADMIN_PASSWORD"]) < 8:
        raise RuntimeError("APP_ADMIN_PASSWORD must be at least 8 characters")
    cfg["AUDIT_FILE"] = cfg["AUDIT_FILE"] or str(Path(cfg["SETTINGS_FILE"]).parent / "audit.jsonl")
    cfg["TOTP_FILE"] = cfg["TOTP_FILE"] or str(Path(cfg["SETTINGS_FILE"]).parent / "totp.json")
    cfg["DEVICE_NAMES_FILE"] = cfg["DEVICE_NAMES_FILE"] or str(Path(cfg["SETTINGS_FILE"]).parent / "device_names.json")
    data_dir = Path(cfg["SETTINGS_FILE"]).parent
    for key, name in (("BACKUP_OVERRIDES_FILE", "backup-overrides.json"), ("ALERT_HISTORY_FILE", "alert-history.jsonl"),
                      ("BACKUP_RUNS_FILE", "backup-runs.jsonl")):
        cfg[key] = cfg[key] or str(data_dir / name)
    monitor_cfg = cfgmod.load_monitor(cfg["MONITOR_CONFIG"])  # ConfigError propagates: refuse to start on bad config

    def bk():
        """Backup config with the saved overrides applied; re-read so a saved edit shows at once."""
        return cfgmod.merged_backups(cfg["BACKUPS_CONFIG"], cfg["BACKUP_OVERRIDES_FILE"])

    bk()
    app = Flask(__name__)
    app.config.update(SECRET_KEY=cfg["SECRET_KEY"], SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Strict",
                      PERMANENT_SESSION_LIFETIME=timedelta(hours=12))
    prom = prom_client or PromClient(cfg["PROM_URL"])
    limiter = RateLimiter(cfg["LOGIN_MAX_ATTEMPTS"], cfg["LOGIN_WINDOW_S"])
    app.jinja_env.filters.update(bytes=lambda v: _bytes(v, g.settings["byte_units"]), urlid=lambda s: quote(s, safe=":/+="),
                           when=lambda ts: time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if isinstance(ts, (int, float)) else "n/a",
                           ago=lambda ts: advisories._ago(max(0, time.time() - ts)) if isinstance(ts, (int, float)) else "n/a")
    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def load_settings():
        g.settings = settings.load(cfg["SETTINGS_FILE"])

    def rng_arg():
        rng = request.args.get("range")
        return rng if rng in RANGES else g.settings["default_range"]

    def refreshed(html):
        r = make_response(html)
        if g.settings["refresh_s"] > 0:
            r.headers["Refresh"] = str(g.settings["refresh_s"])
        return r

    @app.after_request
    def headers(r):
        r.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        r.headers["X-Content-Type-Options"] = "nosniff"
        r.headers["Referrer-Policy"] = "no-referrer"
        r.headers["Cache-Control"] = "no-store"
        return r

    def ip():
        return request.remote_addr or "?"

    def log(action, ok, detail=""):
        audit.record(cfg["AUDIT_FILE"], action, {}, ok, detail, ip())

    def pending():
        p = session.get("pending")
        return p if p and 0 <= time.time() - p["t"] < PENDING_S else None

    def finish():
        session.clear()
        session["auth"] = True
        session.permanent = True
        return redirect(url_for("dashboard"))

    def second_factor(page, **ctx):
        """Shared GET/POST skeleton for the code pages; returns (response, None), or (None, submitted_code) on a POST to check."""
        if not pending():
            session.pop("pending", None)
            return redirect(url_for("login")), None
        err, status = None, 200
        if request.method == "POST":
            if limiter.blocked(ip()):
                err, status = "Too many failed attempts. Try again later.", 429
            else:
                check_csrf()
                return None, request.form.get("code", "")
        return (render_template(page, err=err, **ctx), status), None

    @app.route("/login", methods=["GET", "POST"])
    def login():
        err, code = None, 200
        if request.method == "POST":
            if limiter.blocked(ip()):
                err, code = "Too many failed attempts. Try again later.", 429
            else:
                check_csrf()
                if password_ok(request.form.get("password", ""), cfg["ADMIN_PASSWORD"]):
                    session.clear()
                    session["pending"] = {"t": time.time()}
                    return redirect(url_for("login_totp" if totp.load(cfg["TOTP_FILE"]) else "login_setup"))
                limiter.fail(ip())
                log("login", False, "wrong password")
                err, code = "Wrong password.", 401
        return render_template("login.html", err=err), code

    @app.route("/login/totp", methods=["GET", "POST"])
    def login_totp():
        state = totp.load(cfg["TOTP_FILE"])
        if not state:
            return redirect(url_for("login_setup" if pending() else "login"))
        r, given = second_factor("login_totp.html")
        if given is None:
            return r
        now = time.time()
        step = totp.verify(state["secret"], given, now, state.get("last_step"))
        digest = hashlib.sha256(given.strip().encode()).hexdigest()
        if step is not None:
            state["last_step"] = step
            totp.save(cfg["TOTP_FILE"], state)
            log("login", True, "totp")
            return finish()
        if any(hmac.compare_digest(digest, h) for h in state["recovery"]):
            state["recovery"] = [h for h in state["recovery"] if not hmac.compare_digest(digest, h)]
            totp.save(cfg["TOTP_FILE"], state)
            log("login", True, f"recovery code used, {len(state['recovery'])} left")
            return finish()
        limiter.fail(ip())
        log("login", False, "wrong code")
        return render_template("login_totp.html", err="Wrong code."), 401

    @app.route("/login/setup", methods=["GET", "POST"])
    def login_setup():
        if totp.load(cfg["TOTP_FILE"]):  # enrolled: setup can never be reached again
            return redirect(url_for("login_totp" if pending() else "login"))
        r, given = second_factor("totp_setup.html", **setup_ctx())
        if given is None:
            return r
        s = setup_state()
        step = totp.verify(s["secret"], given, time.time(), None)
        if step is not None:
            totp.save(cfg["TOTP_FILE"], {"secret": s["secret"], "last_step": step,
                                         "recovery": [hashlib.sha256(c.encode()).hexdigest() for c in s["codes"]]})
            setup_file().unlink(missing_ok=True)
            log("totp enrolled", True)
            return finish()
        limiter.fail(ip())
        log("totp enrolled", False, "wrong code")
        return render_template("totp_setup.html", err="Wrong code.", **setup_ctx()), 401

    def setup_file():
        return Path(cfg["TOTP_FILE"]).with_name("totp-setup.json")

    def setup_state():
        """Pending enrollment secret and codes, kept server-side; the cookie holds only its id."""
        try:
            st = totp.load(setup_file())
            if st and st["id"] == session.get("setup") and 0 <= time.time() - st["t"] < PENDING_S:
                return st
        except (ValueError, KeyError, TypeError):
            pass  # not auth state: a bad file just starts a fresh setup
        st = {"id": secrets.token_hex(16), "t": time.time(), "secret": totp.new_secret(), "codes": totp.new_recovery_codes()}
        totp.save(setup_file(), st)
        session["setup"] = st["id"]
        return st

    def setup_ctx():
        s = setup_state()
        return {"secret": s["secret"], "uri": totp.otpauth_uri(s["secret"]), "codes": s["codes"]}

    @app.post("/logout")
    @login_required
    def logout():
        check_csrf()
        session.clear()
        return redirect(url_for("login"))

    def fetch(fn, default, *a):
        try:
            return fn(prom, *a), False
        except PromError:
            return default, True

    app.config["FETCH"] = fetch
    app.config["SERVICES"] = monitor_cfg["services"]
    app.config["AUDIT_FILE"] = cfg["AUDIT_FILE"]
    app.config["DEVICES_FILE"], app.config["DEVICE_NAMES_FILE"] = cfg["DEVICES_FILE"], cfg["DEVICE_NAMES_FILE"]
    app.config["NETCTL"] = netctl or (NetctlClient(cfg["NETCTL_SOCKET"]) if cfg["NETCTL_SOCKET"] else None)
    app.register_blueprint(network.bp)

    def strip_svgs(kind, range_s):
        got, failed = fetch(data.strips, {}, kind, range_s)
        return {k: state_strip(v, STRIP_WORD[kind], _strip_cls(kind, k)) for k, v in got.items()}, failed

    def backup_rows(bks, now):
        """One state per backup target (failed, overdue, ok, n/a, disabled), shared by the dashboard and the backup pages."""
        th = settings.thresholds(g.settings, monitor_cfg["thresholds"])
        by = {b["target"]: b for b in bks or []}
        rows = []
        for t in bk()["targets"]:
            b = by.get(t["name"], {})
            last = b.get("last_success")
            age = None if last is None else max(0, now - last)
            state, cls = (("failed", "bad") if b.get("ok") is False else ("n/a", "warn") if age is None else
                          ("overdue", "warn") if age > th["backup_age_h"] * 3600 else ("ok", "good"))
            rows.append({"name": t["name"], "label": t["label"], "ago": "n/a" if age is None else advisories._ago(age),
                         "size": b.get("size"), "last_run": b.get("last_run"), "last_success": last, "ok": b.get("ok"),
                         "state": state if t["enabled"] else "disabled", "cls": cls if t["enabled"] else "idle"})
        return rows

    def backup_side(current=None):
        """Context for the Backups sidebar: every target with its state, and the archive kinds."""
        bks, failed = fetch(data.device_backups, None)
        return {"brows": backup_rows(bks, time.time()), "kinds": backups.list_backups(cfg["BACKUP_DIR"]),
                "bcurrent": current, "unavailable": failed}

    def register():
        """Everything the sidebar lists, with states, 24h strips, findings and the verdict."""
        devices = load_devices(cfg["DEVICES_FILE"], cfg["DEVICE_NAMES_FILE"])
        peers, d1 = fetch(lambda c: data.peers(c, devices), [])
        for p in _coded("peer", peers):
            p["ago"], p["cls"] = _ago(p["last_handshake"], g.settings["handshake_good_s"])
            p["state"] = "connected" if p["cls"] == "good" else "idle"
        ifs, d2 = fetch(data.interfaces, [])
        for i in _coded("interface", ifs):
            i["state"], i["cls"] = _state(i["up"], off_cls="bad" if i["device"] in CRITICAL_IFS else "idle")
        svcs, d3 = fetch(data.services, [], monitor_cfg["services"])
        for sv in _coded("service", svcs):
            sv["state"], sv["cls"] = _state(sv["active"], "running", "stopped")
        checks, d4 = fetch(data.checks, [])
        for c in _coded("check", checks):
            c["state"], c["cls"] = _state(c["success"])
        post, d5 = fetch(data.posture, {})
        host = _host(post)
        strips, failed = {}, False
        shown = {"peer": "peers", "interface": "interfaces", "service": "services", "check": "checks"}
        for kind in CODES:
            if shown[kind] not in g.settings["panels"]:
                strips[kind] = {}
                continue
            strips[kind], f = strip_svgs(kind, RANGES["24h"])
            failed |= f
        disks, d7 = fetch(data.disks, None)  # None = not evaluated when Prometheus failed
        for d in disks or []:
            d["state"], d["cls"] = _state(d["healthy"], "healthy", "failing")
        conts, d8 = fetch(data.containers, [])
        for c in conts:
            c["state"], c["cls"] = _state(c["running"], "running", "stopped")
        cert, d9 = fetch(data.cert_expiry, None)
        upd, d10 = fetch(data.updates, None)
        bks, d11 = fetch(data.device_backups, None)
        fss, d12 = fetch(data.filesystems, None)
        unavailable = any((d1, d2, d3, d4, d5, failed, d7, d8, d9, d10, d11, d12))
        now = time.time()
        th = settings.thresholds(g.settings, monitor_cfg["thresholds"])
        targets = bk()["targets"]
        rules = advisories.evaluate(peers, ifs, svcs, checks, host, unavailable, disks=disks, cert_expiry=cert, cert_reported=not d9,
                                    now=now, thresholds=th, updates=upd, backups=bks, filesystems=fss,
                                    backup_targets={t["name"]: t["label"] for t in targets if t["enabled"]})
        brows = backup_rows(bks, now)
        rows, n = advisories.findings(rules)
        text, sev = verdict(n)
        return {"disks": disks or [], "containers": conts, "peers": peers, "ifs": ifs, "svcs": svcs, "checks": checks, "host": host, "findings": rows, "rules": rules,
                "verdict": text, "sev": sev, "updates": upd, "brows": brows, "strips": strips, "updated": time.strftime("%H:%M"),
                "unavailable": unavailable, "panels": g.settings["panels"]}

    @app.get("/")
    @login_required
    def dashboard():
        rng = rng_arg()
        reg = register()
        now = time.time()
        chart = None
        if "traffic" in g.settings["panels"]:
            traffic, d6 = fetch(lambda c: data.wg_traffic(c, RANGES[rng]), {"rx": [], "tx": []})
            chart = line_chart({"Received": traffic["rx"], "Sent": traffic["tx"]}, "B/s", None, (now - RANGES[rng], now))
            reg["unavailable"] |= d6
        newest = max((e["when"] for v in backups.list_backups(cfg["BACKUP_DIR"]).values() for e in v), default=None)
        backup = None
        if newest:
            s = max(0, int(now - time.mktime(time.strptime(newest, "%Y-%m-%d %H:%M"))))
            backup = (newest, f"{s // 60} min ago" if s < 7200 else f"{s // 3600} h ago" if s < 172800 else f"{s // 86400} days ago")
        return refreshed(render_template("dashboard.html", **reg, backup=backup, chart=chart, rng=rng, ranges=RANGES, current=None))

    KEYS = {"peer": ("peers", "id"), "interface": ("ifs", "device"), "service": ("svcs", "name"), "check": ("checks", "id")}

    def item(kind, r):
        _b = lambda v: _bytes(v, g.settings["byte_units"])
        """Title and label rows for one register row."""
        if kind == "peer":
            return r["device"], [("Address", r["allowed_ips"]), ("Interface", r["interface"]), ("Last handshake", r["ago"]),
                                 ("Received", _b(r["received"])), ("Sent", _b(r["sent"])), ("Key prefix", r["id"])]
        if kind == "interface":
            return r["device"], [("Received total", _b(r["rx_total"])), ("Sent total", _b(r["tx_total"]))]
        if kind == "service":
            return r["label"], [("Unit or container", r["name"])]
        return f"{r['job']} {r['instance']}", [("Check", r["job"]), ("Target", r["instance"]), (
            "Response time", "n/a" if r["duration_s"] is None else f"{r['duration_s'] * 1000:.1f} ms")]

    @app.get("/detail/<kind>/<path:id>")
    @login_required
    def detail(kind, id):
        if kind not in CODES:
            abort(404)
        rng = rng_arg()
        reg = register()
        lst, key = KEYS[kind]
        r = next((r for r in reg[lst] if r[key] == id), None)
        if r is None:
            if not reg["unavailable"]:
                abort(404)
            r = {"code": None, "state": None, "cls": None}
            title, info = id, []
        else:
            title, info = item(kind, r)
        strip, charts = None, []
        try:
            strip = data.strips(prom, kind, RANGES[rng]).get(id)
            if kind != "service":
                try:
                    hist = data.history(prom, kind, id, RANGES[rng], monitor_cfg["services"])
                except KeyError:  # the item exists but has no samples in this range: draw an empty chart
                    hist = {}
                top = data.scale(prom, kind, RANGES[rng]) if kind == "check" else None
                span = (time.time() - RANGES[rng], time.time())
                if kind == "check":
                    ms = [(t, v * 1000) for t, v in hist.get("duration_s", [])]
                    charts = [("Response time", line_chart({"Response time": ms}, "ms", top and top * 1000, span))]
                else:
                    names = {"received": "Received", "rx": "Received", "sent": "Sent", "tx": "Sent"}
                    charts = [("Traffic", line_chart({names[k]: v for k, v in hist.items()}, "B/s", None, span))]
        except PromError:
            reg["unavailable"] = True
        return refreshed(render_template("detail.html", **reg, kind=kind, id=id, code=r["code"], state=r["state"], cls=r["cls"],
                               title=title, info=info, current=(kind, id),
                               strip=strip and state_strip(strip, STRIP_WORD[kind], _strip_cls(kind, id)),
                               strip_word=STRIP_WORD[kind], charts=charts, rng=rng, ranges=RANGES))

    @app.get("/advisories")
    @login_required
    def advisories_index():
        return render_template("advisories.html", **register(), groups=advisories.GROUPS, current=None)

    @app.get("/advisories/<rid>")
    @login_required
    def advisory(rid):
        if rid not in advisories.RULES:
            abort(404)
        rng = rng_arg()
        reg = register()
        res, (title, group, about) = reg["rules"][rid], advisories.RULES[rid]
        items = [dict(it) for it in res["items"]]
        try:
            kinds = {it["kind"] for it in items if it["kind"] in CODES}
            got = {k: data.strips(prom, k, RANGES[rng]) for k in kinds}
            for it in items:
                if it["kind"] == "posture":
                    slots = data.posture_strip(prom, advisories.POSTURE_KEY[rid], RANGES[rng])
                    word = "healthy"
                else:
                    slots, word = got.get(it["kind"], {}).get(it["id"]), STRIP_WORD.get(it["kind"])
                it["strip"] = slots and state_strip(slots, word, f"k-{it['kind']}")
                it["since"] = _since(slots, RANGES[rng])
        except PromError:
            reg["unavailable"] = True
        html, toc = wiki.render_markdown((advisories.DOCS / f"{rid}.md").read_text(encoding="utf-8"))
        return render_template("advisory.html", **reg, rid=rid, title=title, group=group, about=about, res=res,
                               items=items, html=html, toc=toc, groups=advisories.GROUPS, rng=rng, ranges=RANGES,
                               current=rid)

    @app.get("/alerts")
    @login_required
    def alerts_page():
        sev = request.args.get("sev")
        sev = sev if sev in ("finding", "advisory") else None
        return render_template("alerts.html", events=alert_history.read(cfg["ALERT_HISTORY_FILE"], sev), sev=sev, current=None)

    def render_settings(errors=(), code=200, s=None, **ctx):
        devices = load_devices(cfg["DEVICES_FILE"], cfg["DEVICE_NAMES_FILE"])
        peers, failed = fetch(lambda c: data.peers(c, devices), [])
        return render_template("settings.html", s=s or g.settings, errors=list(errors), saved=request.args.get("saved"),
                               panel_names=settings.PANELS, ranges=RANGES, units=settings._UNITS, refreshes=settings._REFRESH,
                               th_defaults=monitor_cfg["thresholds"], peers=peers, peers_failed=failed, bk=bk(),
                               categories=cfgmod.CATEGORIES, labels=cfgmod.CATEGORY_LABELS, **ctx), code

    @app.route("/settings", methods=["GET", "POST"])
    @login_required
    def settings_page():
        if request.method == "POST":
            check_csrf()
            raw = settings.from_form(request.form)
            try:
                settings.save(cfg["SETTINGS_FILE"], raw)
                return redirect(url_for("settings_page", saved=1), 303)
            except ValueError:
                return render_settings(settings.validate(raw)[1], 400, g.settings)
            except OSError:
                return render_settings(["could not write the settings file"], 500)
        return render_settings()

    @app.post("/settings/devices")
    @login_required
    def settings_devices():
        check_csrf()
        key, new = request.form.get("public_key", "").strip(), request.form.get("name", "").strip()
        if len(key) < 8 or not key.isprintable() or " " in key or not 1 <= len(new) <= 40 or not new.isprintable():
            return render_settings(["device name: needs a peer and a name of 1 to 40 characters"], 400)
        devices = load_devices(cfg["DEVICES_FILE"], cfg["DEVICE_NAMES_FILE"])
        old = devices.get(devmod.peer_label(key), "")
        try:
            devmod.save_override(cfg["DEVICE_NAMES_FILE"], key, new)
            ok, detail = True, "done"
        except OSError as e:
            ok, detail = False, str(e)
        audit.record(cfg["AUDIT_FILE"], "rename", {"public_key": key, "old": old, "new": new}, ok, detail, ip())
        if not ok:
            return render_settings(["could not write the device names file"], 500)
        return redirect(url_for("settings_page", saved=1), 303)

    BK_FIELDS = ("enabled", "interval_h", "categories", "include", "exclude", "retention_daily", "retention_weekly",
                 "retention_monthly")

    def parse_backup_form(f, targets):
        """(proposed settings for the targets in the form, errors); a field that cannot be read stays a string so the validator names it."""
        known = {"csrf_token", "confirm", "destination_root"} | {f"{k}_{t['name']}" for t in targets for k in BK_FIELDS}
        errors = [f"{k}: read-only or unknown, edit config/backups.toml" for k in f if k not in known]
        lines = lambda v: [x.strip() for x in v.splitlines() if x.strip()]
        num = lambda v: int(v) if v.strip().isascii() and v.strip().isdigit() else v
        out = {"targets": {}}
        if "destination_root" in f:
            out["destination_root"] = f["destination_root"].strip()
        for t in targets:
            n = t["name"]
            v = {"enabled": f.get(f"enabled_{n}") == "1", "categories": f.getlist(f"categories_{n}")}
            for k in ("include", "exclude"):
                if f"{k}_{n}" in f:
                    v[k] = lines(f[f"{k}_{n}"])
            if f"interval_h_{n}" in f:
                v["interval_h"] = num(f[f"interval_h_{n}"])
            ret = {k: num(f[f"retention_{k}_{n}"]) for k in ("daily", "weekly", "monthly") if f"retention_{k}_{n}" in f}
            if ret:
                v["retention"] = ret
            out["targets"][n] = v
        return out, errors

    @app.post("/settings/backups")
    @login_required
    def settings_backups():
        """Saves the destination root (Settings) or one target's settings (its target page), or both; other saved overrides are kept."""
        check_csrf()
        cur = bk()
        base = cfgmod.load_backups(cfg["BACKUPS_CONFIG"])
        sent = [t for t in cur["targets"] if f"interval_h_{t['name']}" in request.form]  # every target form has this field
        one = sent[0] if len(sent) == 1 and "destination_root" not in request.form else None
        back = url_for("backup_target", name=one["name"]) if one else url_for("settings_page")
        proposed, errors = parse_backup_form(request.form, sent)
        clean, errs = cfgmod.validate_backup_overrides(base, proposed)
        errors += errs
        if errors:
            return target_page(one, 400, error="Not saved: " + "; ".join(errors), open_settings=True) if one else render_settings(errors, 400)
        rows = []
        if clean.get("destination_root", cur["destination_root"]) != cur["destination_root"]:
            rows.append(("Destination root", cur["destination_root"], clean["destination_root"]))
        show = lambda v: (", ".join(f"{k} {n}" for k, n in v.items()) if isinstance(v, dict)
                          else ", ".join(v) or "none" if isinstance(v, list) else str(v))
        try:
            prev = json.loads(Path(cfg["BACKUP_OVERRIDES_FILE"]).read_text(encoding="utf-8"))
        except FileNotFoundError:
            prev = {}
        names = {t["name"] for t in sent}
        diff = {"targets": {n: d for n, d in prev.get("targets", {}).items() if n not in names}}
        for t in sent:
            for k, new in clean.get("targets", {}).get(t["name"], {}).items():
                old = t[k]
                if new != old:
                    rows.append((f"{t['label']}: {k}", show(old), show(new)))
            b = next(x for x in base["targets"] if x["name"] == t["name"])
            d = {k: v for k, v in clean.get("targets", {}).get(t["name"], {}).items() if k != "retention" and v != b[k]}
            r = {k: v for k, v in clean.get("targets", {}).get(t["name"], {}).get("retention", {}).items() if v != b["retention"][k]}
            if r:
                d["retention"] = r
            if d:
                diff["targets"][t["name"]] = d
        if not diff["targets"]:
            del diff["targets"]
        root = clean["destination_root"] if "destination_root" in request.form else prev.get("destination_root", base["destination_root"])
        if root != base["destination_root"]:
            diff["destination_root"] = root
        if request.form.get("confirm") != "1":
            where = "Hosts, user and MAC address" if one else "Targets"
            return render_template("backup_confirm.html", title=f"Save backup settings for {one['label']}?" if one else "Save backup settings?",
                lines=[f"These values replace the defaults from config/backups.toml. {where} can only be edited in that file."]
                if rows else ["Nothing changes."], rows=rows, action="/settings/backups", cancel=back,
                fields=[(k, v) for k, v in request.form.items(multi=True) if k not in ("csrf_token", "confirm")],
                button="Save backup settings", cats=None, **backup_side(one and one["name"]))
        try:
            Path(cfg["BACKUP_OVERRIDES_FILE"]).parent.mkdir(parents=True, exist_ok=True)
            cfgmod.save_backup_overrides(cfg["BACKUP_OVERRIDES_FILE"], diff)
            ok, detail = True, "saved"
        except OSError as e:
            ok, detail = False, str(e)
        audit.record(cfg["AUDIT_FILE"], "backup-settings", {"changes": [r[0] for r in rows]}, ok, detail, ip())
        if not ok:
            return target_page(one, 500, error="Not saved: could not write the backup overrides file") if one else \
                render_settings(["could not write the backup overrides file"], 500)
        return redirect(back + "?saved=1", 303)

    @app.get("/backups")
    @login_required
    def backups_page():
        here = load_devices(cfg["DEVICES_FILE"], cfg["DEVICE_NAMES_FILE"]).get(f"{request.remote_addr}/32")
        return render_template("backups.html", device=here, intervals={t["name"]: t["interval_h"] for t in bk()["targets"]},
                               **backup_side())

    def target_or_404(name):
        return next((t for t in bk()["targets"] if t["name"] == name), None) or abort(404)

    def snapshots_of(name):
        """(snapshots, error) from the host helper; the web side never holds a restic password."""
        if app.config["NETCTL"] is None:
            return None, "The host helper is not connected, so snapshots cannot be listed here."
        try:
            res = app.config["NETCTL"].call("backup-snapshots", target=name)
            return res.get("snapshots", []), None
        except NetctlError as e:
            return None, f"Snapshots could not be listed: {e}"

    def target_page(t, status=200, **ctx):
        side = backup_side(t["name"])
        snaps, snaps_err = snapshots_of(t["name"])
        runs = backups.read_runs(cfg["BACKUP_RUNS_FILE"], t["name"])
        row = next(r for r in side["brows"] if r["name"] == t["name"])
        reason = runs[0].get("detail") if runs and not runs[0].get("ok") and row["ok"] is False else None
        paths = sorted({p for s in snaps or [] for p in s.get("paths") or []})
        return render_template("backup_target.html", t=t, row=row, reason=reason, snaps=snaps, snaps_err=snaps_err, paths=paths,
                               exports=backups.list_exports(cfg["EXPORT_DIR"], t["name"]), exporting=request.args.get("exporting"),
                               runs=runs, labels=cfgmod.CATEGORY_LABELS, categories=cfgmod.CATEGORIES, helper=app.config["NETCTL"] is not None,
                               root=cfgmod.repo_path(bk(), t["name"]), started=request.args.get("started"),
                               saved=request.args.get("saved"), **side, **ctx), status

    @app.get("/backups/targets/<name>")
    @login_required
    def backup_target(name):
        return target_page(target_or_404(name))

    @app.post("/backups/targets/<name>/run")
    @login_required
    def backup_run(name):
        check_csrf()
        t = target_or_404(name)
        allowed = cfgmod.CATEGORIES[t["kind"]]
        confirmed = request.form.get("confirm") == "1"
        picked = request.form.getlist("categories") if confirmed else t["categories"]
        err = None
        if not picked or any(c not in allowed for c in picked):
            err = "Pick at least one category from the list."
        elif confirmed and app.config["NETCTL"] is None:
            err = "The host helper is not connected, so a backup cannot be started from here."
        if err is None and confirmed:
            args = {"target": name, "categories": list(dict.fromkeys(picked))}
            try:
                res = app.config["NETCTL"].call("backup-run", **args)
                ok, detail = True, res.get("detail", "started") if isinstance(res, dict) else "started"
            except NetctlError as e:
                ok, detail = False, str(e)
            audit.record(cfg["AUDIT_FILE"], "backup-run", args, ok, detail, ip())
            if ok:
                return redirect(url_for("backup_target", name=name, started=1), 303)
            return target_page(t, 502, error=f"Backup not started: {detail}")
        side = backup_side(name)
        row = next(r for r in side["brows"] if r["name"] == name)
        _b = lambda v: _bytes(v, g.settings["byte_units"])
        lines = ["Choose what to include for this run only. The saved selection is not changed."]
        if row["last_run"] is not None:
            lines.append(f"Last run {time.strftime('%Y-%m-%d %H:%M', time.localtime(row['last_run']))}: "
                         f"{'ok' if row['ok'] else 'failed' if row['ok'] is False else 'n/a'}. Last backup size {_b(row['size'])}.")
        if t.get("mac"):
            lines.append("If the PC is off, the server wakes it with Wake-on-LAN"
                         + (" and shuts it down again when the backup is done." if t.get("shutdown_after_wol") else "."))
        lines.append("The result appears under Recent runs on the target page when the run finishes.")
        return render_template("backup_confirm.html", title=f"Run backup of {t['label']} now?", lines=lines, rows=[], error=err,
            action=request.path, cancel=url_for("backup_target", name=name), fields=[], button="Run backup now",
            cats=[(c, cfgmod.CATEGORY_LABELS[c], c in picked) for c in sorted(allowed)], **side), 400 if err else 200

    @app.post("/backups/targets/<name>/export")
    @login_required
    def backup_export(name):
        check_csrf()
        t = target_or_404(name)
        snap, path = request.form.get("snapshot", ""), request.form.get("path", "").strip()
        if request.form.get("full"):
            path = "/"
        err = None
        if not backups.SNAPSHOT_RE.fullmatch(snap):
            err = "Pick a snapshot from the list."
        elif not backups.valid_export_path(path):
            err = "Enter an absolute folder path, for example /home/user/Documents (no ..)."
        elif app.config["NETCTL"] is None:
            err = "The host helper is not connected, so an export cannot be started from here."
        if err:
            return target_page(t, 400, export_err=err, path=path, snap=snap)
        if request.form.get("confirm") != "1":
            return render_template("backup_confirm.html", title=f"Prepare a download from {t['label']}?", lines=[
                "The server unpacks this folder from the backup into a tar archive on the NAS disk. A download link "
                "appears on the target page when it is ready; the archive is deleted about an hour later.",
                "Large folders take a while and need as much free space on the NAS disk as their size.",
                f"Snapshot {snap}, " + ("the whole snapshot." if path == "/" else f"folder {path}.")], rows=[], error=None, action=request.path,
                cancel=url_for("backup_target", name=name), fields=[("snapshot", snap), ("path", path)],
                button="Prepare download", cats=None, **backup_side(name))
        args = {"target": name, "snapshot": snap, "path": path}
        try:
            res = app.config["NETCTL"].call("backup-export", **args)
            ok, detail = True, res.get("detail", "started") if isinstance(res, dict) else "started"
        except NetctlError as e:
            ok, detail = False, str(e)
        audit.record(cfg["AUDIT_FILE"], "backup-export", args, ok, detail, ip())
        if ok:
            return redirect(url_for("backup_target", name=name, exporting=1) + "#h-dl", 303)
        return target_page(t, 502, export_err=f"Export not started: {detail}", path=path, snap=snap)

    @app.get("/backups/exports/<name>")
    @login_required
    def backup_export_file(name):
        path = backups.resolve_export(cfg["EXPORT_DIR"], name)
        if path is None:
            abort(404)
        audit.record(cfg["AUDIT_FILE"], "backup-download", {"file": name}, True, "", ip())
        return send_file(path, mimetype="application/x-tar", as_attachment=True, download_name=name)

    @app.get("/backups/<kind>/<name>")
    @login_required
    def backup_file(kind, name):
        path = backups.resolve(cfg["BACKUP_DIR"], kind, name)
        if path is None:
            abort(404)
        return send_file(path, mimetype="application/gzip", as_attachment=True, download_name=name)

    @app.get("/wiki")
    @login_required
    def wiki_index():
        return wiki_page("index")

    @app.get("/wiki/<slug>")
    @login_required
    def wiki_page(slug):
        try:
            title, html, toc = wiki.render_page(cfg["WIKI_DIR"], slug)
        except (KeyError, ValueError):
            abort(404)
        secs = wiki.sections(cfg["WIKI_DIR"])
        where = next(((name, about) for name, rows in secs for s, _, about in rows if s == slug), (None, None))
        updated = time.strftime("%-d %b %Y", time.localtime((Path(cfg["WIKI_DIR"]) / f"{slug}.md").stat().st_mtime))
        body = re.sub(r"^<h1[^>]*>.*?</h1>\s*", "", html, count=1, flags=re.S)  # the template sets the title itself
        return render_template("wiki_page.html", title=title, html=body, toc=toc, slug=slug, sections=secs,
                               section=where[0], about=where[1], updated=updated)

    return app
