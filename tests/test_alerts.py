import importlib.util
import json
from pathlib import Path

import time
import urllib.error
import urllib.request

import pytest

from conftest import FakeProm, vec

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "monitor/host/omv-alerts.py"
SECRET = "s3cr3t-app-pw"


def load():
    spec = importlib.util.spec_from_file_location("omv_alerts", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeSMTP:
    sent = []
    fail = False

    logins = []
    hosts = []

    def __init__(self, host=None, *a, **k):
        FakeSMTP.hosts.append(host)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def login(self, user, pw):
        FakeSMTP.logins.append((user, pw))
        if FakeSMTP.fail:
            raise OSError("smtp down")

    def send_message(self, msg, *a, **k):
        if FakeSMTP.fail:
            raise OSError("smtp down")
        FakeSMTP.sent.append(msg)

    sendmail = send_message


@pytest.fixture
def env(tmp_path, monkeypatch, fake):
    FakeSMTP.sent, FakeSMTP.fail, FakeSMTP.logins, FakeSMTP.hosts = [], False, [], []
    mod = load()
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "smtp.env").write_text(f"OMV_SMTP_HOST=smtp.example.org\nOMV_SMTP_USER=bot@example.org\n"
                                      f"OMV_SMTP_PASSWORD={SECRET}\n")
    monkeypatch.setattr(mod, "SECRETS_FILE", secrets / "smtp.env", raising=False)
    monkeypatch.setattr(mod, "HISTORY_FILE", tmp_path / "alert-history.jsonl", raising=False)
    monkeypatch.setattr(mod, "MONITOR_TOML", ROOT / "monitor/config/monitor.toml", raising=False)
    monkeypatch.setattr(mod, "SETTINGS_FILE", tmp_path / "settings.json", raising=False)
    monkeypatch.setattr(mod, "STATE_FILE", tmp_path / "state.json", raising=False)
    monkeypatch.setattr(mod, "AUDIT_FILE", tmp_path / "audit.jsonl", raising=False)
    # healthy baseline: the shared fixture has nginx stopped and one ping check down
    fake.data["omv_service_active"] = [vec(1, service="smbd"), vec(1, service="nginx"), vec(1, service="ssh")]
    fake.data["probe_success"] = [vec(1, job="ping", instance="1.1.1.1"), vec(1, job="ping", instance="192.168.1.1"),
                                  vec(1, job="dns", instance="1.1.1.1")]
    fake.data["omv_wg_latest_handshake_timestamp_seconds"] = [vec(time.time() - 60, peer="k1", allowed_ips="10.0.0.2/32")]
    set_web(monkeypatch, True)
    return mod, fake, tmp_path, {}


def set_web(monkeypatch, up):
    """Stub the default probe's network call: up -> any HTTP response, else URLError."""
    def fake_urlopen(*a, **k):
        if up:
            return type("R", (), {"__enter__": lambda s: s, "__exit__": lambda s, *x: False, "status": 200,
                                  "read": lambda s, *n: b"", "close": lambda s: None})()
        raise urllib.error.URLError("refused")
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)


def run(mod, client, e):
    return mod.main([], env=e, client=client, smtp_factory=FakeSMTP)


def fail_check(fake, ok=0):
    fake.data["probe_success"] = [vec(1, job="ping", instance="1.1.1.1"), vec(ok, job="ping", instance="192.168.1.1"),
                                  vec(1, job="dns", instance="1.1.1.1")]


def fnd(cur):
    return [f for f in cur if f["sev"] == "finding"]


def history(tmp_path):
    p = tmp_path / "alert-history.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def body(msg):
    return msg.get_content() if hasattr(msg, "get_content") else str(msg)


def test_healthy_sends_nothing(env):
    mod, fake, _, e = env
    assert run(mod, fake, e) == 0
    assert FakeSMTP.sent == []


def test_failing_check_mailed_once(env):
    mod, fake, _, e = env
    fail_check(fake)
    assert run(mod, fake, e) == 0
    assert len(FakeSMTP.sent) == 1
    assert "192.168.1.1" in body(FakeSMTP.sent[0]) + str(FakeSMTP.sent[0]["Subject"])
    assert run(mod, fake, e) == 0
    assert len(FakeSMTP.sent) == 1


def test_current_findings_keys_and_new_findings(env):
    mod, fake, _, _ = env
    fail_check(fake)
    cur = mod.current_findings(fake, {})
    assert fnd(cur) and {f["sev"] for f in cur} <= {"finding", "advisory"}
    assert all(f["key"] == f"{f['rule']}:{f['title']}" for f in cur)
    assert len(mod.new_findings(cur, [])) == len(cur)
    assert not mod.new_findings(cur, [f["key"] for f in cur])


def test_recurrence_mails_again(env):
    mod, fake, _, e = env
    fail_check(fake)
    run(mod, fake, e)
    fail_check(fake, ok=1)
    run(mod, fake, e)
    assert len(FakeSMTP.sent) == 1
    fail_check(fake)
    run(mod, fake, e)
    assert len(FakeSMTP.sent) == 2


def test_missing_password(env, capsys):
    mod, fake, tmp, _ = env
    fail_check(fake)
    (tmp / "secrets" / "smtp.env").unlink()
    assert run(mod, fake, {"OMV_SMTP_PASSWORD": SECRET}) != 0  # the environment is no longer a credential source
    assert FakeSMTP.sent == []
    out = capsys.readouterr()
    assert SECRET not in out.out + out.err


def test_smtp_failure_retries(env, capsys):
    mod, fake, tmp, e = env
    fail_check(fake)
    FakeSMTP.fail = True
    assert run(mod, fake, e) != 0
    state = tmp / "state.json"
    assert not state.exists() or SECRET not in state.read_text()
    out = capsys.readouterr()
    assert SECRET not in out.out + out.err
    FakeSMTP.fail = False
    assert run(mod, fake, e) == 0
    assert len(FakeSMTP.sent) == 1


def test_prometheus_unavailable_mailed(env):
    mod, _, _, e = env

    class Down:
        def query(self, expr):
            raise OSError("down")

        query_range = lambda self, *a: (_ for _ in ()).throw(OSError("down"))

    assert run(mod, Down(), e) == 0
    assert len(FakeSMTP.sent) == 1
    assert "Prometheus data unavailable" in body(FakeSMTP.sent[0]) + str(FakeSMTP.sent[0]["Subject"])


def test_state_and_audit_have_no_secret(env):
    mod, fake, tmp, e = env
    fail_check(fake)
    run(mod, fake, e)
    assert SECRET not in (tmp / "state.json").read_text()
    lines = [json.loads(x) for x in (tmp / "audit.jsonl").read_text().splitlines()]
    assert lines and lines[-1]["action"] == "alert-email"
    assert SECRET not in json.dumps(lines)
    assert SECRET not in body(FakeSMTP.sent[0]) + str(FakeSMTP.sent[0].items())


def test_recipient_override(env):
    mod, fake, _, e = env
    fail_check(fake)
    run(mod, fake, {**e, "OMV_ALERT_TO": "x@example.com"})
    assert "x@example.com" in str(FakeSMTP.sent[0]["To"])


def test_script_has_no_flask_or_web_import():
    src = SCRIPT.read_text()
    assert "flask" not in src.lower() and "app.web" not in src


def test_units():
    t = (ROOT / "monitor/host/omv-alerts.timer").read_text()
    assert "OnBootSec=2min" in t and "OnUnitActiveSec=60s" in t
    s = (ROOT / "monitor/host/omv-alerts.service").read_text()
    for needle in ("Type=oneshot", "EnvironmentFile=-/etc/omv-monitor/alerts.env", "StateDirectory=omv-alerts",
                   "ExecStart=/usr/bin/python3 /opt/omv-monitor/host/omv-alerts.py"):
        assert needle in s
    assert SECRET not in s


def test_wiki_documents_setup():
    w = (ROOT / "monitor/wiki/alerts.md").read_text()
    for needle in ("secrets/smtp.env", "OMV_SMTP_PASSWORD", "omv-alerts.timer", "600", "revoke"):
        assert needle in w


def titles(cur):
    return {(f["rule"], f["title"]) for f in cur}


def test_web_url_constant(env):
    assert env[0].WEB_URL == "https://192.168.1.10:8443/login"
    assert not hasattr(env[0], "STALE_S")  # replaced by the handshake_stale_s threshold


def test_web_down_finding_via_probe(env):
    mod, fake, _, _ = env
    cur = mod.current_findings(fake, {}, probe=lambda: False)
    assert ("monitoring-data", "Web app unreachable") in titles(cur)
    assert all(f["key"] == f"{f['rule']}:{f['title']}" for f in cur)
    assert not titles(fnd(mod.current_findings(fake, {}, probe=lambda: True)))


def test_web_probe_runs_when_prometheus_down(env):
    mod, fake, _, _ = env
    def boom(*a, **k):
        raise OSError("prom down")
    fake.query = boom
    cur = titles(mod.current_findings(fake, {}, probe=lambda: False))
    assert ("monitoring-data", "Web app unreachable") in cur
    assert any(t == "Prometheus data unavailable" for _, t in cur)


def test_default_probe_semantics(env, monkeypatch):
    mod, fake, _, _ = env
    for up, exc in ((True, None),
                    (True, urllib.error.HTTPError(mod.WEB_URL, 401, "no", {}, None)),
                    (False, urllib.error.URLError("refused")),
                    (False, TimeoutError("slow")),
                    (False, OSError("net"))):
        def fake_urlopen(*a, _exc=exc, **k):
            if _exc:
                raise _exc
            return type("R", (), {"__enter__": lambda s: s, "__exit__": lambda s, *x: False,
                                  "read": lambda s, *n: b"", "close": lambda s: None})()
        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        got = ("monitoring-data", "Web app unreachable") in titles(mod.current_findings(fake, {}))
        assert got is (not up)


def test_web_down_mailed_once(env, monkeypatch):
    mod, fake, _, e = env
    set_web(monkeypatch, False)
    assert run(mod, fake, e) == 0
    assert len(FakeSMTP.sent) == 1 and "Web app unreachable" in FakeSMTP.sent[0]["Subject"]
    run(mod, fake, e)
    assert len(FakeSMTP.sent) == 1


NOW = 1_800_000_000.0


def peers(fake, **hs):
    fake.data["omv_wg_latest_handshake_timestamp_seconds"] = [
        vec(t, peer=k, allowed_ips=f"10.0.0.{n}/32", interface="wgnet1") for n, (k, t) in enumerate(hs.items(), 2)]


def test_stale_peer_only(env):
    mod, fake, _, _ = env
    peers(fake, old=NOW - 7 * 86400 - 60, fresh=NOW - 600, never=0)
    devs = {"10.0.0.2/32": "Old phone", "10.0.0.3/32": "Fresh laptop", "10.0.0.4/32": "Never tablet"}
    cur = mod.current_findings(fake, devs, now=NOW, probe=lambda: True)
    stale = [f for f in fnd(cur) if f["rule"] == "handshake-age"]
    assert len(stale) == 1 and "Old phone" in stale[0]["title"]
    assert not any("Fresh laptop" in f["title"] or "Never tablet" in f["title"] for f in fnd(cur))


def test_stale_peer_mailed(env, monkeypatch):
    mod, fake, _, e = env
    peers(fake, old=time.time() - 8 * 86400)
    assert run(mod, fake, e) == 0
    assert len(FakeSMTP.sent) == 1 and "handshake" in FakeSMTP.sent[0]["Subject"].lower()


def test_fresh_and_never_peers_send_nothing(env):
    mod, fake, _, e = env
    peers(fake, fresh=time.time() - 60, never=0)
    assert run(mod, fake, e) == 0
    assert FakeSMTP.sent == []


def test_failing_disk_mailed(env):
    mod, fake, _, e = env
    fake.data["omv_smart_healthy"] = [vec(1, device="sda"), vec(0, device="sdb")]
    assert any(r == "disk-health" for r, _ in titles(fnd(mod.current_findings(fake, {}, probe=lambda: True))))
    assert run(mod, fake, e) == 0
    assert len(FakeSMTP.sent) == 1 and "sdb" in FakeSMTP.sent[0]["Subject"]


def test_expired_certificate_mailed(env):
    mod, fake, _, e = env
    fake.data["omv_cert_expiry_timestamp_seconds"] = [vec(time.time() - 3600)]
    assert any(r == "certificate-expiry" for r, _ in titles(fnd(mod.current_findings(fake, {}, probe=lambda: True))))
    assert run(mod, fake, e) == 0
    assert len(FakeSMTP.sent) == 1


# ---- credentials from the secrets file ----
def test_credentials_come_from_secrets_file(env):
    mod, fake, _, e = env
    fail_check(fake)
    assert run(mod, fake, e) == 0
    assert FakeSMTP.logins == [("bot@example.org", SECRET)]
    assert FakeSMTP.hosts == ["smtp.example.org"]
    assert "bot@example.org" in str(FakeSMTP.sent[0]["From"])


def test_missing_secrets_file_logs_and_still_writes_history(env, capsys):
    mod, fake, tmp, _ = env
    (tmp / "secrets" / "smtp.env").unlink()
    fail_check(fake)
    rc = run(mod, fake, {"OMV_SMTP_PASSWORD": SECRET})
    assert isinstance(rc, int) and FakeSMTP.sent == []
    assert any(h["event"] == "raised" and h["sev"] == "finding" for h in history(tmp))
    out = capsys.readouterr()
    assert out.err.strip() and SECRET not in out.out + out.err


def test_secrets_file_values_never_logged(env, capsys):
    mod, fake, tmp, e = env
    fail_check(fake)
    FakeSMTP.fail = True
    run(mod, fake, e)
    out = capsys.readouterr()
    assert SECRET not in out.out + out.err


# ---- alert history ----
def test_history_raised_then_cleared(env):
    mod, fake, tmp, e = env
    fail_check(fake)
    run(mod, fake, e)
    raised = [h for h in history(tmp) if h["rule"] == "connectivity-checks"]
    assert len(raised) == 1 and raised[0]["event"] == "raised" and raised[0]["sev"] == "finding"
    assert "192.168.1.1" in raised[0]["title"] and isinstance(raised[0]["ts"], float)
    run(mod, fake, e)  # unchanged -> no new events
    assert len([h for h in history(tmp) if h["rule"] == "connectivity-checks"]) == 1
    fail_check(fake, ok=1)
    run(mod, fake, e)
    ev = [h for h in history(tmp) if h["rule"] == "connectivity-checks"]
    assert [h["event"] for h in ev] == ["raised", "cleared"] and ev[1]["title"] == ev[0]["title"]
    assert len(FakeSMTP.sent) == 1  # clearing mails nothing


def test_history_records_advisories_without_email(env):
    mod, fake, tmp, e = env
    fake.data["omv_reboot_required"] = [vec(1)]
    fake.data["omv_apt_upgrades_pending"] = [vec(0)]
    assert run(mod, fake, e) == 0
    adv_ev = [h for h in history(tmp) if h["rule"] == "reboot-required"]
    assert len(adv_ev) == 1 and adv_ev[0]["event"] == "raised" and adv_ev[0]["sev"] == "advisory"
    assert FakeSMTP.sent == []
    fake.data["omv_reboot_required"] = [vec(0)]
    run(mod, fake, e)
    assert [h["event"] for h in history(tmp) if h["rule"] == "reboot-required"] == ["raised", "cleared"]


def test_history_pruned_to_retention(env):
    mod, fake, tmp, e = env
    old = {"ts": time.time() - 200 * 86400, "event": "raised", "sev": "finding", "rule": "x", "title": "ancient"}
    (tmp / "alert-history.jsonl").write_text(json.dumps(old) + "\n")
    run(mod, fake, e)  # monitor.toml: alert_history_days = 90
    assert "ancient" not in (tmp / "alert-history.jsonl").read_text()


def test_history_written_even_when_smtp_fails(env):
    mod, fake, tmp, e = env
    fail_check(fake)
    FakeSMTP.fail = True
    run(mod, fake, e)
    assert any(h["event"] == "raised" for h in history(tmp))


# ---- thresholds from settings overrides ----
def test_settings_override_changes_handshake_threshold(env):
    mod, fake, tmp, _ = env
    peers(fake, p=NOW - 900)
    kw = dict(now=NOW, probe=lambda: True)
    assert not [f for f in fnd(mod.current_findings(fake, {}, **kw)) if f["rule"] == "handshake-age"]
    (tmp / "settings.json").write_text(json.dumps({"thresholds": {"handshake_stale_s": 600}}))
    assert [f for f in fnd(mod.current_findings(fake, {}, **kw)) if f["rule"] == "handshake-age"]


def test_disk_usage_threshold_from_monitor_toml(env):
    mod, fake, _, _ = env
    fake.data["node_filesystem_size_bytes"] = [vec(1000, mountpoint="/", fstype="ext4")]
    fake.data["node_filesystem_avail_bytes"] = [vec(100, mountpoint="/", fstype="ext4")]  # 90% used, default 85
    assert any(f["rule"] == "disk-usage" for f in mod.current_findings(fake, {}, probe=lambda: True))


def test_escalation_to_finding_is_new(env):
    # state holds finding keys only, so an advisory that later becomes a finding (same rule:title) still mails
    mod = env[0] if isinstance(env, tuple) else env
    f = {"sev": "finding", "rule": "disk-usage", "title": "Disk /srv 95%", "key": "disk-usage:Disk /srv 95%"}
    assert mod.new_findings([f], []) == [f]
