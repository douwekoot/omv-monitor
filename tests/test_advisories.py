from app import advisories as adv

NOW = 1_000_000_000
DAY = 86400


def ev(**kw):
    return adv.evaluate([], [], [], [], [], False, **kw)


def titles(r, rid):
    return {(sev, title) for sev, _code, title, _note in r[rid]["raised"]}


def test_new_rules_registered():
    assert adv.RULES["disk-health"][1] == "Disks"
    assert adv.RULES["certificate-expiry"][1] == "Certificate"
    for rid in ("disk-health", "certificate-expiry"):
        assert (adv.DOCS / f"{rid}.md").is_file()


def test_not_evaluated_passes_without_items():
    r = ev()
    for rid in ("disk-health", "certificate-expiry"):
        assert r[rid]["status"] == "pass" and r[rid]["raised"] == [] and r[rid]["items"] == []


def test_disks_raise_cases():
    r = ev(disks=[{"device": "sda", "healthy": True}, {"device": "sdb", "healthy": False},
                  {"device": "sdc", "healthy": None}])
    assert titles(r, "disk-health") == {("finding", "sdb SMART health check failed"),
                                        ("advisory", "sdc SMART not reported")}
    assert r["disk-health"]["status"] == "finding"
    assert len(r["disk-health"]["items"]) == 3
    assert all(i["kind"] == "disk" and i["href"] is None for i in r["disk-health"]["items"])


def test_disks_healthy_passes_and_empty_is_advisory():
    assert ev(disks=[{"device": "sda", "healthy": True}])["disk-health"]["status"] == "pass"
    r = ev(disks=[])
    assert titles(r, "disk-health") == {("advisory", "Disk health not reported")}
    assert r["disk-health"]["status"] == "advisory"


def test_cert_not_reported():
    r = ev(cert_expiry=None, now=NOW)
    assert r["certificate-expiry"]["status"] == "pass"  # None means not evaluated
    assert adv.CERT_WARN_DAYS == 30 and adv.CERT_FINDING_DAYS == 7


def test_cert_thresholds():
    def t(delta):
        return titles(ev(cert_expiry=NOW + delta, now=NOW), "certificate-expiry")
    assert t(-1) == {("finding", "Certificate has expired")}
    assert t(6.9 * DAY) == {("finding", "Certificate expires within 7 days")}
    assert t(7.1 * DAY) == {("advisory", "Certificate expires within 30 days")}
    assert t(29.9 * DAY) == {("advisory", "Certificate expires within 30 days")}
    assert t(30.1 * DAY) == set()


def test_cert_reported_but_absent_raises_advisory():
    r = ev(cert_expiry=None, cert_reported=True, now=NOW)
    assert titles(r, "certificate-expiry") == {("advisory", "Certificate expiry not reported")}
    assert r["certificate-expiry"]["status"] == "advisory"


def test_cert_reported_with_value_ignores_flag():
    assert ev(cert_expiry=NOW + 90 * DAY, cert_reported=True, now=NOW)["certificate-expiry"]["status"] == "pass"


# ---- maintenance, disk usage, handshake age ----
import pytest  # noqa: E402

from app.config import THRESHOLD_DEFAULTS  # noqa: E402

NEW = ("os-updates", "reboot-required", "backup-overdue", "disk-usage", "handshake-age")
HOUR = 3600


def th(**kw):
    return {**THRESHOLD_DEFAULTS, **kw}


def sevs(r, rid):
    return {s for s, *_ in r[rid]["raised"]}


def bk(age_h=1, ok=True, target="nas", **kw):
    return {"target": target, "last_success": NOW - age_h * HOUR, "last_run": NOW - age_h * HOUR, "ok": ok,
            "size": 1e9, "interval_s": 86400, **kw}


def test_every_new_rule_registered_documented_and_grouped():
    in_groups = {rid for _g, rules in adv.GROUPS for rid, _t, _a in rules}
    for rid in NEW:
        assert rid in adv.RULES and rid in in_groups
        assert (adv.DOCS / f"{rid}.md").read_text().strip()
    for rid in ("os-updates", "reboot-required", "backup-overdue"):
        assert adv.RULES[rid][1] == "Maintenance"
    assert [g for g, _ in adv.GROUPS].count("Maintenance") == 1


def test_old_calls_still_work_and_new_rules_pass_when_not_evaluated():
    r = adv.evaluate([], [], [], [], [], False)
    r2 = ev(disks=[], cert_expiry=None, now=NOW)
    for res in (r, r2):
        for rid in NEW:
            assert res[rid]["status"] == "pass" and res[rid]["raised"] == [] and res[rid]["items"] == []


def test_os_updates():
    assert sevs(ev(updates={"pending": 3, "reboot": False}), "os-updates") == {"advisory"}
    ok = ev(updates={"pending": 0, "reboot": False})
    assert ok["os-updates"]["status"] == "pass" and ok["os-updates"]["items"]


def test_reboot_required():
    assert sevs(ev(updates={"pending": 0, "reboot": True}), "reboot-required") == {"advisory"}
    assert ev(updates={"pending": 0, "reboot": False})["reboot-required"]["status"] == "pass"


def test_updates_unknown_is_na_not_pass():
    r = ev(updates={"pending": None, "reboot": None})
    for rid in ("os-updates", "reboot-required"):
        assert r[rid]["status"] != "pass"
        assert [i["state"] for i in r[rid]["items"]] == ["n/a"]


def test_disk_usage_threshold_and_custom():
    def st(pct, **kw):
        return ev(filesystems=[{"mount": "/", "used_pct": pct}], **kw)["disk-usage"]["status"]
    assert st(84.9) == "pass" and st(85.0) != "pass" and st(97) != "pass"
    assert st(70, thresholds=th(disk_pct=60)) != "pass"
    assert st(90, thresholds=th(disk_pct=95)) == "pass"
    r = ev(filesystems=[{"mount": "/", "used_pct": 40}, {"mount": "/srv", "used_pct": 90}])
    assert len(r["disk-usage"]["items"]) == 2
    assert any("/srv" in t for _s, t in titles(r, "disk-usage"))


def test_disk_usage_unknown_is_na():
    r = ev(filesystems=[{"mount": "/", "used_pct": None}])
    assert r["disk-usage"]["status"] != "pass" and r["disk-usage"]["items"][0]["state"] == "n/a"


def test_handshake_age_threshold_and_custom():
    def st(age, **kw):
        p = [{"device": "Phone", "last_handshake": NOW - age}]
        return adv.evaluate(p, [], [], [], [], False, now=NOW, **kw)["handshake-age"]
    assert st(7 * DAY - 60)["status"] == "pass"
    stale = st(7 * DAY + 60)
    assert stale["status"] == "finding" and any("Phone" in t for _s, _c, t, _n in stale["raised"])
    assert st(900, thresholds=th(handshake_stale_s=600))["status"] != "pass"
    assert st(900, thresholds=th(handshake_stale_s=3600))["status"] == "pass"


def test_handshake_never_is_na():
    r = adv.evaluate([{"device": "Tablet", "last_handshake": None}], [], [], [], [], False, now=NOW)["handshake-age"]
    assert r["status"] != "pass" and r["items"][0]["state"] == "n/a" and "finding" not in sevs({"x": r}, "x")


def test_backup_overdue_threshold_and_severity():
    def st(age, **kw):
        return ev(backups=[bk(age_h=age, **kw.pop("b", {}))], now=NOW, **kw)["backup-overdue"]
    assert st(35)["status"] == "pass"
    assert st(37)["status"] == "advisory"
    assert st(71)["status"] == "advisory"
    assert st(73)["status"] == "finding"
    assert st(37, b={"ok": False})["status"] == "finding"
    assert st(10, thresholds=th(backup_age_h=6))["status"] == "advisory"
    assert st(10, thresholds=th(backup_age_h=48))["status"] == "pass"
    assert st(100, thresholds=th(backup_age_h=48))["status"] == "finding"
    assert any("nas" in t for _s, _c, t, _n in st(37)["raised"])


def test_backup_overdue_unknown_and_unreported_target():
    r = ev(backups=[bk(last_success=None)], now=NOW)["backup-overdue"]
    assert r["status"] != "pass" and r["items"][0]["state"] == "n/a"
    r = ev(backups=[bk(target="nas")], backup_targets=["nas", "laptop"], now=NOW)["backup-overdue"]
    assert r["status"] == "advisory"
    assert any("not reported" in t and "laptop" in t for _s, _c, t, _n in r["raised"])
    r = ev(backups=[], backup_targets=["laptop"], now=NOW)["backup-overdue"]
    assert any("not reported" in t for _s, _c, t, _n in r["raised"])
    assert ev(backups=[bk()], backup_targets=["nas"], now=NOW)["backup-overdue"]["status"] == "pass"


def test_titles_stable_when_numbers_change():
    def titles(pct, n):
        r = adv.evaluate([], [], [], [], [], False, filesystems=[{"mount": "/", "used_pct": pct}], updates={"pending": n, "reboot": False})
        return sorted(f["title"] for f in adv.findings(r)[0])
    assert titles(91, 3) == titles(96, 7)


def test_backup_disabled_target_ignored_and_labels_used():
    r = ev(backups=[bk(target="laptop", last_success=None), bk(target="pc", age_h=37)],
           backup_targets={"pc": "Desktop PC"}, now=NOW)["backup-overdue"]
    titles = [t for _s, _c, t, _n in r["raised"]]
    assert titles == ["Backup of Desktop PC is overdue"]
    assert [it["id"] for it in r["items"]] == ["pc"]
