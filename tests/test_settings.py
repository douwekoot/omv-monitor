import json

import pytest

from app import settings


def test_defaults_when_missing(tmp_path):
    s = settings.load(tmp_path / "nope.json")
    assert s == settings.DEFAULTS
    s["panels"].append("x")
    assert "x" not in settings.DEFAULTS["panels"]


def test_corrupt_json(tmp_path):
    p = tmp_path / "s.json"
    p.write_text("{not json")
    assert settings.load(p) == settings.DEFAULTS


def test_round_trip(tmp_path):
    p = tmp_path / "sub" / "s.json"
    vals = {"default_range": "7d", "refresh_s": 60, "byte_units": "decimal",
            "handshake_good_s": 300, "panels": ["peers", "traffic"], "thresholds": {}}
    assert settings.save(p, vals) == vals
    assert settings.load(p) == vals


def test_unknown_keys_dropped(tmp_path):
    clean, errors = settings.validate({"evil": 1, "refresh_s": 30})
    assert "evil" not in clean and clean["refresh_s"] == 30 and errors == []
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"evil": 1}))
    assert "evil" not in settings.load(p)


@pytest.mark.parametrize("key,value", [
    ("default_range", "30d"),
    ("refresh_s", 7),
    ("handshake_good_s", 5),
    ("handshake_good_s", 99999),
    ("handshake_good_s", "abc"),
    ("handshake_good_s", 1.5),
    ("panels", ["traffic", "bogus"]),
    ("panels", "traffic"),
    ("byte_units", "x"),
])
def test_invalid_values(key, value):
    clean, errors = settings.validate({key: value})
    assert len(errors) == 1 and key in errors[0]
    assert clean[key] == settings.DEFAULTS[key]


def test_save_invalid_leaves_file(tmp_path):
    p = tmp_path / "s.json"
    settings.save(p, {"refresh_s": 30})
    before = p.read_text()
    with pytest.raises(ValueError):
        settings.save(p, {"refresh_s": 7})
    assert p.read_text() == before
    assert [f.name for f in tmp_path.iterdir()] == ["s.json"]


class Form(dict):
    def getlist(self, k):
        v = self.get(k, [])
        return v if isinstance(v, list) else [v]


def test_from_form():
    raw = settings.from_form(Form(default_range="7d", refresh_s="60",
                                  byte_units="decimal", handshake_good_s="120",
                                  panels=["checks", "traffic"]))
    clean, errors = settings.validate(raw)
    assert errors == []
    assert clean == {"default_range": "7d", "refresh_s": 60, "byte_units": "decimal",
                     "handshake_good_s": 120, "panels": ["checks", "traffic"], "thresholds": {}}


def test_from_form_plain_dict_and_bad():
    raw = settings.from_form({"refresh_s": "7", "panels": "peers"})
    clean, errors = settings.validate(raw)
    assert len(errors) == 1 and clean["panels"] == ["peers"]


@pytest.mark.parametrize("value", ["6_0", " 6_0 ", "+60", "٦٠", "60.0"])
def test_numbers_with_odd_syntax_rejected(value):
    _, errors = settings.validate({"handshake_good_s": value})
    assert len(errors) == 1


def test_from_form_drops_hidden_empty_panel_marker():
    raw = settings.from_form({"panels": ""})
    assert raw == {"panels": []}
    clean, errors = settings.validate(raw)
    assert errors == [] and clean["panels"] == []


def test_new_panels_known_and_default_on():
    assert {"disks", "containers"} <= set(settings.PANELS)
    assert {"disks", "containers"} <= set(settings.load("/nonexistent/s.json")["panels"])


def test_old_settings_file_without_thresholds(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"refresh_s": 30, "panels": ["peers"]}))
    s = settings.load(p)
    assert s["refresh_s"] == 30 and s["thresholds"] == {}
    assert settings.DEFAULTS["thresholds"] == {}


def test_threshold_overrides_valid(tmp_path):
    t = {"disk_pct": 90, "handshake_stale_s": 600, "backup_age_h": 12}
    clean, errors = settings.validate({"thresholds": t})
    assert errors == [] and clean["thresholds"] == t
    p = tmp_path / "s.json"
    assert settings.save(p, {"thresholds": {"disk_pct": 70}})["thresholds"] == {"disk_pct": 70}
    assert settings.load(p)["thresholds"] == {"disk_pct": 70}


@pytest.mark.parametrize("t", [
    {"disk_pct": 49}, {"disk_pct": 100}, {"disk_pct": "x"}, {"disk_pct": True},
    {"handshake_stale_s": 59}, {"handshake_stale_s": 604801},
    {"backup_age_h": 0}, {"backup_age_h": 721},
])
def test_threshold_overrides_invalid(t):
    clean, errors = settings.validate({"thresholds": t})
    assert len(errors) == 1 and next(iter(t)) in errors[0]
    assert clean["thresholds"] == {}


def test_threshold_unknown_key_and_wrong_type():
    clean, errors = settings.validate({"thresholds": {"evil": 1, "disk_pct": 60}})
    assert "evil" not in clean["thresholds"] and clean["thresholds"] == {"disk_pct": 60}
    clean, errors = settings.validate({"thresholds": [1]})
    assert len(errors) == 1 and clean["thresholds"] == {}


def test_thresholds_merge():
    defaults = {"disk_pct": 85, "handshake_stale_s": 86400, "backup_age_h": 36}
    assert settings.thresholds({"thresholds": {}}, defaults) == defaults
    assert settings.thresholds({"thresholds": {"disk_pct": 70}}, defaults) == {**defaults, "disk_pct": 70}
    assert settings.thresholds({}, defaults) == defaults


def test_from_form_thresholds():
    raw = settings.from_form(Form(disk_pct="70", handshake_stale_s="", backup_age_h="12"))
    clean, errors = settings.validate(raw)
    assert errors == [] and clean["thresholds"] == {"disk_pct": 70, "backup_age_h": 12}
    _, errors = settings.validate(settings.from_form(Form(disk_pct="5")))
    assert len(errors) == 1


def test_from_form_reset_thresholds():
    raw = settings.from_form(Form(disk_pct="70", reset_thresholds="1"))
    clean, errors = settings.validate(raw)
    assert errors == [] and clean["thresholds"] == {}
