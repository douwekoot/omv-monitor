import pytest

import json

from app.devices import device_name, load_devices, read_overrides, save_override


def test_load_devices(tmp_path):
    f = tmp_path / "devices.toml"
    f.write_text('[devices]\n"10.8.0.2/32" = "Laptop"\n"10.8.0.1/32" = "Phone"\n')
    assert load_devices(f) == {"10.8.0.2/32": "Laptop", "10.8.0.1/32": "Phone"}


def test_missing_file_is_empty(tmp_path):
    assert load_devices(tmp_path / "nope.toml") == {}


def test_device_name_fallback():
    d = {"10.8.0.2/32": "Laptop"}
    assert device_name("10.8.0.2/32", d) == "Laptop"
    assert device_name("10.8.0.9/32", d) == "10.8.0.9/32"


def test_overrides_win_and_add(tmp_path):
    t = tmp_path / "devices.toml"
    t.write_text('[devices]\n"10.8.0.2/32" = "Laptop"\n"10.8.0.1/32" = "Phone"\n')
    o = tmp_path / "device_names.json"
    o.write_text('{"10.8.0.2/32": "Work laptop", "10.8.0.9/32": "Tablet"}')
    assert load_devices(t, o) == {"10.8.0.2/32": "Work laptop", "10.8.0.1/32": "Phone", "10.8.0.9/32": "Tablet"}


def test_overrides_missing_is_ignored(tmp_path):
    t = tmp_path / "devices.toml"
    t.write_text('[devices]\n"10.8.0.2/32" = "Laptop"\n')
    assert load_devices(t, tmp_path / "nope.json") == {"10.8.0.2/32": "Laptop"}
    assert load_devices(t, overrides=None) == {"10.8.0.2/32": "Laptop"}


@pytest.mark.parametrize("body", ["{not json", "", '["a", "b"]', '"just a string"', "\x00\xff"])
def test_overrides_garbled_is_ignored(tmp_path, body):
    t = tmp_path / "devices.toml"
    t.write_text('[devices]\n"10.8.0.2/32" = "Laptop"\n')
    o = tmp_path / "device_names.json"
    o.write_bytes(body.encode("latin-1"))
    assert load_devices(t, o) == {"10.8.0.2/32": "Laptop"}


def test_overrides_work_without_toml(tmp_path):
    o = tmp_path / "device_names.json"
    o.write_text('{"10.8.0.9/32": "Tablet"}')
    assert load_devices(tmp_path / "nope.toml", o) == {"10.8.0.9/32": "Tablet"}


def test_device_name_prefers_public_key_over_allowed_ips():
    d = {"KEY=": "Renamed", "10.8.0.2/32": "Laptop"}
    assert device_name("10.8.0.2/32", d, "KEY=") == "Renamed"
    assert device_name("10.8.0.2/32", d, "OTHER=") == "Laptop"
    assert device_name("10.8.0.9/32", d, "KEY=") == "Renamed"


@pytest.mark.parametrize("name", ["", "   ", "x" * 41, "a\nb", "a\0b", "a\tb", 5, None, ["a"]])
def test_save_override_rejects_bad_names(tmp_path, name):
    f = tmp_path / "names.json"
    with pytest.raises(ValueError):
        save_override(f, "AbCdEfGhIjKl", name)
    assert not f.exists()


@pytest.mark.parametrize("key", ["", "short", "ab cd efgh", "abcdefgh\n", "abcdefgh\0", 5, None])
def test_save_override_rejects_bad_keys(tmp_path, key):
    f = tmp_path / "names.json"
    with pytest.raises(ValueError):
        save_override(f, key, "Laptop")
    assert not f.exists()


def test_read_overrides_drops_non_string_and_oversized_names(tmp_path):
    f = tmp_path / "n.json"
    f.write_text(json.dumps({"AbCdEfGh": "ok", "b": 5, "c": "x" * 5000, "d": "a\nb"}))
    assert read_overrides(f) == {"AbCdEfGh": "ok"}


def test_save_override_rejection_is_oserror(tmp_path):
    with pytest.raises(OSError):
        save_override(tmp_path / "n.json", "abcdefgh!", "x")
