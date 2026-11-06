import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "monitor/host/omv-host-metrics.sh"

BASICS = "sh mkdir mv rm cat awk sed grep tr cut head tail date basename dirname sort printf echo test expr".split()

SMARTCTL = """#!/bin/sh
[ "${FAKE_SMARTCTL_FAIL:-}" ] && exit 1
if [ "$1" = --scan ]; then
  for d in sda sdb sdc; do echo "/dev/$d -d sat # /dev/$d, SAT"; done
  exit 0
fi
for a; do dev=$a; done
case "${dev##*/}" in
  sda) echo "SMART overall-health self-assessment test result: PASSED"; exit 0 ;;
  sdb) echo "SMART overall-health self-assessment test result: FAILED!"; exit 8 ;;
  sdc) echo "Device is in STANDBY mode, exiting..."; exit 2 ;;
esac
"""

# Honours --format with {{.Names}}, {{.State}} and {{.Status}} placeholders.
DOCKER = """#!/bin/sh
[ "${FAKE_DOCKER_FAIL:-}" ] && exit 1
fmt='{{.Names}}'
while [ $# -gt 0 ]; do
  case "$1" in --format|-f) fmt=$2; shift ;; --format=*) fmt=${1#--format=} ;; esac
  shift
done
for row in "minidlna running Up 2 hours" "omv-web exited Exited (0) 1 hour ago"; do
  set -- $row; n=$1; s=$2; shift 2
  echo "$fmt" | sed "s/{{\\.Names}}/$n/g; s/{{\\.State}}/$s/g; s/{{\\.Status}}/$*/g"
done
"""

OPENSSL = """#!/bin/sh
[ "${FAKE_OPENSSL_FAIL:-}" ] && exit 1
echo "notAfter=Jan  1 00:00:00 2030 GMT"
"""
JAN_2030 = 1893456000

# Both apt front ends report the same 3 pending upgrades, so the script may use either.
APT_GET = """#!/bin/sh
[ "${FAKE_APT_FAIL:-}" ] && exit 100
printf 'Reading package lists...\\nInst libc6 [1] (2 Debian)\\nConf libc6 (2 Debian)\\nInst curl [1] (2 Debian)\\nInst bash [1] (2 Debian)\\n'
[ -n "${FAKE_APT_NONE:-}" ] && printf 'Reading package lists...\\n0 upgraded, 0 newly installed\\n'
exit 0
"""
APT = """#!/bin/sh
[ "${FAKE_APT_FAIL:-}" ] && exit 100
printf 'Listing...\\n'
[ -n "${FAKE_APT_NONE:-}" ] && exit 0
printf 'libc6/stable 2 amd64 [upgradable from: 1]\\ncurl/stable 2 amd64 [upgradable from: 1]\\nbash/stable 2 amd64 [upgradable from: 1]\\n'
"""


def make_path(tmp_path, **fakes):
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    for name in BASICS:
        p = shutil.which(name)
        if p and not (b / name).exists():
            (b / name).symlink_to(p)
    for name, body in fakes.items():
        (b / name).write_text(body)
        (b / name).chmod(0o755)
    return str(b)


def run(tmp_path, tools=("smartctl", "docker", "openssl", "apt-get", "apt"), cert=True, reboot=False, **env):
    all_fakes = {"smartctl": SMARTCTL, "docker": DOCKER, "openssl": OPENSSL, "apt-get": APT_GET, "apt": APT}
    flag = tmp_path / "reboot-required"
    if reboot:
        flag.write_text("*** System restart required ***\n")
    path = make_path(tmp_path, **{t: all_fakes[t] for t in tools})
    out = tmp_path / "textfile"
    crt = tmp_path / "tls.crt"
    if cert:
        crt.write_text("fake")
    e = dict(os.environ, PATH=path, OMV_TEXTFILE_DIR=str(out), OMV_CERT=str(crt), OMV_REBOOT_FLAG=str(flag), **env)
    subprocess.run(["sh", str(SCRIPT)], env=e, check=True, capture_output=True)
    return out


def lines(out):
    return (out / "omv-host.prom").read_text().splitlines()


def test_all_metrics(tmp_path):
    out = run(tmp_path)
    ls = lines(out)
    assert 'omv_smart_healthy{device="sda"} 1' in ls
    assert 'omv_container_running{name="minidlna"} 1' in ls
    assert 'omv_container_running{name="omv-web"} 0' in ls
    assert f"omv_cert_expiry_timestamp_seconds {JAN_2030}" in ls


def test_failing_disk_is_zero_and_standby_disk_omitted(tmp_path):
    ls = lines(run(tmp_path))
    assert 'omv_smart_healthy{device="sdb"} 0' in ls
    assert not any('device="sdc"' in line for line in ls)


def test_no_leftover_tmp_file(tmp_path):
    out = run(tmp_path)
    assert [p.name for p in out.iterdir()] == ["omv-host.prom"]


def test_missing_smartctl_omits_only_smart(tmp_path):
    ls = lines(run(tmp_path, tools=("docker", "openssl")))
    assert not any(line.startswith("omv_smart_healthy") for line in ls)
    assert any(line.startswith("omv_container_running") for line in ls)
    assert any(line.startswith("omv_cert_expiry_timestamp_seconds") for line in ls)


def test_missing_docker_omits_only_containers(tmp_path):
    ls = lines(run(tmp_path, tools=("smartctl", "openssl")))
    assert not any(line.startswith("omv_container_running") for line in ls)
    assert any(line.startswith("omv_smart_healthy") for line in ls)
    assert any(line.startswith("omv_cert_expiry_timestamp_seconds") for line in ls)


def test_failing_commands_omit_metrics_but_file_is_written(tmp_path):
    out = run(tmp_path, FAKE_SMARTCTL_FAIL="1", FAKE_DOCKER_FAIL="1", FAKE_OPENSSL_FAIL="1", FAKE_APT_FAIL="1")
    ls = [x for x in lines(out) if not x.startswith("#") and not x.startswith("omv_reboot_required")]
    assert ls == []
    assert [p.name for p in out.iterdir()] == ["omv-host.prom"]


def test_missing_cert_omits_expiry(tmp_path):
    ls = lines(run(tmp_path, tools=("openssl",), cert=False))
    assert not any(line.startswith("omv_cert_expiry") for line in ls)


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
def test_real_self_signed_cert(tmp_path):
    crt = tmp_path / "tls.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
                    "-subj", "/CN=test", "-keyout", str(tmp_path / "k"), "-out", str(crt)],
                   check=True, capture_output=True)
    out = tmp_path / "textfile"
    e = dict(os.environ, OMV_TEXTFILE_DIR=str(out), OMV_CERT=str(crt))
    subprocess.run(["sh", str(SCRIPT)], env=e, check=True, capture_output=True)
    (val,) = [x.split()[1] for x in lines(out) if x.startswith("omv_cert_expiry_timestamp_seconds ")]
    import time
    assert abs(float(val) - (time.time() + 30 * 86400)) < 3 * 86400


def value(out, metric):
    vals = [x.split()[-1] for x in lines(out) if x.startswith(metric + " ")]
    return vals[0] if vals else None


def test_apt_pending_count(tmp_path):
    assert value(run(tmp_path), "omv_apt_upgrades_pending") == "3"


def test_apt_none_pending_is_zero_not_omitted(tmp_path):
    assert value(run(tmp_path, FAKE_APT_NONE="1"), "omv_apt_upgrades_pending") == "0"


def test_apt_failure_omits_metric_only(tmp_path):
    out = run(tmp_path, FAKE_APT_FAIL="1")
    assert value(out, "omv_apt_upgrades_pending") is None
    assert value(out, "omv_reboot_required") == "0"
    assert any(x.startswith("omv_smart_healthy") for x in lines(out))


def test_apt_missing_omits_metric(tmp_path):
    out = run(tmp_path, tools=("smartctl", "docker", "openssl"))
    assert value(out, "omv_apt_upgrades_pending") is None


def test_reboot_required(tmp_path):
    (tmp_path / "a").mkdir(); (tmp_path / "b").mkdir()
    assert value(run(tmp_path / "a", reboot=True), "omv_reboot_required") == "1"
    assert value(run(tmp_path / "b"), "omv_reboot_required") == "0"
