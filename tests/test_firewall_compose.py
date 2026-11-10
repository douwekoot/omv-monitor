import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESTRICT = ROOT / "monitor/host/omv-restrict-8443.sh"
COMPOSE = (ROOT / "monitor/compose.yaml").read_text()


def fake_iptables(tmp_path, fail_after=None):
    """iptables stub: logs calls, -D never matches, -I fails once `fail_after` inserts have succeeded."""
    log, bindir = tmp_path / "calls", tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "iptables"
    stub.write_text(f'''#!/bin/sh
echo "$*" >> {log}
[ "$1" = -D ] && exit 1
if [ "$1" = -I ]; then
  n=$(grep -c '^-I' {log})
  [ -n "{fail_after if fail_after is not None else ''}" ] && [ "$n" -gt "{fail_after if fail_after is not None else 0}" ] && exit 1
fi
exit 0
''')
    stub.chmod(0o755)
    return log, dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")


def inserts(log):
    return [l for l in log.read_text().splitlines() if l.startswith("-I")]


def test_restrict_apply_inserts_reject_before_accepts(tmp_path):
    log, env = fake_iptables(tmp_path)
    subprocess.run(["sh", str(RESTRICT), "apply"], env=env, check=True)
    ins = inserts(log)
    assert "REJECT" in ins[0] and all("ACCEPT" in l for l in ins[1:]) and len(ins) >= 2


def test_restrict_apply_fails_closed_when_a_rule_cannot_be_added(tmp_path):
    log, env = fake_iptables(tmp_path, fail_after=1)
    r = subprocess.run(["sh", str(RESTRICT), "apply"], env=env)
    assert r.returncode != 0
    assert any("REJECT" in l for l in inserts(log))  # no window where 8443 is only accepted-by-default


def test_compose_web_service_is_locked_down():
    web = COMPOSE.split("\n  web:\n", 1)[1].split("\nvolumes:\n", 1)[0]
    assert "read_only: true" in web
    for bad in ("privileged", "cap_add", "pid: host", "user: root", "user: \"0\"", "/var/run/docker.sock"):
        assert bad not in web
    mounts = re.findall(r"^\s+- (\S+?):(/\S+?)(?::(\w+))?(?:\s+#.*)?$", web, re.M)
    rw = [m[1] for m in mounts if m[2] in (None, "") and m[0].startswith(("/", "."))]
    assert set(rw) <= {"/app/data", "/run/omv-netctl"}, rw  # everything else read-only
    assert not any(m[0] in ("/", "/etc", "/opt") or m[0].startswith("/etc/openmediavault") for m in mounts)


def test_compose_only_web_listens_off_loopback():
    assert not re.search(r"^\s+ports:", COMPOSE, re.M)
    for addr in ("127.0.0.1:9090", "127.0.0.1:9100", "127.0.0.1:9115"):
        assert f"--web.listen-address={addr}" in COMPOSE
    assert COMPOSE.count("--web.listen-address") == 3
    assert "USER app" in (ROOT / "monitor/Dockerfile").read_text()
