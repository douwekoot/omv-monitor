import base64
import hashlib
import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "monitor/host/omv-netctl.py"
KEYRE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")


def key(n):
    return base64.b64encode(hashlib.sha256(str(n).encode()).digest()).decode()


SERVER, A, B = key("server"), key("A"), key("B")
PSK_B = key("pskB")
GOOD_ENDPOINT = "vpn.example.org:51820"


def load():
    spec = importlib.util.spec_from_file_location("omv_netctl", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class WgRunner:
    """Simulates wg/wg-quick: peers = {pub: {"ips": [...], "psk": str|None}}; `saved` = wgnet1.conf."""

    def __init__(self):
        self.calls = []
        self.peers = {A: {"ips": ["10.8.0.2/32"], "psk": None, "hs": 1700000000},
                      B: {"ips": ["10.8.0.3/32"], "psk": PSK_B, "hs": 0}}
        self.saved = None
        self.n = 0
        self.privs = []

    def conf(self):
        out = "[Interface]\nPrivateKey = %s\nListenPort = 51820\n" % key("serverpriv")
        for pub, p in self.peers.items():
            out += "\n[Peer]\nPublicKey = %s\n" % pub
            if p["psk"]:
                out += "PresharedKey = %s\n" % p["psk"]
            out += "AllowedIPs = %s\n" % ", ".join(p["ips"])
        return out

    def run(self, argv, input=None):
        self.calls.append(list(argv))
        a = list(argv)
        if a == ["wg", "show", "wgnet1", "dump"]:
            lines = ["\t".join([key("serverpriv"), SERVER, "51820", "off"])]
            for pub, p in self.peers.items():
                lines.append("\t".join([pub, p["psk"] or "(none)", "(none)", ",".join(p["ips"]),
                                        str(p.get("hs", 0)), "0", "0", "off"]))
            return 0, "\n".join(lines) + "\n"
        if a == ["wg", "show", "wgnet1", "public-key"]:
            return 0, SERVER + "\n"
        if a == ["wg", "showconf", "wgnet1"]:
            return 0, self.conf()
        if a == ["wg", "genkey"]:
            self.n += 1
            k = key("gen%d" % self.n)
            self.privs.append(k)
            return 0, k + "\n"
        if a == ["wg", "pubkey"]:
            return 0, key("pub-of-" + input.strip()) + "\n"
        if a == ["wg", "genpsk"]:
            self.n += 1
            return 0, key("psk%d" % self.n) + "\n"
        if a[:3] == ["wg", "set", "wgnet1"] and a[3] == "peer":
            pub, rest = a[4], a[5:]
            if rest == ["remove"]:
                self.peers.pop(pub, None)
                return 0, ""
            p = self.peers.setdefault(pub, {"ips": [], "psk": None, "hs": 0})
            while rest:
                if rest[0] == "allowed-ips":
                    p["ips"] = rest[1].split(",")
                elif rest[0] == "preshared-key":
                    p["psk"] = Path(rest[1]).read_text().strip()
                else:
                    return 1, "bad arg"
                rest = rest[2:]
            return 0, ""
        if a[:3] == ["wg", "syncconf", "wgnet1"]:
            peers, cur = {}, None
            for line in Path(a[3]).read_text().splitlines():
                m = re.match(r"(\w+) = (.*)", line)
                if not m:
                    continue
                k, v = m.groups()
                if k == "PublicKey":
                    cur = peers[v] = {"ips": [], "psk": None, "hs": 0}
                elif cur is not None and k == "PresharedKey":
                    cur["psk"] = v
                elif cur is not None and k == "AllowedIPs":
                    cur["ips"] = v.split(", ")
            self.peers = peers
            return 0, ""
        if a == ["wg-quick", "save", "wgnet1"]:
            self.saved = self.conf()
            return 0, ""
        return 1, "unexpected argv"

    def mutating(self):
        return [c for c in self.calls
                if c[:2] in (["wg", "set"], ["wg", "syncconf"]) or c[:2] == ["wg-quick", "save"]]

    def ips(self):
        return {k: v["ips"] for k, v in self.peers.items()}


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture(autouse=True)
def no_real_subprocess(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("real subprocess used")
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setenv("OMV_NETCTL_ENDPOINT", GOOD_ENDPOINT)


@pytest.fixture
def env(tmp_path):
    mod = load()
    runner, clock = WgRunner(), Clock()
    state = tmp_path / "state"
    return mod, mod.Helper(runner, state, clock=clock), runner, clock, state


def call(h, action, **args):
    return h.handle({"action": action, "args": args})


def ok(h, action, **args):
    r = call(h, action, **args)
    assert r["ok"] is True, r
    return r["result"]


def change(h, action, confirm=True, **args):
    res = ok(h, action, **args)
    assert res["pending"]["id"] and KEYID.match(res["snapshot"])
    if confirm:
        ok(h, "confirm", id=h.pending["id"])
    return res


KEYID = re.compile(r"^[0-9a-f]{12}$")


def expire(h, clock):
    clock.t += 61
    h.expire()


def test_peers_lists_runtime(env):
    _, h, r, _, _ = env
    res = ok(h, "peers")
    assert res["peers"] == [
        {"public_key": A, "allowed_ips": ["10.8.0.2/32"], "enabled": True, "latest_handshake": 1700000000},
        {"public_key": B, "allowed_ips": ["10.8.0.3/32"], "enabled": True, "latest_handshake": None},
    ]
    assert r.calls == [["wg", "show", "wgnet1", "dump"]]


def test_peer_set_sequence_snapshot_and_save(env):
    _, h, r, _, state = env
    res = change(h, "peer-set", confirm=False, public_key=A, allowed_ips=["10.8.0.20/32", "10.8.0.21/32"])
    assert ["wg", "set", "wgnet1", "peer", A, "allowed-ips", "10.8.0.20/32,10.8.0.21/32"] in r.calls
    assert r.calls[-1] == ["wg-quick", "save", "wgnet1"]
    assert r.saved == r.conf()
    snap = state / "snapshots" / (res["snapshot"] + ".conf")
    assert snap.stat().st_mode & 0o777 == 0o600
    assert "10.8.0.2/32" in snap.read_text() and "10.8.0.20" not in snap.read_text()
    # snapshot is taken before the change
    assert r.calls.index(["wg", "showconf", "wgnet1"]) < r.calls.index(
        ["wg", "set", "wgnet1", "peer", A, "allowed-ips", "10.8.0.20/32,10.8.0.21/32"])
    assert h.pending["id"] == res["pending"]["id"]
    assert ok(h, "pending")["pending"]["action"] == "peer-set"


@pytest.mark.parametrize("action,args", [
    ("peer-set", {"allowed_ips": ["10.8.0.20/32"]}),
    ("peer-disable", {}),
    ("peer-remove", {}),
])
def test_mutations_use_argv_undo_that_survives_restart_and_expiry(env, tmp_path, action, args):
    mod, h, r, clock, state = env
    before = r.ips()
    change(h, action, confirm=False, public_key=A, **args)
    assert r.ips() != before
    assert isinstance(h.pending["undo"], list)  # callable undos are lost on helper restart
    # simulated helper restart mid-change: the undo is replayed
    mod.Helper(r, state, clock=clock)
    assert r.ips() == before
    assert ["wg", "syncconf", "wgnet1"] == next(c for c in r.calls if c[:2] == ["wg", "syncconf"])[:3]


@pytest.mark.parametrize("action,args", [
    ("peer-set", {"allowed_ips": ["10.8.0.20/32"]}),
    ("peer-disable", {}),
    ("peer-remove", {}),
])
def test_expiry_restores_pre_change_state(env, action, args):
    _, h, r, clock, state = env
    before = r.ips()
    res = change(h, action, confirm=False, public_key=A, **args)
    assert r.ips() != before
    clock.t += 59
    h.expire()
    assert r.ips() != before
    clock.t += 2
    h.expire()
    snap = state / "snapshots" / (res["snapshot"] + ".conf")
    assert ["wg", "syncconf", "wgnet1", str(snap)] in r.calls
    assert r.ips() == before
    assert h.pending is None


def test_confirm_keeps_change(env):
    _, h, r, clock, _ = env
    change(h, "peer-set", public_key=A, allowed_ips=["10.8.0.20/32"])
    expire(h, clock)
    assert r.ips()[A] == ["10.8.0.20/32"]
    assert not any(c[:2] == ["wg", "syncconf"] for c in r.calls)


def test_peer_set_own_current_ip_allowed(env):
    _, h, r, _, _ = env
    change(h, "peer-set", public_key=A, allowed_ips=["10.8.0.2/32"])


def test_disable_stashes_and_enable_restores(env):
    _, h, r, _, state = env
    change(h, "peer-disable", public_key=B)
    assert B not in r.peers
    assert r.calls[-1] == ["wg-quick", "save", "wgnet1"]
    stash = state / "disabled" / (hashlib.sha256(B.encode()).hexdigest() + ".json")
    d = json.loads(stash.read_text())
    assert d["public_key"] == B and d["allowed_ips"] == ["10.8.0.3/32"]
    peers = {p["public_key"]: p for p in ok(h, "peers")["peers"]}
    assert peers[B]["enabled"] is False and peers[B]["allowed_ips"] == ["10.8.0.3/32"]
    assert peers[A]["enabled"] is True
    change(h, "peer-enable", public_key=B)
    assert r.peers[B]["ips"] == ["10.8.0.3/32"] and r.peers[B]["psk"] == PSK_B
    assert r.calls[-1] == ["wg-quick", "save", "wgnet1"]
    assert {p["public_key"]: p["enabled"] for p in ok(h, "peers")["peers"]}[B] is True


def test_enable_requires_stashed_peer(env):
    _, h, r, _, _ = env
    n = len(r.calls)
    assert call(h, "peer-enable", public_key=A)["ok"] is False
    assert call(h, "peer-enable", public_key=key("nobody"))["ok"] is False
    assert not r.mutating() and h.pending is None


def test_remove_then_expiry_readds_peer_with_psk(env):
    _, h, r, clock, _ = env
    change(h, "peer-remove", confirm=False, public_key=B)
    assert B not in r.peers and r.calls[-1] == ["wg-quick", "save", "wgnet1"]
    expire(h, clock)
    assert r.peers[B]["ips"] == ["10.8.0.3/32"] and r.peers[B]["psk"] == PSK_B


BAD = [
    ("peer-set", {"public_key": "short", "allowed_ips": ["10.8.0.9/32"]}),
    ("peer-set", {"public_key": A + "x", "allowed_ips": ["10.8.0.9/32"]}),
    ("peer-set", {"public_key": 5, "allowed_ips": ["10.8.0.9/32"]}),
    ("peer-set", {"public_key": key("unknown"), "allowed_ips": ["10.8.0.9/32"]}),
    ("peer-set", {"public_key": A, "allowed_ips": ["192.168.1.9/32"]}),
    ("peer-set", {"public_key": A, "allowed_ips": ["10.8.1.9/32"]}),
    ("peer-set", {"public_key": A, "allowed_ips": ["10.8.0.9/24"]}),
    ("peer-set", {"public_key": A, "allowed_ips": ["10.8.0.0/32"]}),
    ("peer-set", {"public_key": A, "allowed_ips": ["10.8.0.255/32"]}),
    ("peer-set", {"public_key": A, "allowed_ips": ["10.8.0.254/32"]}),
    ("peer-set", {"public_key": A, "allowed_ips": ["10.8.0.3/32"]}),  # used by B
    ("peer-set", {"public_key": A, "allowed_ips": ["10.8.0.9/32", "10.8.0.3/32"]}),
    ("peer-set", {"public_key": A, "allowed_ips": []}),
    ("peer-set", {"public_key": A, "allowed_ips": "10.8.0.9/32"}),
    ("peer-set", {"public_key": A, "allowed_ips": [5]}),
    ("peer-set", {"public_key": A, "allowed_ips": ["10.8.0.9/32; rm"]}),
    ("peer-set", {"public_key": A, "allowed_ips": ["10.8.0.%d/32" % i for i in range(10, 19)]}),  # 9 entries
    ("peer-set", {"public_key": A}),
    ("peer-disable", {"public_key": key("unknown")}),
    ("peer-disable", {"public_key": "../x"}),
    ("peer-remove", {"public_key": key("unknown")}),
    ("peer-remove", {"public_key": None}),
    ("peer-add", {"allowed_ip": "10.8.0.3/32"}),
    ("peer-add", {"allowed_ip": "10.8.0.254/32"}),
    ("peer-add", {"allowed_ip": "10.8.1.4/32"}),
    ("peer-add", {"allowed_ip": ["10.8.0.4/32"]}),
    ("restore", {"snapshot": "../x"}),
    ("restore", {"snapshot": "../../etc/passwd"}),
    ("restore", {"snapshot": "ABCDEF012345"}),
    ("restore", {"snapshot": "0123456789a"}),
    ("restore", {"snapshot": "0123456789abc"}),
    ("restore", {"snapshot": "0123456789ab"}),  # well-formed but unknown
    ("restore", {"snapshot": 5}),
    ("restore", {}),
]


@pytest.mark.parametrize("action,args", BAD)
def test_invalid_requests_rejected_without_wg_changes(env, action, args):
    _, h, r, _, state = env
    res = call(h, action, **args)
    assert res["ok"] is False and isinstance(res["error"], str)
    assert r.mutating() == []
    assert h.pending is None and not (state / "pending.json").exists()


def test_valid_ip_list_of_eight_accepted(env):
    _, h, r, _, _ = env
    ips = ["10.8.0.%d/32" % i for i in range(10, 18)]
    change(h, "peer-set", public_key=A, allowed_ips=ips)
    assert r.peers[A]["ips"] == ips


def test_mutation_refused_while_pending(env):
    _, h, r, _, _ = env
    change(h, "peer-set", confirm=False, public_key=A, allowed_ips=["10.8.0.20/32"])
    n = len(r.mutating())
    res = call(h, "peer-set", public_key=B, allowed_ips=["10.8.0.30/32"])
    assert res["ok"] is False
    assert len(r.mutating()) == n


def test_snapshots_newest_first_without_contents(env):
    _, h, r, clock, _ = env
    s1 = change(h, "peer-set", public_key=A, allowed_ips=["10.8.0.20/32"])["snapshot"]
    clock.t += 10
    s2 = change(h, "peer-disable", public_key=B)["snapshot"]
    snaps = ok(h, "snapshots")["snapshots"]
    assert [s["id"] for s in snaps] == [s2, s1]
    for s in snaps:
        assert set(s) == {"id", "time", "action", "summary"}
        assert "PrivateKey" not in json.dumps(s)
    assert snaps[0]["action"] == "peer-disable" and snaps[0]["time"] > snaps[1]["time"]


def test_snapshots_keep_newest_ten(env):
    _, h, r, clock, state = env
    ids = []
    for i in range(12):
        clock.t += 1
        ips = ["10.8.0.%d/32" % (20 + i % 2)]
        ids.append(change(h, "peer-set", public_key=A, allowed_ips=ips)["snapshot"])
    files = {p.stem for p in (state / "snapshots").glob("*.conf")}
    assert files == set(ids[-10:])
    assert [s["id"] for s in ok(h, "snapshots")["snapshots"]] == ids[::-1][:10]


def test_restore_older_snapshot_and_its_auto_revert(env):
    _, h, r, clock, state = env
    original = r.ips()
    s1 = change(h, "peer-set", public_key=A, allowed_ips=["10.8.0.20/32"])["snapshot"]
    change(h, "peer-disable", public_key=B)
    current = r.ips()
    assert current != original
    clock.t += 5
    res = ok(h, "restore", snapshot=s1)
    assert res["pending"]["id"]
    assert r.ips() == original  # s1 is the state before the first change
    assert ["wg", "syncconf", "wgnet1", str(state / "snapshots" / (s1 + ".conf"))] in r.calls
    assert r.calls[-1] == ["wg-quick", "save", "wgnet1"]
    assert isinstance(h.pending["undo"], list)
    expire(h, clock)
    assert r.ips() == current  # back to the pre-restore state


def test_restore_oldest_listed_snapshot(env):
    _, h, r, clock, state = env
    ids = []
    for i in range(10):
        clock.t += 1
        ids.append(change(h, "peer-set", public_key=A, allowed_ips=["10.8.0.%d/32" % (20 + i % 2)])["snapshot"])
    assert [s["id"] for s in ok(h, "snapshots")["snapshots"]][-1] == ids[0]
    ok(h, "restore", snapshot=ids[0])
    assert ["wg", "syncconf", "wgnet1", str(state / "snapshots" / (ids[0] + ".conf"))] in r.calls


def test_remove_disabled_peer_revert_keeps_stash_confirm_deletes(env):
    _, h, r, clock, state = env
    change(h, "peer-disable", public_key=B)
    stash = state / "disabled" / (hashlib.sha256(B.encode()).hexdigest() + ".json")
    change(h, "peer-remove", confirm=False, public_key=B)
    expire(h, clock)
    assert stash.exists()
    assert {p["public_key"] for p in ok(h, "peers")["peers"]} >= {A, B}
    change(h, "peer-remove", public_key=B)
    assert not stash.exists()
    assert B not in {p["public_key"] for p in ok(h, "peers")["peers"]}


def test_restore_confirmed_stays(env):
    _, h, r, clock, _ = env
    original = r.ips()
    s1 = change(h, "peer-set", public_key=A, allowed_ips=["10.8.0.20/32"])["snapshot"]
    ok(h, "restore", snapshot=s1)
    ok(h, "confirm", id=h.pending["id"])
    expire(h, clock)
    assert r.ips() == original


# --- peer-add --------------------------------------------------------------

def test_peer_add_picks_lowest_free_and_builds_client_config(env):
    _, h, r, clock, state = env
    res = change(h, "peer-add", confirm=False)
    pub = res["public_key"]
    assert KEYRE.match(pub)
    assert res["allowed_ips"] == ["10.8.0.1/32"]
    assert r.peers[pub]["ips"] == ["10.8.0.1/32"] and r.peers[pub]["psk"]
    assert ["wg", "genkey"] in r.calls and ["wg", "pubkey"] in r.calls and ["wg", "genpsk"] in r.calls
    assert r.calls[-1] == ["wg-quick", "save", "wgnet1"]
    cfg = res["client_config"]
    priv = r.privs[0]
    for needle in ("[Interface]", "PrivateKey = " + priv, "Address = 10.8.0.1/32", "[Peer]",
                   "PublicKey = " + SERVER, "PresharedKey = " + r.peers[pub]["psk"],
                   "Endpoint = " + GOOD_ENDPOINT, "10.8.0.0/24", "192.168.1.0/24",
                   "PersistentKeepalive = 25"):
        assert needle in cfg, needle
    expire(h, clock)
    assert pub not in r.peers  # auto-revert removes the new peer


def test_peer_add_explicit_ip(env):
    _, h, r, _, _ = env
    res = change(h, "peer-add", allowed_ip="10.8.0.77/32")
    assert res["allowed_ips"] == ["10.8.0.77/32"]
    assert "Address = 10.8.0.77/32" in res["client_config"]


def test_peer_add_without_endpoint_fails_cleanly(env, monkeypatch):
    _, h, r, _, _ = env
    monkeypatch.delenv("OMV_NETCTL_ENDPOINT")
    res = call(h, "peer-add")
    assert res["ok"] is False and "endpoint not configured" in res["error"]
    assert r.mutating() == [] and h.pending is None


def test_peer_add_private_key_never_stored_or_logged(env, capsys):
    _, h, r, clock, state = env
    res = change(h, "peer-add", confirm=False)
    expire(h, clock)  # exercise the undo path too
    ok_ = [res["client_config"]]
    priv = r.privs[0]
    assert priv in ok_[0]
    for p in state.rglob("*"):
        if p.is_file():
            assert priv not in p.read_text(errors="ignore"), p
    cap = capsys.readouterr()
    assert priv not in cap.err and priv not in cap.out
    # nor in any argv that wg was invoked with
    assert not any(priv in " ".join(c) for c in r.calls)
