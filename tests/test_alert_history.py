import json

from app import alert_history as ah

DAY = 86400


def ev(ts, event="raised", sev="finding", rule="disk-health", title="sdb failed"):
    return {"ts": ts, "event": event, "sev": sev, "rule": rule, "title": title}


def test_record_and_read_newest_first(tmp_path):
    p = tmp_path / "sub" / "h.jsonl"  # parent is created
    ah.record(p, [ev(1), ev(3)])
    ah.record(p, [ev(2, "cleared")])
    assert [e["ts"] for e in ah.read(p)] == [3, 2, 1]
    assert ah.read(p)[0] == ev(3)


def test_record_empty_is_noop(tmp_path):
    p = tmp_path / "h.jsonl"
    ah.record(p, [])
    assert ah.read(p) == []


def test_read_missing_file(tmp_path):
    assert ah.read(tmp_path / "none.jsonl") == []


def test_read_filter_and_limit(tmp_path):
    p = tmp_path / "h.jsonl"
    ah.record(p, [ev(1, sev="finding"), ev(2, sev="advisory"), ev(3, sev="finding"), ev(4, sev="advisory")])
    assert [e["ts"] for e in ah.read(p, sev="advisory")] == [4, 2]
    assert [e["ts"] for e in ah.read(p, sev="finding")] == [3, 1]
    assert [e["ts"] for e in ah.read(p, limit=2)] == [4, 3]
    assert [e["ts"] for e in ah.read(p, sev="finding", limit=1)] == [3]


def test_corrupt_lines_skipped(tmp_path):
    p = tmp_path / "h.jsonl"
    ah.record(p, [ev(1)])
    with open(p, "a") as f:
        f.write("not json\n{\"ts\": \n\n[1, 2]\n")
    ah.record(p, [ev(2)])
    assert [e["ts"] for e in ah.read(p)] == [2, 1]
    ah.prune(p, keep_days=1, now=3)  # also survives pruning
    assert [e["ts"] for e in ah.read(p)] == [2, 1]


def test_prune_drops_old_and_keeps_recent(tmp_path):
    p = tmp_path / "h.jsonl"
    now = 100 * DAY
    ah.record(p, [ev(now - 91 * DAY), ev(now - 89 * DAY), ev(now - 1)])
    ah.prune(p, keep_days=90, now=now)
    assert [e["ts"] for e in ah.read(p)] == [now - 1, now - 89 * DAY]
    assert [x.name for x in tmp_path.iterdir()] == ["h.jsonl"]  # atomic rewrite leaves no temp file


def test_prune_missing_file_is_noop(tmp_path):
    ah.prune(tmp_path / "none.jsonl", keep_days=1, now=1)
    assert not (tmp_path / "none.jsonl").exists()


def test_lines_are_json_objects(tmp_path):
    p = tmp_path / "h.jsonl"
    ah.record(p, [ev(1)])
    assert json.loads(p.read_text().splitlines()[0])["rule"] == "disk-health"
