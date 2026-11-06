import json

from app import audit


def _write(path, entries):
    path.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")


def test_limit_and_order_over_many_chunks(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "CHUNK", 64)
    p = tmp_path / "a.log"
    _write(p, [{"i": i, "pad": "x" * 30} for i in range(100)])
    assert [e["i"] for e in audit.recent(p, 5)] == [99, 98, 97, 96, 95]
    assert [e["i"] for e in audit.recent(p, 500)] == list(range(99, -1, -1))


def test_line_spanning_chunk_boundary(tmp_path, monkeypatch):
    p = tmp_path / "a.log"
    entries = [{"i": i, "pad": "y" * (20 + i)} for i in range(30)]
    _write(p, entries)
    for chunk in range(7, 90):
        monkeypatch.setattr(audit, "CHUNK", chunk)
        assert [e["i"] for e in audit.recent(p, 50)] == list(range(29, -1, -1))


def test_corrupt_line_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "CHUNK", 16)
    p = tmp_path / "a.log"
    p.write_text('{"i": 1}\nnot json\n{"i": 2}\n{"i": 3', encoding="utf-8")
    assert [e["i"] for e in audit.recent(p)] == [2, 1]


def test_missing_and_empty(tmp_path):
    assert audit.recent(tmp_path / "none.log") == []
    p = tmp_path / "e.log"
    p.write_text("")
    assert audit.recent(p) == []
