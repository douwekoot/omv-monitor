import re
from pathlib import Path

import pytest

from app.wiki import list_pages, render_page

WIKI = Path(__file__).resolve().parent.parent / "monitor" / "wiki"


@pytest.fixture
def wd(tmp_path):
    (tmp_path / "index.md").write_text("# Home\n\n| a | b |\n|---|---|\n| 1 | 2 |\n")
    (tmp_path / "zed.md").write_text("# Zed\n\n<script>alert(1)</script>\n")
    (tmp_path / "abc.md").write_text("no heading\n")
    return tmp_path


def test_render_heading_and_table(wd):
    title, html, toc = render_page(wd, "index")
    assert title == "Home"
    assert '<h1 id="home">Home</h1>' in html and "<table>" in html


def test_html_escaped(wd):
    _, html, _ = render_page(wd, "zed")
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_code_escaped_once_and_bad_links(tmp_path):
    (tmp_path / "c.md").write_text("`a<b&c`\n\n[x](javascript:alert(1))\n")
    _, html, _ = render_page(tmp_path, "c")
    assert "a&lt;b&amp;c" in html and "&amp;amp;" not in html
    assert "javascript:" not in html


@pytest.mark.parametrize("slug", ["../x", "a/b", "", "A", "a.md"])
def test_bad_slug(wd, slug):
    with pytest.raises(ValueError):
        render_page(wd, slug)


def test_unknown(wd):
    with pytest.raises(KeyError):
        render_page(wd, "nope")


def test_list_order(wd):
    assert list_pages(wd) == [("index", "Home"), ("abc", "abc"), ("zed", "Zed")]


def test_seed_pages_have_no_secrets():
    names = {s for s, _ in list_pages(WIKI)}
    assert {"index", "monitoring", "alerts", "backups", "network-actions", "recovery"} <= names
    for p in WIKI.glob("*.md"):
        t = p.read_text()
        assert "PrivateKey" not in t and "PresharedKey" not in t
        assert not re.search(r"[A-Za-z0-9+/]{43}=", t)


def test_contents_and_sections(tmp_path):
    (tmp_path / "a.md").write_text("# A\n\n## One\n\nx\n\n## Two & more\n")
    (tmp_path / "b.md").write_text("# B\n")
    (tmp_path / "sections.toml").write_text('[[section]]\nname = "Net"\npages = ["b", "missing"]\n[about]\nb = "Bee"\n')
    _, html, toc = render_page(tmp_path, "a")
    assert toc == [("one", "One"), ("two-more", "Two &amp; more")] and 'id="one"' in html
    from app.wiki import sections
    assert sections(tmp_path) == [("Net", [("b", "B", "Bee")]), ("Other", [("a", "A", "")])]


@pytest.mark.parametrize("slug", ["../secret", "..", "a/b", "/etc/passwd", "a\0b", "A", "x\n", "%2e%2e", ""])
def test_render_page_rejects_bad_slugs(tmp_path, slug):
    (tmp_path / "secret.md").write_text("# nope")
    with pytest.raises(ValueError):
        render_page(tmp_path / "wiki", slug)


def test_render_page_refuses_symlink_out_of_dir(tmp_path):
    w = tmp_path / "wiki"
    w.mkdir()
    (tmp_path / "outside.md").write_text("# Outside\nsecret")
    (w / "leak.md").symlink_to(tmp_path / "outside.md")
    with pytest.raises((KeyError, ValueError)):
        render_page(w, "leak")
    assert "leak" not in dict(list_pages(w))


@pytest.mark.parametrize("src", [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "[x](javascript:alert(1))",
    "[x](JaVaScript:alert(1))", "![x](data:text/html;base64,AAAA)", "## <b onmouseover=x>h</b>", "`<i>`",
])
def test_render_markdown_has_no_live_html(src):
    from app.wiki import render_markdown
    html, toc = render_markdown(src)
    assert not re.search(r"<(script|img|b|i)\b", html)
    assert "javascript:" not in html.lower() and "data:text" not in html.lower()
    assert all("<" not in t for _, t in toc)
