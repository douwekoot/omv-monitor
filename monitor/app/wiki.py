import re
import tomllib
from pathlib import Path

import markdown

_SLUG = re.compile(r"[a-z0-9-]+")
_BADHREF = re.compile(r'(href|src)="\s*(?:javascript|data|vbscript):[^"]*"', re.I)
_BADIMG = re.compile(r'<img[^>]*\ssrc="\s*(?:javascript|data|vbscript):[^>]*>', re.I)
_TITLE = re.compile(r"^# (.+)$", re.M)


def _title(text, slug):
    m = _TITLE.search(text)
    return m.group(1).strip() if m else slug


def list_pages(wiki_dir):
    pages = [(p.stem, _title(p.read_text(encoding="utf-8"), p.stem))
             for p in Path(wiki_dir).glob("*.md") if _SLUG.fullmatch(p.stem) and not p.is_symlink()]
    return sorted(pages, key=lambda t: (t[0] != "index", t[0]))


def render_markdown(text):
    """Safe Markdown to HTML plus the h2 contents list [(anchor, text)]."""
    md = markdown.Markdown(extensions=["tables", "fenced_code", "toc"])
    # Drop raw-HTML and entity handling so the serializer escapes < and & exactly once.
    md.preprocessors.deregister("html_block")
    md.inlinePatterns.deregister("html")
    md.inlinePatterns.deregister("entity")
    html = _BADHREF.sub(r'\1="#"', _BADIMG.sub("", md.convert(text)))
    toc = [(t["id"], t["name"]) for h1 in md.toc_tokens for t in h1["children"]]
    return html, toc


def render_page(wiki_dir, slug):
    """(title, html, contents) of one page."""
    if not _SLUG.fullmatch(slug):
        raise ValueError(f"bad slug: {slug!r}")
    path = Path(wiki_dir) / f"{slug}.md"
    if not path.is_file() or path.is_symlink():
        raise KeyError(slug)
    text = path.read_text(encoding="utf-8")
    html, toc = render_markdown(text)
    return _title(text, slug), html, toc


def sections(wiki_dir):
    """[(section name, [(slug, title, about)])] from sections.toml; unlisted pages go under "Other"."""
    path = Path(wiki_dir) / "sections.toml"
    cfg = tomllib.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    titles = dict(list_pages(wiki_dir))
    about = cfg.get("about", {})
    out, seen = [], {"index"}
    for sec in cfg.get("section", []):
        rows = [(s, titles[s], about.get(s, "")) for s in sec.get("pages", []) if s in titles and s not in seen]
        seen.update(s for s, _, _ in rows)
        if rows:
            out.append((sec.get("name", "Other"), rows))
    rest = [(s, t, about.get(s, "")) for s, t in titles.items() if s not in seen]
    return out + ([("Other", rest)] if rest else [])
