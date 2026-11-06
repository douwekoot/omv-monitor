import re
from pathlib import Path

APP = Path(__file__).parent.parent / "monitor" / "app"


def test_templates_have_no_inline_style_or_script():
    for f in (APP / "templates").glob("*.html"):
        text = f.read_text()
        assert not re.search(r"\sstyle\s*=", text), f.name
        assert not re.search(r"<script(?![^>]*\ssrc=)", text), f.name


def test_css_has_phone_breakpoint():
    css = (APP / "static" / "app.css").read_text()
    assert re.search(r"@media \(max-width: 6\d\dpx\)", css)
    assert "min-height: 44px" in css


def _lum(hexc):
    c = [int(hexc[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    c = [v / 12.92 if v <= .03928 else ((v + .055) / 1.055) ** 2.4 for v in c]
    return .2126 * c[0] + .7152 * c[1] + .0722 * c[2]


def _contrast(a, b):
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + .05) / (lo + .05)


def test_idle_tokens_have_3_to_1_contrast():
    css = (APP / "static" / "app.css").read_text()
    cut = css.index("prefers-color-scheme: dark")
    for theme, part in (("light", css[:cut]), ("dark", css[cut:])):
        tok = lambda n: re.search(rf"--{n}:\s*(#[0-9a-fA-F]{{6}})\b", part).group(1)
        for name in ("dot-idle", "st-idle"):
            for surface in ("field", "glass-solid"):
                assert _contrast(tok(name), tok(surface)) >= 3.0, (theme, name, surface)
