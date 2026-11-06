import json
import math
import time
from html import escape


def _fmt(v, unit):
    if unit == "B/s":
        for u in ("B/s", "KiB/s", "MiB/s", "GiB/s"):
            if abs(v) < 1024 or u == "GiB/s":
                return f"{v:.0f} {u}" if u == "B/s" else f"{v:.1f}".removesuffix(".0") + f" {u}"
            v /= 1024
    return f"{v:.3g}{(' ' + unit) if unit else ''}"


def _nice(v, unit):
    """Round an axis top up to 1, 2 or 5 x 10^n in the unit it is shown in, so gridlines read as round numbers."""
    f = 1.0
    while unit == "B/s" and v / f >= 1024 and f < 1024 ** 3:
        f *= 1024
    x = v / f
    p = 10 ** math.floor(math.log10(x))
    return next(m * p for m in (1, 2, 5, 10) if x <= m * p) * f


# The SVG holds only lines and is stretched to the plot box; labels are HTML, so text keeps its size at every width.
W, H, PAD = 1000, 200, 9  # PAD = half a label line, so the top and bottom labels centre on their grid lines


def line_chart(series, unit="", ymax=None, span=None):
    pts = [p for s in series.values() for p in s]
    label = "; ".join(f"{n}: latest {_fmt(s[-1][1], unit)}" for n, s in series.items() if s) or "No data"
    if not pts:
        return f'<figure class="chart" role="img" aria-label="{escape(label)}"><p class="empty">No data in this range</p></figure>'
    # span = the selected range, so the time axis lines up with the state strip above it
    x0, x1 = span or (min(p[0] for p in pts), max(p[0] for p in pts))
    peak = max(p[1] for p in pts)
    ymax = _nice(max(ymax or 0, peak) or 1.0, unit)
    sx = lambda x: (x - x0) / ((x1 - x0) or 1) * W
    sy = lambda y: PAD + (1 - y / ymax) * (H - 2 * PAD)
    # The exact points ride along for static/chart.js, which adds the hover crosshair and value readout.
    raw = {"unit": unit, "x0": x0, "x1": x1, "ymax": ymax, "pad": PAD, "h": H,
           "series": [{"name": str(n), "c": i % 3, "pts": [[t, round(v, 6)] for t, v in s]} for i, (n, s) in enumerate(series.items())]}
    out = [f'<figure class="chart" role="group" aria-label="{escape(label)}" data-chart="{escape(json.dumps(raw, separators=(",", ":")))}">',
           '<div class="legend">']
    out += [f'<span><i class="s{i % 3}"></i>{escape(str(n))}</span>' for i, n in enumerate(series)]
    out.append(f'<span class="peak">Peak {escape(_fmt(peak, unit))}</span></div><div class="plot"><div class="y">')
    out += [f"<span>{escape(_fmt(ymax * f, unit))}</span>" for f in (1, .5, 0)]
    out.append(f'</div><div class="area"><svg viewBox="0 0 {W} {H}" preserveAspectRatio="none" aria-hidden="true">')
    out += [f'<line class="grid" x1="0" x2="{W}" y1="{sy(ymax * f):.1f}" y2="{sy(ymax * f):.1f}"/>' for f in (0, .5, 1)]
    for i, s in enumerate(series.values()):
        if s:
            d = " ".join(f"{'M' if j == 0 else 'L'}{sx(x):.1f},{sy(y):.1f}" for j, (x, y) in enumerate(s))
            # A lone point gets a tiny segment; with round caps it draws as a dot.
            out.append(f'<path class="s{i % 3}" d="{d}{" h0.1" if len(s) == 1 else ""}"/>')
    out.append('</svg></div><div class="x">')
    out += [f'<span>{time.strftime("%d %b %H:%M", time.localtime(x))}</span>' for x in (x0, x1)]
    out.append("</div></div></figure>")
    return "".join(out)


def state_strip(slots, what="up", cls=""):
    """One rect per slot, coloured by the fraction up; segment length is the slot's exact share of the range."""
    n = len(slots)
    known = [v for v in slots if v is not None]
    label = f"{what} {sum(known) / len(known):.0%} of the time" if known else "no data"
    out = [f'<svg class="strip {cls}" viewBox="0 0 {n} 1" preserveAspectRatio="none" role="img" aria-label="{label}">']
    for i, v in enumerate(slots):
        cls = "s-none" if v is None else "s-up" if v >= .999 else "s-down" if v <= .001 else "s-part"
        out.append(f'<rect class="{cls}" x="{i}" y="0" width="1" height="1"/>')
    out.append("</svg>")
    return "".join(out)
