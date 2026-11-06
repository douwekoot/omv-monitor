// Hover, touch and keyboard readout for the server-drawn charts: a crosshair, a dot per series
// and the exact time and values. Charts render fully without this script.
(() => {
  const UNITS = ["B/s", "KiB/s", "MiB/s", "GiB/s"];
  const exact = (v, unit) => {
    if (unit === "B/s") {
      let i = 0;
      while (Math.abs(v) >= 1024 && i < UNITS.length - 1) { v /= 1024; i++; }
      return i ? `${v.toFixed(2)} ${UNITS[i]}` : `${Math.round(v)} B/s`;
    }
    const n = Math.abs(v) >= 100 ? v.toFixed(0) : Math.abs(v) >= 10 ? v.toFixed(1) : v.toFixed(2);
    return unit ? `${n} ${unit}` : n;
  };
  const when = (t) => new Date(t * 1000).toLocaleString(undefined,
    { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const el = (tag, cls, parent) => { const e = document.createElement(tag); e.className = cls; parent?.append(e); return e; };
  // Index of the timestamp in a sorted array closest to t.
  const nearest = (arr, t) => {
    let lo = 0, hi = arr.length - 1;
    while (hi - lo > 1) { const mid = (lo + hi) >> 1; (arr[mid] < t ? (lo = mid) : (hi = mid)); }
    return Math.abs(arr[hi] - t) < Math.abs(arr[lo] - t) ? hi : lo;
  };

  for (const fig of document.querySelectorAll("figure.chart[data-chart]")) {
    const d = JSON.parse(fig.dataset.chart);
    const area = fig.querySelector(".area");
    const times = [...new Set(d.series.flatMap((s) => s.pts.map((p) => p[0])))].sort((a, b) => a - b);
    if (!area || !times.length) continue;
    const step = times.length > 1 ? (times[times.length - 1] - times[0]) / (times.length - 1) : Infinity;
    const cols = d.series.map((s) => s.pts.map((p) => p[0]));
    const layer = el("div", "hover", area);
    layer.hidden = true;
    const line = el("div", "xh", layer);
    const dots = d.series.map((s) => el("span", `hd s${s.c}`, layer));
    const tip = el("div", "tip", layer);
    const live = el("p", "sr-only", fig);
    live.setAttribute("aria-live", "polite");
    area.tabIndex = 0;
    area.setAttribute("aria-label", "Chart values. Use the left and right arrow keys to read them.");
    let at = times.length - 1;

    const show = (i, announce) => {
      at = Math.max(0, Math.min(times.length - 1, i));
      const t = times[at], x = (t - d.x0) / ((d.x1 - d.x0) || 1) * 100;
      layer.hidden = false;
      line.style.left = `${x}%`;
      tip.replaceChildren();
      el("p", "tt", tip).textContent = when(t);
      const read = [];
      d.series.forEach((s, k) => {
        const j = cols[k].length ? nearest(cols[k], t) : -1;
        const ok = j >= 0 && Math.abs(cols[k][j] - t) <= step / 2;
        const v = ok ? s.pts[j][1] : null;
        dots[k].hidden = v === null;
        if (v !== null) {
          dots[k].style.left = `${x}%`;
          dots[k].style.top = `${d.pad + (1 - v / d.ymax) * (d.h - 2 * d.pad)}px`;
        }
        const row = el("p", `tr s${s.c}`, tip);
        el("i", "", row);
        el("span", "", row).textContent = s.name;
        el("b", "", row).textContent = v === null ? "no data" : exact(v, d.unit);
        read.push(`${s.name} ${v === null ? "no data" : exact(v, d.unit)}`);
      });
      tip.classList.toggle("flip", x > 60);
      tip.style.left = `${x}%`;
      if (announce) live.textContent = `${when(t)}: ${read.join(", ")}`;
    };
    const hide = () => { if (document.activeElement !== area) layer.hidden = true; };
    const fromPointer = (e) => {
      const r = area.getBoundingClientRect();
      show(nearest(times, d.x0 + (e.clientX - r.left) / r.width * (d.x1 - d.x0)), false);
    };

    area.addEventListener("pointermove", fromPointer);
    area.addEventListener("pointerdown", fromPointer);
    area.addEventListener("pointerleave", hide);
    area.addEventListener("focus", () => show(at, true));
    area.addEventListener("blur", () => { layer.hidden = true; });
    area.addEventListener("keydown", (e) => {
      const jump = e.shiftKey ? 10 : 1;
      const keys = { ArrowLeft: at - jump, ArrowRight: at + jump, Home: 0, End: times.length - 1 };
      if (e.key in keys) { e.preventDefault(); show(keys[e.key], true); }
      else if (e.key === "Escape") layer.hidden = true;
    });
  }
})();
