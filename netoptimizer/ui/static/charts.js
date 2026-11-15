/* Tiny dependency-free canvas charts with hover tooltips. */
(function () {
  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  const tip = () => document.getElementById("tip");

  function setup(canvas) {
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.font = "12px Segoe UI, Tahoma, sans-serif";
    ctx.direction = "ltr";
    return { ctx, w, h };
  }

  function niceMax(v) {
    if (!isFinite(v) || v <= 0) return 1;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  }

  function attachHover(canvas, hits) {
    canvas.onmousemove = (e) => {
      const r = canvas.getBoundingClientRect();
      const x = e.clientX - r.left, y = e.clientY - r.top;
      const h = hits.find((b) => x >= b.x && x <= b.x + b.w && y >= b.y && y <= b.y + b.h);
      const t = tip();
      if (h) {
        t.textContent = h.text; t.classList.remove("hidden");
        t.style.left = e.clientX + 12 + "px"; t.style.top = e.clientY + 12 + "px";
      } else t.classList.add("hidden");
    };
    canvas.onmouseleave = () => tip().classList.add("hidden");
  }

  /* Grouped horizontal bar chart: labels on the left, one bar per series. */
  function bars(canvas, { labels, series, unit = "ms", highlight = -1 }) {
    const n = labels.length;
    canvas.style.height = Math.max(160, n * (series.length * 12 + 12) + 40) + "px";
    const { ctx, w, h } = setup(canvas);
    const text = css("--text"), muted = css("--muted"), line = css("--line");
    const labelW = Math.min(170, Math.max(...labels.map((l) => ctx.measureText(l).width), 40) + 14);
    const left = labelW, right = w - 50, top = 10, bottom = h - 24;
    const vals = series.flatMap((s) => s.values.filter((v) => v != null && isFinite(v)));
    const max = niceMax(Math.max(...vals, 0));
    ctx.clearRect(0, 0, w, h);
    ctx.strokeStyle = line; ctx.fillStyle = muted; ctx.textAlign = "center";
    for (let i = 0; i <= 4; i++) {
      const x = left + ((right - left) * i) / 4;
      ctx.beginPath(); ctx.moveTo(x, top); ctx.lineTo(x, bottom); ctx.stroke();
      ctx.fillText(((max * i) / 4).toFixed(max < 10 ? 1 : 0) + (i === 4 ? " " + unit : ""), x, h - 6);
    }
    const rowH = (bottom - top) / Math.max(1, n);
    const barH = Math.max(4, Math.min(14, (rowH - 6) / series.length));
    const hits = [];
    labels.forEach((lab, i) => {
      const y0 = top + i * rowH + (rowH - barH * series.length) / 2;
      ctx.fillStyle = i === highlight ? css("--accent") : text;
      ctx.textAlign = "right";
      ctx.fillText(lab.length > 22 ? lab.slice(0, 21) + "…" : lab, left - 8, y0 + (barH * series.length) / 2 + 4);
      series.forEach((s, k) => {
        const v = s.values[i];
        if (v == null || !isFinite(v)) return;
        const bw = ((right - left) * v) / max;
        const y = y0 + k * barH;
        ctx.fillStyle = s.color; ctx.fillRect(left, y, bw, barH - 2);
        hits.push({ x: left, y, w: Math.max(bw, 4), h: barH, text: `${lab}\n${s.name}: ${v.toFixed(1)} ${unit}` });
      });
    });
    attachHover(canvas, hits);
  }

  /* Scatter of MTU probes over time, colored by outcome. */
  function probes(canvas, log) {
    canvas.style.height = "240px";
    const { ctx, w, h } = setup(canvas);
    const muted = css("--muted"), line = css("--line");
    const colors = { ok: css("--good"), frag_needed: css("--bad"), timeout: css("--warn"),
      unreachable: css("--muted"), error: css("--muted") };
    const left = 50, right = w - 12, top = 10, bottom = h - 24;
    const ys = log.map((p) => p.mtu);
    const ymin = Math.min(...ys, 1200), ymax = Math.max(...ys, 1500);
    ctx.clearRect(0, 0, w, h);
    ctx.strokeStyle = line; ctx.fillStyle = muted; ctx.textAlign = "right";
    for (let i = 0; i <= 4; i++) {
      const v = ymin + ((ymax - ymin) * i) / 4, y = bottom - ((bottom - top) * i) / 4;
      ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(right, y); ctx.stroke();
      ctx.fillText(Math.round(v), left - 6, y + 4);
    }
    const hits = [];
    log.forEach((p, i) => {
      const x = left + ((right - left) * i) / Math.max(1, log.length - 1);
      const y = bottom - ((bottom - top) * (p.mtu - ymin)) / Math.max(1, ymax - ymin);
      ctx.fillStyle = colors[p.status] || muted;
      ctx.beginPath(); ctx.arc(x, y, 3.5, 0, Math.PI * 2); ctx.fill();
      hits.push({ x: x - 5, y: y - 5, w: 10, h: 10, text: `#${i + 1} ${p.dest}\nMTU ${p.mtu}: ${p.status}${p.rtt != null ? " (" + p.rtt + " ms)" : ""}` });
    });
    attachHover(canvas, hits);
  }

  /* Distribution (sorted samples) for before/after comparison. */
  function distribution(canvas, sets) {
    canvas.style.height = "240px";
    const { ctx, w, h } = setup(canvas);
    const muted = css("--muted"), line = css("--line");
    const left = 50, right = w - 12, top = 10, bottom = h - 24;
    const all = sets.flatMap((s) => s.values);
    const max = niceMax(Math.max(...all, 1));
    ctx.clearRect(0, 0, w, h);
    ctx.strokeStyle = line; ctx.fillStyle = muted; ctx.textAlign = "right";
    for (let i = 0; i <= 4; i++) {
      const y = bottom - ((bottom - top) * i) / 4;
      ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(right, y); ctx.stroke();
      ctx.fillText(((max * i) / 4).toFixed(0) + (i === 4 ? " ms" : ""), left - 6, y + 4);
    }
    ctx.textAlign = "center";
    ["0%", "50%", "100%"].forEach((t, i) => ctx.fillText(t, left + ((right - left) * i) / 2, h - 6));
    const hits = [];
    sets.forEach((s) => {
      const v = [...s.values].sort((a, b) => a - b);
      ctx.strokeStyle = s.color; ctx.lineWidth = 2; ctx.beginPath();
      v.forEach((val, i) => {
        const x = left + ((right - left) * i) / Math.max(1, v.length - 1);
        const y = bottom - ((bottom - top) * val) / max;
        i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
        hits.push({ x: x - 4, y: y - 4, w: 8, h: 8, text: `${s.name}\np${Math.round((100 * i) / Math.max(1, v.length - 1))}: ${val.toFixed(1)} ms` });
      });
      ctx.stroke(); ctx.lineWidth = 1;
    });
    attachHover(canvas, hits);
  }

  window.Charts = { bars, probes, distribution };
})();
