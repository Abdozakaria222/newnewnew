/* NetworkOptimizer UI */
(function () {
  "use strict";
  const TOKEN = new URLSearchParams(location.hash.slice(1)).get("t") || sessionStorage.getItem("netopt_t") || "";
  if (TOKEN) sessionStorage.setItem("netopt_t", TOKEN);
  let S = null;              // last /api/state
  let lang = "ar", page = "dashboard", lastEvent = 0, activeJob = null;
  const $ = (id) => document.getElementById(id);
  const t = (k) => (I18N[lang] && I18N[lang][k]) || I18N.en[k] || k;
  const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const ms = (v) => (v == null ? "—" : v.toFixed(1) + " ms");
  const pct = (v) => (v == null ? "—" : (v * 100).toFixed(1) + "%");
  const num = (v, d = 1) => (v == null ? "—" : Number(v).toFixed(d));

  async function api(path, opts = {}) {
    const r = await fetch("/api" + path, {
      method: opts.method || "GET",
      headers: { "X-Token": TOKEN, "Content-Type": "application/json" },
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    const ct = r.headers.get("content-type") || "";
    const data = ct.includes("json") ? await r.json() : await r.text();
    if (!r.ok) throw new Error((data && data.error) || r.statusText);
    return data;
  }
  const dl = (path) => { location.href = "/api" + path + (path.includes("?") ? "&" : "?") + "t=" + encodeURIComponent(TOKEN); };

  function toast(msg, cls = "", actions = []) {
    const d = document.createElement("div");
    d.className = "toast " + cls;
    d.innerHTML = `<div>${msg}</div>`;
    if (actions.length) {
      const a = document.createElement("div"); a.className = "actions";
      actions.forEach(([label, fn]) => { const b = document.createElement("button"); b.className = "small"; b.textContent = label; b.onclick = () => { fn(); d.remove(); }; a.appendChild(b); });
      d.appendChild(a);
    }
    $("toasts").appendChild(d);
    setTimeout(() => d.remove(), actions.length ? 30000 : 6000);
  }

  function modal(title, bodyHtml, okLabel = t("confirm")) {
    return new Promise((resolve) => {
      $("modalTitle").textContent = title; $("modalBody").innerHTML = bodyHtml;
      $("modalOk").textContent = okLabel; $("modalCancel").textContent = t("cancel");
      $("modal").classList.remove("hidden");
      const done = (v) => { $("modal").classList.add("hidden"); resolve(v); };
      $("modalOk").onclick = () => done(true); $("modalCancel").onclick = () => done(false);
    });
  }

  // ---------------------------------------------------------------- jobs
  async function startJob(path, body) {
    try {
      const r = await api(path, { method: "POST", body: body || {} });
      trackJob(r.job);
    } catch (e) { toast(esc(e.message), "bad"); }
  }
  function trackJob(job) {
    activeJob = job.id;
    $("jobbar").classList.remove("hidden");
    $("jobKind").textContent = t("job_" + job.kind) || job.kind;
    const tick = async () => {
      if (activeJob !== job.id) return;
      let j;
      try { j = (await api("/job/" + job.id)).job; } catch (e) { return setTimeout(tick, 1500); }
      $("jobMsg").textContent = j.message || "";
      $("jobProg").style.width = Math.round(j.progress * 100) + "%";
      if (j.state === "running") return setTimeout(tick, 600);
      $("jobbar").classList.add("hidden"); activeJob = null;
      if (j.state === "done") toast(t("done") + ": " + esc(t("job_" + j.kind) || j.kind));
      else if (j.state === "cancelled") toast(t("cancelled"));
      else toast(t("failed") + ": " + esc(j.error), "bad");
      if (j.kind.startsWith("tool_") || j.kind === "packet_loss") showToolResult(j);
      await loadState(); render();
    };
    $("jobCancel").onclick = () => api("/job/" + job.id + "/cancel", { method: "POST" });
    tick();
  }

  // ---------------------------------------------------------------- state
  async function loadState() {
    S = await api("/state");
    lang = S.settings.language; applyLang();
    document.documentElement.dataset.theme = S.settings.theme;
    $("ver").textContent = "v" + S.version;
  }
  function applyLang() {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
    document.querySelectorAll("[data-i18n]").forEach((e) => (e.textContent = t(e.dataset.i18n)));
    $("langBtn").textContent = lang === "ar" ? "English" : "العربية";
  }
  async function pollEvents() {
    try {
      const r = await api("/events?since=" + lastEvent);
      r.events.forEach((e) => {
        lastEvent = Math.max(lastEvent, e.id);
        const acts = [];
        if (e.rerun.includes("dns")) acts.push([t("run_dns"), () => startJob("/dns/start")]);
        if (e.rerun.includes("mtu")) acts.push([t("run_mtu"), () => startJob("/mtu/start")]);
        acts.push([t("dismiss"), () => {}]);
        toast(`<b>${t("event_title")}</b><br>${esc(e.message)}`, "", acts);
      });
      if (r.events.length) { await loadState(); if (page === "dashboard") render(); }
    } catch (e) { /* server restarting */ }
    setTimeout(pollEvents, 5000);
  }

  // ---------------------------------------------------------------- pages
  const pages = {};
  function render() {
    document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.page === page));
    banner();
    const out = pages[page]();
    if (out instanceof Promise) out.catch((e) => ($("page").innerHTML = `<div class="banner warn">${esc(e.message)}</div>`));
  }
  function banner() {
    let h = "";
    if (S && S.platform !== "win32") h += `<div class="banner warn">${t("not_windows")}</div>`;
    else if (S && !S.admin) h += `<div class="banner info">${t("admin_note")}</div>`;
    $("banner").innerHTML = h;
  }
  const kpi = (label, value, hint = "") => `<div class="card kpi"><div class="label">${label}</div><div class="value">${value}</div>${hint ? `<div class="hint">${hint}</div>` : ""}</div>`;
  const chip = (txt, cls = "") => `<span class="chip ${cls}">${esc(txt)}</span>`;
  const reasons = (list) => `<ul class="reasons">${(list || []).map((r) => `<li>${esc(r)}</li>`).join("")}</ul>`;
  const decLabel = (d) => t("dec_" + (d || "no_data"));

  pages.dashboard = () => {
    const p = S.primary || {}, r4 = S.recommendations.ipv4, r6 = S.recommendations.ipv6;
    const prof = S.profile;
    const dnsNow = [...(p.dns4 || []), ...(p.dns6 || [])].slice(0, 4).join("<br>") || t("none");
    const recD = r4.dns ? `${esc(r4.dns.name)}<div class="mono" style="font-size:13px">${esc(r4.dns.primary)} / ${esc(r4.dns.secondary || "—")}</div>` : t("not_tested");
    const recM = r4.mtu && r4.mtu.recommended ? `${r4.mtu.recommended} <span class="chip">${esc(decLabel(r4.mtu.decision))}</span>` : t("not_tested");
    const kinds = [];
    if (p.kind) kinds.push(chip(p.kind));
    if (p.is_pppoe) kinds.push(chip(t("pppoe"), "warn"));
    if (S.vpn_active) kinds.push(chip(t("vpn_on") + ": " + S.vpn_adapters.join(", "), "warn"));
    let h = `<h1>${t("dash_title")}</h1><p class="sub">${t("dash_sub")}</p>`;
    if (S.profile_known && prof && prof.history && prof.history.length)
      h += `<div class="banner info"><b>${t("known_network")}</b> — ${esc(prof.label)}<br><span class="muted">${t("known_network_txt")}</span></div>`;
    h += `<div class="row" style="margin-bottom:14px">
      <button class="primary" id="bFull">${t("run_full")}</button>
      <button id="bDns">${t("run_dns")}</button><button id="bMtu">${t("run_mtu")}</button>
      <span class="spacer"></span>
      <button id="bApply" ${r4.dns || (r4.mtu && r4.mtu.recommended) ? "" : "disabled"}>${t("apply_rec")}</button>
      <button class="ghost" id="bRef">${t("refresh")}</button></div>`;
    h += `<div class="grid">
      ${kpi(t("connection"), p.alias ? `<span class="chip good">${t("online")}</span>` : `<span class="chip bad">${t("offline")}</span>`, kinds.join(" "))}
      ${kpi(t("adapter"), esc(p.alias || t("none")), esc(p.description || ""))}
      ${kpi(t("current_dns"), `<span class="mono" style="font-size:14px">${dnsNow}</span>`, p.dns4_source ? t(p.dns4_source) : "")}
      ${kpi(t("rec_dns"), recD, r4.dns && r4.dns.keep_current ? t("keep_current") : "")}
      ${kpi(t("current_mtu"), `IPv4 ${p.mtu4 || "—"} · IPv6 ${p.mtu6 || "—"}`)}
      ${kpi(t("rec_mtu"), recM, r4.mtu ? t("confidence") + ": " + r4.mtu.confidence + "%" : "")}
      ${kpi(t("last_bench"), esc(S.last_benchmark || t("none")))}
      ${kpi(t("profile"), esc(prof ? prof.label : t("none")), prof ? `<span class="mono">${esc(prof.key)}</span>` : "")}
      ${kpi(t("opt_status"), t("st_" + S.optimization_status))}
    </div>`;
    if (S.compare && S.compare.verdict)
      h += `<div class="card section"><h2>${t("nav_compare")}</h2><div class="verdict ${esc(S.compare.verdict)}">${esc(S.compare.summary)}</div></div>`;
    if (prof && prof.history && prof.history.length) {
      h += `<div class="card section"><h2>${t("prev_results")}</h2><div class="table-wrap"><table><tr><th>${t("last_bench")}</th><th>${t("kind")}</th><th>${t("family")}</th><th>${t("recommendation")}</th><th class="num">${t("score")} / ${t("confidence")}</th></tr>
        ${prof.history.slice().reverse().slice(0, 10).map((x) => `<tr><td>${esc(x.date)}</td><td>${esc(x.type)}</td><td>${esc(x.family || "")}</td><td>${esc(x.type === "dns" ? (x.name || "—") + " " + (x.primary || "") : x.type === "mtu" ? (x.recommended || "—") + " (" + (x.decision || "") + ")" : x.summary || "")}</td><td class="num">${esc(x.score ?? x.confidence ?? "")}</td></tr>`).join("")}
      </table></div></div>`;
    }
    $("page").innerHTML = h;
    $("bFull").onclick = () => startJob("/workflow/start");
    $("bDns").onclick = () => startJob("/dns/start");
    $("bMtu").onclick = () => startJob("/mtu/start");
    $("bRef").onclick = async () => { await api("/refresh", { method: "POST" }); await loadState(); render(); };
    $("bApply").onclick = applyDialog;
  };

  async function applyDialog() {
    const r4 = S.recommendations.ipv4, r6 = S.recommendations.ipv6, p = S.primary || {};
    const opts = [];
    if (r4.dns && r4.dns.primary) opts.push(["dns4", t("apply_dns4"), [r4.dns.primary, r4.dns.secondary].filter(Boolean), (p.dns4 || []).join(", ")]);
    if (r6.dns && r6.dns.primary) opts.push(["dns6", t("apply_dns6"), [r6.dns.primary, r6.dns.secondary].filter(Boolean), (p.dns6 || []).join(", ")]);
    if (r4.mtu && r4.mtu.recommended && r4.mtu.recommended !== p.mtu4) opts.push(["mtu4", t("apply_mtu4"), r4.mtu.recommended, p.mtu4]);
    if (r6.mtu && r6.mtu.recommended && r6.mtu.recommended !== p.mtu6) opts.push(["mtu6", t("apply_mtu6"), r6.mtu.recommended, p.mtu6]);
    if (!opts.length) return toast(t("dec_keep"));
    const body = `<p class="muted">${t("apply_txt")}</p><p><b>${esc(p.alias)}</b></p>` + opts.map(([k, label, val, cur]) => {
      const def = !(k.startsWith("dns") && ((k === "dns4" ? r4 : r6).dns.keep_current));
      return `<label class="row" style="margin:8px 0"><input type="checkbox" data-k="${k}" ${def ? "checked" : ""}> <b>${label}</b>: <span class="mono">${esc(cur || "—")}</span> → <span class="mono">${esc(Array.isArray(val) ? val.join(", ") : val)}</span></label>`;
    }).join("");
    if (!(await modal(t("apply_title"), body))) return;
    const sel = {};
    document.querySelectorAll("#modalBody input[data-k]").forEach((c) => { if (c.checked) { const o = opts.find((x) => x[0] === c.dataset.k); sel[o[0]] = o[2]; } });
    if (!Object.keys(sel).length) return;
    sel.adapter_index = p.index;
    try {
      const r = await api("/apply", { method: "POST", body: sel });
      const bad = r.checks.filter((c) => !c.ok);
      toast(bad.length ? t("verify_failed") + ": " + esc(bad.map((c) => c.check + " " + c.detail).join("; ")) : t("applied"), bad.length ? "bad" : "");
      await loadState(); render();
    } catch (e) { toast(esc(e.message), "bad"); }
  }

  pages.dns = async () => {
    const res = await api("/results");
    let h = `<h1>${t("dns_title")}</h1><p class="sub">${t("dns_sub")}</p>
      <div class="row" style="margin-bottom:14px"><button class="primary" id="go">${t("run_dns")}</button></div>`;
    const fams = Object.keys(res.dns);
    if (!fams.length) h += `<div class="card">${t("no_results")}</div>`;
    fams.forEach((fam) => {
      const r = res.dns[fam];
      if (r.skipped) { h += `<div class="card section"><h2>${fam.toUpperCase()}</h2>${t("skipped")}: ${esc(r.skipped)}</div>`; return; }
      const rec = r.recommendation || {};
      h += `<div class="card section"><div class="row"><h2>${fam.toUpperCase()} — ${t("recommendation")}: ${esc(rec.name || "—")}</h2><span class="spacer"></span><span class="muted bidi">${esc(r.date)} · ${r.rounds} rounds · ${r.duration_s}s</span></div>
        ${rec.primary ? `<div class="big mono">${esc(rec.primary)} <span class="muted" style="font-size:16px">/ ${esc(rec.secondary || "—")}</span></div>` : ""}
        <details open><summary>${t("why")}</summary>${reasons(rec.reasons)}<p class="muted">${t("weights_doc")}</p></details></div>
        <div class="grid2 section"><div class="card"><h3>${t("median")} / ${t("p95")}</h3><canvas class="chart" id="c_${fam}"></canvas>
        <div class="legend"><span><i style="background:var(--accent)"></i>${t("median")}</span><span><i style="background:var(--accent2)"></i>P95</span></div></div>
        <div class="card"><h3>${t("cached")} / ${t("uncached")}</h3><canvas class="chart" id="cu_${fam}"></canvas>
        <div class="legend"><span><i style="background:var(--good)"></i>${t("cached")}</span><span><i style="background:var(--warn)"></i>${t("uncached")}</span></div></div></div>
        <div class="card section table-wrap"><table class="sortable"><thead><tr><th>${t("provider")}</th><th>${t("primary")}</th><th class="num">${t("median")}</th><th class="num">P90</th><th class="num">P95</th>
        <th class="num">${t("success")}</th><th class="num">${t("timeouts")}</th><th class="num">${t("consistency")}</th><th class="num">${t("secondary")}</th><th class="num">${t("score")}</th><th>${t("score_parts")}</th></tr></thead><tbody>
        ${r.providers.map((x) => `<tr class="${x.provider === rec.provider ? "best" : ""}"><td>${esc(x.name)} ${x.source === "system" ? chip("current") : ""} ${x.filtering !== "none" ? chip(x.filtering) : ""}</td><td class="mono">${esc(x.primary)}</td>
          <td class="num">${ms(x.metrics.median)}</td><td class="num">${ms(x.metrics.p90)}</td><td class="num">${ms(x.metrics.p95)}</td>
          <td class="num">${pct(x.metrics.success_rate)}</td><td class="num">${pct(x.metrics.timeout_rate)}</td><td class="num">${num(x.metrics.variability, 2)}</td>
          <td class="num">${x.secondary_metrics ? (x.secondary_compatible ? chip("OK", "good") : chip("✗", "bad")) + " " + ms(x.secondary_metrics.median) : "—"}</td>
          <td class="num"><b>${x.eligible ? x.score : chip("✗ " + pct(x.metrics.success_rate), "bad")}</b></td>
          <td class="muted" style="font-size:11px">${Object.entries(x.score_parts || {}).map(([k, v]) => k + " " + v).join(" · ")}</td></tr>`).join("")}
        </tbody></table></div>`;
    });
    $("page").innerHTML = h;
    $("go").onclick = () => startJob("/dns/start");
    fams.forEach((fam) => {
      const r = res.dns[fam]; if (r.skipped) return;
      const rows = r.providers.slice(0, 14), labels = rows.map((x) => x.name);
      const hi = rows.findIndex((x) => x.provider === (r.recommendation || {}).provider);
      Charts.bars($("c_" + fam), { labels, highlight: hi, series: [
        { name: "Median", color: getComputedStyle(document.documentElement).getPropertyValue("--accent"), values: rows.map((x) => x.metrics.median) },
        { name: "P95", color: getComputedStyle(document.documentElement).getPropertyValue("--accent2"), values: rows.map((x) => x.metrics.p95) }] });
      Charts.bars($("cu_" + fam), { labels, highlight: hi, series: [
        { name: t("cached"), color: getComputedStyle(document.documentElement).getPropertyValue("--good"), values: rows.map((x) => x.metrics.cached.median) },
        { name: t("uncached"), color: getComputedStyle(document.documentElement).getPropertyValue("--warn"), values: rows.map((x) => x.metrics.uncached.median) }] });
    });
    sortable();
  };

  pages.mtu = async () => {
    const res = await api("/results");
    let h = `<h1>${t("mtu_title")}</h1><p class="sub">${t("mtu_sub")}</p>
      <div class="row" style="margin-bottom:14px"><button class="primary" id="go">${t("run_mtu")}</button></div>`;
    const fams = Object.keys(res.mtu);
    if (!fams.length) h += `<div class="card">${t("no_results")}</div>`;
    fams.forEach((fam) => {
      const r = res.mtu[fam];
      if (r.skipped) { h += `<div class="card section"><h2>${fam.toUpperCase()}</h2>${t("skipped")}: ${esc(r.skipped)}</div>`; return; }
      const v = r.verification || {};
      h += `<div class="grid section">
        ${kpi(fam.toUpperCase() + " — " + t("rec_mtu"), r.recommended || "—", decLabel(r.decision))}
        ${kpi(t("current_mtu"), r.current_mtu || "—")}
        ${kpi(t("path_mtu"), r.path_mtu || "—", (r.agreeing_destinations || []).join(", "))}
        ${kpi(t("confidence"), (r.confidence ?? 0) + "%", Object.entries(r.confidence_parts || {}).map(([k, x]) => k + " " + x).join(" · "))}
        ${kpi(t("probes"), r.probes_sent, esc(r.date))}</div>
        <div class="card section"><h2>${t("why")}</h2>${reasons(r.reasons)}${r.notes && r.notes.length ? `<h3 style="margin-top:10px">${t("notes")}</h3>${reasons(r.notes)}` : ""}</div>
        ${(r.proof || []).length ? `<div class="card section"><h2>${t("mtu_proof")}</h2><pre class="mono proof">${esc(r.proof.join("\n"))}</pre></div>` : ""}
        <div class="grid2 section"><div class="card"><h3>${t("probes")}</h3><canvas class="chart" id="m_${fam}"></canvas>
          <div class="legend"><span><i style="background:var(--good)"></i>${t("legend_ok")}</span><span><i style="background:var(--bad)"></i>${t("legend_frag")}</span><span><i style="background:var(--warn)"></i>${t("legend_to")}</span></div></div>
        <div class="card table-wrap"><h3>${t("baseline")} / ${t("destinations")}</h3><table><tr><th>${t("destinations")}</th><th>${t("status")}</th><th class="num">${t("replies")}</th><th class="num">MTU</th><th class="num">${t("confidence")}</th></tr>
          ${Object.entries(r.baseline || {}).map(([d, b]) => { const s = (r.destinations || {})[d] || {}; const c = s.confirm || {};
            return `<tr><td class="mono">${esc(d)}</td><td>${chip(b.state, b.state === "ok" ? "good" : "bad")}</td><td class="num">${b.replies}/${b.sent}</td><td class="num">${s.max || "—"}</td><td class="num">${c.attempts ? c.passes + "/" + c.attempts : "—"}</td></tr>`; }).join("")}
          </table>
          ${v.small ? `<h3 style="margin-top:12px">${t("verification")}</h3><table>${["small", "medium", "large"].map((k) => `<tr><td>${k}</td><td class="num">${v[k].mtu}</td><td class="num">${v[k].ok}/${v[k].sent}</td></tr>`).join("")}</table>` : ""}
        </div></div>
        ${(r.trace || []).length ? `<details class="card section"><summary>${t("mtu_trace")} (${r.trace.length})</summary><pre class="mono proof">${esc(r.trace.join("\n"))}</pre></details>` : ""}`;
    });
    $("page").innerHTML = h;
    $("go").onclick = () => startJob("/mtu/start");
    fams.forEach((fam) => { const r = res.mtu[fam]; if (r.probe_log && r.probe_log.length) Charts.probes($("m_" + fam), r.probe_log); });
  };

  pages.compare = async () => {
    const c = await api("/compare");
    let h = `<h1>${t("cmp_title")}</h1><p class="sub">${t("cmp_sub")}</p>
      <div class="row" style="margin-bottom:14px"><button class="primary" id="b1">${t("cmp_before")}</button>
      <button id="b2" ${S.compare_has_before ? "" : "disabled"}>${t("cmp_apply")}</button>
      <button class="primary" id="b3" ${S.compare_has_before ? "" : "disabled"}>${t("cmp_after")}</button></div>`;
    if (!c.verdict) h += `<div class="card">${S.compare_has_before ? "✓ " + t("before") : t("cmp_need_before")}</div>`;
    else {
      h += `<div class="verdict ${esc(c.verdict)}">${esc(c.summary)}</div>
      <div class="card table-wrap"><table><tr><th></th><th class="num">${t("before")}</th><th class="num">${t("after")}</th><th class="num">${t("diff")}</th><th class="num">${t("improvement")}</th><th>p</th><th>${t("significant")}</th></tr>
      ${c.rows.map((r) => { const f = (v) => typeof v === "boolean" ? (v ? "✓" : "✗") : r.metric.includes("rate") || r.metric.includes("loss") ? pct(v) : r.metric === "MTU" ? (v ?? "—") : ms(v);
        return `<tr><td>${esc(r.metric)}</td><td class="num">${f(r.before)}</td><td class="num">${f(r.after)}</td><td class="num">${r.diff_ms != null ? (r.diff_ms > 0 ? "+" : "") + r.diff_ms.toFixed(1) + " ms" : ""}</td>
        <td class="num">${r.improvement_pct != null ? r.improvement_pct + "%" : ""}</td><td>${r.p_value != null ? r.p_value.toFixed(3) : ""}</td>
        <td>${r.significant == null ? "" : r.significant ? chip(r.better ? t("yes") + " ↑" : t("yes") + " ↓", r.better ? "good" : "bad") : chip(t("no"))}</td></tr>`; }).join("")}
      </table><p class="muted">${esc(c.before_time)} → ${esc(c.after_time)}</p></div>
      <div class="card section"><h3>DNS ${t("median")} — distribution</h3><canvas class="chart" id="dist"></canvas>
      <div class="legend"><span><i style="background:var(--muted)"></i>${t("before")}</span><span><i style="background:var(--accent)"></i>${t("after")}</span></div></div>`;
    }
    $("page").innerHTML = h;
    $("b1").onclick = () => startJob("/compare/before");
    $("b2").onclick = applyDialog;
    $("b3").onclick = () => startJob("/compare/after");
    if (c.before_samples) {
      const cs = getComputedStyle(document.documentElement);
      Charts.distribution($("dist"), [{ name: t("before"), color: cs.getPropertyValue("--muted"), values: c.before_samples },
        { name: t("after"), color: cs.getPropertyValue("--accent"), values: c.after_samples }]);
    }
  };

  pages.profiles = async () => {
    const r = await api("/profiles");
    const list = Object.values(r.profiles);
    let h = `<h1>${t("prof_title")}</h1><p class="sub">${t("prof_sub")}</p>`;
    if (!list.length) h += `<div class="card">${t("none")}</div>`;
    list.forEach((p) => {
      const o = p.original || {}, b = p.best || {};
      h += `<div class="card section"><div class="row"><h2>${esc(p.label)} ${p.key === r.current ? chip("●", "good") : ""}</h2><span class="spacer"></span>
        <button class="small" data-ren="${esc(p.key)}">${t("rename")}</button><button class="small danger" data-del="${esc(p.key)}">${t("delete")}</button></div>
        <div class="grid">${kpi(t("adapter"), esc(p.adapter.alias), esc(p.adapter.kind) + " · <span class='mono'>" + esc(p.adapter.mac || "") + "</span>")}
        ${kpi(t("original"), `<span class="mono" style="font-size:13px">DNS ${esc((o.dns4 || []).join(", ") || "—")} (${esc(o.dns4_source)})<br>MTU ${esc(o.mtu4)} / ${esc(o.mtu6)}</span>`, esc(o.recorded))}
        ${kpi(t("best"), `<span style="font-size:13px">DNS ${esc(b.dns_ipv4 ? b.dns_ipv4.name + " " + b.dns_ipv4.primary : "—")}<br>MTU ${esc(b.mtu_ipv4 ? b.mtu_ipv4.mtu + " (" + b.mtu_ipv4.confidence + "%)" : "—")}</span>`, esc(p.last_test || ""))}
        ${kpi(t("created") + " / " + t("last_seen"), esc(p.created), esc(p.last_seen) + " · ×" + p.seen_count)}</div></div>`;
    });
    $("page").innerHTML = h;
    document.querySelectorAll("[data-ren]").forEach((b) => (b.onclick = async () => {
      const v = prompt(t("rename")); if (v) { await api(`/profiles/${b.dataset.ren}/rename`, { method: "POST", body: { label: v } }); render(); } }));
    document.querySelectorAll("[data-del]").forEach((b) => (b.onclick = async () => {
      if (await modal(t("delete") + "?", "")) { await api(`/profiles/${b.dataset.del}`, { method: "DELETE" }); render(); } }));
  };

  pages.backup = async () => {
    const r = await api("/backups");
    let h = `<h1>${t("bk_title")}</h1><p class="sub">${t("bk_sub")}</p>
      <div class="row" style="margin-bottom:14px"><button id="prev">${t("restore_prev")}</button><span class="muted">${t("backup_folder")}: <span class="mono">${esc(r.folder)}</span></span></div>
      <div class="card table-wrap"><table><tr><th>${t("created")}</th><th>${t("kind")}</th><th>${t("adapter")}</th><th>DNS</th><th class="num">MTU</th><th></th></tr>
      ${r.backups.map((b) => { const a = b.adapter || {}; return `<tr><td>${esc(b.created)}</td><td>${b.kind === "original" ? chip(t("original"), "good") : esc(b.reason)}</td><td>${esc(a.alias)}</td>
        <td class="mono">${esc((a.dns4 || []).join(", "))} (${esc(a.dns4_source)})</td><td class="num">${esc(a.mtu4)}</td>
        <td><button class="small" data-r="${esc(b.file)}" data-p="dns">${t("restore_dns")}</button> <button class="small" data-r="${esc(b.file)}" data-p="mtu">${t("restore_mtu")}</button>
        <button class="small" data-r="${esc(b.file)}" data-p="dns,mtu,ip">${t("restore_all")}</button> <button class="small ghost" data-x="${esc(b.file)}">${t("export")}</button></td></tr>`; }).join("") || `<tr><td colspan="6">${t("none")}</td></tr>`}
      </table></div>`;
    $("page").innerHTML = h;
    document.querySelectorAll("[data-x]").forEach((b) => (b.onclick = () => dl("/backups/" + b.dataset.x)));
    document.querySelectorAll("[data-r]").forEach((b) => (b.onclick = async () => {
      if (!(await modal(t("restore_q"), `<p class="mono">${esc(b.dataset.r)}</p><p>${esc(b.dataset.p)}</p><p class="muted">${t("apply_txt")}</p>`))) return;
      try { const res = await api("/restore", { method: "POST", body: { backup: b.dataset.r, parts: b.dataset.p.split(",") } });
        const bad = res.checks.filter((c) => !c.ok); toast(bad.length ? t("verify_failed") : t("applied"), bad.length ? "bad" : ""); await loadState(); render();
      } catch (e) { toast(esc(e.message), "bad"); } }));
    $("prev").onclick = async () => {
      if (!(await modal(t("restore_prev") + "?", `<p class="muted">${t("apply_txt")}</p>`))) return;
      try { await api("/restore/profile", { method: "POST" }); toast(t("applied")); await loadState(); render(); } catch (e) { toast(esc(e.message), "bad"); } };
  };

  const TOOLS = ["connectivity", "ipcheck", "publicip", "leak", "resolution", "packet_loss", "gateway", "adapters"];
  let toolResults = {};
  let lastTool = null;
  function showToolResult(j) {
    const name = lastTool || j.kind.replace("tool_", "");
    toolResults[name] = j.state === "done" ? j.result : { error: j.error };
    if (page === "tools") render();
  }
  pages.tools = () => {
    let h = `<h1>${t("tools_title")}</h1><p class="sub">${t("tools_sub")}</p><div class="grid2">`;
    TOOLS.forEach((n) => {
      const r = toolResults[n];
      h += `<div class="card"><div class="row"><h2>${t("t_" + n)}</h2><span class="spacer"></span><button class="small primary" data-tool="${n}">${t("run")}</button></div>
        ${n === "leak" ? `<p class="muted">${t("leak_note")}</p>` : ""}${r ? toolView(n, r) : ""}</div>`;
    });
    h += `<div class="card"><div class="row"><h2>${t("t_report")}</h2><span class="spacer"></span><button class="small primary" id="rep">${t("export")}</button></div></div></div>`;
    $("page").innerHTML = h;
    document.querySelectorAll("[data-tool]").forEach((b) => (b.onclick = () => { lastTool = b.dataset.tool; startJob("/tool/" + b.dataset.tool); }));
    $("rep").onclick = () => dl("/report");
  };
  function toolView(n, r) {
    if (r.error && typeof r.error === "string" && Object.keys(r).length === 1) return `<p class="chip bad">${esc(r.error)}</p>`;
    if (n === "connectivity") return `<p>${chip(t("online"), r.online ? "good" : "bad")} DNS ${chip(r.dns_working ? "✓" : "✗", r.dns_working ? "good" : "bad")} HTTP ${chip(r.http_working ? "✓" : "✗", r.http_working ? "good" : "bad")}</p>` + kv(r.checks);
    if (n === "ipcheck") return `<p>IPv4 ${chip(r.ipv4 ? "✓" : "✗", r.ipv4 ? "good" : "bad")} IPv6 ${chip(r.ipv6 ? "✓" : "✗", r.ipv6 ? "good" : "bad")} AAAA ${chip(r.ipv6_dns_aaaa ? "✓" : "✗")}</p>`;
    if (n === "publicip") return `<p class="mono big" style="font-size:18px">${esc(r.ipv4 || "—")}<br>${esc(r.ipv6 || "")}</p>`;
    if (n === "leak") return `<p><b>${r.distinct_resolvers.length}</b> resolver(s): <span class="mono">${esc(r.distinct_resolvers.join(", "))}</span></p>` + kv(r.observations) + `<p class="muted">${esc(r.note)}</p>`;
    if (n === "resolution") return (r.hijack_suspected ? `<p class="chip bad">NXDOMAIN hijacking suspected</p>` : "") + `<div class="table-wrap"><table>${r.rows.map((x) => `<tr><td class="mono">${esc(x.server)}</td><td>${esc(x.name)}</td><td>${esc(x.type)}</td><td>${chip(x.rcode || x.error, x.ok ? "good" : "bad")}</td><td class="num">${ms(x.ms)}</td></tr>`).join("")}</table></div>`;
    if (n === "packet_loss") return `<table>${r.targets.map((x) => `<tr><td class="mono">${esc(x.target)}</td><td class="num">${x.received}/${x.sent}</td><td class="num">${pct(x.loss)}</td><td class="num">${ms(x.latency.median)}</td><td class="num">jitter ${ms(x.jitter_ms)}</td></tr>`).join("")}</table>`;
    if (n === "gateway") return r.error ? `<p>${esc(r.error)}</p>` : `<p class="mono">${esc(r.target)}: ${t("median")} ${ms(r.latency.median)} · P95 ${ms(r.latency.p95)} · loss ${pct(r.loss)} · jitter ${ms(r.jitter_ms)}</p>`;
    if (n === "adapters") return `<div class="table-wrap"><table><tr><th>${t("adapter")}</th><th>${t("kind")}</th><th>${t("status")}</th><th>IPv4</th><th>GW</th><th>DNS</th><th class="num">MTU</th><th>MAC</th></tr>${r.map((a) => `<tr><td>${esc(a.alias)}</td><td>${esc(a.kind)}</td><td>${esc(a.status)}</td><td class="mono">${esc(a.ipv4.join(" "))}</td><td class="mono">${esc(a.gateway4.join(" "))}</td><td class="mono">${esc(a.dns4.join(" "))} (${esc(a.dns4_source)})</td><td class="num">${esc(a.mtu4)}</td><td class="mono">${esc(a.mac || "")}</td></tr>`).join("")}</table></div>`;
    return `<pre class="log">${esc(JSON.stringify(r, null, 2))}</pre>`;
  }
  const kv = (o) => `<details><summary>details</summary><pre class="log">${esc(JSON.stringify(o, null, 2))}</pre></details>`;

  pages.providers = async () => {
    const r = await api("/providers");
    let h = `<h1>${t("prov_title")}</h1><p class="sub">${t("prov_sub")}</p>
      <div class="card"><h2>${t("add_custom")}</h2><div class="form-grid">
        <div class="field"><label>${t("id")}</label><input id="pId" placeholder="my-dns"></div>
        <div class="field"><label>${t("name")}</label><input id="pName"></div>
        <div class="field"><label>IPv4 (${t("primary")}, ${t("secondary")})</label><input id="p4" class="mono" placeholder="1.2.3.4, 1.2.3.5"></div>
        <div class="field"><label>IPv6</label><input id="p6" class="mono"></div></div>
        <div class="row" style="margin-top:12px"><button class="primary" id="pAdd">${t("save")}</button><span class="spacer"></span>
        <button id="pExp">${t("export_list")}</button><label class="row"><button id="pImpB">${t("import")}</button><input type="file" id="pImp" accept=".json" class="hidden"></label></div></div>
      <div class="card section table-wrap"><table><tr><th>${t("name")}</th><th>${t("id")}</th><th>IPv4</th><th>IPv6</th><th>${t("filtering")}</th><th>${t("source")}</th><th></th></tr>
      ${r.providers.map((p) => `<tr><td>${esc(p.name)}</td><td class="mono">${esc(p.id)}</td><td class="mono">${esc(p.ipv4.join(", "))}</td><td class="mono" style="font-size:11px">${esc(p.ipv6.join(", "))}</td><td>${esc(p.filtering)}</td><td>${chip(p.source)}</td>
        <td>${p.source === "custom" || p.source === "imported" ? `<button class="small danger" data-del="${esc(p.id)}">${t("delete")}</button>` : ""}</td></tr>`).join("")}</table></div>`;
    $("page").innerHTML = h;
    const split = (s) => s.split(/[,\s]+/).filter(Boolean);
    $("pAdd").onclick = async () => {
      try { await api("/providers", { method: "POST", body: { id: $("pId").value, name: $("pName").value, ipv4: split($("p4").value), ipv6: split($("p6").value) } }); render(); }
      catch (e) { toast(esc(e.message), "bad"); } };
    $("pExp").onclick = () => dl("/providers/export");
    $("pImpB").onclick = () => $("pImp").click();
    $("pImp").onchange = async (e) => {
      const f = e.target.files[0]; if (!f) return;
      try { const data = JSON.parse(await f.text()); const res = await api("/providers/import", { method: "POST", body: data });
        toast(`+${res.added.length} / skipped ${res.skipped.length}` + (res.skipped.length ? "<br><small>" + esc(res.skipped.slice(0, 5).join("; ")) + "</small>" : "")); render();
      } catch (err) { toast(esc(err.message), "bad"); } };
    document.querySelectorAll("[data-del]").forEach((b) => (b.onclick = async () => { await api("/providers/" + b.dataset.del, { method: "DELETE" }); render(); }));
  };

  pages.settings = () => {
    const v = S.settings;
    const field = (k) => {
      const val = v[k];
      let input;
      if (typeof val === "boolean") input = `<input type="checkbox" data-s="${k}" ${val ? "checked" : ""}>`;
      else if (k === "theme") input = `<select data-s="${k}"><option value="dark">Dark</option><option value="light">Light</option></select>`;
      else if (k === "language") input = `<select data-s="${k}"><option value="ar">العربية</option><option value="en">English</option></select>`;
      else input = `<input data-s="${k}" ${typeof val === "number" ? 'type="number"' : 'class="mono"'} value="${esc(val)}">`;
      return `<div class="field"><label>${t("s_" + k)}</label>${input}</div>`;
    };
    $("page").innerHTML = `<h1>${t("set_title")}</h1><p class="sub">${t("set_sub")}</p><div class="card"><div class="form-grid">${Object.keys(v).map(field).join("")}</div>
      <div class="row" style="margin-top:14px"><button class="primary" id="sSave">${t("save")}</button><button class="ghost" id="sReset">${t("reset")}</button></div></div>`;
    document.querySelectorAll("select[data-s]").forEach((s) => (s.value = v[s.dataset.s]));
    $("sSave").onclick = async () => {
      const body = {};
      document.querySelectorAll("[data-s]").forEach((e) => (body[e.dataset.s] = e.type === "checkbox" ? e.checked : e.type === "number" ? Number(e.value) : e.value));
      await api("/settings", { method: "POST", body }); await loadState(); render(); toast("✓");
    };
    $("sReset").onclick = async () => { await api("/settings/reset", { method: "POST" }); await loadState(); render(); };
  };

  pages.log = async () => {
    const txt = await api("/log");
    $("page").innerHTML = `<h1>${t("log_title")}</h1><div class="row" style="margin-bottom:10px"><button id="lr">${t("refresh")}</button></div><pre class="log">${esc(txt)}</pre>`;
    $("lr").onclick = render;
  };

  function sortable() {
    document.querySelectorAll("table.sortable").forEach((tbl) => {
      tbl.querySelectorAll("th").forEach((th, i) => (th.onclick = () => {
        const rows = [...tbl.tBodies[0].rows], dir = th.dataset.dir === "1" ? -1 : 1; th.dataset.dir = dir === 1 ? "1" : "0";
        const val = (r) => { const s = r.cells[i].textContent.replace(/[^\d.\-]/g, ""); const n = parseFloat(s); return isNaN(n) ? r.cells[i].textContent : n; };
        rows.sort((a, b) => (val(a) > val(b) ? dir : val(a) < val(b) ? -dir : 0)).forEach((r) => tbl.tBodies[0].appendChild(r));
      }));
    });
  }

  // ---------------------------------------------------------------- boot
  document.querySelectorAll("#nav a").forEach((a) => (a.onclick = () => { page = a.dataset.page; render(); }));
  $("langBtn").onclick = async () => { await api("/settings", { method: "POST", body: { language: lang === "ar" ? "en" : "ar" } }); await loadState(); render(); };
  $("themeBtn").onclick = async () => { await api("/settings", { method: "POST", body: { theme: S.settings.theme === "dark" ? "light" : "dark" } }); await loadState(); render(); };
  window.addEventListener("resize", () => { if (["dns", "mtu", "compare"].includes(page)) render(); });
  (async () => {
    try { await loadState(); } catch (e) { $("page").innerHTML = `<div class="banner warn">${esc(e.message)} — restart the app from Run.bat</div>`; return; }
    render();
    if (S.running_job) trackJob(S.running_job);
    pollEvents();
  })();
})();
