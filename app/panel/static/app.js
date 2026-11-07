// alert2case analitik paneli. Kitabxana yoxdur, build addımı yoxdur.
// Təhlükəsizlik: bütün mətn textContent ilə yazılır (HTML kimi heç nə yazılmır), çünki alert məzmunu
// xarici mənbədən gəlir. Qrafiklər createElementNS ilə qurulur. Token yalnız sessionStorage-dadır.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var SVG = "http://www.w3.org/2000/svg";
  var REFRESH_MS = 30000;
  var state = { view: "open", selected: null, rows: [], filters: { priority: "", alert_type: "", verdict: "", q: "" }, timer: null };
  // Texniki terminlər ingiliscə qalır (SOC dilində olduğu kimi); izah cümlələri azərbaycanca
  var VERDICT_AZ = { malicious: "malicious", suspicious: "suspicious", unknown: "unknown", clean: "clean" };
  var TYPE_AZ = { malicious_hash: "hash", suspicious_url: "url", suspicious_login: "login" };
  var STAGE_AZ = { ingest: "ingest", normalize: "normalize", enrich: "enrich", decide: "decide", correlate: "correlate",
    act: "act", notify: "notify", feedback: "feedback" };
  var STATUS_AZ = { ok: "ok", error: "error", failed: "failed", not_found: "not found", rate_limited: "rate limited",
    disabled: "disabled", skipped: "skipped", partial: "partial" };
  var REL_AZ = { ioc: "same IOC", host: "same host", user: "same user" };
  // Sistemin verdict-i → analitikin "təsdiqlə" rəyi (feedback yalnız malicious/suspicious/clean qəbul edir)
  var CONFIRM = { malicious: "malicious", suspicious: "suspicious", unknown: "suspicious", clean: "clean" };
  var ICON = {
    malicious_hash: "M7 3h7l5 5v13H7zM14 3v5h5M10 13h6M10 17h6",
    suspicious_url: "M10 14a4 4 0 0 0 6 0l3-3a4 4 0 0 0-6-6l-1 1M14 10a4 4 0 0 0-6 0l-3 3a4 4 0 0 0 6 6l1-1",
    suspicious_login: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0"
  };

  function store(k, v) { try { v == null ? sessionStorage.removeItem(k) : sessionStorage.setItem(k, v); } catch (e) {} }
  function read(k) { try { return sessionStorage.getItem(k); } catch (e) { return null; } }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function sv(tag, attrs, text) {
    var e = document.createElementNS(SVG, tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (text != null) e.textContent = String(text);
    return e;
  }
  function icon(type) {
    var s = sv("svg", { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" });
    s.appendChild(sv("path", { d: ICON[type] || ICON.malicious_hash }));
    return s;
  }
  function toast(msg) {
    var t = $("toast"); t.textContent = msg; t.hidden = false;
    clearTimeout(toast.t); toast.t = setTimeout(function () { t.hidden = true; }, 2600);
  }
  function fmt(ts) {
    if (!ts) return "";
    var d = new Date(ts);
    return isNaN(d) ? String(ts) : d.toLocaleString("az-AZ", { dateStyle: "short", timeStyle: "medium" });
  }
  function ago(ts) {
    var s = (Date.now() - new Date(ts)) / 1000;
    if (!isFinite(s)) return "";
    if (s < 60) return "indicə";
    if (s < 3600) return Math.floor(s / 60) + " dəq əvvəl";
    if (s < 86400) return Math.floor(s / 3600) + " saat əvvəl";
    return Math.floor(s / 86400) + " gün əvvəl";
  }
  function dur(sec) {
    if (sec == null || !isFinite(sec)) return "—";
    if (sec < 1) return (sec * 1000).toFixed(0) + " ms";
    if (sec < 60) return sec.toFixed(sec < 10 ? 1 : 0) + " s";
    return Math.floor(sec / 60) + " dəq " + Math.round(sec % 60) + " s";
  }

  async function api(path, opts) {
    opts = opts || {};
    var headers = { "X-Admin-Token": read("a2c-token") || "" };
    if (opts.body) headers["Content-Type"] = "application/json";
    var r = await fetch(path, { method: opts.method || "GET", headers: headers, body: opts.body ? JSON.stringify(opts.body) : undefined });
    if (r.status === 403) { logout("Token qəbul olunmadı"); throw new Error("forbidden"); }
    if (!r.ok) throw new Error(r.status + " " + (await r.text()).slice(0, 200));
    return r.json();
  }

  // ---------- giriş ----------
  function showApp(on) {
    $("login").hidden = on; $("app").hidden = !on;
    ["liveBox", "who", "refresh", "logout"].forEach(function (id) { $(id).hidden = !on; });
    $("who").textContent = on ? "analyst: " + (read("a2c-analyst") || "") : "";
    schedule();
  }
  function logout(msg) {
    store("a2c-token", null); showApp(false);
    $("loginErr").textContent = msg || "";
  }
  $("loginForm").addEventListener("submit", async function (e) {
    e.preventDefault();
    store("a2c-token", $("token").value.trim());
    store("a2c-analyst", $("analyst").value.trim());
    $("token").value = "";
    try { await api("/api/panel/stats"); showApp(true); load(); }
    catch (err) { if (err.message !== "forbidden") $("loginErr").textContent = "API cavab vermir: " + err.message; }
  });
  $("logout").addEventListener("click", function () { logout(""); });
  $("refresh").addEventListener("click", function () { load(true); });

  // ---------- canlı yeniləmə ----------
  function schedule() {
    clearInterval(state.timer); state.timer = null;
    var on = !$("app").hidden && $("auto").checked;
    $("liveBox").classList.toggle("on", on);
    if (on) state.timer = setInterval(function () { if (!document.hidden) load(); }, REFRESH_MS);
  }
  $("auto").addEventListener("change", schedule);

  // ---------- tablar və filtrlər ----------
  document.querySelectorAll(".tabs button").forEach(function (b) {
    b.addEventListener("click", function () {
      state.view = b.dataset.view;
      document.querySelectorAll(".tabs button").forEach(function (x) { x.setAttribute("aria-selected", x === b ? "true" : "false"); });
      loadList();
    });
  });
  [["fPriority", "priority"], ["fType", "alert_type"], ["fVerdict", "verdict"]].forEach(function (p) {
    $(p[0]).addEventListener("change", function () { state.filters[p[1]] = $(p[0]).value; loadList(); });
  });
  var qt;
  $("q").addEventListener("input", function () {
    clearTimeout(qt); qt = setTimeout(function () { state.filters.q = $("q").value.trim(); loadList(); }, 300);
  });
  $("clear").addEventListener("click", function () {
    ["fPriority", "fType", "fVerdict", "q"].forEach(function (id) { $(id).value = ""; });
    state.filters = { priority: "", alert_type: "", verdict: "", q: "" }; loadList();
  });

  // ---------- yükləmə ----------
  function listUrl() {
    var p = new URLSearchParams({ view: state.view, limit: "200" });
    Object.keys(state.filters).forEach(function (k) { if (state.filters[k]) p.set(k, state.filters[k]); });
    return "/api/panel/alerts?" + p.toString();
  }
  async function loadList() {
    try { state.rows = await api(listUrl()); renderList(); }
    catch (err) { if (err.message !== "forbidden") toast("Siyahı yüklənmədi: " + err.message); }
  }
  async function load(manual) {
    try {
      var res = await Promise.all([api(listUrl()), api("/api/panel/stats")]);
      state.rows = res[0]; renderList(); renderDash(res[1]);
      $("updated").textContent = "updated " + new Date().toLocaleTimeString("az-AZ");
      if (manual) toast("Yeniləndi");
    } catch (err) { if (err.message !== "forbidden") toast("Yüklənmədi: " + err.message); }
  }

  // ---------- dashboard ----------
  function kpi(cls, label, value, sub) {
    var k = el("div", "kpi " + cls);
    var lb = el("div", "lbl", label); lb.lang = "en"; k.appendChild(lb); k.appendChild(el("div", "val", value)); k.appendChild(el("div", "sub", sub));
    return k;
  }
  function renderDash(s) {
    var box = $("kpis"); box.textContent = "";
    var pr = s.open_by_priority || {};
    var agree = s.reviewed ? Math.round(100 * s.agree / s.reviewed) + "%" : "—";
    box.appendChild(kpi("k-coral", "Open cases", s.open, "P1: " + (pr.P1 || 0) + " · P2: " + (pr.P2 || 0) + " · P3: " + (pr.P3 || 0)));
    box.appendChild(kpi("k-crit", "P1", pr.P1 || 0, "analitik gözləyir"));
    box.appendChild(kpi("k-info", "Alerts · 24h", s.last_24h, "cəmi " + s.total + " alert"));
    box.appendChild(kpi("k-ok", "Time to case · median", dur(s.case_median_s), "p90: " + dur(s.case_p90_s) + " · " + s.cases + " case"));
    box.appendChild(kpi("k-warn", "Analyst agreement", agree, s.reviewed + " feedback · shadow close: " + s.would_close));
    hourly(s.hourly || []);
    hbars($("chPriority"), ["P1", "P2", "P3", "P4"].map(function (k) { return { key: k, label: k, n: pr[k] || 0, cls: "f-" + k }; }));
    stacked($("chVerdict"), ["malicious", "suspicious", "unknown", "clean"].map(function (k) {
      return { key: k, label: VERDICT_AZ[k], n: (s.by_verdict || {})[k] || 0, cls: "f-" + k };
    }));
  }
  function hourly(rows) {
    var box = $("chHourly"); box.textContent = "";
    var W = 640, H = 150, pl = 26, pb = 20, pt = 14, n = rows.length || 1;
    var max = Math.max(1, Math.max.apply(null, rows.map(function (r) { return r.n; })));
    var s = sv("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Son 24 saatda saatlıq alert sayı" });
    [0, 0.5, 1].forEach(function (f) {
      var y = pt + (H - pt - pb) * (1 - f);
      s.appendChild(sv("line", { x1: pl, x2: W, y1: y, y2: y, class: "grid" }));
      s.appendChild(sv("text", { x: pl - 6, y: y + 3, "text-anchor": "end", class: "axis" }, Math.round(max * f)));
    });
    var bw = (W - pl) / n;
    rows.forEach(function (r, i) {
      var h = (H - pt - pb) * r.n / max, x = pl + i * bw + 2, y = H - pb - h;
      var rect = sv("rect", { x: x, y: y, width: Math.max(1, bw - 4), height: Math.max(h, r.n ? 2 : 0), rx: 3, class: "bar" + (i === n - 1 ? " hot" : "") });
      var hr = new Date(r.hour);
      rect.appendChild(sv("title", {}, hr.getHours() + ":00 — " + r.n + " alert"));
      s.appendChild(rect);
      if (r.n && h > 14) s.appendChild(sv("text", { x: x + (bw - 4) / 2, y: y - 3, "text-anchor": "middle", class: "val" }, r.n));
      if (i % 4 === 0 || i === n - 1) s.appendChild(sv("text", { x: x + (bw - 4) / 2, y: H - 5, "text-anchor": "middle", class: "axis" }, String(hr.getHours()).padStart(2, "0") + ":00"));
    });
    box.appendChild(s);
  }
  function hbars(box, items) {
    box.textContent = "";
    var W = 300, rh = 26, H = items.length * rh, lw = 30;
    var max = Math.max(1, Math.max.apply(null, items.map(function (i) { return i.n; })));
    var s = sv("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Prioritet üzrə açıq case-lər" });
    items.forEach(function (it, i) {
      var y = i * rh + 4, w = (W - lw - 36) * it.n / max;
      s.appendChild(sv("text", { x: 0, y: y + 13, class: "lab" }, it.label));
      s.appendChild(sv("rect", { x: lw, y: y, width: W - lw - 36, height: 16, rx: 4, class: "grid", fill: "none" }));
      if (it.n) s.appendChild(sv("rect", { x: lw, y: y, width: Math.max(w, 3), height: 16, rx: 4, class: it.cls }));
      s.appendChild(sv("text", { x: lw + Math.max(w, 3) + 6, y: y + 13, class: "val" }, it.n));
    });
    box.appendChild(s);
  }
  function stacked(box, items) {
    box.textContent = "";
    var total = items.reduce(function (a, i) { return a + i.n; }, 0);
    var W = 300, H = 28, x = 0;
    var s = sv("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Sistemin qərarlarının paylanması" });
    s.appendChild(sv("rect", { x: 0, y: 0, width: W, height: H, rx: 6, class: "grid", fill: "none" }));
    items.forEach(function (it) {
      if (!total || !it.n) return;
      var w = W * it.n / total;
      var r = sv("rect", { x: x, y: 0, width: Math.max(w - 2, 1), height: H, rx: 4, class: it.cls });
      r.appendChild(sv("title", {}, it.label + ": " + it.n));
      s.appendChild(r);
      if (w > 30) s.appendChild(sv("text", { x: x + w / 2 - 1, y: 18, "text-anchor": "middle", class: "val" }, Math.round(100 * it.n / total) + "%"));
      x += w;
    });
    box.appendChild(s);
    var lg = el("div", "legend");
    items.forEach(function (it) {
      var sp = el("span"); sp.appendChild(el("i", "sw " + it.cls)); sp.appendChild(document.createTextNode(it.label + " "));
      sp.appendChild(el("b", null, it.n)); lg.appendChild(sp);
    });
    box.appendChild(lg);
  }

  // ---------- siyahı ----------
  function renderList() {
    var list = $("list"); list.textContent = "";
    $("count").textContent = state.rows.length + " alert";
    if (!state.rows.length) { list.appendChild(el("p", "muted empty", "Bu filtrə uyğun alert yoxdur.")); return; }
    state.rows.forEach(function (r) {
      var b = el("button", "row pr-" + r.priority); b.type = "button";
      b.setAttribute("aria-current", r.alert_id === state.selected ? "true" : "false");
      var ic = el("span", "ic"); ic.appendChild(icon(r.alert_type)); b.appendChild(ic);
      b.appendChild(el("span", "t", r.title || r.source_ref));
      var right = el("span", "right");
      right.appendChild(el("span", "pill p-" + r.priority, r.priority));
      right.appendChild(el("span", "pill v-" + r.verdict, VERDICT_AZ[r.verdict] || r.verdict));
      b.appendChild(right);
      var m = el("span", "m");
      m.appendChild(el("span", "mono", r.source_ref || ""));
      if (r.host) m.appendChild(el("span", null, "host: " + r.host));
      if (r.user) m.appendChild(el("span", null, "user: " + r.user));
      m.appendChild(el("span", null, r.ioc_count + " IOC"));
      if (r.case_seconds != null) m.appendChild(el("span", null, "time to case: " + dur(r.case_seconds)));
      if (r.occurrence_count > 1) m.appendChild(el("span", null, "×" + r.occurrence_count));
      if (r.shadow) m.appendChild(el("span", "pill shadow", "shadow: close"));
      if (r.human_verdict) m.appendChild(el("span", "pill done", "feedback: " + (VERDICT_AZ[r.human_verdict] || r.human_verdict)));
      var t = el("span", null, ago(r.received_at)); t.title = fmt(r.received_at); m.appendChild(t);
      b.appendChild(m);
      b.addEventListener("click", function () { select(r.alert_id); });
      list.appendChild(b);
    });
  }

  // ---------- detal ----------
  async function select(id) {
    state.selected = id; renderList();
    try { renderDetail(await api("/api/panel/alerts/" + encodeURIComponent(id))); $("detail").scrollTop = 0; }
    catch (err) { if (err.message !== "forbidden") toast("Alert açılmadı: " + err.message); }
  }
  function section(title, count) {
    var s = el("section", "sec"), h = el("h3", null, title); h.lang = "en";
    if (count != null) h.appendChild(el("span", "n", count));
    s.appendChild(h); return s;
  }
  function kv(pairs) {
    var dl = el("dl", "kv");
    pairs.forEach(function (p) { if (p[1] == null || p[1] === "") return; dl.appendChild(el("dt", null, p[0])); dl.appendChild(el("dd", p[2] || null, p[1])); });
    return dl;
  }
  function renderDetail(a) {
    var box = $("detail"); box.textContent = "";
    var d = a.decision || {};

    // başlıq
    var head = el("header", "dh"), chips = el("div", "chips");
    chips.appendChild(el("span", "pill p-" + d.priority, d.priority));
    chips.appendChild(el("span", "pill v-" + d.verdict, VERDICT_AZ[d.verdict] || d.verdict));
    chips.appendChild(el("span", "pill p-P4", TYPE_AZ[a.alert_type] || a.alert_type));
    if (d.shadow) chips.appendChild(el("span", "pill shadow", "shadow: close"));
    head.appendChild(chips);
    head.appendChild(el("h2", null, a.title || a.source_ref));
    var meta = el("div", "meta");
    meta.appendChild(el("span", "mono", a.source_ref));
    meta.appendChild(el("span", null, fmt(a.received_at)));
    if (a.case && a.case.created_at) meta.appendChild(el("span", null, "time to case: " + dur((new Date(a.case.created_at) - new Date(a.received_at)) / 1000)));
    head.appendChild(meta);
    box.appendChild(head);

    if (d.verdict) box.appendChild(actions(a, d));

    // qərar
    var sq = section("Verdict");
    var v = el("div", "verdict");
    v.appendChild(el("div", "big c-" + d.verdict, VERDICT_AZ[d.verdict] || d.verdict || "—"));
    v.appendChild(kv([["Rule", d.rule_id && d.rule_id + " · v" + d.rule_version, "mono"], ["Action", d.action], ["Severity", d.severity_id]]));
    sq.appendChild(v);
    var ul = el("ul", "reasons");
    (d.reasons || []).forEach(function (x) { ul.appendChild(el("li", null, x)); });
    sq.appendChild(ul);
    box.appendChild(sq);

    // intel
    var e = a.enrichment || {};
    var si = section("Threat intel", (e.providers || []).length);
    var sum = el("div", "sumline");
    [["Status", e.status], ["Score", e.score != null ? e.score + "/100" : "—"], ["Confidence", e.confidence != null ? Math.round(e.confidence * 100) + "%" : "—"],
     ["Conflict", e.conflict ? "yes" : "no"]].forEach(function (p) {
      var x = el("span", null, p[0] + ": "); x.appendChild(el("b", null, p[1] == null ? "—" : p[1])); sum.appendChild(x);
    });
    si.appendChild(sum);
    var grid = el("div", "intel"), byProv = {};
    (e.providers || []).forEach(function (p) { (byProv[p.provider] = byProv[p.provider] || []).push(p); });
    Object.keys(byProv).forEach(function (name) {
      var c = el("div", "src"), n = el("div", "name");
      n.appendChild(el("span", null, name));
      if (byProv[name].some(function (p) { return p.cached; })) n.appendChild(el("span", "cached", "cache"));
      c.appendChild(n);
      byProv[name].forEach(function (p) {
        var ln = el("div", "line");
        ln.appendChild(el("span", null, p.ioc_type));
        ln.appendChild(el("span", "st-" + p.status, (STATUS_AZ[p.status] || p.status) + (p.score != null ? " · " + p.score : "")));
        if (p.score != null) {
          var m = el("div", "meter"), bar = el("i", p.score >= 70 ? "m-high" : p.score >= 30 ? "m-mid" : null);
          bar.style.width = Math.max(2, Math.min(100, p.score)) + "%";
          m.appendChild(bar); ln.appendChild(m);
        }
        if (p.note) ln.appendChild(el("span", "small", p.note));
        c.appendChild(ln);
      });
      grid.appendChild(c);
    });
    if (!Object.keys(byProv).length) grid.appendChild(el("p", "muted", "Intel nəticəsi yoxdur."));
    si.appendChild(grid);
    box.appendChild(si);

    // IOC və kontekst
    var so = section("IOCs & context", a.observables.length);
    var wrap = el("div", "tbl"), t = el("table"), tr = el("tr");
    ["Type", "Value (defanged)", ""].forEach(function (h) { tr.appendChild(el("th", null, h)); });
    t.appendChild(tr);
    a.observables.forEach(function (o) {
      var x = el("tr"); x.appendChild(el("td", null, o.type)); x.appendChild(el("td", "mono", o.value));
      x.appendChild(el("td", "muted", o.internal ? "internal" : "")); t.appendChild(x);
    });
    wrap.appendChild(t); so.appendChild(wrap);
    so.appendChild(el("div", "small", " "));
    so.appendChild(kv([["Host", a.host], ["User", a.user], ["Status", a.status],
      ["Occurrences", a.occurrence_count > 1 ? a.occurrence_count : null],
      ["Case", a.case && a.case.backend + " · " + a.case.case_id, "mono"]]));
    box.appendChild(so);

    // vizual tarixçə
    box.appendChild(timeline(a.timeline || []));

    // əlaqəli alert-lər
    var rel = a.related || [];
    var sr = section("Related alerts · 7d", rel.length);
    if (!rel.length) sr.appendChild(el("p", "muted small", "Eyni IOC, host və ya istifadəçi ilə başqa alert yoxdur."));
    var rels = el("div", "rels");
    rel.forEach(function (r) {
      var b = el("button", "rel"); b.type = "button";
      b.appendChild(el("span", "pill p-" + (r.priority || "P4"), r.priority || "—"));
      var mid = el("span"); mid.appendChild(el("div", "t", r.title || r.source_ref));
      mid.appendChild(el("div", "why", (REL_AZ[r.reason] || r.reason) + " · " + (r.source_ref || "") + " · " + ago(r.received_at)));
      b.appendChild(mid);
      b.appendChild(el("span", "pill v-" + r.verdict, VERDICT_AZ[r.verdict] || r.verdict || ""));
      b.addEventListener("click", function () { select(r.alert_id); });
      rels.appendChild(b);
    });
    sr.appendChild(rels);
    box.appendChild(sr);

    // rəylər
    var fbs = a.feedback || [];
    var sf = section("Feedback", fbs.length);
    var fbx = el("div", "fb");
    if (!fbs.length) fbx.appendChild(el("p", "muted small", "Hələ rəy yoxdur."));
    fbs.forEach(function (f) {
      fbx.appendChild(el("p", null, fmt(f.created_at) + " · " + f.analyst + " (" + f.source + "): " + (VERDICT_AZ[f.human_verdict] || f.human_verdict) + (f.comment ? " · " + f.comment : "")));
    });
    sf.appendChild(fbx);
    box.appendChild(sf);
  }

  function timeline(events) {
    var s = section("Timeline", events.length);
    if (!events.length) { s.appendChild(el("p", "muted small", "Audit qeydi yoxdur.")); return s; }
    var t0 = new Date(events[0].ts);
    // Audit qeydi mərhələ bitəndə yazılır: iki qeyd arasındakı vaxt sonrakı qeydin mərhələsinə aiddir.
    // "duplicate" qeydləri eyni alert-in təkrar gəlişidir, emal vaxtına daxil edilmir.
    var main = events.filter(function (ev) { return ev.event !== "duplicate"; });
    var segs = [], prev = t0;
    main.forEach(function (ev) {
      var ts = new Date(ev.ts), sec = Math.max(0, (ts - prev) / 1000); prev = ts;
      if (segs.length && segs[segs.length - 1].stage === ev.stage) segs[segs.length - 1].sec += sec;
      else segs.push({ stage: ev.stage, sec: sec });
    });
    var total = (prev - t0) / 1000;
    var flow = el("div", "flow"); flow.setAttribute("role", "img"); flow.setAttribute("aria-label", "Mərhələlərin vaxtı");
    segs.forEach(function (g) {
      var sp = el("span", "s-" + g.stage); sp.style.flexGrow = String(Math.max(g.sec, total * 0.02) || 1);
      sp.title = (STAGE_AZ[g.stage] || g.stage) + ": " + dur(g.sec); flow.appendChild(sp);
    });
    s.appendChild(flow);
    var lg = el("div", "flowlegend");
    segs.forEach(function (g) {
      var x = el("span"); x.appendChild(el("i", "sw s-" + g.stage)); x.appendChild(document.createTextNode((STAGE_AZ[g.stage] || g.stage) + " "));
      x.appendChild(el("b", null, dur(g.sec))); lg.appendChild(x);
    });
    var tot = el("span"); tot.appendChild(document.createTextNode("total ")); tot.appendChild(el("b", null, dur(total))); lg.appendChild(tot);
    s.appendChild(lg);
    var ol = el("ol", "tl");
    events.forEach(function (x) {
      var bad = /fail|error|dlq|pending/.test(x.event), ok = /created|ok|agree|sent|linked/.test(x.event);
      var li = el("li", bad ? "ev-bad" : ok ? "ev-ok" : null);
      li.appendChild(el("span", "mono", "+" + ((new Date(x.ts) - t0) / 1000).toFixed(2) + " s"));
      li.appendChild(el("span", null, (STAGE_AZ[x.stage] || x.stage) + " · " + x.event + (x.actor && x.actor !== "system" ? " · " + x.actor : "")));
      ol.appendChild(li);
    });
    s.appendChild(ol);
    return s;
  }

  function actions(a, d) {
    var wrap = el("div", "act"), bar = el("div", "bar");
    var ok = el("button", "btn ok", "✓ Approve: " + (VERDICT_AZ[CONFIRM[d.verdict]] || d.verdict)); ok.type = "button";
    var no = el("button", "btn no", "✕ Reject…"); no.type = "button";
    bar.appendChild(ok); bar.appendChild(no);
    bar.appendChild(el("span", "hint", "Rəy qaydaların yaxşılaşdırılmasına gedir"));
    wrap.appendChild(bar);

    var form = el("form"); form.hidden = true;
    var sel = el("select"); sel.id = "fbVerdict"; sel.setAttribute("aria-label", "Düzgün cavab");
    ["malicious", "suspicious", "clean"].filter(function (v) { return v !== CONFIRM[d.verdict]; }).forEach(function (v) {
      var o = el("option", null, "Correct verdict: " + VERDICT_AZ[v]); o.value = v; sel.appendChild(o);
    });
    var note = el("textarea"); note.id = "fbComment"; note.rows = 2; note.maxLength = 500; note.setAttribute("aria-label", "Səbəb");
    note.placeholder = "Səbəb (məs. VT-də yeni domen, 0/93 inandırıcı deyil)";
    var send = el("button", "btn primary", "Submit feedback"); send.type = "submit";
    form.appendChild(sel); form.appendChild(note); form.appendChild(send); wrap.appendChild(form);

    ok.addEventListener("click", function () { submit(a, CONFIRM[d.verdict], "", [ok, no]); });
    no.addEventListener("click", function () { form.hidden = !form.hidden; if (!form.hidden) sel.focus(); });
    form.addEventListener("submit", function (ev) { ev.preventDefault(); submit(a, sel.value, note.value.trim(), [ok, no, send]); });
    return wrap;
  }
  async function submit(a, verdict, comment, buttons) {
    buttons.forEach(function (b) { b.disabled = true; });
    try {
      var r = await api("/feedback", { method: "POST", body: {
        alert_id: a.alert_id, human_verdict: verdict, analyst: read("a2c-analyst") || "panel", source: "manual", comment: comment
      } });
      toast(r.error ? r.error : (r.agree ? "Rəy yazıldı: sistemlə razısınız" : "Rəy yazıldı: sistemlə razı deyilsiniz (" + r.rule + ")"));
      await load(); await select(a.alert_id);
    } catch (err) {
      if (err.message !== "forbidden") toast("Göndərilmədi: " + err.message);
      buttons.forEach(function (b) { b.disabled = false; });
    }
  }

  // ---------- başlanğıc ----------
  if (read("a2c-token")) { showApp(true); load(); } else { showApp(false); }
})();
