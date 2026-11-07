// alert2case analyst panel. Kitabxana yoxdur, build addımı yoxdur.
// Təhlükəsizlik: bütün mətn textContent ilə yazılır (HTML kimi heç nə yazılmır), çünki alert məzmunu
// xarici mənbədən gəlir. Qrafiklər createElementNS ilə qurulur. Token yalnız sessionStorage-dadır.
// Texniki terminlər ingiliscə (SOC dilində olduğu kimi), izah cümlələri azərbaycancadır.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var SVG = "http://www.w3.org/2000/svg";
  var REFRESH_MS = 30000;
  var PAGES = ["queue", "incidents", "overview", "health", "rules"];
  var TITLES = { queue: "Triage queue", incidents: "Incidents", overview: "Overview", health: "System", rules: "Rules" };
  var state = {
    page: "queue", view: "open", incView: "open", rows: [], incidents: [], selected: null, detail: null, timer: null,
    filters: { priority: "", alert_type: "", verdict: "", q: "", host: "", user: "" }
  };
  var TYPE = { malicious_hash: "hash", suspicious_url: "url", suspicious_login: "login" };
  var STAGES = ["ingest", "normalize", "enrich", "decide", "correlate", "act", "notify", "feedback"];
  var STATUS = { ok: "ok", error: "error", failed: "failed", not_found: "not found", rate_limited: "rate limited",
    disabled: "disabled", skipped: "skipped", partial: "partial", circuit_open: "circuit open" };
  var PROV = { virustotal: "VirusTotal", abuseipdb: "AbuseIPDB", otx: "OTX" };
  // Sistemin verdict-i → "Approve" rəyi (feedback yalnız malicious/suspicious/clean qəbul edir)
  var CONFIRM = { malicious: "malicious", suspicious: "suspicious", unknown: "suspicious", clean: "clean" };

  // ---------- köməkçilər ----------
  function store(k, v) { try { v == null ? sessionStorage.removeItem(k) : sessionStorage.setItem(k, v); } catch (e) {} }
  function read(k) { try { return sessionStorage.getItem(k); } catch (e) { return null; } }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function add(parent) { for (var i = 1; i < arguments.length; i++) if (arguments[i] != null) parent.appendChild(arguments[i]); return parent; }
  function txt(s) { return document.createTextNode(String(s)); }
  function sv(tag, attrs, text) {
    var e = document.createElementNS(SVG, tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (text != null) e.textContent = String(text);
    return e;
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
    if (s < 60) return "now";
    if (s < 3600) return Math.floor(s / 60) + "m";
    if (s < 86400) return Math.floor(s / 3600) + "h";
    return Math.floor(s / 86400) + "d";
  }
  function dur(sec) {
    if (sec == null || !isFinite(sec)) return "—";
    if (sec < 1) return Math.round(sec * 1000) + " ms";
    if (sec < 60) return sec.toFixed(sec < 10 ? 1 : 0) + " s";
    return Math.floor(sec / 60) + "m " + Math.round(sec % 60) + "s";
  }
  function sevClass(score) { return score >= 70 ? "high" : score >= 30 ? "mid" : ""; }
  function prio(p) { return el("span", "pr " + p, p || "—"); }
  function verdict(v) { return el("span", "v " + v, v || "—"); }
  function meter(score) {
    var m = el("span", "meter"), i = el("i", sevClass(score));
    i.style.width = Math.max(2, Math.min(100, score || 0)) + "%"; m.appendChild(i); return m;
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
  function quiet(err, what) { if (err.message !== "forbidden") toast(what + ": " + err.message); }

  // ---------- giriş ----------
  function showApp(on) {
    $("login").hidden = on; $("app").hidden = !on;
    $("who").textContent = on ? "analyst: " + (read("a2c-analyst") || "") : "";
    schedule();
  }
  function logout(msg) { store("a2c-token", null); showApp(false); $("loginErr").textContent = msg || ""; }
  $("loginForm").addEventListener("submit", async function (e) {
    e.preventDefault();
    store("a2c-token", $("token").value.trim());
    store("a2c-analyst", $("analyst").value.trim());
    $("token").value = "";
    try { await api("/api/panel/stats"); showApp(true); setPage("queue"); }
    catch (err) { if (err.message !== "forbidden") $("loginErr").textContent = "API cavab vermir: " + err.message; }
  });
  $("logout").addEventListener("click", function () { logout(""); });
  $("refresh").addEventListener("click", function () { load(true); });

  // ---------- canlı yeniləmə ----------
  function schedule() {
    clearInterval(state.timer); state.timer = null;
    if (!$("app").hidden && $("auto").checked) state.timer = setInterval(function () { if (!document.hidden) load(); }, REFRESH_MS);
  }
  $("auto").addEventListener("change", schedule);

  // ---------- səhifələr ----------
  function setPage(page) {
    state.page = page;
    PAGES.forEach(function (p) { $("page-" + p).hidden = p !== page; });
    document.querySelectorAll("#nav button").forEach(function (b) {
      if (b.dataset.page === page) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
    });
    $("title").textContent = TITLES[page]; $("subtitle").textContent = "";
    load();
  }
  document.querySelectorAll("#nav button").forEach(function (b) { b.addEventListener("click", function () { setPage(b.dataset.page); }); });

  async function load(manual) {
    try {
      var core = await Promise.all([api("/api/panel/health"), api("/api/panel/stats"), api("/api/panel/incidents?view=open")]);
      state.incidents = core[2]; renderStatus(core[0], core[1], core[2]);
      if (state.page === "queue") await loadQueue();
      else if (state.page === "incidents") renderIncidents(state.incView === "open" ? core[2] : await api("/api/panel/incidents?view=all"));
      else if (state.page === "overview") renderOverview(core[1]);
      else if (state.page === "health") renderHealth(core[0]);
      else if (state.page === "rules") renderRules(await api("/api/panel/rules"));
      $("updated").textContent = new Date().toLocaleTimeString("az-AZ");
      if (manual) toast("Yeniləndi");
    } catch (err) { quiet(err, "Yüklənmədi"); }
  }

  // yan paneldəki saylar və sistem vəziyyəti
  function renderStatus(h, s, inc) {
    $("cQueue").textContent = s.open || "";
    $("cInc").textContent = inc.length || "";
    var closing = h.auto_close_enabled && !h.shadow_mode;
    var m = $("sbMode"); m.textContent = "";
    add(m, el("i", "dot " + (closing ? "bad" : "ok")), txt("Auto-close: " + (closing ? "ON" : "OFF") + (h.shadow_mode ? " · shadow" : "")));
    m.title = "AUTO_CLOSE_ENABLED=" + h.auto_close_enabled + ", SHADOW_MODE=" + h.shadow_mode;
    var ok = h.providers.filter(function (p) { return p.state === "ok" || p.state === "idle"; }).length;
    var down = h.providers.some(function (p) { return p.state === "down"; });
    var it = $("sbIntel"); it.textContent = "";
    add(it, el("i", "dot " + (down ? "bad" : ok === h.providers.length ? "ok" : "warn")), txt("Intel: " + ok + "/" + h.providers.length + " ok"));
    it.title = h.providers.map(function (p) { return p.provider + ": " + p.state; }).join(", ");
  }

  // ---------- QUEUE ----------
  (function prioChips() {
    var box = $("prioChips");
    ["P1", "P2", "P3", "P4"].forEach(function (p) {
      var b = el("button", "chip " + p, p); b.type = "button"; b.setAttribute("aria-pressed", "false");
      b.addEventListener("click", function () {
        state.filters.priority = state.filters.priority === p ? "" : p;
        box.querySelectorAll(".chip").forEach(function (x) { x.setAttribute("aria-pressed", x.textContent === state.filters.priority ? "true" : "false"); });
        loadQueue();
      });
      box.appendChild(b);
    });
  })();
  document.querySelectorAll("#segView button").forEach(function (b) {
    b.addEventListener("click", function () {
      state.view = b.dataset.view;
      document.querySelectorAll("#segView button").forEach(function (x) { x.setAttribute("aria-selected", x === b ? "true" : "false"); });
      loadQueue();
    });
  });
  $("fType").addEventListener("change", function () { state.filters.alert_type = this.value; loadQueue(); });
  $("fVerdict").addEventListener("change", function () { state.filters.verdict = this.value; loadQueue(); });
  var qt;
  $("q").addEventListener("input", function () { clearTimeout(qt); qt = setTimeout(function () { state.filters.q = $("q").value.trim(); loadQueue(); }, 300); });

  function setEntity(kind, value) {
    state.filters.host = kind === "host" ? value : ""; state.filters.user = kind === "user" ? value : "";
    var chip = $("entityChip"); chip.textContent = "";
    if (value) {
      var x = el("button", null, "✕"); x.type = "button"; x.title = "Filtri sil";
      x.addEventListener("click", function () { setEntity("", ""); loadQueue(); });
      add(chip, txt(kind + " · " + value), x);
    }
    chip.hidden = !value;
  }

  function queueUrl() {
    var p = new URLSearchParams({ view: state.view, limit: "300" });
    Object.keys(state.filters).forEach(function (k) { if (state.filters[k]) p.set(k, state.filters[k]); });
    return "/api/panel/alerts?" + p.toString();
  }
  async function loadQueue() {
    try { state.rows = await api(queueUrl()); renderQueue(); }
    catch (err) { quiet(err, "Siyahı yüklənmədi"); }
  }
  function renderQueue() {
    var n = state.rows.length;
    $("subtitle").textContent = n + " " + (state.view === "open" ? "open" : state.view) + " · priority, then age";
    var box = $("queueTable"); box.textContent = "";
    if (!n) { box.appendChild(el("p", "empty", "Bu filtrə uyğun alert yoxdur.")); return; }
    var t = el("table"), th = el("thead"), hr = el("tr");
    [["", ""], ["Alert", ""], ["Entity", "ent"], ["Verdict", ""], ["Score", "scol"], ["Age", "num"], ["", ""]].forEach(function (h) { hr.appendChild(el("th", h[1] || null, h[0])); });
    add(t, add(th, hr));
    var tb = el("tbody");
    state.rows.forEach(function (r) {
      var tr = el("tr"); tr.dataset.id = r.alert_id;
      tr.setAttribute("aria-selected", r.alert_id === state.selected ? "true" : "false");
      tr.appendChild(add(el("td"), prio(r.priority)));
      var a = el("td", "alert");
      add(a, el("div", "t", r.title || r.source_ref), el("div", "s", (r.source_ref || "") + " · " + (TYPE[r.alert_type] || r.alert_type) + " · " + (r.rule_id || "")));
      tr.appendChild(a);
      tr.appendChild(el("td", "ent", r.host || r.user || ""));
      tr.appendChild(add(el("td"), verdict(r.verdict)));
      var sc = el("td", "scol");
      if (r.score != null) add(sc, add(el("span", "sc"), meter(+r.score), txt(Math.round(r.score))));
      else sc.appendChild(el("span", "dim", "—"));
      tr.appendChild(sc);
      var ag = el("td", "num mu", ago(r.received_at)); ag.title = fmt(r.received_at); tr.appendChild(ag);
      var st = el("td");
      if (r.human_verdict) { var d = el("span", "done", "✓"); d.title = "feedback: " + r.human_verdict + " (" + r.analyst + ")"; st.appendChild(d); }
      else if (r.shadow) st.appendChild(el("span", "shadowtag", "shadow"));
      tr.appendChild(st);
      tr.addEventListener("click", function () { select(r.alert_id); });
      tb.appendChild(tr);
    });
    add(box, add(t, tb));
  }
  function markSelected() {
    document.querySelectorAll("#queueTable tbody tr").forEach(function (tr) {
      tr.setAttribute("aria-selected", tr.dataset.id === state.selected ? "true" : "false");
    });
  }

  // ---------- DRAWER ----------
  async function select(id) {
    state.selected = id; markSelected();
    try { renderDrawer(await api("/api/panel/alerts/" + encodeURIComponent(id))); $("drawer").scrollTop = 0; }
    catch (err) { quiet(err, "Alert açılmadı"); }
  }
  function closeDrawer() { state.selected = null; state.detail = null; $("qbody").classList.remove("open"); markSelected(); }
  function section(title, right) {
    var s = el("section", "sec"), h = el("h3"), l = el("span", null, title); l.lang = "en";
    add(h, l, right != null ? el("span", "r", right) : null); s.appendChild(h); return s;
  }
  function entityOf(a) { return a.host ? { kind: "host", value: a.host } : a.user ? { kind: "user", value: a.user } : null; }
  // Alert-in incident-i (Incidents səhifəsindəki tam say); yoxdursa related siyahısından təxmin
  function incidentOf(a) {
    var ent = entityOf(a); if (!ent) return null;
    var g = state.incidents.filter(function (x) { return x.kind === ent.kind && x.entity === ent.value; })[0];
    if (g) return { kind: ent.kind, value: ent.value, alerts: g.alerts, p1: g.p1 };
    var rel = (a.related || []).filter(function (r) { return r.reason === ent.kind; }).length;
    return rel ? { kind: ent.kind, value: ent.value, alerts: rel + 1, p1: null, more: (a.related || []).length >= 10 } : null;
  }
  function openIncident(kind, value) {
    setEntity(kind, value);
    state.view = "all";
    document.querySelectorAll("#segView button").forEach(function (x) { x.setAttribute("aria-selected", x.dataset.view === "all" ? "true" : "false"); });
    if (state.page !== "queue") setPage("queue"); else loadQueue();
  }

  // Bir baxışda "niyə": strukturlaşdırılmış məlumatdan qurulur, mətn yalnız textContent ilə
  function summary(a) {
    var d = a.decision || {}, e = a.enrichment || {}, ctx = a.context || {}, v = d.verdict || "unknown";
    var box = el("div", "sum " + v);
    var lead = el("span", "lead " + v, "Why " + v + ": "); lead.lang = "en"; box.appendChild(lead);
    var ioc = (a.observables || []).filter(function (o) { return !o.internal && o.type !== "user" && o.type !== "host"; })[0];
    var flagged = (e.providers || []).filter(function (p) { return p.score != null && p.score >= 70; });
    var parts = [];
    function fact(p) {
      var f = p.facts || {}, n = PROV[p.provider] || p.provider;
      if (p.provider === "virustotal" && f.malicious != null) return n + " (" + f.malicious + (f.engines ? "/" + f.engines : "") + " engine)";
      if (p.provider === "abuseipdb" && f.confidence != null) return n + " (confidence " + f.confidence + ")";
      if (p.provider === "otx" && f.pulses != null) return n + " (" + f.pulses + " pulse)";
      return n + " (score " + p.score + ")";
    }
    if (flagged.length) {
      var seen = {}, names = [];
      flagged.forEach(function (p) { if (!seen[p.provider]) { seen[p.provider] = 1; names.push(fact(p)); } });
      parts.push((ioc ? ioc.type + " " + ioc.value + " " : "IOC ") + names.join(" və ") + " tərəfindən zərərli sayılır.");
    } else if (e.status === "partial" || e.status === "failed") {
      parts.push("Intel natamamdır (status " + e.status + "): fail-safe, analitik baxmalıdır.");
    } else if (v === "clean") {
      parts.push("Intel mənbələri təmiz cavab verdi (score " + (e.score != null ? e.score : "—") + ").");
    } else if (v === "unknown") {
      parts.push("Heç bir intel mənbəyi IOC-u etibarlı tanımadı (score " + (e.score != null ? e.score : "—") + ").");
    } else {
      parts.push("Intel siqnalı zəif və ya ziddiyyətlidir (score " + (e.score != null ? e.score : "—") + (e.conflict ? ", conflict" : "") + ").");
    }
    if (ctx.asset_criticality === "high" || ctx.asset_criticality === "crown_jewel") parts.push("Host " + (a.host || "") + " kritikliyi: " + ctx.asset_criticality + ".");
    if (ctx.user_privileged) parts.push("İstifadəçi " + (a.user || "") + " imtiyazlıdır.");
    if (ctx.user_vip) parts.push("İstifadəçi VIP-dir.");
    if (d.shadow) parts.push("Sistem bunu bağlayardı (shadow mode): təsdiq gözləyir.");
    box.appendChild(txt(parts.join(" ")));
    var inc = incidentOf(a);
    if (inc && inc.alerts > 1) {
      box.appendChild(txt(" Eyni " + (inc.kind === "host" ? "host-da" : "istifadəçidə") + " son 7 gündə daha "));
      var l = el("button", "link", (inc.alerts - 1) + (inc.more ? "+" : "") + " alert"); l.type = "button";
      l.addEventListener("click", function () { openIncident(inc.kind, inc.value); });
      add(box, l, txt("."));
    }
    return box;
  }

  function renderDrawer(a) {
    state.detail = a;
    var dr = $("drawer"); dr.textContent = ""; $("qbody").classList.add("open");
    var d = a.decision || {}, e = a.enrichment || {};

    var head = el("header", "dh");
    var x = el("button", "close", "✕"); x.type = "button"; x.title = "Bağla (Esc)"; x.addEventListener("click", closeDrawer);
    var row = el("div", "row");
    add(row, prio(d.priority), verdict(d.verdict), el("span", "mu", (a.source_ref || "") + " · " + (TYPE[a.alert_type] || a.alert_type) + " · " + ago(a.received_at) + " ago"));
    var meta = el("div", "meta");
    if (a.host) meta.appendChild(el("span", null, "host " + a.host));
    if (a.user) meta.appendChild(el("span", null, "user " + a.user));
    if (a.case && a.case.created_at) meta.appendChild(el("span", null, "case in " + dur((new Date(a.case.created_at) - new Date(a.received_at)) / 1000)));
    if (a.occurrence_count > 1) meta.appendChild(el("span", null, "×" + a.occurrence_count));
    add(head, x, row, el("h2", null, a.title || a.source_ref), meta);
    dr.appendChild(head);
    dr.appendChild(summary(a));
    if (d.verdict) dr.appendChild(actions(a, d));

    // Evidence
    var ev = section("Evidence", "score " + (e.score != null ? Math.round(e.score) + "/100" : "—") + (e.confidence != null ? " · confidence " + Math.round(e.confidence * 100) + "%" : ""));
    (e.providers || []).forEach(function (p) {
      var g = el("div", "ev");
      g.appendChild(el("span", null, (PROV[p.provider] || p.provider)));
      var b = el("div", "bar2"), i = el("i", sevClass(p.score)); i.style.width = (p.score != null ? Math.max(2, p.score) : 0) + "%"; b.appendChild(i);
      add(g, b, el("span", "num", p.score != null ? p.score : "—"));
      var f = p.facts || {}, keys = Object.keys(f);
      var line = p.ioc_type + (keys.length ? " · " + keys.map(function (k) { return k + " " + f[k]; }).join(" · ") : "") + (p.cached ? " · cache" : "");
      g.appendChild(el("span", "f", line));
      if (p.status !== "ok") g.appendChild(el("span", "st", STATUS[p.status] || p.status));
      ev.appendChild(g);
    });
    if (!(e.providers || []).length) ev.appendChild(el("p", "mu", "Intel nəticəsi yoxdur."));
    dr.appendChild(ev);

    // Incident
    var inc = incidentOf(a), rel = a.related || [];
    var si = section("Incident", "last 7 days");
    if (inc && inc.alerts > 1) {
      var box = el("div", "inc"), left = el("div");
      add(left, el("b", null, inc.kind + " · " + inc.value), el("div", "mu", inc.alerts + (inc.more ? "+" : "") + " alerts" + (inc.p1 ? " · " + inc.p1 + " P1" : "")));
      var go = el("button", "link", "Open incident →"); go.type = "button"; go.title = "i";
      go.addEventListener("click", function () { openIncident(inc.kind, inc.value); });
      add(box, left, go); si.appendChild(box);
    } else if (rel.length) {
      si.appendChild(el("p", "mu", rel.length + " alert eyni IOC ilə: " + rel.slice(0, 3).map(function (r) { return r.source_ref; }).join(", ")));
    } else si.appendChild(el("p", "mu", "Eyni IOC, host və ya istifadəçi ilə başqa alert yoxdur."));
    dr.appendChild(si);

    // Decision
    var sd = section("Decision", d.decided_at ? fmt(d.decided_at) : null);
    var kv = el("dl", "kv");
    [["Rule", d.rule_id ? d.rule_id + " · v" + d.rule_version : null, "mono"], ["Action", d.action], ["Severity", d.severity_id], ["Status", a.status],
     ["Case", a.case ? a.case.backend + " · " + a.case.case_id : null, "mono"]].forEach(function (p) {
      if (p[1] == null || p[1] === "") return; add(kv, el("dt", null, p[0]), el("dd", p[2] || null, p[1]));
    });
    sd.appendChild(kv);
    if (a.case_link && /^https?:\/\//.test(a.case_link)) {
      var lk = el("a", "link caselink", "Open in TheHive ↗"); lk.href = a.case_link; lk.target = "_blank"; lk.rel = "noopener noreferrer"; lk.title = "o";
      var p = el("p"); p.appendChild(lk); sd.appendChild(p);
    }
    var ul = el("ul", "reasons");
    (d.reasons || []).forEach(function (r) { ul.appendChild(el("li", null, r)); });
    sd.appendChild(ul);
    dr.appendChild(sd);

    // IOCs
    var so = section("IOCs", (a.observables || []).length + " · defanged");
    var t = el("table", "iocs"), tb = el("tbody");
    (a.observables || []).forEach(function (o) {
      add(tb, add(el("tr"), el("td", "mu", o.type), el("td", "mono", o.value), el("td", "dim", o.internal ? "internal" : "")));
    });
    add(so, add(t, tb)); dr.appendChild(so);

    dr.appendChild(timeline(a.timeline || [], a.received_at));

    var fbs = a.feedback || [];
    var sf = section("Feedback", fbs.length || null), fb = el("div", "fb");
    if (!fbs.length) fb.appendChild(el("p", "mu", "Hələ feedback yoxdur."));
    fbs.forEach(function (f) { fb.appendChild(el("p", null, fmt(f.created_at) + " · " + f.analyst + " (" + f.source + "): " + f.human_verdict + (f.comment ? " · " + f.comment : ""))); });
    sf.appendChild(fb); dr.appendChild(sf);
  }

  function timeline(events, receivedAt) {
    // Audit qeydi mərhələ bitəndə yazılır: iki qeyd arasındakı vaxt sonrakı qeydin mərhələsinə aiddir.
    // "duplicate" qeydləri eyni alert-in təkrar gəlişidir, emal vaxtına daxil edilmir.
    var s = section("Timeline");
    if (!events.length) { s.appendChild(el("p", "mu", "Audit qeydi yoxdur.")); return s; }
    // Saat alert-in API-yə gəldiyi andan başlayır: worker götürənə qədər keçən vaxt "queue"-dur
    var first = new Date(events[0].ts), rcv = receivedAt ? new Date(receivedAt) : first;
    var t0 = rcv < first ? rcv : first, prev = first, segs = [];
    if (first - t0 >= 1000) segs.push({ stage: "queue", sec: (first - t0) / 1000 });
    events.filter(function (x) { return x.event !== "duplicate"; }).forEach(function (x) {
      var ts = new Date(x.ts), sec = Math.max(0, (ts - prev) / 1000); prev = ts;
      if (segs.length && segs[segs.length - 1].stage === x.stage) segs[segs.length - 1].sec += sec; else segs.push({ stage: x.stage, sec: sec });
    });
    var total = (prev - t0) / 1000;
    s.querySelector("h3").appendChild(el("span", "r", "total " + dur(total)));
    var flow = el("div", "flow");
    segs.forEach(function (g) {
      var i = el("i", "s-" + (STAGES.indexOf(g.stage) >= 0 || g.stage === "queue" ? g.stage : "ingest")); i.style.flexGrow = String(Math.max(g.sec, total * 0.015) || 1);
      i.title = g.stage + ": " + dur(g.sec); flow.appendChild(i);
    });
    s.appendChild(flow);
    var lg = el("div", "flowlg");
    segs.forEach(function (g) {
      var x = el("span"); add(x, el("i", "sw s-" + g.stage), txt(g.stage + " "), el("b", null, dur(g.sec))); lg.appendChild(x);
    });
    s.appendChild(lg);
    var ol = el("ol", "tl");
    events.forEach(function (x) {
      var li = el("li", /fail|error|dlq|pending/.test(x.event) ? "bad" : null);
      add(li, el("span", "mono", "+" + ((new Date(x.ts) - t0) / 1000).toFixed(2) + "s"), txt(x.stage + " · " + x.event + (x.actor && x.actor !== "system" ? " · " + x.actor : "")));
      ol.appendChild(li);
    });
    s.appendChild(ol);
    return s;
  }

  function actions(a, d) {
    var wrap = el("div", "acts"), row = el("div", "row");
    var ok = el("button", "btn ok"); ok.type = "button"; ok.id = "btnApprove";
    add(ok, txt("✓ Approve " + CONFIRM[d.verdict]), el("kbd", null, "a"));
    var no = el("button", "btn"); no.type = "button"; no.id = "btnReject";
    add(no, txt("✕ Reject"), el("kbd", null, "r"));
    add(row, ok, no); wrap.appendChild(row);
    var form = el("form"); form.hidden = true;
    var sel = el("select"); sel.setAttribute("aria-label", "Correct verdict");
    ["malicious", "suspicious", "clean"].filter(function (v) { return v !== CONFIRM[d.verdict]; }).forEach(function (v) {
      var o = el("option", null, "Correct verdict: " + v); o.value = v; sel.appendChild(o);
    });
    var note = el("textarea"); note.rows = 2; note.maxLength = 500; note.setAttribute("aria-label", "Comment");
    note.placeholder = "Səbəb (məs. VT-də yeni domen, 0/93 inandırıcı deyil)";
    var send = el("button", "btn primary", "Submit feedback"); send.type = "submit";
    add(form, sel, note, send); wrap.appendChild(form);
    ok.addEventListener("click", function () { submit(a, CONFIRM[d.verdict], "", [ok, no]); });
    no.addEventListener("click", function () { form.hidden = !form.hidden; if (!form.hidden) sel.focus(); });
    form.addEventListener("submit", function (ev) { ev.preventDefault(); submit(a, sel.value, note.value.trim(), [ok, no, send]); });
    return wrap;
  }
  async function submit(a, v, comment, buttons) {
    buttons.forEach(function (b) { b.disabled = true; });
    try {
      var r = await api("/feedback", { method: "POST", body: {
        alert_id: a.alert_id, human_verdict: v, analyst: read("a2c-analyst") || "panel", source: "manual", comment: comment
      } });
      toast(r.error ? r.error : (r.agree ? "Feedback yazıldı: sistemlə razısınız" : "Feedback yazıldı: sistemlə razı deyilsiniz (" + r.rule + ")"));
      // "Open" görünüşündə baxılmış alert siyahıdan çıxır: növbətisinə keç
      var idx = state.rows.findIndex(function (r2) { return r2.alert_id === a.alert_id; });
      await load();
      if (state.view === "open" && state.rows.length) select(state.rows[Math.min(Math.max(idx, 0), state.rows.length - 1)].alert_id);
      else if (state.rows.some(function (r2) { return r2.alert_id === a.alert_id; })) select(a.alert_id);
      else closeDrawer();
    } catch (err) {
      quiet(err, "Göndərilmədi");
      buttons.forEach(function (b) { b.disabled = false; });
    }
  }

  // ---------- INCIDENTS ----------
  document.querySelectorAll("#segInc button").forEach(function (b) {
    b.addEventListener("click", function () {
      state.incView = b.dataset.view;
      document.querySelectorAll("#segInc button").forEach(function (x) { x.setAttribute("aria-selected", x === b ? "true" : "false"); });
      load();
    });
  });
  function renderIncidents(list) {
    $("subtitle").textContent = list.length + " · grouped by host or user · last 7 days";
    var box = $("incTable"); box.textContent = "";
    if (!list.length) { box.appendChild(el("p", "empty", "Incident yoxdur: eyni host və ya istifadəçidə 2+ alert gəlməyib.")); return; }
    var t = el("table"), hr = el("tr");
    [["", ""], ["Entity", ""], ["Alerts", "num"], ["Verdicts", ""], ["Types", ""], ["First seen", "num"], ["Last seen", "num"], ["", ""]].forEach(function (h) { hr.appendChild(el("th", h[1] || null, h[0])); });
    add(t, add(el("thead"), hr));
    var tb = el("tbody");
    list.forEach(function (g) {
      var tr = el("tr");
      tr.appendChild(add(el("td"), prio(g.open_priority || g.priority)));
      tr.appendChild(add(el("td"), el("b", null, g.kind + " · " + g.entity)));
      tr.appendChild(el("td", "num", g.open + " / " + g.alerts));
      var mixTd = el("td"), mix = el("span", "mix");
      [["malicious", "m"], ["suspicious", "s2"], ["unknown", "u"], ["clean", "c"]].forEach(function (k) {
        if (g[k[0]]) { var i = el("i", k[1]); i.style.flexGrow = String(g[k[0]]); i.title = k[0] + ": " + g[k[0]]; mix.appendChild(i); }
      });
      mixTd.appendChild(mix);
      var top = g.malicious ? g.malicious + " malicious" : g.suspicious ? g.suspicious + " suspicious" : "";
      if (top) mixTd.appendChild(el("span", g.malicious ? "malicious" : "suspicious", top));
      tr.appendChild(mixTd);
      tr.appendChild(el("td", "mu", (g.types || []).map(function (x) { return TYPE[x] || x; }).join(", ")));
      tr.appendChild(el("td", "num mu", ago(g.first_seen)));
      tr.appendChild(el("td", "num mu", ago(g.last_seen)));
      var go = el("button", "link", "Review →"); go.type = "button";
      tr.appendChild(add(el("td"), go));
      tr.addEventListener("click", function () { openIncident(g.kind, g.entity); });
      tb.appendChild(tr);
    });
    add(box, add(t, tb));
  }

  // ---------- OVERVIEW ----------
  function card(cls, label, value, sub) {
    var c = el("div", cls), l = el("div", "l", label); l.lang = "en";
    add(c, l, el("div", "v2", value), sub ? el("div", "s3", sub) : null); return c;
  }
  function renderOverview(s) {
    var pr = s.open_by_priority || {};
    var agree = s.reviewed ? Math.round(100 * s.agree / s.reviewed) + "%" : "—";
    var box = $("kpis"); box.textContent = "";
    add(box,
      card("kpi", "Open", s.open, "P1 " + (pr.P1 || 0) + " · P2 " + (pr.P2 || 0) + " · P3 " + (pr.P3 || 0) + " · P4 " + (pr.P4 || 0)),
      card("kpi", "P1 open", pr.P1 || 0, "təcili, analitik gözləyir"),
      card("kpi", "Alerts · 24h", s.last_24h, "cəmi " + s.total),
      card("kpi", "Time to case · median", dur(s.case_median_s), "p90 " + dur(s.case_p90_s) + " · " + s.cases + " case"),
      card("kpi", "Analyst agreement", agree, s.reviewed + " feedback"));
    hourly(s.hourly || []);
    hbars($("chPriority"), ["P1", "P2", "P3", "P4"].map(function (k) { return { label: k, n: pr[k] || 0, cls: "f-" + k }; }));
    stacked($("chVerdict"), ["malicious", "suspicious", "unknown", "clean"].map(function (k) { return { label: k, n: (s.by_verdict || {})[k] || 0, cls: "f-" + k }; }));
  }
  function hourly(rows) {
    var box = $("chHourly"); box.textContent = "";
    var W = 640, H = 150, pl = 26, pb = 20, pt = 14, n = rows.length || 1;
    var max = Math.max(1, Math.max.apply(null, rows.map(function (r) { return r.n; })));
    var s = sv("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Alerts per hour" });
    [0, 0.5, 1].forEach(function (f) {
      var y = pt + (H - pt - pb) * (1 - f);
      s.appendChild(sv("line", { x1: pl, x2: W, y1: y, y2: y, class: "grid" }));
      s.appendChild(sv("text", { x: pl - 6, y: y + 3, "text-anchor": "end", class: "axis" }, Math.round(max * f)));
    });
    var bw = (W - pl) / n;
    rows.forEach(function (r, i) {
      var h = (H - pt - pb) * r.n / max, x = pl + i * bw + 2, y = H - pb - h, hr = new Date(r.hour);
      var rect = sv("rect", { x: x, y: y, width: Math.max(1, bw - 4), height: Math.max(h, r.n ? 2 : 0), rx: 2, class: "bar" + (i === n - 1 ? " hot" : "") });
      rect.appendChild(sv("title", {}, hr.getHours() + ":00 — " + r.n));
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
    var s = sv("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Open by priority" });
    items.forEach(function (it, i) {
      var y = i * rh + 4, w = (W - lw - 36) * it.n / max;
      s.appendChild(sv("text", { x: 0, y: y + 13, class: "lab" }, it.label));
      s.appendChild(sv("rect", { x: lw, y: y, width: W - lw - 36, height: 16, rx: 3, class: "grid" }));
      if (it.n) s.appendChild(sv("rect", { x: lw, y: y, width: Math.max(w, 3), height: 16, rx: 3, class: it.cls }));
      s.appendChild(sv("text", { x: lw + Math.max(w, 3) + 6, y: y + 13, class: "val" }, it.n));
    });
    box.appendChild(s);
  }
  function stacked(box, items) {
    box.textContent = "";
    var total = items.reduce(function (a, i) { return a + i.n; }, 0), W = 300, H = 24, x = 0;
    var s = sv("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Verdicts" });
    s.appendChild(sv("rect", { x: 0, y: 0, width: W, height: H, rx: 4, class: "grid" }));
    items.forEach(function (it) {
      if (!total || !it.n) return;
      var w = W * it.n / total, r = sv("rect", { x: x, y: 0, width: Math.max(w - 2, 1), height: H, rx: 3, class: it.cls });
      r.appendChild(sv("title", {}, it.label + ": " + it.n)); s.appendChild(r);
      if (w > 34) s.appendChild(sv("text", { x: x + w / 2 - 1, y: 16, "text-anchor": "middle", class: "val" }, Math.round(100 * it.n / total) + "%"));
      x += w;
    });
    box.appendChild(s);
    var lg = el("div", "legend");
    items.forEach(function (it) { lg.appendChild(add(el("span"), el("i", "sw " + it.cls), txt(it.label + " "), el("b", null, it.n))); });
    box.appendChild(lg);
  }

  // ---------- SYSTEM ----------
  function renderHealth(h) {
    var m = $("hMode"); m.textContent = "";
    var closing = h.auto_close_enabled && !h.shadow_mode;
    add(m,
      card("hc " + (closing ? "bad" : "good"), "Auto-close", closing ? "ON" : "OFF", closing ? "Sistem təmiz alert-ləri özü bağlayır" : "Sistem heç bir alert-i özü bağlamır (ADR-0003)"),
      card("hc " + (h.shadow_mode ? "good" : "warn"), "Shadow mode", h.shadow_mode ? "ON" : "OFF",
        (h.decisions_24h.shadow || 0) + " / " + (h.decisions_24h.decided || 0) + " qərar son 24 saatda \"sistem bağlayardı\""),
      card("hc", "Case backend", h.case_backend, h.case_backend === "thehive" ? "case-lər TheHive-da açılır" : "case-lər faylda (var/cases)"));
    var box = $("hIntel"); box.textContent = "";
    h.providers.forEach(function (p) {
      var c = el("div", "hc"), head = el("div", "head");
      add(head, el("b", null, PROV[p.provider] || p.provider), el("span", "state " + (p.configured ? p.state : "down"), p.configured ? p.state : "no key"));
      c.appendChild(head);
      var cnt = el("div", "counts"), lh = p.last_hour || {}, keys = Object.keys(lh);
      cnt.appendChild(el("span", null, "last 1h:"));
      if (!keys.length) cnt.appendChild(el("span", null, "—"));
      keys.forEach(function (k) { cnt.appendChild(add(el("span"), txt((k === "cached" ? "from cache" : (STATUS[k] || k)) + " "), el("b", null, lh[k]))); });
      c.appendChild(cnt);
      var pct = p.quota_used == null ? 0 : Math.min(100, 100 * p.quota_used / p.quota_day);
      var mt = el("span", "meter"), bar = el("i", pct >= 80 ? "high" : pct >= 50 ? "mid" : ""); bar.style.width = Math.max(pct, 1) + "%"; mt.appendChild(bar);
      mt.style.width = "100%";
      add(c, el("div", "counts", "daily quota " + (p.quota_used == null ? "—" : p.quota_used) + " / " + p.quota_day + " · " + p.per_minute + "/min"), mt);
      box.appendChild(c);
    });
    var qb = $("hQueue"); qb.textContent = ""; var q = h.queue || {};
    if (!q.available) { qb.appendChild(card("hc bad", "Redis", "unavailable", "növbə məlumatı oxunmadı")); return; }
    add(qb,
      card("hc " + (q.lag ? "warn" : "good"), "Waiting", q.lag, "hələ heç kim götürməyib"),
      card("hc", "In progress", q.pending, "worker emal edir"),
      card("hc " + (q.alerts_dlq ? "bad" : "good"), "alerts.dlq", q.alerts_dlq, "3 cəhddən sonra düşənlər"),
      card("hc " + (q.cases_dlq ? "bad" : "good"), "cases.dlq", q.cases_dlq, "case açılmayanlar"));
  }

  // ---------- RULES ----------
  function renderRules(r) {
    var sp = r.shadow_progress || {}, box = $("rProgress"); box.textContent = "";
    var real = sp.reviewed_real || 0, target = sp.target || 30;
    var c = card("hc" + (real >= target ? " good" : ""), "Auto-close readiness · shadow review", real + " / " + target,
      "\"Sistem bağlayardı\" deyilən və analitikin baxdığı real alert-lər (ADR-0003). Dataset alert-ləri (HASH-/URL-/LOGIN-NN) sayılmır; onlarla birlikdə " + (sp.reviewed || 0) + ".");
    var bb = el("div", "big"), bi = el("i"); bi.style.width = Math.min(100, 100 * real / target) + "%"; bb.appendChild(bi);
    c.insertBefore(bb, c.lastChild); box.appendChild(c);
    box.appendChild(card("hc " + ((sp.would_miss_real || 0) ? "bad" : "good"), "Would-miss · target 0", sp.would_miss_real || 0,
      "sistem bağlayardı, analitik malicious/suspicious dedi · dataset daxil: " + (sp.would_miss || 0)));
    var tot = r.rules.reduce(function (a, x) { return a + x.reviewed; }, 0), ag = r.rules.reduce(function (a, x) { return a + x.agree; }, 0);
    box.appendChild(card("hc", "Overall agreement", tot ? Math.round(100 * ag / tot) + "%" : "—", tot + " feedback · " + r.rules.length + " rules"));
    $("subtitle").textContent = r.rules.length + " rules";
    var wrap = $("rTable"); wrap.textContent = "";
    var t = el("table", "rules"), hr = el("tr");
    [["Rule", ""], ["Alerts", "num"], ["Shadow", "num"], ["Feedback", "num"], ["Agreement", ""], ["Top verdict", ""], ["Last seen", "num"]].forEach(function (h) { hr.appendChild(el("th", h[1] || null, h[0])); });
    add(t, add(el("thead"), hr));
    var tb = el("tbody");
    r.rules.forEach(function (x) {
      var row = el("tr");
      add(row, el("td", "mono", x.rule_id), el("td", "num", x.alerts), el("td", "num", x.shadow), el("td", "num", x.reviewed));
      var td = el("td");
      if (x.reviewed) {
        var pct = Math.round(100 * x.agree / x.reviewed), m = el("span", "meter"), i = el("i", pct < 70 ? "high" : ""); i.style.width = Math.max(pct, 2) + "%"; m.appendChild(i);
        add(td, add(el("span", "sc"), m, txt(pct + "%")), pct < 70 ? el("span", "tune", "tuning") : null);
      } else td.appendChild(el("span", "dim", "—"));
      row.appendChild(td);
      row.appendChild(add(el("td"), verdict(x.top_verdict)));
      var ls = el("td", "num mu", ago(x.last_seen)); ls.title = fmt(x.last_seen); row.appendChild(ls);
      tb.appendChild(row);
    });
    add(wrap, add(t, tb));
  }

  // ---------- klaviatura ----------
  function move(step) {
    if (state.page !== "queue" || !state.rows.length) return;
    var i = state.rows.findIndex(function (r) { return r.alert_id === state.selected; });
    i = i < 0 ? 0 : Math.max(0, Math.min(state.rows.length - 1, i + step));
    select(state.rows[i].alert_id);
    var tr = document.querySelector('#queueTable tr[data-id="' + state.rows[i].alert_id + '"]');
    if (tr) tr.scrollIntoView({ block: "nearest" });
  }
  function showHelp(on) { $("helpBox").hidden = !on; if (on) $("helpClose").focus(); }
  $("help").addEventListener("click", function () { showHelp(true); });
  $("helpClose").addEventListener("click", function () { showHelp(false); });
  $("helpBox").addEventListener("click", function (e) { if (e.target === $("helpBox")) showHelp(false); });
  document.addEventListener("keydown", function (e) {
    if ($("app").hidden || e.ctrlKey || e.metaKey || e.altKey) return;
    var tag = (e.target.tagName || "").toLowerCase();
    if (e.key === "Escape") {
      if (!$("helpBox").hidden) { showHelp(false); return; }
      if (tag === "input" || tag === "select") { e.target.blur(); return; }
      var f = document.querySelector(".acts form"); if (f && !f.hidden) { f.hidden = true; return; }
      if (state.selected) closeDrawer();
      return;
    }
    if (tag === "input" || tag === "textarea" || tag === "select" || !$("helpBox").hidden) return;
    var k = e.key, a = state.detail;
    if (k === "?") showHelp(true);
    else if (k >= "1" && k <= "5") setPage(PAGES[+k - 1]);
    else if (k === "j") move(1);
    else if (k === "k") move(-1);
    else if (k === "/") { if (state.page !== "queue") setPage("queue"); $("q").focus(); }
    else if (k === "a" && $("btnApprove") && !$("btnApprove").disabled && state.selected) $("btnApprove").click();
    else if (k === "r" && $("btnReject") && state.selected) $("btnReject").click();
    else if (k === "i" && a && incidentOf(a)) openIncident(incidentOf(a).kind, incidentOf(a).value);
    else if (k === "o" && a && a.case_link) { var lk = document.querySelector(".caselink"); if (lk) lk.click(); }
    else return;
    e.preventDefault();
  });

  // ---------- başlanğıc ----------
  if (read("a2c-token")) { showApp(true); setPage("queue"); } else { showApp(false); }
})();
