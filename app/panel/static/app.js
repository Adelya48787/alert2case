// alert2case analitik paneli. Kitabxana yoxdur, build addımı yoxdur.
// Təhlükəsizlik: bütün mətn textContent ilə yazılır (HTML kimi heç nə yazılmır), çünki alert məzmunu
// xarici mənbədən gəlir. Token yalnız sessionStorage-dadır və hər sorğuda başlıqla göndərilir.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var state = { view: "open", selected: null, rows: [] };
  var VERDICT_AZ = { malicious: "zərərli", suspicious: "şübhəli", unknown: "naməlum", clean: "təmiz" };
  // Sistemin verdict-i → analitikin "təsdiqlə" rəyi (feedback yalnız malicious/suspicious/clean qəbul edir)
  var CONFIRM = { malicious: "malicious", suspicious: "suspicious", unknown: "suspicious", clean: "clean" };

  function store(k, v) { try { v == null ? sessionStorage.removeItem(k) : sessionStorage.setItem(k, v); } catch (e) {} }
  function read(k) { try { return sessionStorage.getItem(k); } catch (e) { return null; } }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function toast(msg) {
    var t = $("toast"); t.textContent = msg; t.hidden = false;
    clearTimeout(toast.t); toast.t = setTimeout(function () { t.hidden = true; }, 2200);
  }
  function fmt(ts) {
    if (!ts) return "";
    var d = new Date(ts);
    return isNaN(d) ? String(ts) : d.toLocaleString("az-AZ", { dateStyle: "short", timeStyle: "medium" });
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
    ["stats", "who", "refresh", "logout"].forEach(function (id) { $(id).hidden = !on; });
    $("who").textContent = on ? "analitik: " + (read("a2c-analyst") || "") : "";
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
  $("refresh").addEventListener("click", function () { load(); });

  // ---------- tablar ----------
  document.querySelectorAll(".tabs button").forEach(function (b) {
    b.addEventListener("click", function () {
      state.view = b.dataset.view;
      document.querySelectorAll(".tabs button").forEach(function (x) { x.setAttribute("aria-selected", x === b ? "true" : "false"); });
      load();
    });
  });

  // ---------- siyahı ----------
  async function load() {
    try {
      var res = await Promise.all([api("/api/panel/alerts?view=" + state.view), api("/api/panel/stats")]);
      state.rows = res[0]; renderStats(res[1]); renderList();
    } catch (err) { if (err.message !== "forbidden") toast("Yüklənmədi: " + err.message); }
  }
  function renderStats(s) {
    var box = $("stats"); box.textContent = "";
    var agree = s.reviewed ? Math.round(100 * s.agree / s.reviewed) + "%" : "—";
    [["Açıq", s.open], ["Sistem bağlayardı", s.would_close], ["Baxılıb", s.reviewed], ["Razılaşma", agree]].forEach(function (p) {
      var c = el("span", "stat", p[0] + ": "); c.appendChild(el("b", null, p[1])); box.appendChild(c);
    });
  }
  function renderList() {
    var list = $("list"); list.textContent = "";
    if (!state.rows.length) { list.appendChild(el("p", "muted", "Bu bölmədə alert yoxdur.")); return; }
    state.rows.forEach(function (r) {
      var b = el("button", "row"); b.type = "button";
      b.setAttribute("aria-current", r.alert_id === state.selected ? "true" : "false");
      b.appendChild(el("span", "pill p-" + r.priority, r.priority));
      b.appendChild(el("span", "t", r.title || r.source_ref));
      b.appendChild(el("span", "v-" + r.verdict, VERDICT_AZ[r.verdict] || r.verdict));
      var m = el("span", "m");
      m.appendChild(el("span", null, r.source_ref || r.alert_type));
      m.appendChild(el("span", "mono", r.rule_id));
      if (r.shadow) m.appendChild(el("span", "pill shadow", "sistem bağlayardı"));
      if (r.human_verdict) m.appendChild(el("span", "pill done", "rəy: " + (VERDICT_AZ[r.human_verdict] || r.human_verdict)));
      m.appendChild(el("span", null, fmt(r.received_at)));
      b.appendChild(m);
      b.addEventListener("click", function () { select(r.alert_id); });
      list.appendChild(b);
    });
  }

  // ---------- detal ----------
  async function select(id) {
    state.selected = id; renderList();
    try { renderDetail(await api("/api/panel/alerts/" + encodeURIComponent(id))); }
    catch (err) { if (err.message !== "forbidden") toast("Alert açılmadı: " + err.message); }
  }
  function kv(pairs) {
    var dl = el("dl", "kv");
    pairs.forEach(function (p) { if (p[1] == null || p[1] === "") return; dl.appendChild(el("dt", null, p[0])); dl.appendChild(el("dd", p[2] || null, p[1])); });
    return dl;
  }
  function table(head, rows) {
    var wrap = el("div", "tbl"), t = el("table"), tr = el("tr");
    head.forEach(function (h) { tr.appendChild(el("th", null, h)); });
    t.appendChild(tr);
    rows.forEach(function (r) { var x = el("tr"); r.forEach(function (c) { x.appendChild(el("td", null, c == null ? "" : c)); }); t.appendChild(x); });
    wrap.appendChild(t); return wrap;
  }
  function renderDetail(a) {
    var box = $("detail"); box.textContent = "";
    var d = a.decision || {};
    box.appendChild(el("h2", null, a.title || a.source_ref));
    box.appendChild(kv([
      ["Prioritet", d.priority], ["Sistemin verdict-i", (VERDICT_AZ[d.verdict] || d.verdict) + (d.shadow ? " · sistem bağlayardı (shadow)" : "")],
      ["Qayda", d.rule_id && d.rule_id + " · v" + d.rule_version, "mono"], ["Hərəkət", d.action],
      ["Status", a.status], ["Host", a.host], ["İstifadəçi", a.user], ["Qəbul", fmt(a.received_at)],
      ["Təkrar", a.occurrence_count > 1 ? a.occurrence_count + " dəfə" : null],
      ["Case", a.case && a.case.backend + " · " + a.case.case_id, "mono"]
    ]));

    box.appendChild(el("h3", null, "Niyə belə qərar verildi"));
    var ul = el("ul", "reasons");
    (d.reasons || []).forEach(function (x) { ul.appendChild(el("li", null, x)); });
    box.appendChild(ul);

    box.appendChild(el("h3", null, "IOC-lar (defang)"));
    box.appendChild(table(["Tip", "Dəyər", ""], a.observables.map(function (o) { return [o.type, o.value, o.internal ? "daxili" : ""]; })));

    var e = a.enrichment || {};
    box.appendChild(el("h3", null, "Intel: " + (e.status || "—") + (e.score != null ? " · skor " + e.score : "") + (e.confidence != null ? " · etibarlılıq " + e.confidence : "")));
    box.appendChild(table(["Mənbə", "IOC", "Status", "Skor", "Cache", "Qeyd"], (e.providers || []).map(function (p) {
      return [p.provider, p.ioc_type, p.status, p.score, p.cached ? "bəli" : "", p.note];
    })));

    box.appendChild(el("h3", null, "Tarixçə"));
    var ol = el("ol", "tl"); var t0 = a.timeline.length ? new Date(a.timeline[0].ts) : null;
    a.timeline.forEach(function (x) {
      var li = el("li"); li.appendChild(el("span", "mono", "+" + ((new Date(x.ts) - t0) / 1000).toFixed(2) + " s "));
      li.appendChild(el("span", null, x.stage + " · " + x.event + (x.actor && x.actor !== "system" ? " · " + x.actor : "")));
      ol.appendChild(li);
    });
    box.appendChild(ol);

    box.appendChild(el("h3", null, "Analitik rəyi"));
    (a.feedback || []).forEach(function (f) {
      box.appendChild(el("p", "muted", fmt(f.created_at) + " · " + f.analyst + " (" + f.source + "): " + (VERDICT_AZ[f.human_verdict] || f.human_verdict) + (f.comment ? " · " + f.comment : "")));
    });
    if (d.verdict) box.appendChild(actions(a, d));
  }
  function actions(a, d) {
    var wrap = el("div", "actions"), bar = el("div", "bar");
    var ok = el("button", "btn ok", "Təsdiqlə: " + (VERDICT_AZ[CONFIRM[d.verdict]] || d.verdict)); ok.type = "button";
    var no = el("button", "btn", "Rədd et…"); no.type = "button";
    bar.appendChild(ok); bar.appendChild(no); wrap.appendChild(bar);

    var form = el("form", "actions"); form.hidden = true;
    var sel = el("select"); sel.id = "fbVerdict";
    ["malicious", "suspicious", "clean"].filter(function (v) { return v !== CONFIRM[d.verdict]; }).forEach(function (v) {
      var o = el("option", null, "Düzgün cavab: " + VERDICT_AZ[v]); o.value = v; sel.appendChild(o);
    });
    var note = el("textarea"); note.id = "fbComment"; note.rows = 2; note.maxLength = 500; note.placeholder = "Səbəb (məs. VT-də yeni domen, 0/93 inandırıcı deyil)";
    var send = el("button", "btn primary", "Rəyi göndər"); send.type = "submit";
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
