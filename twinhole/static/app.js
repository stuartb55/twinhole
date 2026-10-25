"use strict";

// ---------- helpers ------------------------------------------------------------

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

const BLOCKED = new Set([
  "GRAVITY", "REGEX", "DENYLIST", "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA",
  "EXTERNAL_BLOCKED_EDE15", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME", "SPECIAL_DOMAIN",
]);
const NOUN = { groups: "group", domains: "domain", lists: "adlist", clients: "client", hosts: "local DNS", cnames: "CNAME" };

const fmt = {
  num: (n) => (n == null ? "–" : Number(n).toLocaleString("en-GB")),
  pct: (n) => (n == null ? "–" : `${Number(n).toFixed(1)}%`),
  time: (ts) => new Date(ts * 1000).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
  dateTime: (ts) => new Date(ts * 1000).toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }),
  day: (ts) => new Date(ts * 1000).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "2-digit" }),
  ago(ts) {
    if (!ts) return "never";
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 60) return `${Math.round(s)}s ago`;
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 172800) return `${Math.round(s / 3600)}h ago`;
    return `${Math.round(s / 86400)} days ago`;
  },
};

async function api(path, { method, body } = {}) {
  const init = { method: method || (body === undefined ? "GET" : "POST"), headers: {} };
  if (body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const r = await fetch(path, init);
  const text = await r.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!r.ok) {
    const detail = data && data.detail;
    throw new Error(typeof detail === "string" ? detail : detail ? JSON.stringify(detail) : `HTTP ${r.status}`);
  }
  return data;
}

let toastTimer;
function toast(message, bad = false) {
  $(".toast")?.remove();
  const t = document.createElement("div");
  t.className = "toast" + (bad ? " bad" : "");
  t.textContent = message;
  document.body.append(t);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.remove(), bad ? 8000 : 4000);
}

// ---------- state & routing ----------------------------------------------------

const state = {
  status: null,
  page: null,
  charts: [],
  timers: [],
  historyRange: "24h",
  topDays: 7,
  topPihole: "",
  manageTab: "domains",
  manage: null,
  queries: null,
  queryFilter: { text: "", status: "all", pihole: "" },
  deviceFilter: { text: "", scope: "active", unnamed: false, oneOnly: false },
  target: "both",
};

const pages = { overview, history, queries, devices, sync, manage, actions };

function piholes() { return state.status ? state.status.piholes : []; }
function byId(id) { return piholes().find((p) => p.id === id); }
function colorFor(id) { return byId(id)?.role === "secondary" ? css("--c-sec") : css("--c-main"); }
function chip(id) {
  const p = byId(id);
  if (!p) return `<span class="pill">${esc(id)}</span>`;
  return `<span class="pill ${p.role === "secondary" ? "sec" : "main"}">${esc(p.name)}</span>`;
}
function writesOff() { return !state.status?.writes; }

function cleanup() {
  state.charts.forEach((c) => c.destroy());
  state.charts = [];
  state.timers.forEach((t) => clearInterval(t));
  state.timers = [];
}

async function go() {
  const page = (location.hash.slice(1) || "overview").split(/[/?]/)[0];
  const fn = pages[page] || overview;
  cleanup();
  state.page = page in pages ? page : "overview";
  $$("#nav button").forEach((b) => b.classList.toggle("active", b.dataset.page === state.page));
  const el = $("#page");
  el.onclick = el.onchange = null; // drop the previous page's handlers
  try {
    await fn(el);
  } catch (e) {
    el.innerHTML = `<div class="banner bad">Couldn't load this page: ${esc(e.message)}</div>`;
  }
}

async function refreshStatus() {
  try {
    state.status = await api("/api/status");
  } catch (e) {
    $("#updated").textContent = `twinhole unreachable: ${e.message}`;
    return;
  }
  const s = state.status;
  $("#mode").innerHTML = s.writes ? "" : `<span class="pill">Read-only</span>`;
  $("#updated").textContent = `Checked ${fmt.time(Math.max(...s.piholes.map((p) => p.checked || 0)) || s.now)}`;
  const navOverview = $('#nav [data-page="overview"]');
  navOverview.innerHTML = "Overview" + (s.alerts.length ? `<span class="count">${s.alerts.length}</span>` : "");
  const navSync = $('#nav [data-page="sync"]');
  navSync.innerHTML = "Sync" + (s.sync.count ? `<span class="count" style="background:var(--warn)">${s.sync.count}</span>` : "");
}

document.addEventListener("click", (e) => {
  const nav = e.target.closest("#nav button");
  if (nav) location.hash = nav.dataset.page;
});
window.addEventListener("hashchange", go);

// ---------- overview -------------------------------------------------------------

function health(p) {
  const alerts = state.status.alerts.filter((a) => a.key.startsWith(p.id + ":"));
  if (p.api.ok === null) return ["unknown", "Checking…"];
  if (!p.api.ok || (p.dns.v4 && !p.dns.v4.ok)) return ["bad", "Not working"];
  const r = p.resolver || {};
  if (alerts.length || (p.dns.v6 && !p.dns.v6.ok) || p.blocking !== "enabled" || r.recursion?.ok === false || r.dnssec?.ok === false) return ["warn", "Needs attention"];
  return ["ok", "Healthy"];
}

function dnsCell(r) {
  if (!r) return `<span class="muted">not checked (no IPv6 address)</span>`;
  if (r.ok) return `<span class="dot ok"></span>${r.ms} ms <span class="muted mono">${esc(r.server)}</span>`;
  return `<span class="dot bad"></span>${esc(r.error)} <span class="muted mono">${esc(r.server)}</span>`;
}

function upstreamCell(p) {
  const ups = p.resolver?.upstreams;
  if (!ups) return `<span class="muted">–</span>`;
  if (!ups.length) return `<span class="muted">none used yet</span>`;
  const s = p.summary || {};
  const forwarded = s.forwarded || 0;
  return ups.map((u) => `<span class="mono">${esc(u.server)}</span> · ${u.ms} ms avg${ups.length > 1 && forwarded ? ` · ${fmt.pct((100 * u.count) / forwarded)}` : ""}`).join("<br>");
}

function cacheCell(p) {
  const s = p.summary || {};
  const answered = (s.cached || 0) + (s.forwarded || 0);
  if (!answered) return `<span class="muted">–</span>`;
  return `${fmt.pct((100 * s.cached) / answered)} of lookups answered from cache`;
}

function recursionCell(p) {
  const r = p.resolver?.recursion;
  if (!r) return `<span class="muted">not checked yet</span>`;
  const when = `<span class="muted">checked ${fmt.ago(r.checked)}</span>`;
  return r.ok ? `<span class="dot ok"></span>resolving new names${r.ms != null ? ` · ${r.ms} ms` : ""} ${when}`
    : `<span class="dot bad"></span>${esc(r.error || "failing")} ${when}`;
}

function dnssecCell(p) {
  const d = p.resolver?.dnssec;
  if (!d) return `<span class="muted">not checked yet</span>`;
  const dot = d.ok === true ? "ok" : d.ok === false ? "bad" : "unknown";
  return `<span class="dot ${dot}"></span>${esc(d.detail || "unknown")} <span class="muted">checked ${fmt.ago(d.checked)}</span>`;
}

function uptimeCell(p) {
  const r = p.reliability || {};
  if (r.uptime_pct == null) return `<span class="muted">not measured yet</span>`;
  const partial = r.since && state.status.now - r.since < 29 * 86400;
  const dot = r.uptime_pct >= 99.9 ? "ok" : r.uptime_pct >= 99 ? "warn" : "bad";
  return `<span class="dot ${dot}"></span>${r.uptime_pct.toFixed(r.uptime_pct === 100 ? 0 : 2)}% <span class="muted">${partial ? `since ${new Date(r.since * 1000).toLocaleDateString("en-GB", { day: "numeric", month: "short" })}` : "last 30 days"}</span>`;
}

function outageCell(p) {
  const now = state.status.alerts.find((a) => ["api", "dns4", "dns6", "recursion"].some((k) => a.key === `${p.id}:${k}`));
  if (now) return `<span class="dot bad"></span>now: ${esc(now.title)} <span class="muted">since ${fmt.dateTime(now.since)}</span>`;
  const o = p.reliability?.last_outage;
  if (!o) return `<span class="muted">none recorded</span>`;
  return `${fmt.dateTime(o.since)}, ${duration(o.until - o.since)} <span class="muted">${esc(o.title)}</span>`;
}

function duration(s) {
  if (s < 120) return `${Math.round(s)} s`;
  if (s < 7200) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`;
  return `${Math.round(s / 86400)} days`;
}

function versionsCell(p, other) {
  if (!p.versions) return `<span class="muted">–</span>`;
  const parts = ["core", "web", "ftl"].map((k) => {
    const v = p.versions[k];
    const differs = other?.versions && other.versions[k].local !== v.local;
    return `<span title="${differs ? "Differs from the other Pi-hole" : ""}" style="${differs ? "color:var(--warn);font-weight:600" : ""}">${k === "ftl" ? "FTL" : k[0].toUpperCase() + k.slice(1)} ${esc(v.local || "?")}</span>`;
  });
  const updates = ["core", "web", "ftl"].filter((k) => p.versions[k].update);
  return parts.join(" · ") + (updates.length ? ` <span class="pill warn" title="${esc(updates.map((k) => `${k}: ${p.versions[k].remote}`).join(", "))}">update available</span>` : "");
}

function piholeCard(p, other) {
  const [level, label] = health(p);
  const s = p.summary || {};
  const g = p.gravity || {};
  const gAge = g.last_update ? (state.status.now - g.last_update) / 86400 : null;
  const blocking = p.blocking == null ? `<span class="muted">–</span>`
    : p.blocking === "enabled" ? `<span class="pill ok">enabled</span>`
    : `<span class="pill bad">${esc(p.blocking)}</span>${p.blocking_timer ? ` <span class="muted">re-enables in ${Math.ceil(p.blocking_timer / 60)} min</span>` : ""}`;
  return `
  <section class="card pihole-card" style="--c:${p.role === "secondary" ? "var(--c-sec)" : "var(--c-main)"}">
    <div class="title">
      <h2>${esc(p.name)}</h2>
      <span class="pill">${p.role}</span>
      <span class="pill ${level}" style="margin-left:auto"><span class="dot ${level}"></span>${label}</span>
    </div>
    <div class="small muted"><a href="${esc(p.url)}/admin/" target="_blank" rel="noopener">${esc(p.url)}</a></div>
    <div class="stats">
      <div class="stat"><b>${fmt.num(s.total)}</b><span>queries (24h)</span></div>
      <div class="stat"><b>${fmt.pct(s.percent_blocked)}</b><span>blocked</span></div>
      <div class="stat"><b>${fmt.num(s.clients_active)}</b><span>active clients</span></div>
    </div>
    <dl class="kv">
      <dt>Uptime</dt><dd>${uptimeCell(p)}</dd>
      <dt>Last outage</dt><dd>${outageCell(p)}</dd>
      <dt>API</dt><dd>${p.api.ok === null ? "–" : p.api.ok ? `<span class="dot ok"></span>answering` : `<span class="dot bad"></span>${esc(p.api.error)}`}</dd>
      <dt>DNS (IPv4)</dt><dd>${dnsCell(p.dns.v4)}</dd>
      <dt>DNS (IPv6)</dt><dd>${dnsCell(p.dns.v6)}</dd>
      <dt>Upstream</dt><dd>${upstreamCell(p)}</dd>
      <dt>Recursion</dt><dd>${recursionCell(p)}</dd>
      <dt>DNSSEC</dt><dd>${dnssecCell(p)}</dd>
      <dt>Cache</dt><dd>${cacheCell(p)}</dd>
      <dt>Blocking</dt><dd>${blocking}</dd>
      <dt>Gravity</dt><dd>${gAge == null ? "–" : `<span class="dot ${gAge > 8 ? "warn" : "ok"}"></span>updated ${fmt.ago(g.last_update)} · ${fmt.num(g.domains_being_blocked)} domains`}</dd>
      <dt>Versions</dt><dd>${versionsCell(p, other)}</dd>
    </dl>
  </section>`;
}

async function overview(el) {
  const draw = async () => {
    const s = state.status;
    if (!s) return;
    const [m, sec] = s.piholes;
    const events = await api("/api/events?limit=25");
    const alerts = s.alerts.length
      ? `<div class="banner bad"><b>${s.alerts.length} active alert${s.alerts.length > 1 ? "s" : ""}</b><ul>${s.alerts.map((a) => `<li><b>${esc(a.title)}</b> – ${esc(a.detail)} <span class="muted">(since ${fmt.dateTime(a.since)})</span></li>`).join("")}</ul></div>`
      : "";
    const sync = s.sync;
    const syncText = sync.error ? `<span class="dot bad"></span>Couldn't compare: ${esc(sync.error)}`
      : !sync.checked ? `<span class="muted">Not checked yet</span>`
      : sync.auto?.held ? `<span class="dot bad"></span>Auto-sync waiting for you: ${esc(sync.summary)}`
      : sync.count ? `<span class="dot warn"></span>${esc(sync.summary)}` : `<span class="dot ok"></span>In sync`;
    el.innerHTML = `
      ${alerts}
      <div class="grid cols-2">${piholeCard(m, sec)}${piholeCard(sec, m)}</div>
      <div class="grid cols-2">
        <section class="card fill" id="day-card">
          <div class="card-head"><h2>Last 24 hours</h2><div class="right"><a href="#history">History →</a></div></div>
          <p class="empty">Loading…</p>
        </section>
        <section class="card">
          <div class="card-head"><h2>Sync</h2><div class="right"><a href="#sync">Review →</a></div></div>
          <p style="display:flex;gap:8px;align-items:center;margin:0 0 6px">${syncText}</p>
          <p class="small muted" style="margin:0">${esc(sec.name)} mirrors ${esc(m.name)}${sync.auto?.enabled ? ", synced automatically" : ""}. Checked ${fmt.ago(sync.checked)}.</p>
          <h3 style="margin-top:18px">Recent events</h3>
          ${eventsList(events.slice(0, 8))}
        </section>
      </div>`;
    const [hist, top] = await Promise.all([api("/api/history?range=24h"), api("/api/top?days=1&limit=5")]);
    dayCard($("#day-card"), hist, top);
  };
  await draw();
  state.timers.push(setInterval(async () => {
    await refreshStatus();
    if (state.page !== "overview") return;
    state.charts.forEach((c) => c.destroy());
    state.charts = [];
    await draw();
  }, 15000));
}

function dayCard(card, hist, top) {
  const byT = new Map();
  let total = 0, blocked = 0;
  for (const p of hist.piholes) {
    for (const x of p.points) {
      total += x.total;
      blocked += x.blocked;
      byT.set(x.t, (byT.get(x.t) || 0) + x.total);
    }
  }
  let peak = null;
  for (const [t, n] of byT) if (!peak || n > peak.n) peak = { t, n };
  const hourly = byT.size ? Math.round(total / (byT.size * hist.step / 3600)) : null;
  const swatch = (color, dashed) => `<i class="swatch${dashed ? " dashed" : ""}" style="--c:${color}"></i>`;
  card.innerHTML = `
    <div class="card-head"><h2>Last 24 hours</h2><span class="muted small">both Pi-holes</span><div class="right"><a href="#history">History →</a></div></div>
    <div class="stats cols-4">
      <div class="stat"><b>${fmt.num(total)}</b><span>queries</span></div>
      <div class="stat"><b>${fmt.num(blocked)}</b><span>blocked (${total ? fmt.pct((100 * blocked) / total) : "–"})</span></div>
      <div class="stat"><b>${fmt.num(hourly)}</b><span>per hour, average</span></div>
      <div class="stat"><b>${peak ? fmt.num(peak.n) : "–"}</b><span>peak 10 min${peak ? `, ${new Date(peak.t * 1000).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })}` : ""}</span></div>
    </div>
    <div class="chart-box grow"><canvas></canvas></div>
    <div class="legend">
      ${hist.piholes.map((p) => `<span>${swatch(colorFor(p.id))}${esc(byId(p.id)?.name || p.name)}</span>`).join("")}
      <span class="muted">${swatch("var(--muted)")}all queries</span>
      <span class="muted">${swatch("var(--muted)", true)}blocked</span>
    </div>
    <h3 style="margin-top:16px">Yesterday's top <span class="muted small" style="text-transform:none;letter-spacing:0;font-weight:400">${esc(top.last_day)}</span></h3>
    <div class="grid cols-2">
      <div>${topTable(top.blocked, "Blocked domain")}</div>
      <div>${topTable(top.clients, "Client", true)}</div>
    </div>`;
  historyChart($("canvas", card), hist, { compact: true });
}

function eventsList(events) {
  if (!events.length) return `<p class="empty">Nothing yet</p>`;
  const icon = { alert: "bad", recovered: "ok", sync: "warn", action: "unknown", info: "unknown" };
  return `<ul class="events">${events.map((e) => `
    <li><time>${fmt.dateTime(e.ts)}</time><span><span class="dot ${icon[e.kind] || "unknown"}"></span> ${esc(e.message)}</span></li>`).join("")}</ul>`;
}

// ---------- history ----------------------------------------------------------------

// The x axis both history charts share: ticks on whole local hours (24h) or local
// midnights (7d) instead of wherever the data happens to start.
function timeAxis(hist, compact = false) {
  const daily = hist.step >= 86400;
  const tickHours = hist.range === "24h" ? (compact ? 4 : 3) : hist.range === "7d" ? 24 : null;
  const now = Date.now();
  const bounds = hist.range === "24h" ? { min: now - 86400000, max: now } : {};
  const alignedTicks = (axis) => {
    const t = new Date(axis.min);
    t.setMinutes(0, 0, 0);
    if (tickHours === 24) t.setHours(0);
    else t.setHours(Math.ceil(t.getHours() / tickHours) * tickHours);
    const ticks = [];
    for (; t.getTime() <= axis.max; t.setHours(t.getHours() + tickHours)) if (t.getTime() >= axis.min) ticks.push({ value: t.getTime() });
    axis.ticks = ticks;
  };
  const tickFmt = (v) => {
    const d = new Date(v);
    return daily || hist.range === "30d" ? d.toLocaleDateString("en-GB", { day: "numeric", month: "short" })
      : hist.range === "7d" ? d.toLocaleDateString("en-GB", { weekday: "short", day: "numeric" })
      : d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  };
  return {
    type: "linear", ...bounds,
    ...(tickHours ? { afterBuildTicks: alignedTicks } : {}),
    ticks: { callback: tickFmt, color: css("--muted"), maxRotation: 0, ...(tickHours ? { autoSkip: false } : { maxTicksLimit: compact ? 6 : 10 }) },
    grid: { color: css("--line") },
  };
}

function bucketTitle(hist, x) {
  const d = new Date(x);
  if (hist.step >= 86400) return d.toLocaleDateString("en-GB", { weekday: "short", day: "numeric", month: "short", year: "numeric" });
  const end = new Date(d.getTime() + hist.step * 1000).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  return `${d.toLocaleString("en-GB", { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })}–${end}`;
}

function latencyChart(canvas, hist) {
  if (typeof Chart === "undefined") return;
  const datasets = [];
  for (const p of hist.piholes) {
    const color = colorFor(p.id);
    const name = byId(p.id)?.name || p.id;
    datasets.push({ label: `${name} – DNS check`, data: p.latency.map((x) => ({ x: x.t * 1000, y: x.dns_ms })), borderColor: color, borderWidth: 1.6, pointRadius: 0, tension: 0.25, spanGaps: false });
    datasets.push({ label: `${name} – new names`, data: p.latency.map((x) => ({ x: x.t * 1000, y: x.rec_ms })), borderColor: color, borderDash: [4, 3], borderWidth: 1.4, pointRadius: p.latency.length < 60 ? 2 : 0, tension: 0.25, spanGaps: true });
  }
  const grid = css("--line"), text = css("--muted");
  state.charts.push(new Chart(canvas, {
    type: "line",
    data: { datasets },
    options: {
      animation: false,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        x: timeAxis(hist),
        y: { beginAtZero: true, ticks: { color: text, maxTicksLimit: 6, callback: (v) => `${v} ms` }, grid: { color: grid } },
      },
      plugins: {
        legend: { labels: { color: text, boxWidth: 14 } },
        tooltip: { callbacks: { title: (items) => bucketTitle(hist, items[0].parsed.x), label: (item) => ` ${item.dataset.label}: ${item.parsed.y} ms` } },
      },
    },
  }));
}

function historyChart(canvas, hist, { compact = false } = {}) {
  if (typeof Chart === "undefined") {
    canvas.parentElement.innerHTML = `<p class="empty">Chart library missing (static/vendor/chart.umd.min.js)</p>`;
    return;
  }
  const datasets = [];
  for (const p of hist.piholes) {
    const color = colorFor(p.id);
    const name = byId(p.id)?.name || p.id;
    datasets.push({ label: `${name} – queries`, kind: "total", data: p.points.map((x) => ({ x: x.t * 1000, y: x.total })), borderColor: color, backgroundColor: color + "22", fill: !compact, borderWidth: 1.6, pointRadius: 0, tension: 0.25 });
    datasets.push({ label: `${name} – blocked`, kind: "blocked", data: p.points.map((x) => ({ x: x.t * 1000, y: x.blocked })), borderColor: color, borderDash: [4, 3], borderWidth: 1.4, pointRadius: 0, tension: 0.25 });
  }
  const grid = css("--line"), text = css("--muted");
  const chart = new Chart(canvas, {
    type: "line",
    data: { datasets },
    options: {
      animation: false,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        x: timeAxis(hist, compact),
        y: { beginAtZero: true, ticks: { color: text, maxTicksLimit: compact ? 5 : 8, callback: (v) => fmt.num(v) }, grid: { color: grid } },
      },
      plugins: {
        legend: { display: !compact, labels: { color: text, boxWidth: 14 } },
        tooltip: {
          callbacks: {
            title: (items) => bucketTitle(hist, items[0].parsed.x),
            label: (item) => ` ${item.dataset.label}: ${fmt.num(item.parsed.y)}`,
            footer: (items) => {
              const sum = (kind) => items.filter((i) => i.dataset.kind === kind).reduce((a, i) => a + i.parsed.y, 0);
              const total = sum("total");
              return total ? `${fmt.pct((100 * sum("blocked")) / total)} blocked` : "";
            },
          },
        },
      },
    },
  });
  state.charts.push(chart);
}

function seg(name, options, current) {
  return `<div class="seg" data-seg="${name}">${options.map(([v, l]) => `<button data-v="${esc(v)}" class="${String(v) === String(current) ? "active" : ""}">${esc(l)}</button>`).join("")}</div>`;
}

function topTable(rows, label, showLabel = false) {
  if (!rows.length) return `<p class="empty">No data yet</p>`;
  const max = rows[0].count || 1;
  return `<table><thead><tr><th>${label}</th><th class="num">Queries</th></tr></thead><tbody>${rows.map((r) => `
    <tr><td class="break">${esc(r.item)}${showLabel && r.label ? ` <span class="muted">${esc(r.label)}</span>` : ""}
      <div style="height:3px;background:var(--accent);opacity:.35;border-radius:2px;margin-top:3px;width:${(100 * r.count) / max}%"></div></td>
    <td class="num">${fmt.num(r.count)}</td></tr>`).join("")}</tbody></table>`;
}

async function history(el) {
  const ranges = [["24h", "24 hours"], ["7d", "7 days"], ["30d", "30 days"], ["1y", "1 year"], ["all", "All"]];
  const pihOptions = [["", "Both"], ...piholes().map((p) => [p.id, p.name])];
  const [hist, top] = await Promise.all([
    api(`/api/history?range=${state.historyRange}`),
    api(`/api/top?days=${state.topDays}${state.topPihole ? `&pihole=${encodeURIComponent(state.topPihole)}` : ""}`),
  ]);
  el.innerHTML = `
    <section class="card">
      <div class="card-head"><h2>Queries and blocked</h2><div class="right">${seg("range", ranges, state.historyRange)}</div></div>
      <div class="chart-box"><canvas id="hist"></canvas></div>
      <p class="small muted" style="margin:8px 0 0">Solid lines are all queries, dashed lines are blocked queries, in ${hist.step >= 86400 ? "daily" : hist.step >= 3600 ? `${hist.step / 3600}-hour` : "10-minute"} totals.</p>
    </section>
    <section class="card">
      <div class="card-head"><h2>DNS reply time</h2></div>
      ${hist.piholes.some((p) => p.latency.length) ? `<div class="chart-box"><canvas id="latency"></canvas></div>
      <p class="small muted" style="margin:8px 0 0">Average reply time of twinhole's own checks. Solid lines are the regular DNS check (usually answered from cache), dashed lines are lookups of new names, which go through the resolver behind each Pi-hole.</p>`
      : `<p class="empty">No checks recorded yet. Reply times appear here once twinhole has been running a while.</p>`}
    </section>
    <section class="card">
      <div class="card-head"><h2>Top lists</h2>
        <span class="muted small">${esc(top.first_day)} to ${esc(top.last_day)}</span>
        <div class="right">${seg("topPihole", pihOptions, state.topPihole)} ${seg("topDays", [[1, "Yesterday"], [7, "7 days"], [30, "30 days"], [365, "1 year"]], state.topDays)}</div>
      </div>
      <div class="grid cols-3">
        <div><h3>Domains</h3>${topTable(top.domains, "Domain")}</div>
        <div><h3>Blocked domains</h3>${topTable(top.blocked, "Domain")}</div>
        <div><h3>Clients</h3>${topTable(top.clients, "Client", true)}</div>
      </div>
    </section>`;
  historyChart($("#hist"), hist);
  if ($("#latency")) latencyChart($("#latency"), hist);
  el.onclick = (e) => {
    const b = e.target.closest("[data-seg] button");
    if (!b) return;
    const name = b.closest("[data-seg]").dataset.seg;
    if (name === "range") state.historyRange = b.dataset.v;
    if (name === "topDays") state.topDays = Number(b.dataset.v);
    if (name === "topPihole") state.topPihole = b.dataset.v;
    go();
  };
}

// ---------- query log --------------------------------------------------------------

// #queries?client=ip1,ip2&name=Phone narrows the log to one device's addresses
function hashParams() {
  const h = location.hash;
  return new URLSearchParams(h.includes("?") ? h.slice(h.indexOf("?") + 1) : "");
}

async function queries(el) {
  const f = state.queryFilter;
  const params = hashParams();
  const clients = (params.get("client") || "").split(",").filter(Boolean);
  const device = params.get("name") || clients[0];
  el.innerHTML = `
    <section class="card">
      <div class="card-head"><h2>Query log</h2><span class="muted small" id="qcount"></span>
        <div class="right">
          ${clients.length ? `<span class="pill main" title="${esc(clients.join("\n"))}">Device: ${esc(device)} <a href="#queries" class="clear" title="Show all devices">×</a></span>` : ""}
          <input type="search" id="qtext" placeholder="Filter domain or client" value="${esc(f.text)}">
          <select id="qstatus"><option value="all">All</option><option value="blocked">Blocked</option><option value="allowed">Allowed</option></select>
          <select id="qpihole"><option value="">Both Pi-holes</option>${piholes().map((p) => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join("")}</select>
          <button class="btn" id="qreload">Reload</button>
        </div>
      </div>
      <div id="qerrors"></div>
      <div class="table-wrap" id="qtable"><p class="empty">Loading…</p></div>
    </section>`;
  $("#qstatus").value = f.status;
  $("#qpihole").value = f.pihole;
  const load = async () => {
    state.queries = await api("/api/queries" + (clients.length ? "?" + clients.map((c) => `client=${encodeURIComponent(c)}`).join("&") : ""));
    $("#qerrors").innerHTML = state.queries.errors.map((e) => `<div class="banner warn">${esc(e)}</div>`).join("");
    draw();
  };
  const draw = () => {
    const text = f.text.toLowerCase();
    const rows = (state.queries?.queries || []).filter((q) => {
      const blocked = BLOCKED.has(q.status);
      if (f.status === "blocked" && !blocked) return false;
      if (f.status === "allowed" && blocked) return false;
      if (f.pihole && q.pihole !== f.pihole) return false;
      return !text || (q.domain || "").toLowerCase().includes(text) || (q.client || "").includes(text) || (q.client_name || "").toLowerCase().includes(text);
    });
    $("#qcount").textContent = `${rows.length} of ${state.queries?.queries.length || 0} recent queries${clients.length ? ` from ${device}` : ""}`;
    if (!rows.length) { $("#qtable").innerHTML = `<p class="empty">No matching queries</p>`; return; }
    const off = writesOff() ? "disabled title='Read-only mode'" : "";
    $("#qtable").innerHTML = `<table><thead><tr><th>Time</th><th>Pi-hole</th><th>Client</th><th>Domain</th><th>Type</th><th>Status</th><th class="num">Reply</th><th></th></tr></thead><tbody>${rows.map((q) => {
      const blocked = BLOCKED.has(q.status);
      return `<tr>
        <td class="mono">${fmt.time(q.time)}</td><td>${chip(q.pihole)}</td>
        <td>${esc(q.client_name || q.client)}${q.client_name ? `<div class="muted small mono">${esc(q.client)}</div>` : ""}</td>
        <td class="break">${esc(q.domain)}</td><td class="mono">${esc(q.type)}</td>
        <td><span class="pill ${blocked ? "bad" : "ok"}">${esc((q.status || "").toLowerCase().replace(/_/g, " "))}</span></td>
        <td class="num mono">${q.reply_ms} ms</td>
        <td class="actions"><button class="btn small" ${off} data-qact="${blocked ? "allow" : "deny"}" data-domain="${esc(q.domain)}">${blocked ? "Allow" : "Block"}</button></td>
      </tr>`;
    }).join("")}</tbody></table>`;
  };
  $("#qtext").oninput = (e) => { f.text = e.target.value; draw(); };
  $("#qstatus").onchange = (e) => { f.status = e.target.value; draw(); };
  $("#qpihole").onchange = (e) => { f.pihole = e.target.value; draw(); };
  $("#qreload").onclick = load;
  $("#qtable").onclick = async (e) => {
    const b = e.target.closest("[data-qact]");
    if (!b) return;
    const type = b.dataset.qact, domain = b.dataset.domain;
    if (!confirm(`${type === "deny" ? "Block" : "Allow"} ${domain} on both Pi-holes?`)) return;
    await edit({ resource: "domains", action: "add", key: [type, "exact", domain], comment: "Added from the twinhole query log" });
  };
  await load();
}

// ---------- devices ------------------------------------------------------------------

function deviceGroups(d) {
  const exact = d.clients.find((c) => c.exact);
  if (exact) return `${esc(exact.groups.join(", ") || "none")}<div class="muted small mono">${esc(exact.client)}</div>`;
  const subnet = d.clients.find((c) => !c.exact);
  if (subnet) return `${esc(subnet.groups.join(", "))}<div class="muted small">via ${esc(subnet.client)}</div>`;
  return `<span class="muted">Default</span>`;
}

function deviceEditor(d, groups, pis) {
  const exact = d.clients.find((c) => c.exact);
  const ids = exact ? [[exact.client, exact.client]] : [
    ...(d.mac ? [[d.mac, `MAC ${d.mac} (recommended)`]] : []),
    ...d.ips.filter((ip) => !ip.includes(":")).map((ip) => [ip, `IP ${ip}`]),
    ...d.ips.filter((ip) => ip.includes(":") && !ip.startsWith("fe80")).slice(0, 3).map((ip) => [ip, `IP ${ip}`]),
  ];
  const selected = exact ? exact.groups : ["Default"];
  const onlyDefault = groups.length <= 1;
  return `<tr class="editor"><td colspan="${6 + pis.length}">
    <form class="inline" data-device="${esc(d.id)}" data-existing="${exact ? esc(exact.client) : ""}">
      <label>Identify by<select name="ident" ${exact ? "disabled" : ""}>${ids.map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join("")}</select></label>
      <label class="grow">Comment<input type="text" name="comment" value="${esc(exact ? exact.comment : d.name || d.vendor || "")}"></label>
      <label>Groups${groupChecks(groups, selected)}</label>
      <button class="btn primary" type="submit">${exact ? "Save" : "Assign"}</button>
      ${exact ? `<button class="btn danger" type="button" data-remove>Remove entry</button>` : ""}
      <button class="btn" type="button" data-cancel>Cancel</button>
    </form>
    <p class="small muted" style="margin:8px 0 0">${onlyDefault
      ? `You only have the Default group, which every device is already in. Create a group on <a href="#manage" data-gotab="groups">Manage → Groups</a> first, then assign devices to it.`
      : `Saved to both Pi-holes. Pi-hole only recognises a device by MAC when it's on the same network segment; use an IP if it isn't.`}</p>
  </td></tr>`;
}

async function devices(el) {
  const f = state.deviceFilter;
  el.innerHTML = `<section class="card"><p class="empty">Reading both Pi-holes' device lists…</p></section>`;
  const data = await api("/api/devices");
  const pis = data.piholes;
  const piholeIps = new Set(pis.map((p) => p.id));
  let editing = null;

  const draw = () => {
    const text = f.text.toLowerCase();
    const rows = data.devices.filter((d) => {
      if (f.scope === "active" && !d.active) return false;
      if (f.unnamed && d.name) return false;
      if (f.oneOnly && !d.only_uses) return false;
      return !text || [d.name, d.vendor, d.mac, ...d.ips].some((v) => (v || "").toLowerCase().includes(text));
    });
    const active = data.devices.filter((d) => d.active);
    const off = writesOff() ? "disabled title='Read-only mode'" : "";
    const nameOf = (id) => pis.find((p) => p.id === id)?.name || id;
    el.innerHTML = `
      ${data.errors.map((e) => `<div class="banner warn">${esc(e)}</div>`).join("")}
      <section class="card">
        <div class="card-head"><h2>Devices</h2>
          <span class="muted small">${active.length} active in the last 7 days · ${data.devices.length} ever seen · ${active.filter((d) => !d.name).length} active without a name · ${active.filter((d) => d.only_uses).length} using only one Pi-hole</span>
          <div class="right">
            <input type="search" id="dtext" placeholder="Name, vendor, MAC or IP" value="${esc(f.text)}">
            ${seg("dscope", [["active", "Active (7 days)"], ["all", "All"]], f.scope)}
            <label class="small"><input type="checkbox" id="dunnamed" ${f.unnamed ? "checked" : ""}> No name</label>
            <label class="small"><input type="checkbox" id="doneonly" ${f.oneOnly ? "checked" : ""}> One Pi-hole only</label>
          </div>
        </div>
        <p class="small muted" style="margin-top:-4px">Every device either Pi-hole has seen, matched up by MAC address. Devices are in the Default group unless you assign them to others.</p>
        ${!rows.length ? `<p class="empty">No matching devices</p>` : `<div class="table-wrap"><table>
          <thead><tr><th>Device</th><th>Vendor</th><th>Address</th><th>Last query</th>
            ${pis.map((p) => `<th class="num">${chip(p.id)}</th>`).join("")}<th>Groups</th><th></th></tr></thead>
          <tbody>${rows.map((d) => {
            const isPihole = d.ips.some((ip) => piholeIps.has(ip));
            const more = d.ips.length > 1 ? ` <span class="muted small" title="${esc(d.ips.slice(1).join("\n"))}">+${d.ips.length - 1}</span>` : "";
            const row = `<tr>
              <td>${d.ips.length
                  ? `<a href="#queries?${new URLSearchParams({ client: d.ips.join(","), name: d.name || d.ips[0] })}" title="Show this device's queries">${d.name ? esc(d.name) : "(no name)"}</a>`
                  : d.name ? esc(d.name) : `<span class="muted">(no name)</span>`}
                ${isPihole ? ` <span class="pill">Pi-hole itself</span>` : ""}
                ${d.only_uses ? ` <span class="pill warn" title="Only ${esc(nameOf(d.only_uses))} has had queries from it in the last 7 days">only ${esc(nameOf(d.only_uses))}</span>` : ""}
                <div class="muted small mono">${esc(d.mac || d.id)}</div></td>
              <td class="small" style="max-width:140px">${esc(d.vendor || "")}</td>
              <td class="mono small" style="max-width:170px"><span style="${(d.ips[0] || "").includes(":") ? "word-break:break-all" : "white-space:nowrap"}">${esc(d.ips[0] || "")}</span>${more}</td>
              <td class="small">${d.last_query ? fmt.ago(d.last_query) : "never"}</td>
              ${pis.map((p) => `<td class="num">${d.queries[p.id] ? fmt.num(d.queries[p.id].count) : `<span class="muted">–</span>`}</td>`).join("")}
              <td class="small">${deviceGroups(d)}</td>
              <td class="actions"><button class="btn small" data-edit="${esc(d.id)}" ${off}>Groups…</button></td>
            </tr>`;
            return row + (editing === d.id ? deviceEditor(d, data.groups, pis) : "");
          }).join("")}</tbody></table></div>`}
      </section>`;
    $("#dtext").oninput = (e) => {
      f.text = e.target.value;
      const pos = e.target.selectionStart;
      draw();
      $("#dtext").focus();
      $("#dtext").setSelectionRange(pos, pos);
    };
    $("#dunnamed").onchange = (e) => { f.unnamed = e.target.checked; draw(); };
    $("#doneonly").onchange = (e) => { f.oneOnly = e.target.checked; draw(); };
    const form = $("form[data-device]");
    if (form) form.onsubmit = save;
  };

  const save = async (e) => {
    e.preventDefault();
    const form = e.target;
    const existing = form.dataset.existing;
    const groups = $$("input[name=groups]:checked", form).map((x) => x.value);
    const body = {
      resource: "clients",
      action: existing ? "update" : "add",
      key: [existing || form.elements.ident.value],
      comment: form.elements.comment.value.trim(),
      groups: groups.length ? groups : ["Default"],
    };
    await edit(body);
    go(); // reload either way: the main Pi-hole may have changed even if the secondary refused
  };

  el.onclick = async (e) => {
    const s = e.target.closest('[data-seg="dscope"] button');
    if (s) { f.scope = s.dataset.v; return draw(); }
    const b = e.target.closest("[data-edit]");
    if (b) { editing = editing === b.dataset.edit ? null : b.dataset.edit; return draw(); }
    if (e.target.closest("[data-cancel]")) { editing = null; return draw(); }
    if (e.target.closest("[data-gotab]")) { state.manageTab = "groups"; return; }
    if (e.target.closest("[data-remove]")) {
      const form = e.target.closest("form");
      if (!confirm(`Remove the client entry ${form.dataset.existing}? The device goes back to the Default group.`)) return;
      if (await edit({ resource: "clients", action: "delete", key: [form.dataset.existing] })) go();
    }
  };
  draw();
}

// ---------- sync -------------------------------------------------------------------

function changeDiff(c) {
  if (c.action !== "update") return "";
  const fields = Object.keys(c.after).filter((k) => !["raw", "id"].includes(k) && JSON.stringify(c.after[k]) !== JSON.stringify(c.before[k]));
  const show = (v) => (Array.isArray(v) ? v.join(", ") || "none" : typeof v === "boolean" ? (v ? "on" : "off") : v === "" ? "(empty)" : v);
  return fields.map((k) => `<div class="diff">${esc(k)}: <del>${esc(show(c.before[k]))}</del> → <ins>${esc(show(c.after[k]))}</ins></div>`).join("");
}

function autoNote(auto) {
  if (!auto?.enabled) return "";
  if (auto.held) return `<div class="banner warn"><b>Auto-sync is waiting for you.</b> It held these changes back because ${esc(auto.held.reason)}. Check them, then press Apply if they're right.</div>`;
  return `<p class="small muted">Auto-sync is on: changes are applied after each background check, except ones that would delete more than ${auto.max_deletes} items, remove an adlist, or copy an empty ${esc(state.status.piholes[0].name)}. Those wait for you.</p>`;
}

async function sync(el) {
  const s = state.status;
  const [m, sec] = s.piholes;
  el.innerHTML = `<section class="card"><p class="empty">Comparing ${esc(m.name)} and ${esc(sec.name)}…</p></section>`;
  let preview;
  try {
    preview = await api("/api/sync/preview", { body: {} });
  } catch (e) {
    preview = { ...(await api("/api/sync")), error: e.message };
  }
  refreshStatus();
  let result = null;
  const draw = () => {
    const changes = preview.changes || [];
    const deletes = changes.filter((c) => c.action === "delete").length;
    const results = result ? `
      <div class="banner ${result.results.every((r) => r.ok) ? "info" : "bad"}">
        <b>Applied ${result.results.filter((r) => r.ok).length} of ${result.results.length} changes.</b>
        ${result.gravity_started ? ` Gravity is rebuilding on ${esc(sec.name)} – follow it on <a href="#actions">Actions</a>.` : ""}
        ${result.results.filter((r) => !r.ok).length ? `<ul>${result.results.filter((r) => !r.ok).map((r) => `<li>${esc(NOUN[r.resource])} ${esc(r.label)}: ${esc(r.error)}</li>`).join("")}</ul>` : ""}
      </div>` : "";
    el.innerHTML = `
      ${results}
      <section class="card">
        <div class="card-head">
          <h2>${esc(m.name)} → ${esc(sec.name)}</h2>
          <span class="muted small">${preview.checked ? `checked ${fmt.ago(preview.checked)}` : "not checked yet"}</span>
          <div class="right">
            <button class="btn" id="check">Check now</button>
            <button class="btn primary" id="apply" ${!changes.length || writesOff() || preview.error ? "disabled" : ""} ${writesOff() ? "title='Read-only mode: set ALLOW_WRITES=true'" : ""}>Apply ${changes.length || ""} change${changes.length === 1 ? "" : "s"}</button>
          </div>
        </div>
        <p class="small muted" style="margin-top:-4px">One-way sync of groups, domains, adlists, clients, local DNS and CNAME records. ${esc(sec.name)} is made an exact mirror, so anything only it has is deleted.${writesOff() ? " <b>Read-only mode:</b> you can preview, but Apply is off until ALLOW_WRITES=true." : ""}</p>
        ${autoNote(preview.auto)}
        ${preview.error ? `<div class="banner bad">Couldn't compare: ${esc(preview.error)}</div>` : ""}
        ${!preview.checked ? `<p class="empty">Press “Check now” to compare the two Pi-holes.</p>`
          : !changes.length ? `<p class="empty"><span class="dot ok"></span> Both Pi-holes match.</p>`
          : `<p><b>${esc(preview.summary)}</b>${deletes ? ` <span class="pill bad">${deletes} deletion${deletes > 1 ? "s" : ""} on ${esc(sec.name)}</span>` : ""}</p>
            <div class="table-wrap"><table><thead><tr><th></th><th>What</th><th>Item</th></tr></thead><tbody>
            ${changes.map((c) => `<tr>
              <td class="change-${c.action}" style="font-weight:700;width:90px;white-space:nowrap">${{ add: "+ add", delete: "− delete", update: "~ change" }[c.action]}</td>
              <td style="width:130px">${esc(NOUN[c.resource])}</td>
              <td class="break">${esc(c.label)}${changeDiff(c)}</td></tr>`).join("")}
            </tbody></table></div>`}
      </section>`;
    $("#check").onclick = async () => {
      $("#check").disabled = true;
      $("#check").textContent = "Checking…";
      try { preview = await api("/api/sync/preview", { body: {} }); result = null; } catch (e) { toast(e.message, true); }
      await refreshStatus();
      draw();
    };
    $("#apply").onclick = async () => {
      const warn = deletes ? `\n\nThis deletes ${deletes} item${deletes > 1 ? "s" : ""} from ${sec.name}.` : "";
      if (!confirm(`Apply ${changes.length} change${changes.length > 1 ? "s" : ""} to ${sec.name}?${warn}`)) return;
      $("#apply").disabled = true;
      $("#apply").textContent = "Applying…";
      try {
        result = await api("/api/sync/apply", { body: { plan_id: preview.plan_id } });
        preview = result.after;
      } catch (e) {
        toast(e.message, true);
        try { preview = await api("/api/sync/preview", { body: {} }); } catch {}
      }
      await refreshStatus();
      draw();
    };
  };
  draw();
}

// ---------- manage -----------------------------------------------------------------

const MANAGE_TABS = [["domains", "Domains"], ["lists", "Adlists"], ["hosts", "Local DNS"], ["cnames", "CNAMEs"], ["clients", "Clients"], ["groups", "Groups"]];

async function edit(body) {
  try {
    const r = await api("/api/manage", { body });
    const failed = r.results.filter((x) => !x.ok);
    if (failed.length) toast(failed.map((x) => `${x.name}: ${x.error}`).join(" · "), true);
    else toast(r.gravity_suggested ? "Saved on both Pi-holes. Run gravity (Actions) to download the list." : "Saved on both Pi-holes");
    return !failed.length;
  } catch (e) {
    toast(e.message, true);
    return false;
  }
}

function presence(r) {
  if (r.on_main && r.on_secondary) return r.same ? `<span class="pill ok">both</span>` : `<span class="pill warn" title="Settings differ – the next sync fixes this">differs</span>`;
  return r.on_main ? `<span class="pill warn">main only</span>` : `<span class="pill bad" title="The next sync deletes this">secondary only</span>`;
}

function groupChecks(available, selected = ["Default"]) {
  return `<div class="checks">${available.map((g) => `<label><input type="checkbox" name="groups" value="${esc(g)}" ${selected.includes(g) ? "checked" : ""}> ${esc(g)}</label>`).join("")}</div>`;
}

function manageForm(tab, groups) {
  const off = writesOff() ? "disabled" : "";
  const g = `<label>Groups${groupChecks(groups)}</label>`;
  const forms = {
    domains: `<label class="grow">Domain or regex<input type="text" name="domain" required placeholder="ads.example.com or (\\.|^)example\\.com$"></label>
      <label>Action<select name="type"><option value="deny">Block</option><option value="allow">Allow</option></select></label>
      <label>Kind<select name="kind"><option value="exact">Exact</option><option value="regex">Regex</option></select></label>
      <label>Comment<input type="text" name="comment"></label>${g}`,
    lists: `<label class="grow">List URL<input type="text" name="address" required placeholder="https://…/hosts.txt"></label>
      <label>Type<select name="type"><option value="block">Blocklist</option><option value="allow">Allowlist</option></select></label>
      <label>Comment<input type="text" name="comment"></label>${g}`,
    hosts: `<label>IP address<input type="text" name="ip" required placeholder="192.168.1.50"></label>
      <label class="grow">Host name(s)<input type="text" name="names" required placeholder="nas.lan nas"></label>`,
    cnames: `<label class="grow">Domain<input type="text" name="from" required placeholder="files.lan"></label>
      <label class="grow">Points to<input type="text" name="to" required placeholder="nas.lan"></label>`,
    clients: `<label class="grow">Client (IP, subnet, MAC or host name)<input type="text" name="client" required placeholder="192.168.1.42 or 192.168.1.0/24"></label>
      <label>Comment<input type="text" name="comment"></label>${g}`,
    groups: `<label class="grow">Group name<input type="text" name="name" required></label>
      <label class="grow">Comment<input type="text" name="comment"></label>`,
  };
  return `<form class="inline" id="addform"><fieldset ${off} style="display:contents">${forms[tab]}<button class="btn primary" type="submit">Add to both</button></fieldset></form>`;
}

function formToEdit(tab, form) {
  const v = (n) => (form.elements[n]?.value || "").trim();
  const groups = $$("input[name=groups]:checked", form).map((x) => x.value);
  const base = { resource: tab, action: "add", comment: v("comment"), groups: groups.length ? groups : ["Default"] };
  if (tab === "domains") return { ...base, key: [v("type"), v("kind"), v("domain")] };
  if (tab === "lists") return { ...base, key: [v("type"), v("address")] };
  if (tab === "hosts") return { ...base, key: [`${v("ip")} ${v("names")}`] };
  if (tab === "cnames") return { ...base, key: [`${v("from")},${v("to")}`] };
  if (tab === "clients") return { ...base, key: [v("client")] };
  return { ...base, key: [v("name")] };
}

function manageRows(tab, rows) {
  if (!rows.length) return `<p class="empty">Nothing here yet</p>`;
  const off = writesOff() ? "disabled" : "";
  const toggles = ["domains", "lists", "groups"].includes(tab);
  const head = { domains: "Domain", lists: "Address", hosts: "Record", cnames: "CNAME (domain → target)", clients: "Client", groups: "Group" }[tab];
  return `<div class="table-wrap"><table><thead><tr>
      <th>${head}</th>${tab === "domains" || tab === "lists" ? "<th>Type</th>" : ""}
      ${["hosts", "cnames"].includes(tab) ? "" : "<th>Comment</th>"}${["domains", "lists", "clients"].includes(tab) ? "<th>Groups</th>" : ""}
      ${toggles ? "<th>Enabled</th>" : ""}<th>On</th><th></th></tr></thead><tbody>
    ${rows.map((r, i) => {
      const k = r.key;
      const item = tab === "domains" ? k[2] : tab === "lists" ? k[1] : tab === "cnames" ? k[0].replace(",", " → ") : k[0];
      const type = tab === "domains" ? `<span class="pill ${k[0] === "deny" ? "bad" : "ok"}">${k[0] === "deny" ? "block" : "allow"}</span> <span class="pill">${k[1]}</span>`
        : tab === "lists" ? `<span class="pill ${k[0] === "block" ? "bad" : "ok"}">${k[0]}</span>` : "";
      const isDefault = tab === "groups" && k[0] === "Default";
      return `<tr>
        <td class="break ${tab === "domains" && k[1] === "regex" ? "mono" : ""}">${esc(item)}</td>
        ${type ? `<td>${type}</td>` : ""}
        ${["hosts", "cnames"].includes(tab) ? "" : `<td>${esc(r.comment)}</td>`}
        ${["domains", "lists", "clients"].includes(tab) ? `<td class="small">${esc((r.groups || []).join(", "))}</td>` : ""}
        ${toggles ? `<td><label class="switch"><input type="checkbox" data-toggle="${i}" ${r.enabled ? "checked" : ""} ${off}><span></span></label></td>` : ""}
        <td>${presence(r)}</td>
        <td class="actions">${isDefault ? "" : `<button class="btn small danger" data-del="${i}" ${off}>Delete</button>`}</td>
      </tr>`;
    }).join("")}</tbody></table></div>`;
}

async function manage(el) {
  const tab = state.manageTab;
  el.innerHTML = `<div class="subnav">${seg("mtab", MANAGE_TABS, tab)}</div><section class="card"><p class="empty">Loading…</p></section>`;
  try {
    state.manage = await api("/api/manage");
  } catch (e) {
    el.innerHTML = `<div class="banner bad">Couldn't read the Pi-holes: ${esc(e.message)}</div>`;
    return;
  }
  const rows = state.manage[tab];
  const label = MANAGE_TABS.find(([t]) => t === tab)[1];
  el.innerHTML = `
    <div class="subnav">${seg("mtab", MANAGE_TABS.map(([t, l]) => [t, `${l} (${state.manage[t].length})`]), tab)}</div>
    ${writesOff() ? `<div class="banner info">Read-only mode: editing is off until you set <code>ALLOW_WRITES=true</code> in <code>.env</code> and restart twinhole.</div>` : ""}
    <section class="card"><h2>Add ${esc(NOUN[tab])}</h2>${manageForm(tab, state.manage.groups_available)}
      <p class="small muted" style="margin:10px 0 0">Changes go to the main Pi-hole first, then the same change is made on the secondary.${["hosts", "cnames"].includes(tab) ? " Each local DNS change briefly restarts Pi-hole's DNS (about a second)." : ""}</p></section>
    <section class="card"><div class="card-head"><h2>${esc(label)}</h2><div class="right"><button class="btn" id="mreload">Reload</button></div></div>${manageRows(tab, rows)}</section>`;

  el.onclick = async (e) => {
    const t = e.target.closest('[data-seg="mtab"] button');
    if (t) { state.manageTab = t.dataset.v; return go(); }
    if (e.target.id === "mreload") return go();
    const del = e.target.closest("[data-del]");
    if (del) {
      const r = rows[Number(del.dataset.del)];
      if (!confirm(`Delete ${NOUN[tab]} ${r.label} from both Pi-holes?`)) return;
      del.disabled = true;
      if (await edit({ resource: tab, action: "delete", key: r.key })) go(); else del.disabled = false;
    }
  };
  el.onchange = async (e) => {
    const tg = e.target.closest("[data-toggle]");
    if (!tg) return;
    const r = rows[Number(tg.dataset.toggle)];
    tg.disabled = true;
    const ok = await edit({ resource: tab, action: "update", key: r.key, comment: r.comment || "", groups: r.groups || ["Default"], enabled: tg.checked });
    if (!ok) tg.checked = !tg.checked;
    go();
  };
  $("#addform").onsubmit = async (e) => {
    e.preventDefault();
    const btn = $("#addform button[type=submit]");
    btn.disabled = true;
    if (await edit(formToEdit(tab, e.target))) go(); else btn.disabled = false;
  };
}

// ---------- actions ----------------------------------------------------------------

async function actions(el) {
  const off = writesOff() ? "disabled" : "";
  const targets = [["both", "Both"], ...piholes().map((p) => [p.role, p.name])];
  const draw = async () => {
    const grav = await api("/api/actions/gravity");
    const status = state.status;
    el.innerHTML = `
      ${writesOff() ? `<div class="banner info">Read-only mode: actions are off until you set <code>ALLOW_WRITES=true</code> in <code>.env</code> and restart twinhole.</div>` : ""}
      <div style="margin-bottom:14px;display:flex;gap:10px;align-items:center">Apply to ${seg("target", targets, state.target)}</div>
      <div class="grid cols-2">
        <section class="card">
          <h2>Blocking</h2>
          <dl class="kv" style="margin-top:0">${status.piholes.map((p) => `<dt>${esc(p.name)}</dt><dd>${p.blocking === "enabled" ? `<span class="pill ok">enabled</span>` : `<span class="pill bad">${esc(p.blocking || "unknown")}</span>${p.blocking_timer ? ` <span class="muted">re-enables in ${Math.ceil(p.blocking_timer / 60)} min</span>` : ""}`}</dd>`).join("")}</dl>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:16px">
            <button class="btn" data-block="5" ${off}>Pause 5 min</button>
            <button class="btn" data-block="30" ${off}>Pause 30 min</button>
            <button class="btn" data-block="60" ${off}>Pause 1 hour</button>
            <button class="btn danger" data-block="off" ${off}>Disable</button>
            <button class="btn primary" data-block="on" ${off}>Enable</button>
          </div>
          <p class="small muted">Pauses shorter than 10 minutes don't send an alert.</p>
        </section>
        <section class="card">
          <div class="card-head"><h2>Gravity</h2><div class="right"><button class="btn primary" id="gravrun" ${off}>Update gravity</button></div></div>
          <p class="small muted" style="margin-top:-4px">Downloads all adlists again and rebuilds the block database. It takes a minute or two.</p>
          ${status.piholes.map((p) => {
            const run = grav[p.id];
            const head = !run ? `<span class="muted">Not run from twinhole yet</span>`
              : run.running ? `<span class="pill warn">running</span> since ${fmt.time(run.started)}`
              : run.ok ? `<span class="pill ok">finished</span> ${fmt.dateTime(run.finished)}`
              : `<span class="pill bad">failed</span> ${esc(run.error || "")}`;
            return `<h3 style="margin-top:14px">${esc(p.name)}</h3><div class="small" style="margin-bottom:6px">${head}</div>
              ${run ? `<pre class="log" id="log-${esc(p.id)}">${esc(run.log.join("\n"))}</pre>` : ""}`;
          }).join("")}
        </section>
      </div>`;
    $$(".log").forEach((l) => (l.scrollTop = l.scrollHeight));
    return Object.values(grav).some((r) => r.running);
  };
  const running = await draw();
  el.onclick = async (e) => {
    const t = e.target.closest('[data-seg="target"] button');
    if (t) { state.target = t.dataset.v; return draw(); }
    const b = e.target.closest("[data-block]");
    if (b) {
      const v = b.dataset.block;
      const body = v === "on" ? { target: state.target, enabled: true } : v === "off" ? { target: state.target, enabled: false } : { target: state.target, enabled: false, minutes: Number(v) };
      try {
        const r = await api("/api/actions/blocking", { body });
        const failed = r.results.filter((x) => !x.ok);
        failed.length ? toast(failed.map((x) => x.error).join(" · "), true) : toast("Done");
      } catch (err) { toast(err.message, true); }
      setTimeout(async () => { await refreshStatus(); draw(); }, 800);
    }
    if (e.target.id === "gravrun") {
      try {
        await api("/api/actions/gravity", { body: { target: state.target } });
        toast("Gravity started");
      } catch (err) { toast(err.message, true); }
      poll();
    }
  };
  let polling = null;
  const poll = () => {
    if (polling) return;
    polling = setInterval(async () => {
      if (state.page !== "actions") return;
      if (!(await draw())) { clearInterval(polling); polling = null; refreshStatus(); }
    }, 1500);
    state.timers.push(polling);
  };
  if (running) poll();
}

// ---------- start --------------------------------------------------------------------

(async () => {
  await refreshStatus();
  setInterval(() => { if (state.page !== "overview") refreshStatus(); }, 15000);
  await go();
})();
