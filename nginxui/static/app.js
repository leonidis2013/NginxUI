/* NginxUI web UI - no external dependencies */
"use strict";

const S = { user: null, host: "", version: "", page: "dashboard", timers: [], files: [], cur: null, wiz: null };
const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const ACT = {};   // click actions: data-act="name"
const CHG = {};   // change actions: data-chg="name"

// ------------------------------------------------------------------ api
async function api(path, body) {
  const opt = { credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    opt.method = "POST";
    opt.headers["Content-Type"] = "application/json";
    opt.headers["X-NginxUI"] = "1";
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);
  let data = {};
  try { data = await r.json(); } catch (e) { /* ignore */ }
  if (r.status === 401 && !path.startsWith("/api/login") && !path.startsWith("/api/password")) {
    S.user = null; boot(); throw new Error("Please log in");
  }
  if (!r.ok) { const e = new Error(data.error || `Request failed (${r.status})`); e.data = data; throw e; }
  return data;
}

function toast(msg, bad) {
  const t = document.createElement("div");
  t.className = "toast" + (bad ? " bad" : "");
  t.textContent = msg;
  $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), bad ? 7000 : 3500);
}

function every(ms, fn) { S.timers.push(setInterval(fn, ms)); }
function clearTimers() { S.timers.forEach(clearInterval); S.timers = []; }

const fmtBytes = (n) => { if (n == null) return "-"; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return `${n.toFixed(n < 10 && i ? 1 : 0)} ${u[i]}`; };
const fmtDur = (s) => { const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`; };
const fmtNum = (n) => (n ?? 0).toLocaleString();
const fmtTime = (t) => new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

// ------------------------------------------------------------------ modal
function modal(html, wide) {
  closeModal();
  const bg = document.createElement("div");
  bg.className = "modal-bg"; bg.id = "modal";
  bg.innerHTML = `<div class="modal ${wide ? "wide" : ""}">${html}</div>`;
  bg.addEventListener("mousedown", (e) => { if (e.target === bg) closeModal(); });
  document.body.appendChild(bg);
  return bg.firstChild;
}
function closeModal() { const m = $("#modal"); if (m) m.remove(); }
ACT.closeModal = closeModal;

function confirmBox(title, html, ok = "Continue", danger = false, typeWord = null) {
  return new Promise((res) => {
    const m = modal(`<h2>${esc(title)}</h2><div>${html}</div>
      ${typeWord ? `<label class="f"><span>Type <b>${typeWord}</b> to confirm</span><input type="text" id="cfmTxt" autocomplete="off"></label>` : ""}
      <div class="row" style="justify-content:flex-end;margin-top:16px">
        <button class="btn" id="cfmNo">Cancel</button>
        <button class="btn ${danger ? "danger" : "primary"}" id="cfmYes">${esc(ok)}</button></div>`);
    $("#cfmNo", m).onclick = () => { closeModal(); res(false); };
    $("#cfmYes", m).onclick = () => {
      if (typeWord && $("#cfmTxt", m).value.trim() !== typeWord) { toast(`Type ${typeWord} to confirm`, true); return; }
      closeModal(); res(typeWord ? $("#cfmTxt", m).value.trim() : true);
    };
  });
}

function showApplyError(e, title = "Change not applied") {
  const out = e.data && e.data.test_output;
  if (!out) { toast(e.message, true); return; }
  modal(`<h2>${esc(title)}</h2><p>${esc(e.message)}</p><h3>nginx said</h3>
    <div class="out bad">${esc(out)}</div>
    <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" data-act="closeModal">OK</button></div>`);
}

// ------------------------------------------------------------------ boot / auth
async function boot() {
  clearTimers();
  let s;
  try { s = await (await fetch("/api/session", { credentials: "same-origin" })).json(); }
  catch (e) { $("#root").innerHTML = `<div class="login"><div class="card">Cannot reach NginxUI.</div></div>`; return; }
  S.version = s.version; S.host = s.hostname;
  if (s.setup_needed) return renderSetup();
  if (!s.authenticated) return renderLogin();
  S.user = s.user;
  renderShell();
  route();
}

function renderLogin() {
  $("#root").innerHTML = `<div class="login"><form class="card" id="lf">
    <div class="brand"><div class="logo">NU</div><div><b>NginxUI</b><span>${esc(S.host)}</span></div></div>
    <label class="f"><span>Username</span><input type="text" name="u" autocomplete="username" required></label>
    <label class="f"><span>Password</span><input type="password" name="p" autocomplete="current-password" required></label>
    <div id="lerr" class="small" style="color:#ff8f8f;min-height:18px"></div>
    <button class="btn primary" style="width:100%">Log in</button></form></div>`;
  $("#lf").onsubmit = async (ev) => {
    ev.preventDefault();
    try { await api("/api/login", { username: ev.target.u.value, password: ev.target.p.value }); boot(); }
    catch (e) { $("#lerr").textContent = e.message; }
  };
}

function renderSetup() {
  $("#root").innerHTML = `<div class="login"><form class="card" id="sf">
    <div class="brand"><div class="logo">NU</div><div><b>Welcome to NginxUI</b><span>${esc(S.host)}</span></div></div>
    <p class="muted">Create the admin account for this web UI. This is separate from your Ubuntu login.</p>
    <label class="f"><span>Username</span><input type="text" name="u" value="admin" required></label>
    <label class="f"><span>Password (10+ characters)</span><input type="password" name="p" autocomplete="new-password" required></label>
    <label class="f"><span>Repeat password</span><input type="password" name="p2" autocomplete="new-password" required></label>
    <div id="serr" class="small" style="color:#ff8f8f;min-height:18px"></div>
    <button class="btn primary" style="width:100%">Create account</button></form></div>`;
  $("#sf").onsubmit = async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    if (f.p.value !== f.p2.value) { $("#serr").textContent = "Passwords do not match"; return; }
    try { await api("/api/setup", { username: f.u.value, password: f.p.value }); boot(); }
    catch (e) { $("#serr").textContent = e.message; }
  };
}

const PAGES = [
  ["dashboard", "Dashboard", "◉"], ["configs", "Configs", "≣"], ["wizards", "Wizards", "✦"],
  ["flow", "Traffic Flow", "⇄"], ["stats", "Stats", "▤"], ["logs", "Logs", "☰"],
  ["updates", "Updates", "⟳"], ["backups", "Backups", "⛁"], ["settings", "Settings", "⚙"],
];

function renderShell() {
  $("#root").innerHTML = `<div class="app">
    <aside class="side" id="side">
      <div class="brand"><div class="logo">NU</div><div><b>NginxUI</b><span>${esc(S.host)}</span></div></div>
      <nav class="nav">${PAGES.map(([k, l, i]) => `<a href="#/${k}" data-nav="${k}"><span class="ico">${i}</span>${l}<span class="badge hidden" id="nb-${k}"></span></a>`).join("")}</nav>
      <div class="foot">Signed in as <b>${esc(S.user)}</b><br><a href="#" data-act="logout">Log out</a> · v${esc(S.version)}</div>
    </aside>
    <main class="main"><div class="topbar"><button class="btn menu-btn" data-act="menu">☰</button><h1 id="ptitle" class="grow"></h1><div id="pactions" class="row"></div></div>
    <div id="page"></div></main></div>`;
}
ACT.menu = () => $("#side").classList.toggle("open");
ACT.logout = async (el, ev) => { ev.preventDefault(); await api("/api/logout", {}); S.user = null; boot(); };

window.addEventListener("hashchange", () => { if (S.user) route(); });

function route() {
  clearTimers(); closeModal();
  const parts = location.hash.replace(/^#\/?/, "").split("/");
  const page = PAGES.find((p) => p[0] === parts[0]) ? parts[0] : "dashboard";
  S.page = page;
  $$("[data-nav]").forEach((a) => a.classList.toggle("active", a.dataset.nav === page));
  $("#side").classList.remove("open");
  $("#ptitle").textContent = PAGES.find((p) => p[0] === page)[1];
  $("#pactions").innerHTML = "";
  $("#page").innerHTML = `<div class="empty">Loading…</div>`;
  const fn = { dashboard: pgDashboard, configs: pgConfigs, wizards: pgWizards, flow: pgFlow, stats: pgStats, logs: pgLogs, updates: pgUpdates, backups: pgBackups, settings: pgSettings }[page];
  fn(decodeURIComponent(parts.slice(1).join("/"))).catch((e) => { $("#page").innerHTML = `<div class="banner bad">${esc(e.message)}</div>`; });
}

document.addEventListener("click", (ev) => {
  const el = ev.target.closest("[data-act]");
  if (el && ACT[el.dataset.act]) {
    if (el.tagName === "A" && el.getAttribute("href") === "#") ev.preventDefault();
    ACT[el.dataset.act](el, ev);
  }
});
document.addEventListener("change", (ev) => {
  const el = ev.target.closest("[data-chg]");
  if (el && CHG[el.dataset.chg]) CHG[el.dataset.chg](el, ev);
});

// ------------------------------------------------------------------ charts
function barChart(timeline, h = 180) {
  const W = 640, H = h, pl = 34, pb = 20, pt = 8;
  const n = timeline.length || 1;
  const max = Math.max(1, ...timeline.map((b) => b.total));
  const bw = (W - pl - 4) / n;
  let bars = "";
  timeline.forEach((b, i) => {
    const x = pl + i * bw + 0.5, scale = (H - pb - pt) / max;
    const h5 = b.c5 * scale, h4 = b.c4 * scale, h2 = (b.total - b.c4 - b.c5) * scale;
    let y = H - pb;
    if (h2 > 0) { y -= h2; bars += `<rect class="bar" x="${x}" y="${y}" width="${Math.max(bw - 1, 1)}" height="${h2}"><title>${fmtTime(b.t)} · ${b.total} requests</title></rect>`; }
    if (h4 > 0) { y -= h4; bars += `<rect class="bar4" x="${x}" y="${y}" width="${Math.max(bw - 1, 1)}" height="${h4}"><title>${b.c4} client errors (4xx)</title></rect>`; }
    if (h5 > 0) { y -= h5; bars += `<rect class="bar5" x="${x}" y="${y}" width="${Math.max(bw - 1, 1)}" height="${h5}"><title>${b.c5} server errors (5xx)</title></rect>`; }
  });
  const gl = [0, 0.5, 1].map((f) => { const y = H - pb - f * (H - pb - pt); return `<line x1="${pl}" x2="${W}" y1="${y}" y2="${y}"/>`; }).join("");
  const yl = [0, 0.5, 1].map((f) => { const y = H - pb - f * (H - pb - pt); return `<text class="axis" x="${pl - 6}" y="${y + 3}" text-anchor="end">${Math.round(max * f)}</text>`; }).join("");
  const xl = timeline.length ? [0, Math.floor(n / 2), n - 1].map((i) => `<text class="axis" x="${pl + i * bw + bw / 2}" y="${H - 5}" text-anchor="middle">${fmtTime(timeline[i].t)}</text>`).join("") : "";
  return `<div class="chart"><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none"><g class="grid">${gl}</g>${bars}${yl}${xl}</svg></div>`;
}

function hbars(rows, total) {
  if (!rows.length) return `<div class="muted small">No data in this window</div>`;
  const max = Math.max(...rows.map((r) => r[1]));
  return rows.map(([k, v]) => `<div style="margin-bottom:8px"><div class="row between small"><span class="mono" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:75%">${esc(k)}</span><span>${fmtNum(v)}</span></div><div class="hbar"><i style="width:${(v / max * 100).toFixed(1)}%"></i></div></div>`).join("");
}

// ------------------------------------------------------------------ dashboard
async function pgDashboard() {
  const load = async () => {
    const d = await api("/api/overview");
    if (S.page !== "dashboard") return;
    const sy = d.system, ng = d.nginx, tr = d.traffic;
    const c4 = tr.classes["4xx"] || 0, c5 = tr.classes["5xx"] || 0;
    let banners = d.env.warnings.map((w) => `<div class="banner warn">${esc(w)}</div>`).join("");
    if (!ng.active) banners += `<div class="banner bad row between"><span><b>nginx is not running.</b> Websites behind this proxy are down.</span><button class="btn" data-act="startNginx">Start nginx</button></div>`;
    if (!ng.test_ok) banners += `<div class="banner bad"><b>The current nginx config has errors.</b> nginx will refuse to reload until they are fixed.<div class="out bad" style="margin-top:8px">${esc(ng.test_output)}</div></div>`;
    if (sy.reboot_required) banners += `<div class="banner warn row between"><span><b>Reboot required</b> to finish installing updates.</span><a class="btn" href="#/updates">Go to Updates</a></div>`;
    const memPct = sy.mem_total ? (1 - sy.mem_avail / sy.mem_total) * 100 : 0;
    const diskPct = sy.disk_total ? sy.disk_used / sy.disk_total * 100 : 0;
    $("#page").innerHTML = `${banners}
    <div class="grid g4">
      <div class="card stat"><div class="l">nginx</div><div class="v"><span class="dot ${ng.active ? "good" : "bad"}"></span>${ng.active ? "Running" : "Stopped"}</div><div class="s">${esc(sy.nginx_version || "not found")} · config ${ng.test_ok ? "OK" : "<b style='color:#ff8f8f'>errors</b>"}</div></div>
      <div class="card stat"><div class="l">Sites</div><div class="v">${d.sites_enabled}<span class="muted" style="font-size:15px"> / ${d.sites_total}</span></div><div class="s">enabled / total config files</div></div>
      <div class="card stat"><div class="l">Requests · last hour</div><div class="v">${fmtNum(tr.total)}</div><div class="s">${tr.rpm}/min · ${fmtBytes(tr.bytes)} sent</div></div>
      <div class="card stat"><div class="l">Errors · last hour</div><div class="v"><span style="color:${c5 ? "var(--bad)" : "inherit"}">${fmtNum(c5)}</span> <span class="muted" style="font-size:15px">5xx</span></div><div class="s">${fmtNum(c4)} client errors (4xx)</div></div>
    </div><div class="spacer"></div>
    <div class="grid g3">
      <div class="card span2"><div class="row between"><h3>Traffic · last 60 minutes</h3><a class="small" href="#/stats">Details →</a></div>${barChart(tr.timeline)}
        <div class="row small muted"><span><span class="dot" style="background:var(--accent2)"></span>OK</span><span><span class="dot warn"></span>4xx</span><span><span class="dot bad"></span>5xx</span></div></div>
      <div class="card"><h3>Live</h3>${d.live.enabled ? `<div class="stat"><div class="v">${d.live.active}</div><div class="s">open connections</div></div>
        <div class="kv small" style="margin-top:10px"><dt>Reading</dt><dd>${d.live.reading}</dd><dt>Writing</dt><dd>${d.live.writing}</dd><dt>Idle keep-alive</dt><dd>${d.live.waiting}</dd><dt>Total requests</dt><dd>${fmtNum(d.live.requests)}</dd></div>`
        : `<p class="muted small">Live connection counts are off. Turning them on adds a small status page that only this server can reach.</p><button class="btn" data-act="enableLive">Turn on live stats</button>`}
        <div class="spacer"></div><h3>Updates</h3>
        ${d.updates.checked ? `<div>${d.updates.count ? `<b>${d.updates.count}</b> available` : "Up to date"} ${d.updates.security ? `<span class="badge bad">${d.updates.security} security</span>` : ""} ${d.updates.nginx ? `<span class="badge info">nginx</span>` : ""}</div><div class="small muted">checked ${esc(d.updates.checked)}</div>` : `<div class="muted small">Not checked yet</div>`}
        <a class="btn sm" style="margin-top:8px;display:inline-block;text-decoration:none" href="#/updates">Open Updates</a>
      </div>
    </div><div class="spacer"></div>
    <div class="grid g2">
      <div class="card"><h3>Server</h3><dl class="kv"><dt>Host</dt><dd>${esc(sy.hostname)}</dd><dt>OS</dt><dd>${esc(sy.os)}</dd><dt>Kernel</dt><dd>${esc(sy.kernel)}</dd>
        <dt>Uptime</dt><dd>${fmtDur(sy.uptime_s)}</dd><dt>Load</dt><dd>${sy.load.join(" · ")} <span class="muted small">(${sy.cpus} CPU)</span></dd></dl>
        <div class="small" style="margin-top:12px">Memory ${fmtBytes(sy.mem_total - sy.mem_avail)} / ${fmtBytes(sy.mem_total)}<div class="meter"><i style="width:${memPct.toFixed(0)}%"></i></div></div>
        <div class="small" style="margin-top:10px">Disk ${fmtBytes(sy.disk_used)} / ${fmtBytes(sy.disk_total)}<div class="meter"><i style="width:${diskPct.toFixed(0)}%;${diskPct > 90 ? "background:var(--bad)" : ""}"></i></div></div></div>
      <div class="card"><h3>Recent activity</h3>${d.activity.length ? `<table>${d.activity.map((a) => `<tr><td class="small muted" style="white-space:nowrap">${esc(a.t.slice(5, 16))}</td><td><span class="dot ${a.ok ? "good" : "bad"}"></span>${esc(a.action)}</td><td class="small">${esc(a.target)}</td><td class="small muted">${esc(a.user)}</td></tr>`).join("")}</table>` : `<div class="empty">Nothing yet</div>`}</div>
    </div>`;
    setBadge("updates", d.updates.security ? d.updates.security : (sy.reboot_required ? "!" : ""), d.updates.security ? "bad" : "warn");
  };
  $("#pactions").innerHTML = `<button class="btn" data-act="testConfig">Test config</button><button class="btn" data-act="reloadNginx">Reload nginx</button>`;
  await load();
  every(15000, () => load().catch(() => {}));
}
function setBadge(page, txt, cls) { const b = $(`#nb-${page}`); if (!b) return; b.textContent = txt; b.className = `badge ${cls || ""} ${txt ? "" : "hidden"}`; }

ACT.startNginx = async () => { try { await api("/api/nginx/start", {}); toast("nginx started"); route(); } catch (e) { showApplyError(e, "nginx did not start"); } };
ACT.testConfig = async () => {
  const r = await api("/api/nginx/test", {});
  modal(`<h2>Config test ${r.ok ? "passed" : "failed"}</h2><div class="out ${r.ok ? "good" : "bad"}">${esc(r.output)}</div><div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" data-act="closeModal">Close</button></div>`);
};
ACT.reloadNginx = async () => { try { await api("/api/nginx/reload", {}); toast("nginx reloaded"); } catch (e) { showApplyError(e, "Reload failed"); } };
ACT.enableLive = async () => {
  const ok = await confirmBox("Turn on live stats", `<p>NginxUI will add <span class="mono">conf.d/nginxui-status.conf</span>, a tiny status page on <span class="mono">127.0.0.1</span> that nothing outside this server can reach. The config is tested before it goes live.</p>`, "Turn on");
  if (!ok) return;
  try { await api("/api/live/enable", {}); toast("Live stats on"); route(); } catch (e) { showApplyError(e); }
};

// ------------------------------------------------------------------ configs
const GROUP_ORDER = [["sites", "Sites"], ["enabled", "Sites (enabled folder only)"], ["conf", "conf.d"], ["snippets", "Snippets"], ["main", "Main config"]];

async function pgConfigs(arg) {
  $("#pactions").innerHTML = `<button class="btn" data-act="newFile">+ New file</button><button class="btn" data-act="testConfig">Test config</button><a class="btn primary" href="#/wizards" style="text-decoration:none">Use a wizard</a>`;
  const [fl, del] = await Promise.all([api("/api/files"), api("/api/deleted")]);
  S.files = fl.files;
  const sel = arg || (S.cur && S.cur.id) || (S.files[0] && S.files[0].id);
  $("#page").innerHTML = `<div class="split"><div class="flist card tight" id="flist"></div><div id="fedit"></div></div>`;
  renderFileList(del.deleted);
  if (sel && S.files.find((f) => f.id === sel)) openFile(sel); else $("#fedit").innerHTML = `<div class="card empty">Pick a file on the left, or create a site with a wizard.</div>`;
}

function renderFileList(deleted) {
  let html = "";
  for (const [g, label] of GROUP_ORDER) {
    const fs = S.files.filter((f) => f.group === g);
    if (!fs.length) continue;
    html += `<div class="grp">${label}</div>`;
    html += fs.map((f) => `<div class="fitem ${S.cur && S.cur.id === f.id ? "sel" : ""}" data-act="openFile" data-id="${esc(f.id)}">
      <span class="dot ${f.enabled === null ? "" : f.enabled ? "good" : ""}"></span>
      <span class="n">${esc(f.name)}</span>${f.managed ? `<span class="badge info" title="Created by a NginxUI wizard">wizard</span>` : ""}
      ${f.enabled !== null && g !== "enabled" ? `<label class="toggle" title="${f.enabled ? "Enabled" : "Disabled"}" data-act="noop"><input type="checkbox" data-chg="toggleFile" data-id="${esc(f.id)}" ${f.enabled ? "checked" : ""}><span></span></label>` : ""}</div>`).join("");
  }
  if (!S.files.length) html += `<div class="empty">No config files found.</div>`;
  if (deleted && deleted.length) {
    html += `<div class="grp">Recently deleted</div>` + deleted.map((d) => `<div class="fitem"><span class="n muted">${esc(d.name)}</span><button class="btn sm" data-act="restoreDeleted" data-id="${esc(d.id)}" data-v="${esc(d.v)}">Restore</button></div>`).join("");
  }
  $("#flist").innerHTML = html;
}
ACT.noop = (el, ev) => ev.stopPropagation();

CHG.toggleFile = async (el) => {
  const id = el.dataset.id, en = el.checked;
  try {
    const r = await api("/api/file/enable", { id, enabled: en });
    toast(`${en ? "Enabled" : "Disabled"} and reloaded`);
    if (S.cur && S.cur.id === id) S.cur.id = r.id;
    pgConfigs(S.cur ? S.cur.id : r.id);
  } catch (e) { el.checked = !en; showApplyError(e); }
};

ACT.restoreDeleted = async (el) => {
  try { await api("/api/history/rollback", { id: el.dataset.id, v: el.dataset.v }); toast("Restored"); pgConfigs(el.dataset.id); }
  catch (e) { showApplyError(e); }
};

ACT.openFile = async (el) => {
  if (S.cur && S.cur.dirty && !(await confirmBox("Discard changes?", "You have unsaved edits in this file.", "Discard", true))) return;
  history.replaceState(null, "", `#/configs/${encodeURIComponent(el.dataset.id)}`);
  openFile(el.dataset.id);
};

async function openFile(id) {
  const f = await api(`/api/file?id=${encodeURIComponent(id)}`);
  S.cur = { id, name: f.name, group: f.group, orig: f.content, dirty: false, errLine: null };
  $$(".fitem").forEach((x) => x.classList.toggle("sel", x.dataset.id === id));
  const info = S.files.find((x) => x.id === id) || {};
  $("#fedit").innerHTML = `<div class="card">
    <div class="row between"><div><h2 style="margin:0">${esc(f.name)}</h2><div class="small muted">${esc(info.group_label || "")} ${info.enabled === false ? "· <b>disabled</b>" : ""}</div></div>
    <div class="row"><button class="btn sm" data-act="showHistory">History (${f.history.length})</button>${f.group !== "main" ? `<button class="btn sm danger" data-act="deleteFile">Delete</button>` : ""}</div></div>
    <div class="spacer"></div>
    <div class="editor"><div class="gut" id="gut"></div><div class="area"><pre id="hl"></pre><textarea id="ta" spellcheck="false" autocapitalize="off" autocomplete="off"></textarea></div></div>
    <div class="spacer"></div>
    <div class="row"><input type="text" id="note" placeholder="What did you change? (optional, shows in history)" style="flex:1;min-width:200px">
      <button class="btn" data-act="discard">Discard</button><button class="btn primary" data-act="saveFile" id="saveBtn">Test &amp; apply</button></div>
    <div class="small muted" style="margin-top:6px">Saving runs <span class="mono">nginx -t</span> first. If the test or reload fails, your previous version is put back automatically.</div>
    <div id="fout" style="margin-top:12px"></div></div>`;
  const ta = $("#ta");
  ta.value = f.content;
  ta.addEventListener("input", () => { S.cur.dirty = ta.value !== S.cur.orig; S.cur.errLine = null; paintEditor(); });
  ta.addEventListener("scroll", syncScroll);
  ta.addEventListener("keydown", (e) => {
    if (e.key === "Tab") { e.preventDefault(); const s = ta.selectionStart; ta.setRangeText("    ", s, ta.selectionEnd, "end"); ta.dispatchEvent(new Event("input")); }
    if ((e.ctrlKey || e.metaKey) && e.key === "s") { e.preventDefault(); ACT.saveFile(); }
  });
  paintEditor();
}

function highlight(text) {
  return text.split("\n").map((line) => {
    let out = "", i = 0, first = true;
    const m = line.match(/^(\s*)/); out += m[1]; i = m[1].length;
    while (i < line.length) {
      const rest = line.slice(i);
      let t;
      if (rest[0] === "#") { out += `<span class="hl-c">${esc(rest)}</span>`; break; }
      if ((t = rest.match(/^("([^"\\]|\\.)*"?|'([^'\\]|\\.)*'?)/))) { out += `<span class="hl-s">${esc(t[0])}</span>`; i += t[0].length; first = false; continue; }
      if ((t = rest.match(/^[{};]/))) { out += `<span class="hl-b">${t[0]}</span>`; i++; if (t[0] !== "}") first = true; continue; }
      if ((t = rest.match(/^\s+/))) { out += t[0]; i += t[0].length; continue; }
      if ((t = rest.match(/^[^\s{};#"']+/))) {
        const w = t[0];
        if (first) out += `<span class="hl-d">${esc(w)}</span>`;
        else out += esc(w).replace(/(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)/g, '<span class="hl-v">$1</span>').replace(/^(\d+[kmgsKMG]?)$/, '<span class="hl-n">$1</span>');
        first = false; i += w.length; continue;
      }
      out += esc(rest[0]); i++;
    }
    return out;
  }).join("\n") + "\n";
}

function paintEditor() {
  const ta = $("#ta"); if (!ta) return;
  $("#hl").innerHTML = highlight(ta.value);
  const n = ta.value.split("\n").length;
  let g = "";
  for (let i = 1; i <= n; i++) g += (i === S.cur.errLine ? `<span class="err">${i}</span>` : i) + "\n";
  $("#gut").innerHTML = g;
  $("#saveBtn").textContent = S.cur.dirty ? "Test & apply •" : "Test & apply";
  syncScroll();
}
function syncScroll() { const ta = $("#ta"); $("#hl").scrollTop = ta.scrollTop; $("#hl").scrollLeft = ta.scrollLeft; $("#gut").scrollTop = ta.scrollTop; }

function markErrorLine(output) {
  const m = (output || "").match(/in (\S+):(\d+)/);
  if (m && S.cur && m[1].split("/").pop() === S.cur.name) {
    S.cur.errLine = parseInt(m[2], 10); paintEditor();
    const ta = $("#ta"); ta.scrollTop = Math.max(0, (S.cur.errLine - 5) * 20);
  }
}

ACT.saveFile = async () => {
  const ta = $("#ta"); if (!ta) return;
  const btn = $("#saveBtn"); btn.disabled = true;
  try {
    const r = await api("/api/file/save", { id: S.cur.id, content: ta.value, note: $("#note").value });
    S.cur.orig = ta.value; S.cur.dirty = false; S.cur.errLine = null; $("#note").value = "";
    $("#fout").innerHTML = `<div class="banner good">Saved, tested and live. <span class="small muted">${esc(r.reload)}</span></div>`;
    toast("Applied"); paintEditor();
  } catch (e) {
    $("#fout").innerHTML = `<div class="banner bad"><b>${esc(e.message)}</b>${e.data && e.data.test_output ? `<div class="out bad" style="margin-top:8px">${esc(e.data.test_output)}</div>` : ""}</div>`;
    markErrorLine(e.data && e.data.test_output);
  } finally { btn.disabled = false; }
};
ACT.discard = () => { $("#ta").value = S.cur.orig; S.cur.dirty = false; S.cur.errLine = null; paintEditor(); $("#fout").innerHTML = ""; };

ACT.deleteFile = async () => {
  if (!(await confirmBox(`Delete ${S.cur.name}?`, `<p>The file is removed and nginx reloads. A copy stays in history, so you can restore it from <b>Recently deleted</b>.</p>`, "Delete", true))) return;
  try { await api("/api/file/delete", { id: S.cur.id }); toast("Deleted"); S.cur = null; history.replaceState(null, "", "#/configs"); pgConfigs(); }
  catch (e) { showApplyError(e); }
};

ACT.newFile = () => {
  const m = modal(`<h2>New config file</h2>
    <label class="f"><span>Where</span><select id="nfG"><option value="sites">Sites (sites-available, can be enabled/disabled)</option><option value="conf">conf.d (always loaded)</option><option value="snippets">Snippets (included from other files)</option></select></label>
    <label class="f"><span>File name</span><input type="text" id="nfN" placeholder="myapp.example.com"></label>
    <label class="check"><input type="checkbox" id="nfE" checked><span>Enable it right away<small>Only for Sites</small></span></label>
    <p class="small muted">Tip: the <a href="#/wizards" data-act="closeModal">wizards</a> write a complete, working config for you.</p>
    <div class="row" style="justify-content:flex-end"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" id="nfOk">Create</button></div>`);
  $("#nfOk", m).onclick = async () => {
    const g = $("#nfG").value, n = $("#nfN").value.trim();
    const tpl = g === "snippets" ? `# ${n}\n` : `# ${n}\nserver {\n    listen 80;\n    server_name example.com;\n\n    location / {\n        return 200 "ok";\n    }\n}\n`;
    try {
      const r = await api("/api/file/create", { group: g, name: n, content: tpl, enable: $("#nfE").checked && g === "sites" });
      closeModal(); toast("Created"); history.replaceState(null, "", `#/configs/${encodeURIComponent(r.id)}`); pgConfigs(r.id);
    } catch (e) { showApplyError(e); }
  };
};

// history + diff
function diffLines(a, b) {
  const A = a.split("\n"), B = b.split("\n");
  if (A.length * B.length > 4e6) return [["gap", "File too large to compare"]];
  const n = A.length, m = B.length, dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out = []; let i = 0, j = 0;
  while (i < n && j < m) {
    if (A[i] === B[j]) { out.push(["same", A[i]]); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) out.push(["del", A[i++]]);
    else out.push(["add", B[j++]]);
  }
  while (i < n) out.push(["del", A[i++]]);
  while (j < m) out.push(["add", B[j++]]);
  // collapse long unchanged runs
  const res = []; let run = [];
  const flush = (end) => {
    if (run.length > 7) { res.push(...run.slice(0, 3).map((x) => ["same", x])); if (!end) res.push(["gap", `… ${run.length - 6} unchanged lines …`]); else res.push(["gap", `… ${run.length - 3} unchanged lines`]); if (!end) res.push(...run.slice(-3).map((x) => ["same", x])); }
    else res.push(...run.map((x) => ["same", x]));
    run = [];
  };
  for (const [t, l] of out) { if (t === "same") run.push(l); else { flush(false); res.push([t, l]); } }
  flush(true);
  return res;
}
function diffHtml(a, b) {
  return `<div class="diff">${diffLines(a, b).map(([t, l]) => `<div class="${t === "same" ? "" : t}">${t === "add" ? "+ " : t === "del" ? "- " : t === "gap" ? "" : "  "}${esc(l)}</div>`).join("")}</div>`;
}

ACT.showHistory = async () => {
  const h = (await api(`/api/history?id=${encodeURIComponent(S.cur.id)}`)).history;
  const m = modal(`<div class="row between"><h2>History · ${esc(S.cur.name)}</h2><button class="btn sm" data-act="closeModal">Close</button></div>
    ${h.length ? `<div class="tablewrap"><table><tr><th>When</th><th>Who</th><th>What</th><th></th></tr>${h.map((v) => `<tr class="click" data-act="viewVersion" data-v="${v.v}"><td class="small" style="white-space:nowrap">${esc(v.t)}</td><td class="small">${esc(v.user)}</td><td class="small">${esc(v.note)} <span class="badge">${esc(v.action)}</span></td><td><button class="btn sm">View</button></td></tr>`).join("")}</table></div>` : `<div class="empty">No history yet. Every save made in NginxUI is kept here, and the original file is saved the first time you edit it.</div>`}
    <div id="hv"></div>`, true);
};
ACT.viewVersion = async (el) => {
  const rec = await api(`/api/history/version?id=${encodeURIComponent(S.cur.id)}&v=${el.dataset.v}`);
  const cur = $("#ta") ? $("#ta").value : "";
  $("#hv").innerHTML = `<div class="spacer"></div><div class="row between"><h3 style="margin:0">Changes from ${esc(rec.t)} → what's in the editor now</h3>
    <div class="row"><button class="btn sm" data-act="loadVersion" data-v="${el.dataset.v}">Load into editor</button><button class="btn sm primary" data-act="rollback" data-v="${el.dataset.v}">Restore this version</button></div></div>
    <div class="small muted" style="margin:6px 0"><span style="color:#ffaaaa">- red</span> = only in that version, <span style="color:#9ff0b8">+ green</span> = only in the current version</div>${diffHtml(rec.content, cur)}`;
  $("#hv").scrollIntoView({ behavior: "smooth" });
};
ACT.loadVersion = async (el) => {
  const rec = await api(`/api/history/version?id=${encodeURIComponent(S.cur.id)}&v=${el.dataset.v}`);
  $("#ta").value = rec.content; S.cur.dirty = rec.content !== S.cur.orig; paintEditor(); closeModal();
  toast("Loaded. Press Test & apply to make it live.");
};
ACT.rollback = async (el) => {
  try { await api("/api/history/rollback", { id: S.cur.id, v: el.dataset.v }); closeModal(); toast("Restored and live"); openFile(S.cur.id); }
  catch (e) { closeModal(); showApplyError(e, "Restore failed"); }
};

// ------------------------------------------------------------------ wizards
const WIZ = {
  proxy: { icon: "⇢", title: "Reverse proxy", desc: "Send a domain to an app on another port or machine (Home Assistant, a NAS, Docker apps…)." },
  loadbalance: { icon: "⇉", title: "Load balancer", desc: "Spread visitors across two or more copies of the same app, skipping ones that are down." },
  static: { icon: "▣", title: "Static website", desc: "Serve files from a folder on this server, including single-page apps." },
  redirect: { icon: "↪", title: "Redirect", desc: "Point an old domain or a typo domain at another address." },
};
const WSTEPS = ["Basics", "HTTPS", "Access & options", "Review"];

async function pgWizards(arg) {
  if (!arg || !WIZ[arg]) {
    S.wiz = null;
    $("#page").innerHTML = `<p class="muted">Pick what you want to set up. Each wizard asks a few questions, shows you the finished config, and only makes it live if nginx accepts it.</p>
      <div class="wcards">${Object.entries(WIZ).map(([k, w]) => `<a class="card wcard" href="#/wizards/${k}" style="text-decoration:none;color:inherit"><div class="big">${w.icon}</div><h2>${w.title}</h2><div class="muted small">${w.desc}</div></a>`).join("")}</div>
      <div class="spacer"></div><div class="card"><h3>Also handy</h3><div class="row"><button class="btn" data-act="enableLive">Turn on live connection stats</button><a class="btn" href="#/backups" style="text-decoration:none">Back up all configs</a></div></div>`;
    return;
  }
  if (!S.wiz || S.wiz.type !== arg) {
    S.wiz = { type: arg, step: 0, name: "", nameTouched: false, enable: true, overwrite: false,
      p: { ssl: "none", force_https: true, http2: true, hsts: false, websocket: true, max_body_mb: 10, timeout: 60, method: "round_robin", code: 301, keep_path: true, basic_auth_users: [], max_fails: 3, fail_timeout: 30 } };
    try { S.wiz.certs = (await api("/api/certs")).certs; } catch (e) { S.wiz.certs = []; }
  }
  renderWizard();
}

function wf(key, label, opts = {}) {
  const p = S.wiz.p, v = key === "_name" ? S.wiz.name : p[key];
  if (opts.type === "check") return `<label class="check"><input type="checkbox" data-k="${key}" ${v ? "checked" : ""}><span>${label}${opts.hint ? `<small>${opts.hint}</small>` : ""}</span></label>`;
  if (opts.type === "select") return `<label class="f"><span>${label}</span><select data-k="${key}">${opts.options.map(([ov, ol]) => `<option value="${ov}" ${String(v) === String(ov) ? "selected" : ""}>${ol}</option>`).join("")}</select>${opts.hint ? `<div class="hint">${opts.hint}</div>` : ""}</label>`;
  if (opts.type === "textarea") return `<label class="f"><span>${label}</span><textarea rows="3" data-k="${key}" placeholder="${esc(opts.ph || "")}">${esc(v || "")}</textarea>${opts.hint ? `<div class="hint">${opts.hint}</div>` : ""}</label>`;
  return `<label class="f"><span>${label}</span><input type="${opts.num ? "number" : "text"}" data-k="${key}" value="${esc(v ?? "")}" placeholder="${esc(opts.ph || "")}" autocapitalize="off" spellcheck="false">${opts.hint ? `<div class="hint">${opts.hint}</div>` : ""}</label>`;
}

function renderWizard() {
  const w = S.wiz, info = WIZ[w.type], p = w.p;
  let body = "";
  if (w.step === 0) {
    body += wf("domains", "Domain name(s)", { ph: "app.example.com", hint: "Separate several with spaces. Use _ to catch any name." });
    if (w.type === "proxy") {
      body += wf("upstream", "Where is the app?", { ph: "192.168.1.20:8123", hint: "IP or hostname and port of the app this domain should reach." });
      body += wf("upstream_https", "The app itself uses HTTPS", { type: "check", hint: "Leave off for most apps on your LAN." });
    } else if (w.type === "loadbalance") {
      body += wf("upstreams", "Backends", { type: "textarea", ph: "192.168.1.21:8080\n192.168.1.22:8080", hint: "One address:port per line." });
      body += wf("method", "How to pick a backend", { type: "select", options: [["round_robin", "Take turns (round robin)"], ["least_conn", "Least busy (least connections)"], ["ip_hash", "Same visitor → same backend (sticky)"]] });
    } else if (w.type === "static") {
      body += wf("root", "Web folder on this server", { ph: "/var/www/mysite" });
      body += wf("spa", "This is a single-page app (React, Vue…)", { type: "check", hint: "Unknown paths load index.html instead of a 404." });
    } else if (w.type === "redirect") {
      body += wf("target", "Send visitors to", { ph: "https://www.example.com" });
      body += wf("code", "Redirect type", { type: "select", options: [[301, "301 · permanent"], [302, "302 · temporary"], [308, "308 · permanent, keeps POST"], [307, "307 · temporary, keeps POST"]] });
      body += wf("keep_path", "Keep the rest of the address (/page?x=1)", { type: "check" });
    }
    body += wf("_name", "Config file name", { ph: "app.example.com", hint: "Filled in from the first domain. Letters, digits, dot, dash, underscore." });
  } else if (w.step === 1) {
    body += wf("ssl", "HTTPS", { type: "select", options: [["none", "No HTTPS (plain HTTP only)"], ["existing", "Use a certificate already on this server"]] });
    if (p.ssl === "existing") {
      if (w.certs.length) body += `<label class="f"><span>Let's Encrypt certificates found</span><select data-act="noop" data-chg="pickCert"><option value="">Choose…</option>${w.certs.map((c, i) => `<option value="${i}">${esc(c.name)}${c.days_left != null ? ` · expires in ${c.days_left} days` : ""}</option>`).join("")}</select></label>`;
      else body += `<div class="banner info small">No Let's Encrypt certificates were found in /etc/letsencrypt/live. Enter the file paths below, or get one first with certbot (e.g. <span class="mono">sudo certbot certonly --webroot -w /var/www/html -d ${esc((p.domains || "app.example.com").split(/[\s,]+/)[0])}</span>).</div>`;
      body += wf("ssl_cert", "Certificate file (fullchain)", { ph: "/etc/letsencrypt/live/example.com/fullchain.pem" });
      body += wf("ssl_key", "Private key file", { ph: "/etc/letsencrypt/live/example.com/privkey.pem" });
      body += wf("force_https", "Send HTTP visitors to HTTPS", { type: "check" });
      body += wf("http2", "Turn on HTTP/2", { type: "check" });
      body += wf("hsts", "HSTS (tell browsers to always use HTTPS)", { type: "check", hint: "Only turn on once HTTPS works - browsers remember it for a year." });
    }
  } else if (w.step === 2) {
    body += wf("allow_ips", "Only allow these addresses (optional)", { type: "textarea", ph: "192.168.1.0/24\n10.0.0.5", hint: "Leave empty to allow everyone. Everyone else gets 403 Forbidden." });
    if (w.type !== "redirect") {
      body += `<label class="f"><span>Password prompt (optional)</span></label><div id="authRows">${(p.basic_auth_users || []).map((u, i) => `<div class="authrow"><input type="text" placeholder="username" data-au="${i}" data-f="user" value="${esc(u.user)}"><input type="password" placeholder="password (8+)" data-au="${i}" data-f="password" value="${esc(u.password)}"><button class="btn sm danger" data-act="delAuth" data-i="${i}">Remove</button></div>`).join("")}</div>
        <button class="btn sm" data-act="addAuth">+ Add a login</button><div class="spacer"></div>`;
    }
    if (w.type === "proxy" || w.type === "loadbalance") {
      body += wf("websocket", "WebSocket support", { type: "check", hint: "Needed by Home Assistant, Node-RED, dashboards and many web apps." });
      body += `<div class="grid g2">${wf("max_body_mb", "Max upload size (MB)", { num: true })}${w.type === "proxy" ? wf("timeout", "Timeout (seconds)", { num: true, hint: "Raise for long-running requests or streams." }) : wf("max_fails", "Mark a backend down after N failures", { num: true })}</div>`;
      if (w.type === "proxy") body += wf("buffering_off", "Turn off buffering (live streams, server-sent events)", { type: "check" });
    }
    if (w.type === "static") { body += wf("cache_assets", "Let browsers cache images, CSS and JS for 7 days", { type: "check" }); body += wf("max_body_mb", "Max upload size (MB)", { num: true }); }
  } else {
    body += `<div id="wprev"><div class="empty">Building config…</div></div>
      <label class="check"><input type="checkbox" id="wEnable" ${w.enable ? "checked" : ""}><span>Enable this site right away</span></label>
      <label class="check"><input type="checkbox" id="wOver" ${w.overwrite ? "checked" : ""}><span>Replace an existing site with the same name<small>The old version stays in history.</small></span></label>`;
  }
  $("#page").innerHTML = `<div class="row"><a href="#/wizards" class="small">← All wizards</a></div><div class="spacer"></div>
    <div class="card" style="max-width:820px"><h2>${info.icon} ${info.title}</h2>
    <div class="steps">${WSTEPS.map((s, i) => `<div class="${i === w.step ? "on" : i < w.step ? "done" : ""}">${i + 1}. ${s}</div>`).join("")}</div>
    <div id="wbody">${body}</div><div id="werr"></div>
    <div class="row between" style="margin-top:14px"><button class="btn" data-act="wizBack" ${w.step === 0 ? "disabled" : ""}>Back</button>
    ${w.step < 3 ? `<button class="btn primary" data-act="wizNext">Next</button>` : `<button class="btn primary" data-act="wizApply" id="wApply">Test &amp; apply</button>`}</div></div>`;
  $$("#wbody [data-k]").forEach((el) => el.addEventListener(el.type === "checkbox" || el.tagName === "SELECT" ? "change" : "input", () => wizSet(el)));
  $$("#wbody [data-au]").forEach((el) => el.addEventListener("input", () => { w.p.basic_auth_users[+el.dataset.au][el.dataset.f] = el.value; }));
  if (w.step === 3) wizPreview();
}

function wizSet(el) {
  const w = S.wiz, k = el.dataset.k;
  let v = el.type === "checkbox" ? el.checked : el.value;
  if (k === "_name") { w.name = v; w.nameTouched = true; return; }
  w.p[k] = v;
  if (k === "domains" && !w.nameTouched) {
    w.name = (v.split(/[\s,]+/).filter(Boolean)[0] || "").replace(/^\*\./, "wildcard.").replace(/[^A-Za-z0-9._-]/g, "");
    const n = $('[data-k="_name"]'); if (n) n.value = w.name;
  }
  if (k === "ssl") renderWizard();
}
CHG.pickCert = (el) => {
  const c = S.wiz.certs[+el.value]; if (!c) return;
  S.wiz.p.ssl_cert = c.cert; S.wiz.p.ssl_key = c.key; renderWizard();
};
ACT.addAuth = () => { S.wiz.p.basic_auth_users.push({ user: "", password: "" }); renderWizard(); };
ACT.delAuth = (el) => { S.wiz.p.basic_auth_users.splice(+el.dataset.i, 1); renderWizard(); };
ACT.wizBack = () => { S.wiz.step = Math.max(0, S.wiz.step - 1); renderWizard(); };
ACT.wizNext = async () => {
  try {
    // validate by asking the server to build the config
    await api("/api/wizard/preview", { type: S.wiz.type, name: S.wiz.name, params: wizParams() });
    S.wiz.step++; renderWizard();
  } catch (e) {
    // only block on errors that belong to the current/earlier steps
    const msg = e.message;
    const later = S.wiz.step === 0 && /certificate|key file/i.test(msg);
    if (later) { S.wiz.step++; renderWizard(); return; }
    $("#werr").innerHTML = `<div class="banner bad">${esc(msg)}</div>`;
  }
};
function wizParams() {
  const p = { ...S.wiz.p };
  if (p.basic_auth_users) p.basic_auth_users = p.basic_auth_users.filter((u) => u.user || u.password);
  return p;
}
async function wizPreview() {
  try {
    const r = await api("/api/wizard/preview", { type: S.wiz.type, name: S.wiz.name, params: wizParams() });
    $("#wprev").innerHTML = `<h3>This is the config that will be written to sites-available/${esc(S.wiz.name)}</h3><div class="out" style="max-height:420px">${highlight(r.content)}</div><div class="spacer"></div>`;
  } catch (e) { $("#wprev").innerHTML = `<div class="banner bad">${esc(e.message)}</div>`; $("#wApply").disabled = true; }
}
ACT.wizApply = async () => {
  const w = S.wiz; w.enable = $("#wEnable").checked; w.overwrite = $("#wOver").checked;
  $("#wApply").disabled = true;
  try {
    const r = await api("/api/wizard/apply", { type: w.type, name: w.name, params: wizParams(), enable: w.enable, overwrite: w.overwrite });
    $("#page").innerHTML = `<div class="card" style="max-width:820px"><div class="banner good"><b>${esc(w.name)} is live.</b> nginx accepted the config and reloaded.</div>
      <p>Next steps:</p><ul><li>Point the domain's DNS at this server (or add it to your local DNS).</li>${w.p.ssl === "none" ? "<li>Add HTTPS later by running the wizard again with the same name and choosing a certificate.</li>" : ""}<li>Watch it on the <a href="#/flow">Traffic Flow</a> map.</li></ul>
      <div class="row"><a class="btn" href="#/configs/${encodeURIComponent(r.id)}" style="text-decoration:none">Open the config</a><a class="btn" href="#/flow" style="text-decoration:none">Traffic Flow</a><a class="btn primary" href="#/wizards" style="text-decoration:none">Another wizard</a></div></div>`;
    S.wiz = null;
  } catch (e) {
    $("#wApply").disabled = false;
    $("#werr").innerHTML = `<div class="banner bad"><b>${esc(e.message)}</b>${e.data && e.data.test_output ? `<div class="out bad" style="margin-top:8px">${esc(e.data.test_output)}</div>` : ""}</div>`;
  }
};

// ------------------------------------------------------------------ traffic flow
async function pgFlow() {
  $("#pactions").innerHTML = `<label class="row small"><label class="toggle"><input type="checkbox" id="flAuto" checked><span></span></label>Auto-refresh</label><button class="btn" data-act="flowRefresh">Refresh</button>`;
  $("#page").innerHTML = `<div id="flowTop"></div><div class="grid" style="grid-template-columns:minmax(0,1fr) 320px" id="flowGrid"><div class="flowwrap" id="flowSvg"><div class="empty">Reading nginx config…</div></div><div class="card" id="flowSide"><h3>Details</h3><p class="muted small">Tap a site or backend to see more.</p></div></div>
    <div class="small muted" style="margin-top:10px">${window.innerWidth < 900 ? "Swipe the map sideways to see where each site goes. " : ""}Lines show where requests go. Thicker, moving lines = more requests in the last 5 minutes. Red dashed = backend not answering. Backends are checked by opening a TCP connection.</div>`;
  if (window.innerWidth < 900) $("#flowGrid").style.gridTemplateColumns = "1fr";
  S.flowSel = null;
  await flowLoad();
  every(10000, () => { if ($("#flAuto") && $("#flAuto").checked) flowLoad().catch(() => {}); });
}
ACT.flowRefresh = () => flowLoad();

async function flowLoad() {
  const [d, fl] = await Promise.all([api("/api/flow"), S.files.length ? Promise.resolve({ files: S.files }) : api("/api/files")]);
  S.files = fl.files; S.flow = d;
  if (S.page !== "flow") return;
  const down = d.backends.filter((b) => !b.up).length;
  $("#flowTop").innerHTML = `<div class="grid g4" style="margin-bottom:14px">
    <div class="card stat tight"><div class="l">Sites</div><div class="v">${d.servers.filter((s) => s.kind === "http").length}</div></div>
    <div class="card stat tight"><div class="l">Backends</div><div class="v">${d.backends.length}</div></div>
    <div class="card stat tight"><div class="l">Backends down</div><div class="v" style="color:${down ? "var(--bad)" : "inherit"}">${down}</div></div>
    <div class="card stat tight"><div class="l">Requests · 5 min</div><div class="v">${fmtNum(d.servers.reduce((a, s) => a + (s.req_5m || 0), 0) + (d.shared_req_5m || 0))}</div></div></div>
    ${d.servers.some((s) => s.shared_log) ? `<div class="banner info small">Some sites share one access log, so their request counts can't be split. Sites made with a wizard get their own log.</div>` : ""}
    ${d.errors.length ? `<div class="banner warn small">${d.errors.map(esc).join("<br>")}</div>` : ""}`;
  drawFlow(d);
  if (S.flowSel) flowDetails(S.flowSel);
}

function drawFlow(d) {
  const NH = 46, GAP = 12, top = 34;
  const servers = d.servers.slice().sort((a, b) => (a.listen[0]?.port || 0) - (b.listen[0]?.port || 0) || a.names[0].localeCompare(b.names[0]));
  // targets column: backends + static/redirect pseudo targets
  const targets = [];
  const tIndex = {};
  const addT = (key, label, sub, kind, extra) => { if (!(key in tIndex)) { tIndex[key] = targets.length; targets.push({ key, label, sub, kind, ...extra }); } return tIndex[key]; };
  const bmap = Object.fromEntries(d.backends.map((b) => [b.address, b]));
  const links = [];
  servers.forEach((s) => {
    s.routes.forEach((r) => {
      if (r.type === "proxy" && r.backends && r.backends.length) r.backends.forEach((a) => { const b = bmap[a] || {}; links.push([s, addT(a, a, r.upstream ? `pool ${r.upstream}` : (b.up ? `up · ${b.ms} ms` : "not answering"), "backend", { up: b.up, ms: b.ms })]); });
      else if (r.type === "proxy") links.push([s, addT("dyn:" + r.target, r.target.slice(0, 30), "dynamic target", "other")]);
      else if (r.type === "static") links.push([s, addT("static:" + r.target, "Files", r.target, "static")]);
      else if (r.type === "return") links.push([s, addT("ret:" + r.target, r.target.startsWith("301") || r.target.startsWith("302") || r.target.startsWith("30") ? "Redirect" : "Fixed reply", r.target.slice(0, 34), "return")]);
      else if (r.type === "status") links.push([s, addT("status", "Status page", "stub_status", "other")]);
    });
  });
  const ports = d.ports;
  const rows = Math.max(servers.length, targets.length, ports.length, 1);
  const H = top + rows * (NH + GAP) + 10;
  const X = { inet: 14, port: 150, site: 300, tgt: 600 }, W = 840;
  const colY = (i, n) => top + i * (NH + GAP) + ((rows - n) * (NH + GAP)) / 2;
  const portY = (p) => colY(ports.findIndex((x) => x.port === p.port && x.ssl === p.ssl), ports.length);
  const siteY = (i) => colY(i, servers.length), tY = (i) => colY(i, targets.length);
  const inetY = colY(0, 1);
  const curve = (x1, y1, x2, y2) => `M${x1},${y1} C${(x1 + x2) / 2},${y1} ${(x1 + x2) / 2},${y2} ${x2},${y2}`;
  const width = (n) => 1.5 + Math.min(8, Math.log2(1 + (n || 0)) * 1.4);
  let edges = "", nodes = "";
  ports.forEach((p) => { edges += `<path class="fedge" d="${curve(X.inet + 110, inetY + NH / 2, X.port, portY(p) + NH / 2)}" stroke-width="2"/>`; });
  servers.forEach((s, i) => {
    const y = siteY(i) + NH / 2, hot = (s.req_5m || 0) > 0;
    const seen = new Set();
    s.listen.forEach((l) => { const k = l.port + "" + l.ssl; if (seen.has(k)) return; seen.add(k); const p = ports.find((x) => x.port === l.port && x.ssl === l.ssl); if (!p) return; edges += `<path class="fedge ${hot ? "hot anim" : ""}" d="${curve(X.port + 110, portY(p) + NH / 2, X.site, y)}" stroke-width="${width(s.req_5m)}"/>`; });
  });
  links.forEach(([s, ti]) => {
    const t = targets[ti], i = servers.indexOf(s), hot = (s.req_5m || 0) > 0;
    const cls = t.kind === "backend" && t.up === false ? "down" : hot ? "hot anim" : "";
    edges += `<path class="fedge ${cls}" d="${curve(X.site + 220, siteY(i) + NH / 2, X.tgt, tY(ti) + NH / 2)}" stroke-width="${width(s.req_5m)}"/>`;
  });
  const node = (x, y, w, title, sub, dot, key, sel) => `<g class="fnode ${sel ? "sel" : ""}" ${key ? `data-act="flowPick" data-key="${esc(key)}"` : ""} transform="translate(${x},${y})"><rect width="${w}" height="${NH}" rx="8"/>
    ${dot ? `<circle cx="14" cy="${NH / 2}" r="5" fill="${dot}"/>` : ""}<text x="${dot ? 26 : 12}" y="19">${esc(title.length > 26 ? title.slice(0, 25) + "…" : title)}</text><text class="sub" x="${dot ? 26 : 12}" y="35">${esc(sub.length > 34 ? sub.slice(0, 33) + "…" : sub)}</text></g>`;
  nodes += node(X.inet, inetY, 110, "Internet / LAN", "visitors", null);
  ports.forEach((p) => { nodes += node(X.port, portY(p), 110, `:${p.port}`, p.ssl ? "HTTPS" : "HTTP", p.ssl ? "#3ec6a8" : "#5aa9f0"); });
  servers.forEach((s, i) => {
    const sub = (s.req_5m != null ? `${s.req_5m} req / 5 min` : s.shared_log ? "shared log" : "no log") + (s.routes.some((r) => r.auth || r.ip_rules) ? " · 🔒" : "");
    nodes += node(X.site, siteY(i), 220, s.names.join(" ") === "_" ? "(any name)" : s.names.join(" "), sub, null, "s:" + s.id, S.flowSel === "s:" + s.id);
  });
  targets.forEach((t, i) => {
    const dot = t.kind === "backend" ? (t.up ? "#3ec66d" : "#ef5b5b") : t.kind === "static" ? "#e6c07b" : "#8b96a5";
    nodes += node(X.tgt, tY(i), 220, t.label, t.sub, dot, "t:" + t.key, S.flowSel === "t:" + t.key);
  });
  const heads = [["Visitors", X.inet], ["Ports", X.port], ["Sites", X.site], ["Goes to", X.tgt]].map(([l, x]) => `<text class="colhead" x="${x}" y="18">${l}</text>`).join("");
  S.flowTargets = targets;
  $("#flowSvg").innerHTML = servers.length ? `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">${heads}${edges}${nodes}</svg>` : `<div class="empty">No enabled server blocks found. Create one with a <a href="#/wizards">wizard</a>.</div>`;
}

ACT.flowPick = (el) => {
  S.flowSel = el.dataset.key; drawFlow(S.flow); flowDetails(S.flowSel);
  if (window.innerWidth < 900) $("#flowSide").scrollIntoView({ behavior: "smooth" });
};
function fileIdFor(path) {
  const base = path.split("/").pop();
  const f = S.files.find((x) => x.name === base && x.group !== "enabled") || S.files.find((x) => x.name === base);
  return f ? f.id : null;
}
function flowDetails(key) {
  const d = S.flow, side = $("#flowSide");
  if (key.startsWith("s:")) {
    const s = d.servers.find((x) => "s:" + x.id === key); if (!s) return;
    const fid = fileIdFor(s.file);
    side.innerHTML = `<h3>Site</h3><h2 style="word-break:break-all">${esc(s.names.join(" "))}</h2>
      <dl class="kv small"><dt>Listens on</dt><dd>${s.listen.map((l) => esc(l.raw)).join("<br>")}</dd><dt>File</dt><dd class="mono">${esc(s.file)}</dd>
      <dt>Requests</dt><dd>${s.req_5m != null ? `${s.req_5m} in last 5 min` : s.shared_log ? "uses a shared log" : "logging off"}</dd><dt>Logs</dt><dd class="mono">${s.logs.map(esc).join("<br>") || "off"}</dd></dl>
      <div class="spacer"></div><h3>Routes</h3>${s.routes.map((r) => `<div class="small" style="margin-bottom:8px"><span class="mono">${esc(r.path)}</span> → <b>${esc(r.type)}</b> <span class="mono">${esc(r.target || "")}</span> ${r.auth ? '<span class="badge warn">password</span>' : ""}${r.ip_rules ? '<span class="badge warn">IP rules</span>' : ""}</div>`).join("") || '<div class="muted small">No routes</div>'}
      ${fid ? `<div class="spacer"></div><a class="btn sm" href="#/configs/${encodeURIComponent(fid)}" style="text-decoration:none">Open config</a>` : ""}`;
  } else {
    const t = S.flowTargets.find((x) => "t:" + x.key === key); if (!t) return;
    const b = d.backends.find((x) => x.address === t.key);
    const users = b ? b.servers.map((i) => d.servers[i]).filter(Boolean) : [];
    side.innerHTML = `<h3>${t.kind === "backend" ? "Backend" : "Target"}</h3><h2 style="word-break:break-all">${esc(t.label)}</h2>
      ${b ? `<div class="banner ${b.up ? "good" : "bad"} small">${b.up ? `Answering · ${b.ms} ms to connect` : `Not answering${b.error ? ` (${esc(b.error)})` : ""}. Check the app is running and the address/port are right.`}</div>` : `<div class="small muted">${esc(t.sub)}</div>`}
      ${users.length ? `<h3>Used by</h3>${users.map((s) => `<div class="small"><a href="#" data-act="flowPick" data-key="s:${s.id}">${esc(s.names.join(" "))}</a></div>`).join("")}` : ""}`;
  }
}

// ------------------------------------------------------------------ stats
async function pgStats() {
  S.statWin = S.statWin || 60; S.statLog = S.statLog || "";
  const load = async () => {
    const d = await api(`/api/stats?minutes=${S.statWin}&log=${encodeURIComponent(S.statLog)}`);
    if (S.page !== "stats") return;
    const c = d.classes;
    $("#pactions").innerHTML = `<select data-chg="statLog" style="width:auto"><option value="">All access logs</option>${d.logs.map((l) => `<option ${l === S.statLog ? "selected" : ""}>${esc(l)}</option>`).join("")}</select>
      <select data-chg="statWin" style="width:auto">${[[15, "15 min"], [60, "1 hour"], [360, "6 hours"], [1440, "24 hours"]].map(([v, l]) => `<option value="${v}" ${v == S.statWin ? "selected" : ""}>${l}</option>`).join("")}</select>`;
    const total = d.total || 1;
    $("#page").innerHTML = `<div class="grid g4">
      <div class="card stat"><div class="l">Requests</div><div class="v">${fmtNum(d.total)}</div><div class="s">${d.rpm} per minute</div></div>
      <div class="card stat"><div class="l">Data sent</div><div class="v">${fmtBytes(d.bytes)}</div></div>
      <div class="card stat"><div class="l">Client errors 4xx</div><div class="v" style="color:${c["4xx"] ? "var(--warn)" : "inherit"}">${fmtNum(c["4xx"] || 0)}</div><div class="s">${((c["4xx"] || 0) / total * 100).toFixed(1)}%</div></div>
      <div class="card stat"><div class="l">Server errors 5xx</div><div class="v" style="color:${c["5xx"] ? "var(--bad)" : "inherit"}">${fmtNum(c["5xx"] || 0)}</div><div class="s">${((c["5xx"] || 0) / total * 100).toFixed(1)}% · usually a backend that's down</div></div></div>
      <div class="spacer"></div>
      <div class="grid g3"><div class="card span2"><h3>Requests over time</h3>${barChart(d.timeline, 200)}</div>
        <div class="card"><h3>Live connections</h3>${d.live.enabled ? `<div class="stat"><div class="v">${d.live.active}</div><div class="s">open right now</div></div><div class="kv small" style="margin-top:10px"><dt>Reading</dt><dd>${d.live.reading}</dd><dt>Writing</dt><dd>${d.live.writing}</dd><dt>Waiting</dt><dd>${d.live.waiting}</dd><dt>Since start</dt><dd>${fmtNum(d.live.requests)} requests</dd></div>` : `<p class="muted small">Off.</p><button class="btn" data-act="enableLive">Turn on</button>`}
        <div class="spacer"></div><h3>Status codes</h3>${hbars(d.statuses.map(([k, v]) => [String(k), v]))}</div></div>
      <div class="spacer"></div>
      <div class="grid g3"><div class="card"><h3>Top visitors (IP)</h3>${hbars(d.top_ips)}</div><div class="card"><h3>Top pages</h3>${hbars(d.top_paths)}</div><div class="card"><h3>Top browsers / clients</h3>${hbars(d.top_agents)}</div></div>
      <div class="small muted" style="margin-top:10px">Read from nginx access logs in the standard "combined" format. Per-log totals: ${Object.entries(d.per_log).map(([k, v]) => `${esc(k)} ${v}`).join(" · ") || "none"}</div>`;
  };
  await load();
  every(15000, () => load().catch(() => {}));
}
CHG.statWin = (el) => { S.statWin = +el.value; route(); };
CHG.statLog = (el) => { S.statLog = el.value; route(); };

// ------------------------------------------------------------------ logs
async function pgLogs() {
  const d = await api("/api/logs");
  S.logFile = S.logFile && d.logs.find((l) => l.name === S.logFile) ? S.logFile : (d.logs.find((l) => l.name === "error.log") || d.logs[0] || {}).name;
  $("#page").innerHTML = `<div class="row" style="margin-bottom:12px">
    <select id="lgF" style="width:auto">${d.logs.map((l) => `<option ${l.name === S.logFile ? "selected" : ""} value="${esc(l.name)}">${esc(l.name)} (${fmtBytes(l.size)})</option>`).join("")}</select>
    <select id="lgN" style="width:auto"><option>200</option><option>500</option><option>2000</option></select>
    <input type="text" id="lgQ" placeholder="Filter (e.g. 502, an IP, a domain)" style="flex:1;min-width:160px">
    <label class="row small"><label class="toggle"><input type="checkbox" id="lgFollow" checked><span></span></label>Follow</label></div>
    <div class="logview" id="lgV"><div class="muted">Loading…</div></div>`;
  if (!d.logs.length) { $("#lgV").innerHTML = `<div class="muted">No logs in the nginx log folder.</div>`; return; }
  const load = async () => {
    const r = await api(`/api/logs/tail?file=${encodeURIComponent($("#lgF").value)}&lines=${$("#lgN").value}&q=${encodeURIComponent($("#lgQ").value)}`);
    const v = $("#lgV"); if (!v) return;
    const atBottom = v.scrollTop + v.clientHeight >= v.scrollHeight - 30;
    v.innerHTML = r.lines.length ? r.lines.map((l) => {
      const m = l.match(/" (\d{3}) /); const s = m ? +m[1] : 0;
      const cls = s >= 500 ? "s5" : s >= 400 ? "s4" : /\[(error|crit|alert|emerg)\]/.test(l) ? "err" : /\[warn\]/.test(l) ? "wrn" : "";
      return `<div class="${cls}">${esc(l)}</div>`;
    }).join("") : `<div class="muted" style="padding:10px 12px">No matching lines.</div>`;
    if (atBottom || !S.logLoaded) v.scrollTop = v.scrollHeight;
    S.logLoaded = true;
  };
  S.logLoaded = false;
  ["#lgF", "#lgN"].forEach((s) => $(s).addEventListener("change", () => { S.logFile = $("#lgF").value; S.logLoaded = false; load(); }));
  let t; $("#lgQ").addEventListener("input", () => { clearTimeout(t); t = setTimeout(() => { S.logLoaded = false; load(); }, 350); });
  await load();
  every(3000, () => { if ($("#lgFollow") && $("#lgFollow").checked) load().catch(() => {}); });
}

// ------------------------------------------------------------------ updates
async function pgUpdates() {
  const d = await api("/api/updates");
  const sy = d.system, np = d.nginx_pkg, pk = d.packages || [];
  const sec = pk.filter((p) => p.security).length, ngx = pk.filter((p) => p.nginx).length;
  const ngUpd = np.installed && np.candidate && np.installed !== np.candidate && np.installed !== "(none)";
  $("#pactions").innerHTML = d.allowed ? `<button class="btn" data-act="updCheck">Check for updates</button>` : "";
  $("#page").innerHTML = `${!d.allowed ? `<div class="banner warn">System updates are turned off in the NginxUI config file (allow_system_updates).</div>` : ""}
    ${sy.reboot_required ? `<div class="banner warn row between"><span><b>Reboot required</b> to finish installing updates${sy.reboot_pkgs.length ? ` (${esc(sy.reboot_pkgs.join(", "))})` : ""}. Sites are offline for a minute or two while it restarts.</span><button class="btn danger" data-act="reboot">Reboot server</button></div>` : ""}
    <div class="grid g3">
      <div class="card"><h3>Ubuntu</h3><dl class="kv small"><dt>System</dt><dd>${esc(sy.os)}</dd><dt>Kernel</dt><dd>${esc(sy.kernel)}</dd><dt>Uptime</dt><dd>${fmtDur(sy.uptime_s)}</dd><dt>Last check</dt><dd>${esc(d.checked || "never")}</dd></dl>
        <div class="spacer"></div><div class="row between"><div><b>Automatic security updates</b><div class="small muted">${d.auto.installed ? "Ubuntu installs security fixes daily on its own" : "unattended-upgrades is not installed"}</div></div>
        <label class="toggle"><input type="checkbox" data-chg="autoUpd" ${d.auto.enabled ? "checked" : ""} ${d.auto.installed && d.allowed ? "" : "disabled"}><span></span></label></div></div>
      <div class="card"><h3>nginx</h3><dl class="kv small"><dt>Running</dt><dd>${esc(sy.nginx_version || "-")}</dd><dt>Installed pkg</dt><dd class="mono">${esc(np.installed || "-")}</dd><dt>Newest available</dt><dd class="mono">${esc(np.candidate || "-")}</dd><dt>From</dt><dd class="small">${esc(np.source || "-")}</dd></dl>
        <div class="spacer"></div>${ngUpd ? `<span class="badge info">update available</span> ` : `<span class="badge good">up to date</span> `}
        <button class="btn sm" data-act="updApply" data-scope="nginx" ${ngUpd && d.allowed ? "" : "disabled"}>Update nginx only</button></div>
      <div class="card"><h3>Waiting updates</h3><div class="stat"><div class="v">${pk.length}</div><div class="s">${sec} security · ${ngx} nginx</div></div><div class="spacer"></div>
        <div class="row"><button class="btn ${sec ? "primary" : ""}" data-act="updApply" data-scope="security" ${sec && d.allowed ? "" : "disabled"}>Install security (${sec})</button><button class="btn" data-act="updApply" data-scope="all" ${pk.length && d.allowed ? "" : "disabled"}>Install all (${pk.length})</button></div></div>
    </div><div class="spacer"></div>
    <div class="card hidden" id="jobCard"><div class="row between"><h3 id="jobTitle" style="margin:0"></h3><span id="jobState"></span></div><div class="spacer"></div><div class="out console" id="jobOut"></div></div>
    <div class="spacer"></div>
    <div class="card"><h3>Packages</h3>${pk.length ? `<div class="tablewrap"><table><tr><th>Package</th><th>Current</th><th>New</th><th></th></tr>${pk.sort((a, b) => b.security - a.security || b.nginx - a.nginx || a.name.localeCompare(b.name)).map((p) => `<tr><td class="mono">${esc(p.name)}</td><td class="mono small muted">${esc(p.old)}</td><td class="mono small">${esc(p.new)}</td><td>${p.security ? '<span class="badge bad">security</span>' : ""} ${p.nginx ? '<span class="badge info">nginx</span>' : ""}</td></tr>`).join("")}</table></div>` : `<div class="empty">${d.checked ? "Everything is up to date." : "Press <b>Check for updates</b> to see what's available."}</div>`}</div>
    <p class="small muted">Before installing, NginxUI backs up /etc/nginx. Your edited config files are always kept (apt is told to keep your versions), and nginx is tested and started again afterwards.</p>`;
  if (d.job && !d.job.done) followJob(d.job.id);
}
CHG.autoUpd = async (el) => { try { await api("/api/updates/auto", { enabled: el.checked }); toast(`Automatic security updates ${el.checked ? "on" : "off"}`); } catch (e) { el.checked = !el.checked; toast(e.message, true); } };
ACT.updCheck = async () => { try { const r = await api("/api/updates/check", {}); followJob(r.job, () => route()); } catch (e) { toast(e.message, true); } };
ACT.updApply = async (el) => {
  const scope = el.dataset.scope;
  const what = { all: "all waiting updates", security: "security updates", nginx: "the newest nginx" }[scope];
  if (!(await confirmBox(`Install ${what}?`, `<ol class="small"><li>Back up /etc/nginx</li><li>Install ${what} with apt (your config files are kept)</li><li>Test the nginx config and make sure nginx is running</li></ol><p class="small muted">Sites may blip for a second if nginx restarts. Keep this page open to watch progress - it keeps running if you leave.</p>`, "Install"))) return;
  try { const r = await api("/api/updates/apply", { scope }); followJob(r.job, () => route()); } catch (e) { toast(e.message, true); }
};
function followJob(id, onDone) {
  const card = $("#jobCard"); if (!card) return;
  card.classList.remove("hidden");
  let since = 0;
  const tick = async () => {
    const j = await api(`/api/job?id=${id}&since=${since}`);
    since = j.next;
    if (!$("#jobOut")) return;
    $("#jobTitle").textContent = j.title;
    $("#jobState").innerHTML = j.done ? `<span class="badge ${j.ok ? "good" : "bad"}">${j.ok ? "done" : "finished with problems"}</span>` : `<span class="badge info">running…</span>`;
    const o = $("#jobOut"); o.textContent += j.lines.join("\n") + (j.lines.length ? "\n" : ""); o.scrollTop = o.scrollHeight;
    if (j.done) { clearTimers(); toast(`${j.title}: ${j.ok ? "done" : "finished with problems"}`, !j.ok); if (onDone) setTimeout(onDone, 1500); }
  };
  tick();
  every(1500, () => tick().catch(() => {}));
}
ACT.reboot = async () => {
  if (!(await confirmBox("Reboot the server?", `<p>Every site behind this proxy goes offline until Ubuntu is back up (usually 1-2 minutes). This page will reconnect by itself.</p>`, "Reboot", true, "REBOOT"))) return;
  try {
    await api("/api/system/reboot", { confirm: "REBOOT" });
    $("#page").innerHTML = `<div class="card empty">Rebooting… this page reloads when the server is back.</div>`;
    setTimeout(() => setInterval(async () => { try { await fetch("/api/session"); location.reload(); } catch (e) { /* wait */ } }, 5000), 20000);
  } catch (e) { toast(e.message, true); }
};

// ------------------------------------------------------------------ backups
async function pgBackups() {
  const d = await api("/api/backups");
  $("#pactions").innerHTML = `<button class="btn primary" data-act="bkCreate">Back up now</button>`;
  $("#page").innerHTML = `<p class="muted">A backup is a copy of the whole <span class="mono">/etc/nginx</span> folder. One is taken automatically before every update and every restore. The newest 30 automatic backups are kept; ones you make yourself are never removed automatically.</p>
    <div class="card">${d.backups.length ? `<div class="tablewrap"><table><tr><th>Backup</th><th>When</th><th>Size</th><th></th></tr>${d.backups.map((b) => `<tr><td class="mono small">${esc(b.name)}</td><td class="small">${esc(b.t)}</td><td class="small">${fmtBytes(b.size)}</td>
      <td><div class="row" style="justify-content:flex-end"><a class="btn sm" href="/api/backups/download?name=${encodeURIComponent(b.name)}" style="text-decoration:none">Download</a><button class="btn sm" data-act="bkRestore" data-n="${esc(b.name)}">Restore</button><button class="btn sm danger" data-act="bkDelete" data-n="${esc(b.name)}">Delete</button></div></td></tr>`).join("")}</table></div>` : `<div class="empty">No backups yet.</div>`}</div>`;
}
ACT.bkCreate = async () => { try { const r = await api("/api/backups/create", {}); toast(`Saved ${r.name}`); route(); } catch (e) { toast(e.message, true); } };
ACT.bkRestore = async (el) => {
  if (!(await confirmBox("Restore this backup?", `<p>All of <span class="mono">/etc/nginx</span> is replaced with <span class="mono">${esc(el.dataset.n)}</span>. Your current config is backed up first, and if the restored one fails the nginx test, nothing changes.</p>`, "Restore", true))) return;
  try { await api("/api/backups/restore", { name: el.dataset.n }); toast("Restored and live"); route(); } catch (e) { showApplyError(e, "Restore failed"); }
};
ACT.bkDelete = async (el) => {
  if (!(await confirmBox("Delete backup?", `<span class="mono">${esc(el.dataset.n)}</span>`, "Delete", true))) return;
  await api("/api/backups/delete", { name: el.dataset.n }); route();
};

// ------------------------------------------------------------------ settings
async function pgSettings() {
  const [u, a] = await Promise.all([api("/api/users"), api("/api/audit")]);
  $("#page").innerHTML = `<div class="grid g2">
    <form class="card" id="pwF"><h3>Change your password</h3>
      <label class="f"><span>Current password</span><input type="password" name="c" autocomplete="current-password" required></label>
      <label class="f"><span>New password (10+ characters)</span><input type="password" name="p" autocomplete="new-password" required></label>
      <label class="f"><span>Repeat new password</span><input type="password" name="p2" autocomplete="new-password" required></label>
      <button class="btn primary">Change password</button></form>
    <div class="card"><h3>Users</h3><table>${u.users.map((n) => `<tr><td>${esc(n)} ${n === u.me ? '<span class="badge">you</span>' : ""}</td><td style="text-align:right">${n !== u.me ? `<button class="btn sm danger" data-act="userDel" data-u="${esc(n)}">Remove</button>` : ""}</td></tr>`).join("")}</table>
      <div class="spacer"></div><form id="uF" class="row"><input type="text" name="u" placeholder="username" required style="flex:1;min-width:120px"><input type="password" name="p" placeholder="password (10+)" autocomplete="new-password" required style="flex:1;min-width:120px"><button class="btn">Add user</button></form>
      <p class="small muted">Every user has full access. Five wrong passwords from one address locks it out for 5 minutes.</p></div></div>
    <div class="spacer"></div>
    <div class="card"><h3>Activity log</h3><div class="tablewrap" style="max-height:420px;overflow:auto"><table><tr><th>When</th><th>Who</th><th>Action</th><th>Target</th></tr>${a.entries.map((e) => `<tr><td class="small" style="white-space:nowrap">${esc(e.t)}</td><td class="small">${esc(e.user)}</td><td class="small"><span class="dot ${e.ok ? "good" : "bad"}"></span>${esc(e.action)}</td><td class="small">${esc(e.target)}</td></tr>`).join("")}</table></div></div>
    <div class="spacer"></div><div class="card small muted">NginxUI v${esc(S.version)} · settings file <span class="mono">/etc/nginxui/nginxui.json</span> · service <span class="mono">sudo systemctl restart nginxui</span></div>`;
  $("#pwF").onsubmit = async (ev) => {
    ev.preventDefault(); const f = ev.target;
    if (f.p.value !== f.p2.value) return toast("New passwords do not match", true);
    try { await api("/api/password", { current: f.c.value, password: f.p.value }); toast("Password changed"); f.reset(); } catch (e) { toast(e.message, true); }
  };
  $("#uF").onsubmit = async (ev) => {
    ev.preventDefault(); const f = ev.target;
    try { await api("/api/users/add", { username: f.u.value, password: f.p.value }); toast("User added"); route(); } catch (e) { toast(e.message, true); }
  };
}
ACT.userDel = async (el) => {
  if (!(await confirmBox(`Remove ${el.dataset.u}?`, "They are signed out right away.", "Remove", true))) return;
  try { await api("/api/users/delete", { username: el.dataset.u }); route(); } catch (e) { toast(e.message, true); }
};

boot();
