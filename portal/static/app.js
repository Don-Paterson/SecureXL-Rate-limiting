/* SecureXL DoS Shield portal - client side. No framework, no build step. */

const S = { settings: null, profiles: [], snap: null, spark: [], lastMon: {}, monTimer: null };
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const TITLES = {
  overview: ["Overview", "A-GW-Cluster · Alpha site"],
  profiles: ["Protection profiles", "Preset and custom rule sets for A-DMZ"],
  rules: ["Rate-limit rules", "Installed SecureXL rate-limiting policy, per member"],
  pbox: ["Penalty Box", "Early drop for sources that keep exceeding limits"],
  deny: ["Deny list", "Explicit address blocking"],
  monitor: ["Live monitor", "Rule counters and Penalty Box, refreshed continuously"],
  test: ["Test lab", "Trigger the policy from A-Host with Lab-Traffic-Gen"],
  activity: ["Activity", "Every command the portal has sent"],
  settings: ["Settings", "Gateways, credentials and command syntax"],
};

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function toast(msg, kind = "ok") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.innerHTML = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), 4800);
}

function modal(title, body, buttons = []) {
  $("#modalTitle").textContent = title;
  $("#modalBody").innerHTML = body;
  const foot = $("#modalFoot");
  foot.innerHTML = "";
  for (const b of [...buttons, { label: "Close", cls: "ghost", close: true }]) {
    const btn = document.createElement("button");
    btn.className = `btn ${b.cls || ""}`;
    btn.textContent = b.label;
    btn.onclick = async () => {
      if (b.close) return closeModal();
      btn.disabled = true;
      try { await b.onClick(btn); } finally { btn.disabled = false; }
    };
    foot.appendChild(btn);
  }
  $("#modal").hidden = false;
}
function closeModal() { $("#modal").hidden = true; }
$("#modal").addEventListener("click", (e) => { if (e.target.id === "modal" || e.target.dataset.close !== undefined) closeModal(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });

function renderResults(results) {
  return Object.entries(results).map(([member, list]) => `
    <div class="member-block"><h4>${esc(member)}</h4>
      ${list.length ? list.map((r) => `
        <div class="cmd"><span class="st ${r.ok ? "ok" : "bad"}">${r.ok ? "✓" : "✗"}</span>
          <div><div class="${r.cmd.includes(" del ") ? "del" : ""}">${esc(r.cmd)}</div>
          ${(r.out || r.err) ? `<div class="out">${esc((r.out + r.err).trim())}</div>` : ""}</div></div>`).join("")
        : `<div class="muted small">Nothing to do on this member.</div>`}
    </div>`).join("");
}

function renderPlan(plan) {
  return Object.entries(plan).map(([member, cmds]) => `
    <div class="member-block"><h4>${esc(member)} · ${cmds.length} command(s)</h4>
      ${cmds.map((c) => `<div class="cmd"><span class="st pending">›</span><div class="${c.includes(" del ") ? "del" : ""}">${esc(c)}</div></div>`).join("")}
    </div>`).join("");
}

async function runAction(title, promise) {
  try {
    const res = await promise;
    const failed = res.failed || 0;
    toast(failed ? `${esc(title)}: ${failed} command(s) failed` : `${esc(title)}: done`, failed ? "bad" : "ok");
    if (res.results) modal(`${title} · result`, renderResults(res.results));
    await refresh();
    return res;
  } catch (e) {
    toast(`${esc(title)}: ${esc(e.message)}`, "bad");
  }
}

function copyBtn(text) {
  return `<button class="btn ghost sm copy" data-copy="${esc(text)}">Copy</button>`;
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-copy]");
  if (!b) return;
  navigator.clipboard.writeText(b.dataset.copy).then(() => { b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy"), 1200); });
});

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

function showTab(tab) {
  $$("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.tab === tab));
  $$(".tab").forEach((t) => t.classList.toggle("active", t.id === `tab-${tab}`));
  $("#pageTitle").textContent = TITLES[tab][0];
  $("#pageSub").textContent = TITLES[tab][1];
  history.replaceState(null, "", `#${tab}`);
  if (tab === "monitor") pollMonitor();
  if (tab === "activity") loadAudit();
}
$$("#nav a").forEach((a) => (a.onclick = () => showTab(a.dataset.tab)));
$("#refreshBtn").onclick = () => refresh(true);

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

async function refresh(announce) {
  const btn = $("#refreshBtn");
  btn.disabled = true;
  try {
    const [snap, profiles] = await Promise.all([api("GET", "/api/state"), api("GET", "/api/profiles")]);
    S.snap = snap;
    S.profiles = profiles;
    renderAll();
    if (announce) toast("State refreshed from the gateways");
  } catch (e) {
    toast(`Refresh failed: ${esc(e.message)}`, "bad");
  } finally {
    btn.disabled = false;
  }
}

function renderAll() {
  renderHeader();
  renderBanner();
  renderOverview();
  renderProfiles();
  renderRules();
  renderPbox();
  renderDeny();
}

function memberEntries() { return Object.entries(S.snap?.members || {}); }
function profileById(id) { return S.profiles.find((p) => p.id === id); }

function renderHeader() {
  const sim = S.snap.simulator;
  const badge = $("#modeBadge");
  badge.className = `badge ${sim ? "sim" : "live"}`;
  badge.textContent = sim ? "Simulator" : "Live · SSH";
  $("#dmzIp").textContent = S.snap.dmz_ip;
  $$(".pfx").forEach((e) => (e.textContent = `${S.snap.prefix}*`));
  $("#memberPills").innerHTML = memberEntries().map(([name, m]) => {
    const st = !m.reachable ? "down" : (m.cluster_state || "").toLowerCase();
    const label = !m.reachable ? "unreachable" : (m.cluster_state || "reachable");
    return `<span class="pill ${st}"><span class="led"></span>${esc(name)} <span class="muted">${esc(label)}</span></span>`;
  }).join("");
}

function renderBanner() {
  const out = [];
  const down = memberEntries().filter(([, m]) => !m.reachable);
  for (const [name, m] of memberEntries().filter(([, m]) => m.clish)) {
    out.push(`<div class="banner warn"><b>${esc(name)} answers in clish.</b>
      <span>The SSH user's login shell is clish, so <code>fwaccel</code> commands are rejected. The portal can switch it to bash
      (<code>set user … shell /bin/bash</code> and <code>save config</code>) and check the result.<br>
      <button class="btn sm" style="margin-top:8px" data-fixshell="${esc(name)}">Switch ${esc(name)} to bash</button></span></div>`);
  }
  for (const [name, m] of down.filter(([, m]) => !m.clish)) {
    out.push(`<div class="banner bad"><b>${esc(name)} unreachable.</b> <span>${esc(m.error)}<br>Check the address and credentials in Settings, and that SSH is allowed from A-GUI.</span></div>`);
  }
  if (!S.snap.in_sync && !down.length) {
    out.push(`<div class="banner warn"><b>Cluster members differ.</b> <span>Lab rules are not identical on every member. The member that is Active after a failover would enforce a different policy. Re-apply a profile to bring them back in line.</span></div>`);
  }
  if (S.snap.simulator) {
    out.push(`<div class="banner info"><b>Simulator mode.</b> <span>Commands go to an in-memory model, not to the gateways. Switch to live mode in Settings.</span></div>`);
  }
  $("#banner").innerHTML = out.join("");
}

document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-fixshell]");
  if (!b) return;
  const name = b.dataset.fixshell;
  modal(`Switch ${name} to bash?`, `<p>Sends these clish commands to <b>${esc(name)}</b>, then reconnects and checks that bash answers:</p>
    <pre class="raw">set user ${esc(S.settings?.ssh_user || "admin")} shell /bin/bash\nsave config</pre>
    <p class="muted small">This changes the login shell for that user on the gateway, for SSH and console logins alike. To undo it later in Expert mode: <code>clish -c "set user admin shell /etc/cli.sh" && clish -c "save config"</code>.</p>`,
    [{ label: "Switch to bash", onClick: () => runAction(`Switch ${name} to bash`, api("POST", `/api/members/${encodeURIComponent(name)}/fix-shell`)) }]);
});

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

function renderOverview() {
  const members = memberEntries();
  const active = profileById(S.snap.active_profile);
  const anyRules = Object.values(S.snap.lab_rules).some((l) => l.length);
  const pboxOn = members.filter(([, m]) => m.pbox.enabled).length;
  const boxed = [...new Set(members.flatMap(([, m]) => m.pbox.boxed))];
  const deny = [...new Set(members.flatMap(([, m]) => m.deny))];
  const ruleCounts = members.map(([, m]) => m.rules.length);

  const kpi = (label, value, hint, glow) =>
    `<div class="kpi" style="--glow:${glow}"><div class="label">${label}</div><div class="value">${value}</div><div class="hint">${hint}</div></div>`;

  $("#kpis").innerHTML = [
    kpi("Active profile", active ? esc(active.name) : (anyRules ? "Mixed" : "None"),
      active ? esc(active.tagline) : (anyRules ? "Lab rules don't match one profile" : "A-DMZ is not rate limited"),
      active ? (active.level === 3 ? "rgba(236,14,90,.28)" : active.level === 2 ? "rgba(245,165,36,.25)" : "rgba(56,189,248,.25)") : "rgba(240,68,68,.25)"),
    kpi("Rules installed", ruleCounts.join(" / ") || "0", members.map(([n]) => n).join(" / "), "rgba(139,92,246,.25)"),
    kpi("Penalty Box", pboxOn === members.length && pboxOn ? "On" : pboxOn ? "Partial" : "Off",
      boxed.length ? `${boxed.length} source(s) boxed now` : "No sources boxed", boxed.length ? "rgba(240,68,68,.35)" : "rgba(34,197,94,.22)"),
    kpi("Cluster sync", S.snap.in_sync ? "✓ In sync" : "✗ Drift", S.snap.in_sync ? "Same lab rules on every member" : "Re-apply a profile", S.snap.in_sync ? "rgba(34,197,94,.22)" : "rgba(240,68,68,.35)"),
    kpi("Deny list", deny.length, deny.length ? esc(deny.join(", ")) : "No explicit blocks", "rgba(56,189,248,.2)"),
  ].join("");

  $("#topology").innerHTML = topology(active, boxed);

  const cols = members.map(([name]) => {
    const mine = S.snap.lab_rules[name] || [];
    const all = [...new Set(Object.values(S.snap.lab_rules).flat())].sort();
    return `<div class="sync-col"><h4>${esc(name)} <span class="muted">${mine.length}</span></h4><ul>${
      all.length ? all.map((r) => `<li class="${mine.includes(r) ? "" : "miss"}">${mine.includes(r) ? "●" : "○ missing"} ${esc(r)}</li>`).join("")
        : `<li class="muted">No lab rules</li>`}</ul></div>`;
  }).join("");
  $("#syncView").innerHTML = `<div class="sync-grid">${cols}</div>
    <p class="small ${S.snap.in_sync ? "sync-ok" : "sync-bad"}" style="margin:12px 0 0">${S.snap.in_sync ? "✓ Both members enforce the same lab policy, so failover keeps protection identical." : "✗ Members differ. Re-apply a profile."}</p>`;

  const presets = S.profiles.filter((p) => p.kind === "preset");
  $("#quick").innerHTML = presets.map((p) =>
    `<button class="btn ${p.id === S.snap.active_profile ? "" : "ghost"}" data-apply="${p.id}">Apply ${esc(p.name)}</button>`).join("") +
    `<button class="btn ghost" data-clear>Remove lab rules</button>
     <button class="btn ghost" data-tabgo="monitor">Open live monitor →</button>`;
}

function topology(active, boxed) {
  const level = active?.level || 0;
  const shield = ["#5b6582", "#38bdf8", "#f5a524", "#ec0e5a"][level];
  const hostBoxed = boxed.includes("192.168.11.201");
  const lineCol = hostBoxed ? "#f04444" : "#ec0e5a";
  const blockMark = hostBoxed
    ? `<g transform="translate(225 118)"><circle r="16" fill="#f04444" class="pulse"/><path d="M-7 -7l14 14M7 -7l-14 14" stroke="#fff" stroke-width="3" stroke-linecap="round"/></g>
       <text x="225" y="152" text-anchor="middle" fill="#ff8a8a" font-size="11" font-weight="700">PENALTY BOX</text>`
    : "";
  return `<div class="topo"><svg viewBox="0 0 760 270" role="img" aria-label="A-Host to A-DMZ through the cluster">
    <defs>
      <linearGradient id="gw" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ff4d8a"/><stop offset="1" stop-color="#b3004a"/></linearGradient>
      <filter id="glow"><feGaussianBlur stdDeviation="6" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    </defs>
    <!-- links -->
    <path d="M150 118 H 300" stroke="${lineCol}" stroke-width="3" class="flow ${level ? "" : "fast"}" fill="none"/>
    <path d="M460 118 H 600" stroke="#22c55e" stroke-width="3" class="flow" fill="none" opacity="${hostBoxed ? .25 : .9}"/>
    <path d="M380 60 V 30 H 640" stroke="#38bdf8" stroke-width="2" stroke-dasharray="3 5" fill="none" opacity=".6"/>
    <text x="225" y="94" text-anchor="middle" fill="#8a93a9" font-size="11">eth2 · A-INT-NET</text>
    <text x="530" y="94" text-anchor="middle" fill="#8a93a9" font-size="11">eth3 · A-DMZ-NET</text>
    <text x="510" y="24" text-anchor="middle" fill="#8a93a9" font-size="11">eth0 · A-MGMT-NET (SSH)</text>
    ${blockMark}
    <!-- A-Host -->
    <g transform="translate(40 80)">
      <rect width="110" height="76" rx="12" fill="#192238" stroke="#2f3d5c"/>
      <rect x="30" y="16" width="50" height="32" rx="4" fill="none" stroke="#ff8a8a" stroke-width="2"/>
      <path d="M24 54 h62" stroke="#ff8a8a" stroke-width="2"/>
      <text x="55" y="100" text-anchor="middle" fill="#e7eaf3" font-size="13" font-weight="700">A-Host</text>
      <text x="55" y="116" text-anchor="middle" fill="#8a93a9" font-size="11" font-family="JetBrains Mono">192.168.11.201</text>
      <text x="55" y="-10" text-anchor="middle" fill="#ff8a8a" font-size="10.5" font-weight="700" letter-spacing=".08em">TEST SOURCE</text>
    </g>
    <!-- Cluster -->
    <g transform="translate(300 60)">
      <rect width="160" height="116" rx="16" fill="#1b1222" stroke="#ec0e5a" stroke-dasharray="5 4"/>
      <rect x="18" y="22" width="56" height="44" rx="6" fill="url(#gw)"/>
      <rect x="86" y="22" width="56" height="44" rx="6" fill="url(#gw)" opacity=".75"/>
      <path d="M46 34 l9 3.5v6c0 4.6-3.5 7.6-9 9.5-5.5-1.9-9-4.9-9-9.5v-6z" fill="#fff" opacity=".9"/>
      <path d="M114 34 l9 3.5v6c0 4.6-3.5 7.6-9 9.5-5.5-1.9-9-4.9-9-9.5v-6z" fill="#fff" opacity=".7"/>
      <text x="80" y="88" text-anchor="middle" fill="#e7eaf3" font-size="13" font-weight="700">A-GW-Cluster</text>
      <text x="80" y="104" text-anchor="middle" fill="#ff8ab4" font-size="11">SecureXL rate limiting</text>
    </g>
    <!-- A-DMZ -->
    <g transform="translate(600 80)">
      <circle cx="55" cy="38" r="52" fill="${shield}" opacity=".13" filter="url(#glow)"/>
      <rect width="110" height="76" rx="12" fill="#192238" stroke="${shield}"/>
      <path d="M55 12 l20 7v13c0 11-7.8 18-20 22-12.2-4-20-11-20-22V19z" fill="${shield}"/>
      <path d="M46 34l6 6 12-12" stroke="#0a0e19" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round" opacity="${level ? 1 : 0}"/>
      <text x="55" y="100" text-anchor="middle" fill="#e7eaf3" font-size="13" font-weight="700">A-DMZ</text>
      <text x="55" y="116" text-anchor="middle" fill="#8a93a9" font-size="11" font-family="JetBrains Mono">${esc(S.snap.dmz_ip)}</text>
      <text x="55" y="-10" text-anchor="middle" fill="${shield}" font-size="10.5" font-weight="700" letter-spacing=".08em">${active ? esc(active.name.toUpperCase()) : "UNPROTECTED"}</text>
    </g>
    <!-- A-GUI -->
    <g transform="translate(640 12)">
      <rect width="96" height="34" rx="9" fill="#192238" stroke="#38bdf8" opacity=".9"/>
      <text x="48" y="22" text-anchor="middle" fill="#7dd3fc" font-size="12" font-weight="700">A-GUI · portal</text>
    </g>
    <text x="380" y="230" text-anchor="middle" fill="#8a93a9" font-size="12">${
      hostBoxed ? "A-Host is in the Penalty Box: SecureXL drops its packets early until the timeout expires."
        : active ? `${esc(active.rules.length)} per-source limits enforced on both members · Penalty Box ${active.pbox.enabled ? "armed" : "off"}`
          : "No lab profile applied: traffic reaches A-DMZ without rate limits."}</text>
  </svg></div>`;
}

document.addEventListener("click", (e) => {
  const a = e.target.closest("[data-apply]");
  if (a) return applyProfile(a.dataset.apply);
  if (e.target.closest("[data-clear]")) return clearLab();
  const t = e.target.closest("[data-tabgo]");
  if (t) showTab(t.dataset.tabgo);
});

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

const limitLabel = { "pkt-rate": "pkt/s", "new-conn-rate": "conn/s", "concurrent-conns": "conns", bytes: "B/s" };
const svcLabel = (s) => ({ any: "any", "6/80": "HTTP", "6/443": "HTTPS", "6/22": "SSH", "17/53": "DNS" }[s] || s);

function renderProfiles() {
  $("#profiles").innerHTML = S.profiles.map((p) => {
    const isActive = p.id === S.snap.active_profile;
    return `<div class="profile lvl-${p.level} ${p.kind === "custom" ? "custom" : ""} ${isActive ? "is-active" : ""}">
      <div class="p-top">
        <div><h2>${esc(p.name)}</h2><div class="tag">${esc(p.tagline)}</div>
          <div class="meter l${p.level}" title="Strictness"><i></i><i></i><i></i></div></div>
        ${isActive ? `<span class="active-flag">ACTIVE</span>` : p.kind === "custom" ? `<span class="chip">custom</span>` : ""}
      </div>
      <div class="desc">${esc(p.description)}</div>
      <table class="p-rules">${p.rules.map((r) => `
        <tr><td><span class="chip ${r.action}">${r.action}</span></td>
          <td>${esc(r.note || r.name)}<div class="muted small mono">${esc(r.name)} · ${svcLabel(r.service)}${r.track !== "none" ? " · per source" : " · all sources"}</div></td>
          <td>${Number(r.value).toLocaleString()} ${limitLabel[r.limit]}</td></tr>`).join("")}
      </table>
      <div class="p-pbox">
        <span class="chip ${p.pbox.enabled ? "on" : ""}">Penalty Box ${p.pbox.enabled ? "on" : "off"}</span>
        ${p.pbox.enabled ? `<span class="chip">box after ${p.pbox.threshold} drops/s</span><span class="chip">hold ${p.pbox.timeout}s</span>` : ""}
      </div>
      <div class="p-actions">
        <button class="btn" data-apply="${p.id}">Apply to cluster</button>
        <button class="btn ghost" data-preview="${p.id}">Preview</button>
        <button class="btn ghost" data-edit="${p.id}">${p.kind === "custom" ? "Edit" : "Clone & edit"}</button>
        <a class="btn ghost" href="/api/profiles/${p.id}/export.sh" title="Bash script to run on a member in Expert mode">⤓ .sh</a>
        ${p.kind === "custom" ? `<button class="btn link" data-delprof="${p.id}">Delete</button>` : ""}
      </div>
    </div>`;
  }).join("") + `<div class="profile custom" style="justify-content:center;align-items:center;text-align:center;min-height:300px">
      <h2>New profile</h2><p class="muted">Start from an empty rule set, or clone a preset above.</p>
      <button class="btn" data-edit="__new">Create custom profile</button></div>`;
}

document.addEventListener("click", async (e) => {
  const pv = e.target.closest("[data-preview]");
  if (pv) {
    const p = profileById(pv.dataset.preview);
    try {
      const { plan } = await api("POST", `/api/profiles/${p.id}/preview`, { replace: true });
      modal(`Preview · ${p.name}`, `<p class="muted small">These commands would run on each member, in this order. <span class="del">Red lines</span> remove existing lab rules.</p>${renderPlan(plan)}`,
        [{ label: "Apply now", onClick: () => { closeModal(); return applyProfile(p.id); } }]);
    } catch (err) { toast(esc(err.message), "bad"); }
  }
  const ed = e.target.closest("[data-edit]");
  if (ed) openEditor(ed.dataset.edit);
  const dp = e.target.closest("[data-delprof]");
  if (dp && confirm("Delete this custom profile? Rules already installed on the gateways stay until you change them.")) {
    try { await api("DELETE", `/api/profiles/${dp.dataset.delprof}`); toast("Profile deleted"); refresh(); }
    catch (err) { toast(esc(err.message), "bad"); }
  }
});

async function applyProfile(id) {
  const p = profileById(id);
  if (!p) return;
  const drops = p.rules.filter((r) => r.action === "drop").length;
  const warn = drops ? `${drops} rule(s) will <b>drop</b> traffic${p.pbox.enabled ? " and the Penalty Box will be <b>enabled</b>" : ""}.` : "All rules are notify-only.";
  modal(`Apply ${p.name}?`, `<p>This replaces the lab rules (<code>${esc(S.snap.prefix)}*</code>) on every cluster member with the <b>${esc(p.name)}</b> profile. ${warn}</p>
    <p class="muted small">Rules not named with the lab prefix are left alone. Penalty Box settings are global to each gateway.</p>`,
    [{ label: `Apply ${p.name}`, onClick: async () => { await runAction(`Apply ${p.name}`, api("POST", `/api/profiles/${id}/apply`, { replace: true })); } }]);
}

function clearLab() {
  modal("Remove lab rules?", `<p>Deletes every rate-limit rule named <code>${esc(S.snap.prefix)}*</code> on all members. Penalty Box settings are not changed. Use the Penalty Box tab to switch it off.</p>`,
    [{ label: "Remove lab rules", cls: "danger", onClick: () => runAction("Remove lab rules", api("POST", "/api/rules/clear-lab")) }]);
}

// Profile editor ------------------------------------------------------------

function ruleRow(r = {}) {
  const sel = (name, opts, val) => `<select name="${name}">${opts.map((o) => `<option ${o === val ? "selected" : ""}>${o}</option>`).join("")}</select>`;
  return `<div class="editor-rule">
    <input name="name" value="${esc(r.name || S.snap.prefix)}" class="mono" placeholder="${esc(S.snap.prefix)}name">
    ${sel("action", ["drop", "notify"], r.action || "notify")}
    <input name="source" value="${esc(r.source || "any")}" class="mono" title="any, or an IP/CIDR">
    <input name="service" value="${esc(r.service || "any")}" class="mono" title="any, or proto/port e.g. 6/80">
    ${sel("limit", ["pkt-rate", "new-conn-rate", "concurrent-conns", "bytes"], r.limit || "pkt-rate")}
    <input name="value" type="number" min="1" value="${esc(r.value || 1000)}">
    ${sel("track", ["source", "source-service", "none"], r.track || "source")}
    <button type="button" class="btn link" data-rmrow>✕</button>
    <input name="note" type="hidden" value="${esc(r.note || "")}">
  </div>`;
}

function openEditor(id) {
  const base = id === "__new" ? null : profileById(id);
  const isCustom = base?.kind === "custom";
  const p = base ? structuredClone(base) : { name: "", tagline: "Custom profile", description: "", level: 2, rules: [], pbox: { enabled: false, threshold: 500, timeout: 180, log_drops: true } };
  if (base && !isCustom) {
    p.name = `${base.name} (custom)`;
    p.rules = p.rules.map((r) => ({ ...r, name: r.name.replace(/^ADMZ-[A-Z]{3}-/, `${S.snap.prefix}CUS-`) }));
  }
  const body = `
    <div class="row" style="margin-bottom:12px">
      <label class="f">Profile name<input id="edName" value="${esc(p.name)}" maxlength="40"></label>
      <label class="f">Tagline<input id="edTag" value="${esc(p.tagline)}" maxlength="60"></label>
      <label class="f" style="max-width:160px">Strictness<select id="edLevel">${[1, 2, 3].map((l) => `<option value="${l}" ${l === p.level ? "selected" : ""}>${["", "Observe", "Moderate", "Tight"][l]}</option>`).join("")}</select></label>
    </div>
    <label class="f" style="margin-bottom:14px">Description<input id="edDesc" value="${esc(p.description)}" maxlength="400"></label>
    <div class="editor-rule editor-head"><span>Name</span><span>Action</span><span>Source</span><span>Service</span><span>Limit</span><span>Value</span><span>Track</span><span></span></div>
    <div id="edRules">${p.rules.map(ruleRow).join("")}</div>
    <button type="button" class="btn ghost sm" id="edAdd">+ Add rule</button>
    <div class="card" style="margin:16px 0 0;padding:14px">
      <div class="row" style="align-items:end">
        <label class="switch"><input type="checkbox" id="edPbox" ${p.pbox.enabled ? "checked" : ""}><span></span> Penalty Box</label>
        <label class="f">Drops threshold (per s)<input id="edThr" type="number" min="1" value="${p.pbox.threshold}"></label>
        <label class="f">Timeout (s)<input id="edTmo" type="number" min="1" value="${p.pbox.timeout}"></label>
        <label class="switch"><input type="checkbox" id="edLog" ${p.pbox.log_drops ? "checked" : ""}><span></span> Log drops</label>
      </div>
    </div>
    <p class="muted small">Destination is always A-DMZ (${esc(S.snap.dmz_ip)}). Track <b>source</b> applies the limit to each source separately. Track <b>none</b> applies it to all sources combined. Names must start with <code>${esc(S.snap.prefix)}</code>.</p>`;
  modal(isCustom ? `Edit · ${p.name}` : "New custom profile", body, [{
    label: "Save profile", onClick: async () => {
      const rules = $$("#edRules .editor-rule").map((row) => {
        const o = {};
        $$("input,select", row).forEach((i) => (o[i.name] = i.value));
        o.value = Number(o.value);
        return o;
      });
      try {
        await api("POST", "/api/profiles", {
          id: isCustom ? p.id : "", name: $("#edName").value, tagline: $("#edTag").value, description: $("#edDesc").value,
          level: Number($("#edLevel").value), rules,
          pbox: { enabled: $("#edPbox").checked, threshold: Number($("#edThr").value), timeout: Number($("#edTmo").value), log_drops: $("#edLog").checked },
        });
        toast("Profile saved");
        closeModal();
        refresh();
      } catch (err) { toast(esc(err.message), "bad"); }
    },
  }]);
  $("#edAdd").onclick = () => $("#edRules").insertAdjacentHTML("beforeend", ruleRow());
  $("#edRules").addEventListener("click", (e) => { if (e.target.closest("[data-rmrow]")) e.target.closest(".editor-rule").remove(); });
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

function renderRuleForm() {
  const f = $("#ruleForm");
  if (f.dataset.ready) return;
  f.dataset.ready = 1;
  f.innerHTML = `
    <label class="f">Name<input name="name" class="mono" value="${esc(S.snap.prefix)}custom-1" required></label>
    <label class="f">Action<select name="action"><option>notify</option><option>drop</option></select></label>
    <label class="f">Source<input name="source" class="mono" value="any" title="any, IP or CIDR"></label>
    <label class="f">Service<select name="service"><option value="any">any</option><option value="6/80">HTTP 6/80</option><option value="6/443">HTTPS 6/443</option><option value="6/22">SSH 6/22</option><option value="6/3389">RDP 6/3389</option><option value="6/5201">iperf3 6/5201</option><option value="17/5202">iperf3 UDP 17/5202</option></select></label>
    <label class="f">Limit<select name="limit"><option value="pkt-rate">pkt-rate (pkt/s)</option><option value="new-conn-rate">new-conn-rate (conn/s)</option><option value="concurrent-conns">concurrent-conns</option><option value="bytes">bytes (B/s)</option></select></label>
    <label class="f">Value<input name="value" type="number" min="1" value="100"></label>
    <label class="f">Track<select name="track"><option>source</option><option>source-service</option><option>none</option></select></label>
    <button class="btn">Add to cluster</button>`;
  f.onsubmit = (e) => {
    e.preventDefault();
    const o = Object.fromEntries(new FormData(f));
    o.value = Number(o.value);
    runAction(`Add ${o.name}`, api("POST", "/api/rules", o));
  };
}

function renderRules() {
  renderRuleForm();
  const prefix = S.snap.prefix;
  $("#rulesByMember").innerHTML = memberEntries().map(([name, m]) => `
    <div class="card">
      <div class="card-head"><h3>${esc(name)} <span class="muted small">${m.cluster_state || ""}</span></h3><span class="muted small">${m.rules.length} rule(s)</span></div>
      ${m.rules.length ? `<div class="table-wrap"><table class="t"><thead><tr><th>Name</th><th>Action</th><th>Match</th><th>Limit</th><th>Track</th><th>UID</th><th></th></tr></thead><tbody>
        ${m.rules.map((r) => {
          const limit = ["pkt-rate", "new-conn-rate", "concurrent-conns", "bytes"].find((k) => r[k]);
          const lab = (r.name || "").startsWith(prefix);
          return `<tr class="${lab ? "lab-row" : ""}"><td class="mono">${esc(r.name || "—")}</td>
            <td><span class="chip ${r.action || ""}">${esc(r.action || "?")}</span></td>
            <td class="small mono">${esc(r.source || "any")} → ${esc(r.destination || "any")} · ${esc(svcLabel(r.service || "any"))}</td>
            <td class="mono">${limit ? `${Number(r[limit]).toLocaleString()} ${limitLabel[limit]}` : "—"}</td>
            <td>${esc(r.track || "—")}</td>
            <td class="small mono muted">${esc(r.uid || "")}</td>
            <td>${r.uid ? `<button class="btn link" data-delrule="${esc(r.uid)}" data-member="${esc(name)}" data-name="${esc(r.name || "")}" data-lab="${lab ? 1 : ""}">Delete</button>` : ""}</td></tr>`;
        }).join("")}</tbody></table></div>` : `<div class="empty">No rate-limiting rules parsed from this member.</div>`}
      <details><summary>Raw output · fwaccel dos rate get</summary><pre class="raw">${esc(m.raw.rate_get)}</pre></details>
    </div>`).join("");
}

document.addEventListener("click", (e) => {
  const d = e.target.closest("[data-delrule]");
  if (!d) return;
  const { delrule: uid, member, name, lab } = d.dataset;
  const buttons = [{ label: `Delete on ${member} only`, cls: "ghost", onClick: () => runAction(`Delete ${name || uid}`, api("POST", "/api/rules/delete", { uid, member })) }];
  if (lab) buttons.unshift({ label: "Delete on all members", cls: "danger", onClick: () => runAction(`Delete ${name}`, api("POST", "/api/rules/delete-by-name", { name })) });
  modal(`Delete ${name || "rule"}?`, `<p class="mono small">${esc(uid)}</p>${lab ? "" : `<div class="banner warn">This rule was not created by the lab profiles. It may be part of a production policy.</div>`}`, buttons);
});

// ---------------------------------------------------------------------------
// Penalty Box and deny list
// ---------------------------------------------------------------------------

function renderPbox() {
  const members = memberEntries();
  const first = members[0]?.[1].pbox || {};
  const f = $("#pboxForm");
  if (!f.dataset.ready) {
    f.dataset.ready = 1;
    f.innerHTML = `
      <label class="switch"><input type="checkbox" name="enabled"><span></span> Enforce Penalty Box</label>
      <div class="row">
        <label class="f">Drops threshold (packets/s)<input name="threshold" type="number" min="1"></label>
        <label class="f">Timeout (seconds)<input name="timeout" type="number" min="1"></label>
      </div>
      <label class="switch"><input type="checkbox" name="log_drops"><span></span> Log Penalty Box drops</label>
      <div class="row" style="flex:none"><button class="btn">Apply to cluster</button></div>`;
    f.onsubmit = (e) => {
      e.preventDefault();
      runAction("Penalty Box", api("POST", "/api/pbox", {
        enabled: f.enabled.checked, threshold: Number(f.threshold.value), timeout: Number(f.timeout.value), log_drops: f.log_drops.checked,
      }));
    };
  }
  if (document.activeElement?.form !== f) {
    f.enabled.checked = !!first.enabled;
    f.log_drops.checked = !!first.log_drops;
    f.threshold.value = first.threshold ?? 500;
    f.timeout.value = first.timeout ?? 180;
  }
  const boxed = members.flatMap(([n, m]) => m.pbox.boxed.map((ip) => [n, ip]));
  $("#pboxStamp").textContent = `as of ${S.snap.time}`;
  $("#pboxList").innerHTML = boxed.length
    ? boxed.map(([n, ip]) => `<div class="boxed-ip"><span>⛔ ${esc(ip)}${ip === "192.168.11.201" ? " · A-Host" : ""}</span><span class="muted small">${esc(n)}</span></div>`).join("")
    : `<div class="empty">No sources in the Penalty Box.</div>`;
  $("#pboxRaw").innerHTML = `<div class="grid-2">${members.map(([n, m]) => `
    <div class="card"><div class="card-head"><h3>${esc(n)}</h3><span class="chip ${m.pbox.enabled ? "on" : ""}">${m.pbox.enabled ? "enabled" : m.pbox.enabled === false ? "disabled" : "unknown"}</span></div>
      <pre class="raw">${esc(m.raw.pbox_show_config)}\n${esc(m.raw.pbox_show)}</pre></div>`).join("")}</div>`;
}

function renderDeny() {
  const rows = memberEntries().flatMap(([n, m]) => m.deny.map((ip) => [n, ip]));
  const ips = [...new Set(rows.map((r) => r[1]))];
  $("#denyList").innerHTML = ips.length
    ? `<table class="t"><thead><tr><th>Address</th><th>Present on</th><th></th></tr></thead><tbody>${ips.map((ip) => `
      <tr><td class="mono">${esc(ip)}</td><td>${rows.filter((r) => r[1] === ip).map((r) => esc(r[0])).join(", ")}</td>
      <td><button class="btn link" data-undeny="${esc(ip)}">Remove</button></td></tr>`).join("")}</tbody></table>`
    : `<div class="empty">Deny list is empty.</div>`;
}
$("#denyForm").onsubmit = (e) => {
  e.preventDefault();
  const ip = e.target.ip.value.trim();
  runAction(`Deny ${ip}`, api("POST", "/api/deny", { ip, op: "add" })).then(() => (e.target.ip.value = ""));
};
document.addEventListener("click", (e) => {
  const u = e.target.closest("[data-undeny]");
  if (u) runAction(`Remove ${u.dataset.undeny}`, api("POST", "/api/deny", { ip: u.dataset.undeny, op: "del" }));
});

// ---------------------------------------------------------------------------
// Live monitor
// ---------------------------------------------------------------------------

function diffLines(prev, next) {
  const old = new Set((prev || "").split("\n"));
  return esc(next).split("\n").map((l, i) => (prev && !old.has(next.split("\n")[i]) ? `<span class="chg">${l}</span>` : l)).join("\n");
}

function setPre(pre, prevText, text) {
  if (prevText === text && pre.childNodes.length) return;
  const top = pre.scrollTop, left = pre.scrollLeft;
  pre.innerHTML = diffLines(prevText, text);
  pre.scrollTop = top;
  pre.scrollLeft = left;
}

async function pollMonitor() {
  clearTimeout(S.monTimer);
  if (!$("#tab-monitor").classList.contains("active")) return;
  try {
    const m = await api("GET", "/api/monitor");
    const boxed = new Set(Object.values(m.boxed).flat());
    S.spark.push(boxed.size);
    if (S.spark.length > 100) S.spark.shift();
    drawSpark();
    $("#monStamp").textContent = `updated ${m.time}`;
    // Build each member's pane once, then only swap the text, so a refresh
    // never resets the reader's scroll position.
    const panes = $("#monitorPanes");
    for (const member of Object.keys(m.rate_counters)) {
      let card = panes.querySelector(`[data-member="${CSS.escape(member)}"]`);
      if (!card) {
        card = document.createElement("div");
        card.className = "card";
        card.dataset.member = member;
        card.innerHTML = `<div class="card-head"><h3>${esc(member)}</h3><span class="chip boxed-chip"></span></div>
          <div class="muted small">fwaccel dos rate counters</div><pre class="raw tall" data-k="c"></pre>
          <div class="muted small" style="margin-top:10px">fwaccel dos pbox --show</div><pre class="raw" data-k="p"></pre>`;
        panes.appendChild(card);
      }
      const n = m.boxed[member].length;
      const chip = card.querySelector(".boxed-chip");
      chip.className = `chip boxed-chip ${n ? "drop" : "on"}`;
      chip.textContent = `${n} boxed`;
      const prev = S.lastMon[member] || {};
      setPre(card.querySelector('[data-k="c"]'), prev.c, m.rate_counters[member]);
      setPre(card.querySelector('[data-k="p"]'), prev.p, m.pbox_show[member]);
    }
    for (const member of Object.keys(m.rate_counters)) S.lastMon[member] = { c: m.rate_counters[member], p: m.pbox_show[member] };
  } catch (e) {
    $("#monStamp").textContent = `monitor error: ${e.message}`;
  }
  if ($("#autoMon").checked) S.monTimer = setTimeout(pollMonitor, 3000);
}
$("#autoMon").onchange = pollMonitor;

function drawSpark() {
  const c = $("#spark");
  const w = (c.width = c.clientWidth * devicePixelRatio), h = (c.height = 90 * devicePixelRatio);
  const ctx = c.getContext("2d");
  ctx.clearRect(0, 0, w, h);
  const data = S.spark, max = Math.max(2, ...data);
  ctx.strokeStyle = "rgba(138,147,169,.18)";
  ctx.lineWidth = 1;
  for (let i = 1; i <= 2; i++) { ctx.beginPath(); ctx.moveTo(0, (h / 3) * i); ctx.lineTo(w, (h / 3) * i); ctx.stroke(); }
  if (data.length < 2) return;
  const x = (i) => (i / 99) * w, y = (v) => h - 8 * devicePixelRatio - (v / max) * (h - 20 * devicePixelRatio);
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, "rgba(236,14,90,.45)"); grad.addColorStop(1, "rgba(236,14,90,0)");
  ctx.beginPath(); ctx.moveTo(x(0), h);
  data.forEach((v, i) => ctx.lineTo(x(i), y(v)));
  ctx.lineTo(x(data.length - 1), h); ctx.fillStyle = grad; ctx.fill();
  ctx.beginPath(); data.forEach((v, i) => (i ? ctx.lineTo(x(i), y(v)) : ctx.moveTo(x(i), y(v))));
  ctx.strokeStyle = "#ff4d8a"; ctx.lineWidth = 2 * devicePixelRatio; ctx.stroke();
  ctx.fillStyle = "#e7eaf3"; ctx.font = `${12 * devicePixelRatio}px Inter`;
  ctx.fillText(`${data[data.length - 1]} boxed now · peak ${Math.max(...data)}`, 8 * devicePixelRatio, 16 * devicePixelRatio);
}

// ---------------------------------------------------------------------------
// Test lab guide
// ---------------------------------------------------------------------------

function code(text) {
  return `<div class="code">${copyBtn(text)}<pre>${esc(text)}</pre></div>`;
}

function renderTestGuide() {
  const dmz = S.snap?.dmz_ip || "192.168.12.101";
  const raw = "https://raw.githubusercontent.com/Don-Paterson/Lab-Traffic-Gen/main/LabTraffic.ps1";
  $("#testGuide").innerHTML = `
  <div class="card">
    <div class="card-head"><h3>Expected outcome</h3><span class="muted small">Lab-Traffic-Gen client on A-Host → A-DMZ. Figures are approximate.</span></div>
    <div class="table-wrap"><table class="t matrix">
      <thead><tr><th>Load (A-Host)</th><th>Rough rate to A-DMZ</th><th>Monitor</th><th>Basic · high tolerance</th><th>Strict · low tolerance</th></tr></thead>
      <tbody>
        <tr><td><b>Light</b></td><td class="small">~31 HTTP conn/s · ~3,300 pkt/s</td><td class="note">notify: HTTP, pkt</td><td class="pass">passes</td><td class="box">drops HTTP + pkt → Penalty Box</td></tr>
        <tr><td><b>Medium</b></td><td class="small">~78 HTTP conn/s · ~14,000 pkt/s</td><td class="note">notify: HTTP, pkt</td><td class="pass">passes (close to pkt cap)</td><td class="box">drops → Penalty Box</td></tr>
        <tr><td><b>Heavy</b></td><td class="small">~230 HTTP conn/s · ~41,000 pkt/s</td><td class="note">notify: all</td><td class="box">drops HTTP + pkt → Penalty Box</td><td class="box">drops → Penalty Box</td></tr>
      </tbody></table></div>
    <p class="muted small">Rates come from the Lab-Traffic-Gen profiles: HTTP clients from OpenWebLoad, and packets from iperf3 TCP plus 256-byte UDP. Real numbers depend on the Skillable host. Read the counters in Live Monitor rather than relying on this table.</p>
  </div>

  <div class="card"><div class="steps">
    <div class="step"><h4>Allow the test traffic <span class="where sc">SmartConsole</span></h4>
      <p class="muted small">Add an access rule above the cleanup rule and install policy. Set Track to <b>None</b>, because the HTTP load alone creates dozens of logs a second.</p>
      <table class="t small"><thead><tr><th>Source</th><th>Destination</th><th>Services</th><th>Action</th><th>Track</th></tr></thead>
      <tbody><tr><td>A-Host</td><td>A-DMZ</td><td>http, TCP 5201-5202, UDP 5201-5202</td><td>Accept</td><td>None</td></tr></tbody></table></div>

    <div class="step"><h4>Start the receiver <span class="where dmz">A-DMZ</span></h4>
      <p class="muted small">Elevated PowerShell. This starts iperf3 listeners on 5201/5202 and opens the Windows firewall. The web server on A-DMZ serves the HTTP load.</p>
      ${code(`irm ${raw} -OutFile C:\\LabTraffic.ps1\nC:\\LabTraffic.ps1 -Role Server -Action Start`)}</div>

    <div class="step"><h4>Baseline in Monitor mode <span class="where gui">A-GUI · this portal</span></h4>
      <p class="muted small">Apply <b>Monitor</b>, then open Live Monitor. Nothing is dropped. The counters show what each rule would have done.</p>
      <button class="btn ghost sm" data-apply="monitor">Apply Monitor</button> <button class="btn ghost sm" data-tabgo="monitor">Open Live Monitor</button></div>

    <div class="step"><h4>Generate load from inside the network <span class="where host">A-Host</span></h4>
      <p class="muted small">A-Host acts as the misbehaving internal client. Start with Light, watch the counters, then step up. Five-minute runs keep it light on the shared lab host.</p>
      ${code(`irm ${raw} -OutFile C:\\LabTraffic.ps1\nC:\\LabTraffic.ps1 -Role Client -Action Start -Load Light -Target ${dmz} -Duration 300`)}
      ${code(`C:\\LabTraffic.ps1 -Action Stop\nC:\\LabTraffic.ps1 -Role Client -Action Start -Load Heavy -Target ${dmz} -Duration 300`)}</div>

    <div class="step"><h4>Switch profiles and repeat <span class="where gui">A-GUI · this portal</span></h4>
      <p class="muted small">Apply <b>Basic</b> and run Light: it passes. Run Heavy: the HTTP and packet limits drop, and A-Host lands in the Penalty Box. Apply <b>Strict</b> and run Light again: it is caught straight away.</p>
      <button class="btn ghost sm" data-apply="basic">Apply Basic</button> <button class="btn ghost sm" data-apply="strict">Apply Strict</button></div>

    <div class="step"><h4>Watch it on the gateway <span class="where gui">Expert mode, active member</span></h4>
      ${code(`watch -n2 'fwaccel dos rate counters; fwaccel dos pbox --show'\nfwaccel dos stats get\ncpview   # Advanced > SecureXL`)}
      <p class="muted small">If A-Host is boxed, all of its traffic through the gateway is dropped until the timeout ends. That includes your RDP session to A-Host if it crosses the gateway, so use the lab console.</p></div>

    <div class="step"><h4>Test failover <span class="where gui">Expert mode</span></h4>
      ${code(`clusterXL_admin down   # on the active member\ncphaprob state\nclusterXL_admin up`)}
      <p class="muted small">Re-run the load. Overview → Cluster consistency should show identical lab rules, so protection carries over.</p></div>

    <div class="step"><h4>Clean up <span class="where host">A-Host</span> <span class="where gui">A-GUI</span></h4>
      ${code(`C:\\LabTraffic.ps1 -Action Stop`)}
      <button class="btn ghost sm" data-clear>Remove lab rules</button> <button class="btn ghost sm" data-tabgo="pbox">Penalty Box → switch off</button></div>
  </div></div>

  <div class="card"><div class="card-head"><h3>If nothing triggers</h3></div>
    <ul class="small" style="margin:0;padding-left:18px;line-height:1.9">
      <li>Counters stay at zero: check that traffic is on the member you are watching (<code>cphaprob state</code>) and is accelerated (<code>fwaccel stats -s</code>).</li>
      <li>Rate limiting or the Penalty Box can be limited to external interfaces. A-Host is behind eth2 (internal). Check <code>fwaccel dos config get</code> for the internal-interfaces setting.</li>
      <li>A command was rejected: open Settings → Command syntax and adjust the template to match <code>fwaccel dos rate -h</code> on your build.</li>
      <li>The client stops at "Cannot reach ${dmz} on TCP 5201": the receiver isn't running on A-DMZ, or the access rule is missing.</li>
    </ul></div>`;
}

// ---------------------------------------------------------------------------
// Activity and diagnostics
// ---------------------------------------------------------------------------

const DIAG = { cluster_state: "Cluster state", accel_stats: "SecureXL stats", dos_config: "DoS config", dos_stats: "DoS stats",
  rate_get: "Rate rules", rate_counters: "Rate counters", pbox_show_config: "PBox config", pbox_show: "PBox list", deny_show: "Deny list" };
$("#diagButtons").innerHTML = Object.entries(DIAG).map(([k, l]) => `<button class="btn ghost sm" data-diag="${k}">${l}</button>`).join("");
document.addEventListener("click", async (e) => {
  const d = e.target.closest("[data-diag]");
  if (!d) return;
  d.disabled = true;
  try {
    const res = await api("POST", `/api/diagnostics/${d.dataset.diag}`);
    modal(DIAG[d.dataset.diag], Object.entries(res).map(([m, r]) => `<div class="member-block"><h4>${esc(m)} <span class="${r.ok ? "st-ok" : "st-bad"}">${r.ok ? "✓" : "✗"}</span></h4><div class="muted small mono">${esc(r.cmd)}</div><pre class="raw">${esc(r.out || r.err)}</pre></div>`).join(""));
    loadAudit();
  } catch (err) { toast(esc(err.message), "bad"); }
  d.disabled = false;
});

async function loadAudit() {
  const rows = await api("GET", "/api/audit");
  $("#audit").innerHTML = rows.length ? rows.map((r) => `
    <div class="audit-row"><div class="meta"><span class="muted mono">${esc(r.ts)}</span><span class="chip">${esc(r.member)}</span>
      <span class="${r.ok ? "st-ok" : "st-bad"}">${r.ok ? "✓" : `✗ rc=${r.rc ?? "–"}`}</span><span class="muted small">${r.ms} ms</span></div>
      <div class="c">${esc(r.cmd)}</div>
      ${(r.out || r.err) ? `<details><summary>output</summary><pre class="raw">${esc((r.out || "") + (r.err || ""))}</pre></details>` : ""}</div>`).join("")
    : `<div class="empty">No commands sent yet.</div>`;
}
$("#clearAudit").onclick = async () => { await api("DELETE", "/api/audit"); loadAudit(); };

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

async function renderSettings() {
  const s = (S.settings = await api("GET", "/api/settings"));
  const f = $("#settingsForm");
  f.innerHTML = `
    <div class="grid-2">
      <div class="card"><div class="card-head"><h3>Cluster members</h3><span class="muted small">Reached over SSH from A-GUI</span></div>
        <div class="stack" id="memberRows">${s.members.map((m) => `
          <div class="row member-row"><label class="f">Name<input name="mname" value="${esc(m.name)}"></label><label class="f">Management IP<input name="mhost" class="mono" value="${esc(m.host)}"></label></div>`).join("")}</div>
        <div class="row" style="margin-top:12px">
          <label class="f">SSH user<input name="ssh_user" value="${esc(s.ssh_user)}"></label>
          <label class="f">Password<input name="ssh_password" type="password" value="${esc(s.ssh_password)}" placeholder="not set"></label>
          <label class="f" style="max-width:110px">Port<input name="ssh_port" type="number" value="${s.ssh_port}"></label>
        </div>
        <p class="muted small">The user's login shell must be bash (Expert). In clish: <code>set user admin shell /bin/bash</code> then <code>save config</code>. The password is stored in plain text in <code>data/settings.json</code> on A-GUI. That's acceptable for a lab, not for production.</p>
      </div>
      <div class="card"><div class="card-head"><h3>Scope</h3></div>
        <div class="stack">
          <label class="f">Protected server (A-DMZ)<input name="dmz_ip" class="mono" value="${esc(s.dmz_ip)}"></label>
          <label class="f">Lab rule prefix<input name="lab_prefix" class="mono" value="${esc(s.lab_prefix)}"></label>
          <p class="muted small" style="margin:0">Only rules whose name starts with this prefix are removed by "Apply" and "Remove lab rules".</p>
          <label class="switch"><input type="checkbox" name="simulator" ${s.simulator ? "checked" : ""}><span></span> Simulator mode (no SSH, in-memory gateways)</label>
        </div>
      </div>
    </div>
    <div class="card"><div class="card-head"><h3>Command syntax</h3><span class="muted small">Adjust to match <code>fwaccel dos … -h</code> on your R82 build / JHF</span></div>
      <div class="grid-2">${Object.entries(s.commands).map(([k, v]) => `
        <label class="f">${esc(k)}${v !== s.default_commands[k] ? ' <span class="pfx">· customised</span>' : ""}<textarea name="cmd_${k}" rows="1">${esc(v)}</textarea></label>`).join("")}</div>
      <p class="muted small">Placeholders: <code>{action}</code> d|n, <code>{name}</code>, <code>{match}</code>, <code>{limit}</code>, <code>{value}</code>, <code>{track}</code>, <code>{uid}</code>, <code>{onoff}</code>, <code>{ip}</code>. Clear a field to restore its default.</p>
    </div>
    <div class="row" style="flex:none"><button class="btn">Save settings</button> <button type="button" class="btn ghost" data-diag="cluster_state">Test connection</button></div>`;
  f.onsubmit = async (e) => {
    e.preventDefault();
    const names = $$("[name=mname]", f).map((i) => i.value), hosts = $$("[name=mhost]", f).map((i) => i.value);
    const commands = {};
    $$("textarea", f).forEach((t) => (commands[t.name.slice(4)] = t.value));
    try {
      await api("POST", "/api/settings", {
        members: names.map((n, i) => ({ name: n, host: hosts[i] })),
        ssh_user: f.ssh_user.value, ssh_password: f.ssh_password.value, ssh_port: Number(f.ssh_port.value),
        dmz_ip: f.dmz_ip.value, lab_prefix: f.lab_prefix.value, simulator: f.simulator.checked, commands,
      });
      toast("Settings saved");
      renderSettings();
      refresh();
    } catch (err) { toast(esc(err.message), "bad"); }
  };
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

(async function boot() {
  await refresh();
  renderTestGuide();
  renderSettings();
  const tab = location.hash.slice(1);
  showTab(TITLES[tab] ? tab : "overview");
  setInterval(() => { if (!$("#modal").hidden) return; if (!$("#tab-monitor").classList.contains("active")) refresh(); }, 20000);
})();
window.addEventListener("hashchange", () => { const t = location.hash.slice(1); if (TITLES[t]) showTab(t); });
