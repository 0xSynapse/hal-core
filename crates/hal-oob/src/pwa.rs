//! Embedded mobile-first PWA frontend (**HAL Key**) served on `hal-oob` (`mgmt0` / `wg-oob`).

pub const HAL_KEY_ICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64" fill="none">
  <rect width="64" height="64" rx="14" fill="#06110D"/>
  <path d="M32 8L54 17v15c0 14.4-9.6 24-22 27.6C19.6 56 10 46.4 10 32V17L32 8z" stroke="#00FF93" stroke-width="3" fill="#0B1D16"/>
  <circle cx="32" cy="28" r="6" stroke="#00FF93" stroke-width="2.8"/>
  <path d="M32 34v12M32 41h6" stroke="#00FF93" stroke-width="2.8" stroke-linecap="round"/>
</svg>
"##;

pub const HAL_KEY_MANIFEST_JSON: &str = r##"{
  "name": "HAL Key — Out-of-Band Sovereignty",
  "short_name": "HAL Key",
  "description": "Out-of-band human sovereignty controller for HAL Core",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#06110D",
  "theme_color": "#06110D",
  "icons": [
    {
      "src": "/icon.svg",
      "sizes": "any",
      "type": "image/svg+xml",
      "purpose": "any"
    }
  ]
}
"##;

pub const HAL_KEY_INDEX_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <meta name="theme-color" content="#06110D" />
  <meta name="apple-mobile-web-app-capable" content="yes" />
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
  <title>HAL Key · Out-of-Band Sovereignty</title>
  <link rel="manifest" href="/manifest.json" />
  <link rel="icon" type="image/svg+xml" href="/icon.svg" />
  <style>
    :root {
      --bg: #06110D;
      --card: #0B1B15;
      --card2: #0F241C;
      --border: #173B2D;
      --text: #E6F7EF;
      --muted: #84AC9A;
      --accent: #00FF93;
      --accent-dim: rgba(0, 255, 147, 0.14);
      --warn: #F59E0B;
      --warn-dim: rgba(245, 158, 11, 0.16);
      --danger: #EF4444;
      --danger-dim: rgba(239, 68, 68, 0.16);
      --radius: 12px;
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      padding: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      -webkit-font-smoothing: antialiased;
    }
    .wrap {
      max-width: 780px;
      margin: 0 auto;
      padding: 14px 14px 88px;
    }
    header.topbar {
      position: sticky;
      top: 0;
      z-index: 20;
      background: rgba(6, 17, 13, 0.94);
      backdrop-filter: blur(8px);
      border-bottom: 1px solid var(--border);
      padding: 10px 14px;
    }
    .topbar-inner {
      max-width: 780px;
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      flex-wrap: wrap;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .brand img { width: 28px; height: 28px; }
    .brand h1 { font-size: 16px; margin: 0; letter-spacing: 0.3px; }
    .brand small { display: block; color: var(--muted); font-size: 11px; }
    .controls {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      border: 1px solid var(--border);
      background: var(--card);
    }
    .pill.ok { color: var(--accent); background: var(--accent-dim); border-color: rgba(0,255,147,0.35); }
    .pill.warn { color: var(--warn); background: var(--warn-dim); border-color: rgba(245,158,11,0.35); }
    .pill.danger { color: var(--danger); background: var(--danger-dim); border-color: rgba(239,68,68,0.4); }
    .summary-strip {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 8px;
      margin: 12px 0;
    }
    .stat {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 10px 12px;
    }
    .stat label { display: block; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.4px; }
    .stat .val { font-size: 17px; font-weight: 700; margin-top: 2px; font-family: var(--mono); }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 14px;
      margin-bottom: 12px;
    }
    .card h2 { margin: 0 0 8px; font-size: 15px; }
    .card h3 { margin: 0 0 6px; font-size: 14px; }
    .muted { color: var(--muted); font-size: 12px; }
    .mono { font-family: var(--mono); word-break: break-all; }
    pre.args {
      background: #040B08;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px 10px;
      font-family: var(--mono);
      font-size: 12px;
      overflow-x: auto;
      margin: 8px 0;
      white-space: pre-wrap;
    }
    input, select, button {
      font-family: inherit;
      font-size: 14px;
      border-radius: 8px;
    }
    input, select {
      width: 100%;
      padding: 10px 12px;
      background: #040B08;
      color: var(--text);
      border: 1px solid var(--border);
      outline: none;
    }
    input:focus, select:focus { border-color: var(--accent); }
    button {
      cursor: pointer;
      border: 1px solid var(--border);
      background: var(--card2);
      color: var(--text);
      padding: 9px 13px;
      font-weight: 600;
    }
    button.primary { background: var(--accent); color: #04130D; border-color: var(--accent); }
    button.warn { background: var(--warn-dim); color: var(--warn); border-color: rgba(245,158,11,0.45); }
    button.danger { background: var(--danger-dim); color: var(--danger); border-color: rgba(239,68,68,0.5); }
    button.small { padding: 6px 10px; font-size: 12px; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .row > .grow { flex: 1 1 180px; }
    .kv { display: grid; grid-template-columns: 110px 1fr; gap: 4px 10px; font-size: 12px; margin: 8px 0; }
    .kv b { color: var(--muted); font-weight: 600; }
    .banner {
      padding: 10px 12px;
      border-radius: 8px;
      margin-bottom: 12px;
      font-size: 13px;
      border: 1px solid var(--danger);
      background: var(--danger-dim);
      color: #FECACA;
    }
    .banner.info {
      border-color: rgba(0,255,147,0.4);
      background: var(--accent-dim);
      color: var(--text);
    }
    .hidden { display: none !important; }
    nav.tabs {
      position: fixed;
      left: 0;
      right: 0;
      bottom: 0;
      z-index: 30;
      background: rgba(6, 17, 13, 0.96);
      backdrop-filter: blur(8px);
      border-top: 1px solid var(--border);
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      padding: 6px 8px calc(6px + env(safe-area-inset-bottom));
      gap: 6px;
    }
    nav.tabs button {
      background: transparent;
      border: 1px solid transparent;
      color: var(--muted);
      padding: 8px 4px;
      font-size: 12px;
      border-radius: 8px;
    }
    nav.tabs button.active {
      color: var(--accent);
      background: var(--accent-dim);
      border-color: rgba(0,255,147,0.3);
    }
    .mode-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 8px;
      margin-top: 10px;
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand">
        <img src="/icon.svg" alt="HAL Key" />
        <div>
          <h1>HAL Key · OOB</h1>
          <small id="hdrAudit">Sovereignty Console (mgmt0 / wg-oob)</small>
        </div>
      </div>
      <div class="controls">
        <span id="hdrMode" class="pill ok">Locked</span>
        <button id="btnPoll" class="small hidden" type="button">Auto: On</button>
        <button id="btnRefresh" class="small hidden" type="button">Refresh</button>
        <button id="btnLock" class="small danger hidden" type="button">Lock</button>
      </div>
    </div>
  </header>

  <main class="wrap">
    <div id="banner" class="banner hidden"></div>

    <section id="unlockView" class="card">
      <h2>Unlock HAL Key</h2>
      <p class="muted">Enter your out-of-band operator token (<code>X-Hal-Oob-Token</code>). Stored only in browser <code>sessionStorage</code> until locked or closed.</p>
      <form id="unlockForm" class="row" style="margin-top: 10px;">
        <div class="grow">
          <input id="tokenInput" type="password" placeholder="OOB Operator Token" autocomplete="off" required />
        </div>
        <button class="primary" type="submit">Unlock</button>
      </form>
    </section>

    <section id="appView" class="hidden">
      <div class="summary-strip">
        <div class="stat"><label>Pending L2</label><div class="val" id="statPending">0</div></div>
        <div class="stat"><label>Agents / Frozen</label><div class="val" id="statAgents">0 / 0</div></div>
        <div class="stat"><label>Audit Chain</label><div class="val" id="statAudit">0</div></div>
      </div>

      <div id="tab-approvals" class="tab-panel"></div>
      <div id="tab-agents" class="tab-panel hidden"></div>
      <div id="tab-mode" class="tab-panel hidden"></div>
      <div id="tab-audit" class="tab-panel hidden"></div>
    </section>
  </main>

  <nav id="tabBar" class="tabs hidden">
    <button type="button" data-tab="approvals" class="active">Approvals</button>
    <button type="button" data-tab="agents">Agents</button>
    <button type="button" data-tab="mode">Mode</button>
    <button type="button" data-tab="audit">Audit</button>
  </nav>

  <script>
    (function () {
      const STORAGE_KEY = "hal_key_oob_token";
      const state = {
        token: sessionStorage.getItem(STORAGE_KEY) || "",
        tab: "approvals",
        autoPoll: true,
        timer: null,
        status: null,
        approvals: [],
        agents: [],
        systemMode: "Autonomous",
        auditRecords: [],
        verifyInfo: null
      };

      const $ = (id) => document.getElementById(id);

      function el(tag, attrs, ...children) {
        const node = document.createElement(tag);
        if (attrs) {
          for (const [k, v] of Object.entries(attrs)) {
            if (k === "class") node.className = v;
            else if (k === "type") node.type = v;
            else if (k === "value") node.value = v;
            else if (k === "placeholder") node.placeholder = v;
            else if (k === "disabled") node.disabled = !!v;
            else if (k === "onClick") node.addEventListener("click", v);
            else node.setAttribute(k, v);
          }
        }
        for (const ch of children) {
          if (ch === null || ch === undefined) continue;
          node.appendChild(typeof ch === "string" ? document.createTextNode(ch) : ch);
        }
        return node;
      }

      function showBanner(msg, isInfo) {
        const b = $("banner");
        if (!msg) {
          b.className = "banner hidden";
          b.textContent = "";
          return;
        }
        b.className = isInfo ? "banner info" : "banner";
        b.textContent = msg;
      }

      async function api(method, path, body) {
        const headers = { "X-Hal-Oob-Token": state.token };
        const opts = { method, headers };
        if (body !== undefined) {
          headers["Content-Type"] = "application/json";
          opts.body = JSON.stringify(body);
        }
        const resp = await fetch(path, opts);
        let data = {};
        try { data = await resp.json(); } catch (_) {}
        if (resp.status === 401) {
          lockKey("Session locked: unauthorized token (401).");
          throw new Error(data.reason || "Unauthorized");
        }
        if (!resp.ok) {
          throw new Error((data.code ? data.code + ": " : "") + (data.reason || ("HTTP " + resp.status)));
        }
        return data;
      }

      function modePillClass(mode) {
        const m = String(mode || "").toLowerCase();
        if (m === "autonomous") return "pill ok";
        if (m === "advisory") return "pill warn";
        return "pill danger";
      }

      function lockKey(reason) {
        state.token = "";
        sessionStorage.removeItem(STORAGE_KEY);
        if (state.timer) { clearInterval(state.timer); state.timer = null; }
        $("unlockView").classList.remove("hidden");
        $("appView").classList.add("hidden");
        $("tabBar").classList.add("hidden");
        $("btnPoll").classList.add("hidden");
        $("btnRefresh").classList.add("hidden");
        $("btnLock").classList.add("hidden");
        $("hdrMode").className = "pill warn";
        $("hdrMode").textContent = "Locked";
        $("hdrAudit").textContent = "Sovereignty Console (mgmt0 / wg-oob)";
        if (reason) showBanner(reason, false);
      }

      function showUnlocked() {
        $("unlockView").classList.add("hidden");
        $("appView").classList.remove("hidden");
        $("tabBar").classList.remove("hidden");
        $("btnPoll").classList.remove("hidden");
        $("btnRefresh").classList.remove("hidden");
        $("btnLock").classList.remove("hidden");
        startPolling();
      }

      function startPolling() {
        if (state.timer) { clearInterval(state.timer); state.timer = null; }
        if (state.autoPoll && state.token) {
          state.timer = setInterval(() => { refreshAll(true); }, 2000);
        }
        $("btnPoll").textContent = "Auto: " + (state.autoPoll ? "On" : "Off");
      }

      async function refreshAll(quiet) {
        if (!state.token) return;
        try {
          const [status, approvals, agents, audit] = await Promise.all([
            api("GET", "/api/v1/status"),
            api("GET", "/api/v1/approvals"),
            api("GET", "/api/v1/agents"),
            api("GET", "/api/v1/audit/records?after_seq=0")
          ]);
          state.status = status;
          state.approvals = approvals.approvals || [];
          state.agents = agents.agents || [];
          state.systemMode = agents.system_mode || status.system_mode || "Autonomous";
          state.auditRecords = audit.records || [];
          if (!quiet) showBanner("");
          renderHeader();
          renderActiveTab();
        } catch (err) {
          showBanner(err.message || String(err), false);
        }
      }

      function renderHeader() {
        const s = state.status || {};
        const mode = s.system_mode || state.systemMode || "Unknown";
        const pill = $("hdrMode");
        pill.className = modePillClass(mode);
        pill.textContent = mode;
        const hash = String(s.audit_head_hash || "");
        $("hdrAudit").textContent = "Records: " + (s.audit_records || 0) + (hash ? " · Head " + hash.slice(0, 12) + "..." : "");
        $("statPending").textContent = String(s.pending_approval_count || 0);
        $("statAgents").textContent = String(s.agent_count || 0) + " / " + String(s.frozen_count || 0);
        $("statAudit").textContent = String(s.audit_records || 0);

        const pendingCount = s.pending_approval_count || 0;
        const tabBtn = document.querySelector('nav.tabs button[data-tab="approvals"]');
        if (tabBtn) tabBtn.textContent = pendingCount > 0 ? "Approvals (" + pendingCount + ")" : "Approvals";
      }

      function renderApprovals() {
        const root = $("tab-approvals");
        root.textContent = "";
        const pending = state.approvals.filter((a) => a.status === "Pending");
        const resolved = state.approvals.filter((a) => a.status !== "Pending").slice().reverse();

        if (pending.length === 0) {
          root.appendChild(el("div", { class: "card" },
            el("h2", null, "No Pending L2 Approvals"),
            el("p", { class: "muted" }, "All high-risk external, vault, merge, or actuator proposals are clear.")
          ));
        } else {
          for (const item of pending) {
            const noteInput = el("input", { type: "text", placeholder: "Operator note (optional)" });
            const p = item.proposal || {};
            const prin = item.principal || {};
            const card = el("div", { class: "card" },
              el("div", { class: "row", style: "justify-content:space-between;" },
                el("h3", null, (prin.agent_id || p.agent_id || "unknown") + " -> " + (p.action || "?")),
                el("span", { class: "pill warn" }, item.risk_tier || "L2")
              ),
              el("div", { class: "kv" },
                el("b", null, "Approval ID"), el("span", { class: "mono" }, item.approval_id || ""),
                el("b", null, "Target Path"), el("span", { class: "mono" }, p.target_path || ""),
                el("b", null, "Trust Domain"), el("span", null, String(prin.trust_domain || "")),
                el("b", null, "Reason"), el("span", null, p.reason || item.summary || "")
              ),
              el("pre", { class: "args" }, JSON.stringify(p.args || {}, null, 2)),
              el("div", { class: "row" },
                el("div", { class: "grow" }, noteInput),
                el("button", {
                  class: "primary",
                  type: "button",
                  onClick: async () => {
                    try {
                      await api("POST", "/api/v1/approvals/" + encodeURIComponent(item.approval_id) + "/approve", {
                        note: noteInput.value.trim() || "approved via HAL Key"
                      });
                      showBanner("Approved " + item.approval_id, true);
                      await refreshAll(true);
                    } catch (e) { showBanner(e.message, false); }
                  }
                }, "Approve"),
                el("button", {
                  class: "danger",
                  type: "button",
                  onClick: async () => {
                    try {
                      await api("POST", "/api/v1/approvals/" + encodeURIComponent(item.approval_id) + "/reject", {
                        note: noteInput.value.trim() || "rejected via HAL Key"
                      });
                      showBanner("Rejected " + item.approval_id, true);
                      await refreshAll(true);
                    } catch (e) { showBanner(e.message, false); }
                  }
                }, "Reject")
              )
            );
            root.appendChild(card);
          }
        }

        if (resolved.length > 0) {
          const hist = el("div", { class: "card" }, el("h2", null, "Recent Resolved (" + resolved.length + ")"));
          for (const item of resolved.slice(0, 10)) {
            const p = item.proposal || {};
            const cls = item.status === "Approved" ? "pill ok" : "pill danger";
            hist.appendChild(el("div", { class: "kv", style: "border-top:1px solid var(--border);padding-top:8px;" },
              el("b", null, item.approval_id),
              el("div", { class: "row" },
                el("span", { class: cls }, item.status),
                el("span", { class: "mono" }, (p.agent_id || "") + " · " + (p.target_path || ""))
              ),
              el("b", null, "Note"),
              el("span", { class: "muted" }, item.resolution_note || "-")
            ));
          }
          root.appendChild(hist);
        }
      }

      function renderAgents() {
        const root = $("tab-agents");
        root.textContent = "";
        if (state.agents.length === 0) {
          root.appendChild(el("div", { class: "card" },
            el("h2", null, "No Agents Registered"),
            el("p", { class: "muted" }, "Agents appear once they bind to hal-bus or authenticate via hal-gateway.")
          ));
          return;
        }
        for (const entry of state.agents) {
          const prin = entry.principal || {};
          const frozen = !!entry.frozen_reason;
          const id = prin.agent_id || "unknown";
          const reasonInput = el("input", { type: "text", placeholder: "Freeze / revoke reason" });
          const card = el("div", { class: "card" },
            el("div", { class: "row", style: "justify-content:space-between;" },
              el("h3", { class: "mono" }, id),
              el("span", { class: frozen ? "pill danger" : "pill ok" }, frozen ? "FROZEN" : "ACTIVE")
            ),
            el("div", { class: "kv" },
              el("b", null, "Trust Domain"), el("span", null, String(prin.trust_domain || "")),
              el("b", null, "Auth Kind"), el("span", null, String(prin.auth_kind || "")),
              el("b", null, "Credential"), el("span", { class: "mono" }, String(prin.peer_cred_or_cert_fp || "")),
              frozen ? el("b", null, "Frozen Reason") : null,
              frozen ? el("span", { class: "mono" }, entry.frozen_reason) : null
            ),
            el("div", { class: "row" },
              el("div", { class: "grow" }, reasonInput),
              frozen
                ? el("button", {
                    class: "primary small",
                    type: "button",
                    onClick: async () => {
                      try {
                        await api("POST", "/api/v1/agents/" + encodeURIComponent(id) + "/unfreeze", {});
                        showBanner("Unfroze " + id, true);
                        await refreshAll(true);
                      } catch (e) { showBanner(e.message, false); }
                    }
                  }, "Unfreeze")
                : el("button", {
                    class: "warn small",
                    type: "button",
                    onClick: async () => {
                      try {
                        await api("POST", "/api/v1/agents/" + encodeURIComponent(id) + "/freeze", {
                          reason: reasonInput.value.trim() || "hal-key surgical freeze"
                        });
                        showBanner("Froze " + id, true);
                        await refreshAll(true);
                      } catch (e) { showBanner(e.message, false); }
                    }
                  }, "Freeze"),
              el("button", {
                class: "danger small",
                type: "button",
                onClick: async () => {
                  try {
                    await api("POST", "/api/v1/agents/" + encodeURIComponent(id) + "/revoke", {
                      reason: reasonInput.value.trim() || "hal-key operator revoke"
                    });
                    showBanner("Revoked " + id, true);
                    await refreshAll(true);
                  } catch (e) { showBanner(e.message, false); }
                }
              }, "Revoke")
            )
          );
          root.appendChild(card);
        }
      }

      function renderMode() {
        const root = $("tab-mode");
        root.textContent = "";
        const reasonInput = el("input", { type: "text", placeholder: "Mode transition reason (optional)" });
        const modes = [
          { id: "autonomous", label: "Autonomous", cls: "primary" },
          { id: "advisory", label: "Advisory (L0 only)", cls: "warn" },
          { id: "frozen", label: "FROZEN (Halt Cognition)", cls: "danger" },
          { id: "lockdown", label: "LOCKDOWN (Cut wan0)", cls: "danger" }
        ];
        const grid = el("div", { class: "mode-grid" });
        for (const m of modes) {
          grid.appendChild(el("button", {
            class: m.cls,
            type: "button",
            onClick: async () => {
              if ((m.id === "frozen" || m.id === "lockdown") &&
                  !window.confirm("Switch HAL Core to " + m.id.toUpperCase() + "? Cognitive agents will be halted.")) {
                return;
              }
              try {
                await api("POST", "/api/v1/mode", {
                  mode: m.id,
                  reason: reasonInput.value.trim() || "hal-key operator switch"
                });
                showBanner("System mode set to " + m.id.toUpperCase(), true);
                await refreshAll(true);
              } catch (e) { showBanner(e.message, false); }
            }
          }, m.label));
        }

        root.appendChild(el("div", { class: "card" },
          el("h2", null, "Global Degradation Mode · " + state.systemMode),
          el("p", { class: "muted" }, "Unidirectional security lock: only human out-of-band actions via HAL Key or serial console can restore Autonomous mode."),
          reasonInput,
          grid
        ));

        const resInput = el("input", { type: "text", value: "/habitat/study/temp", placeholder: "Resource path e.g. /habitat/study/temp" });
        root.appendChild(el("div", { class: "card" },
          el("h2", null, "OOB Effector Lease Preemption"),
          el("p", { class: "muted" }, "Immediately preempt any active agent lease on a shared physical effector or workspace."),
          el("div", { class: "row" },
            el("div", { class: "grow" }, resInput),
            el("button", {
              class: "warn",
              type: "button",
              onClick: async () => {
                try {
                  const res = await api("POST", "/api/v1/leases/preempt", {
                    resource_path: resInput.value.trim(),
                    ttl_ms: 60000
                  });
                  showBanner("Preempted lease on " + resInput.value.trim() + " (previous=" + (res.preempted_lease_id || "none") + ")", true);
                } catch (e) { showBanner(e.message, false); }
              }
            }, "Preempt Lease")
          )
        ));
      }

      function renderAudit() {
        const root = $("tab-audit");
        root.textContent = "";
        const verifyCard = el("div", { class: "card" },
          el("div", { class: "row", style: "justify-content:space-between;" },
            el("h2", null, "SHA-256 Append-Only Audit Black Box"),
            el("button", {
              class: "primary small",
              type: "button",
              onClick: async () => {
                try {
                  const v = await api("GET", "/api/v1/audit/verify");
                  state.verifyInfo = v;
                  showBanner("Audit chain verified: " + v.record_count + " records (head_seq=" + v.head_seq + ")", true);
                  renderAudit();
                } catch (e) { showBanner(e.message, false); }
              }
            }, "Verify Hash Chain")
          ),
          state.verifyInfo
            ? el("p", { class: "mono muted" }, "Verified count=" + state.verifyInfo.record_count + " head_hash=" + state.verifyInfo.head_hash)
            : el("p", { class: "muted" }, "Tap Verify Hash Chain to cryptographically validate every record on the host audit log.")
        );
        root.appendChild(verifyCard);

        const recs = state.auditRecords.slice().reverse().slice(0, 50);
        if (recs.length === 0) {
          root.appendChild(el("div", { class: "card" }, el("p", { class: "muted" }, "No audit records yet.")));
          return;
        }
        const listCard = el("div", { class: "card" }, el("h3", null, "Latest Events (" + recs.length + ")"));
        for (const r of recs) {
          const actor = (r.principal && r.principal.agent_id) || "?";
          listCard.appendChild(el("div", { class: "kv", style: "border-top:1px solid var(--border);padding-top:6px;" },
            el("b", null, "#" + r.seq + " " + actor),
            el("span", { class: "mono" }, (r.action || "") + " " + (r.target_path || "")),
            el("b", null, "Decision"),
            el("span", { class: "mono muted" }, r.decision_summary || "")
          ));
        }
        root.appendChild(listCard);
      }

      function renderActiveTab() {
        for (const name of ["approvals", "agents", "mode", "audit"]) {
          const panel = $("tab-" + name);
          if (name === state.tab) panel.classList.remove("hidden");
          else panel.classList.add("hidden");
        }
        document.querySelectorAll("nav.tabs button").forEach((btn) => {
          btn.classList.toggle("active", btn.getAttribute("data-tab") === state.tab);
        });
        if (state.tab === "approvals") renderApprovals();
        else if (state.tab === "agents") renderAgents();
        else if (state.tab === "mode") renderMode();
        else renderAudit();
      }

      $("unlockForm").addEventListener("submit", async (e) => {
        e.preventDefault();
        const tok = $("tokenInput").value.trim();
        if (!tok) return;
        state.token = tok;
        try {
          await api("GET", "/api/v1/status");
          sessionStorage.setItem(STORAGE_KEY, tok);
          $("tokenInput").value = "";
          showUnlocked();
          await refreshAll(false);
        } catch (err) {
          state.token = "";
          showBanner("Unlock failed: " + (err.message || err), false);
        }
      });

      $("btnLock").addEventListener("click", () => lockKey("HAL Key locked by operator."));
      $("btnRefresh").addEventListener("click", () => refreshAll(false));
      $("btnPoll").addEventListener("click", () => {
        state.autoPoll = !state.autoPoll;
        startPolling();
      });

      document.querySelectorAll("nav.tabs button").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.tab = btn.getAttribute("data-tab") || "approvals";
          renderActiveTab();
        });
      });

      if (state.token) {
        showUnlocked();
        refreshAll(false);
      }
    })();
  </script>
</body>
</html>
"##;
