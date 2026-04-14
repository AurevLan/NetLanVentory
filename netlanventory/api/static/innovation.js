/* Innovation roadmap UI (v0.14)
 *
 * Standalone module that adds five new sections to the dashboard without
 * touching app.js (~9000 lines). Each section is rendered into its own
 * container appended to <main> on first call, and exposes a tiny global
 * window.NLV_Innovation API so the existing app.js navigation can wire
 * tabs into it later.
 *
 * Sections:
 *   - Compensating Controls : per-asset effective severity table
 *   - Attack Paths          : top critical chains, with hop list
 *   - Scheduler Priorities  : smart re-scan queue + budget
 *   - Remediation Workflow  : kanban-style state board
 *   - AI Triage             : urgency-coloured recommendation card
 *
 * Uses fetch + the JWT in localStorage (same pattern as app.js).
 */
(function () {
  "use strict";

  // ── HTTP helper ──────────────────────────────────────────────────────────
  async function api(path, opts = {}) {
    const token = localStorage.getItem("token") || localStorage.getItem("jwt");
    const headers = Object.assign(
      { "Content-Type": "application/json" },
      opts.headers || {},
      token ? { Authorization: "Bearer " + token } : {},
    );
    const resp = await fetch("/api/v1" + path, Object.assign({}, opts, { headers }));
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new Error(`HTTP ${resp.status}: ${text || resp.statusText}`);
    }
    if (resp.status === 204) return null;
    return resp.json();
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function el(tag, attrs = {}, html = "") {
    const node = document.createElement(tag);
    Object.entries(attrs).forEach(([k, v]) => {
      if (k === "class") node.className = v;
      else if (k === "dataset") Object.assign(node.dataset, v);
      else node.setAttribute(k, v);
    });
    if (html) node.innerHTML = html;
    return node;
  }

  function ensureSection(id, title) {
    let section = document.getElementById(id);
    if (section) return section;
    section = el("section", { id, class: "innovation-section" });
    section.innerHTML = `
      <header class="innov-header">
        <h2>${escapeHtml(title)}</h2>
        <button class="innov-refresh" type="button">↻ Refresh</button>
      </header>
      <div class="innov-body">Loading…</div>
    `;
    document.body.appendChild(section);
    return section;
  }

  // ── 1. Compensating Controls ─────────────────────────────────────────────
  async function renderCompensating(assetId) {
    const section = ensureSection("nlv-compensating", "Effective Severity");
    const body = section.querySelector(".innov-body");
    section.querySelector(".innov-refresh").onclick = () => renderCompensating(assetId);
    if (!assetId) {
      body.innerHTML = "<p>Select an asset to load its effective severities.</p>";
      return;
    }
    body.textContent = "Loading…";
    try {
      const rows = await api(`/assets/${assetId}/effective-severities`);
      if (!rows.length) {
        body.innerHTML = "<p>No CVE attached to this asset.</p>";
        return;
      }
      const tbody = rows
        .map((r) => {
          const downgraded = r.downgrade > 0;
          const kev = r.kev_clamped ? '<span class="kev-tag">KEV clamp</span>' : "";
          const factors = (r.factors || [])
            .map(
              (f) =>
                `<li title="${escapeHtml(f.evidence)}">${escapeHtml(f.rule)} (${f.delta})</li>`,
            )
            .join("");
          return `
          <tr class="${downgraded ? "downgraded" : ""}">
            <td>${escapeHtml(r.cve_id)}</td>
            <td><strong>${r.base.toFixed(1)}</strong></td>
            <td><strong>${r.effective.toFixed(1)}</strong> ${kev}</td>
            <td>${r.downgrade ? "−" + r.downgrade.toFixed(1) : "—"}</td>
            <td><ul class="factor-list">${factors || "<li>none</li>"}</ul></td>
          </tr>`;
        })
        .join("");
      body.innerHTML = `
        <table class="innov-table">
          <thead><tr><th>CVE</th><th>Raw</th><th>Effective</th><th>Δ</th><th>Factors</th></tr></thead>
          <tbody>${tbody}</tbody>
        </table>`;
    } catch (e) {
      body.innerHTML = `<p class="error">${escapeHtml(e.message)}</p>`;
    }
  }

  // ── 2. Attack Paths ──────────────────────────────────────────────────────
  async function renderAttackPaths(limit = 20) {
    const section = ensureSection("nlv-attack-paths", "Critical Attack Paths");
    const body = section.querySelector(".innov-body");
    section.querySelector(".innov-refresh").onclick = () => renderAttackPaths(limit);
    body.textContent = "Loading…";
    try {
      const rows = await api(`/attack-paths/critical?limit=${limit}`);
      if (!rows.length) {
        body.innerHTML = `
          <p>No attack paths computed yet.</p>
          <button class="innov-refresh" id="nlv-attack-refresh-btn">Trigger refresh (admin)</button>
        `;
        const btn = body.querySelector("#nlv-attack-refresh-btn");
        if (btn)
          btn.onclick = async () => {
            btn.disabled = true;
            btn.textContent = "Computing…";
            try {
              const out = await api("/attack-paths/refresh", { method: "POST" });
              alert(`Computed ${out.paths_persisted} paths`);
              renderAttackPaths(limit);
            } catch (e) {
              alert(e.message);
            }
          };
        return;
      }
      const cards = rows
        .map((p) => {
          const hops = (p.hops || [])
            .map(
              (h) =>
                `<li><span class="edge-${escapeHtml(h.edge_type)}">${escapeHtml(h.edge_type)}</span> → ${escapeHtml(h.asset_id.slice(0, 8))} (w=${h.weight.toFixed(1)})${h.cve_id ? " [" + escapeHtml(h.cve_id) + "]" : ""}</li>`,
            )
            .join("");
          return `
          <div class="path-card">
            <div class="path-header">
              <strong>weight ${p.total_weight.toFixed(1)}</strong>
              · ${p.hop_count} hops
              · ${escapeHtml(p.source_asset_id.slice(0, 8))} → ${escapeHtml(p.target_asset_id.slice(0, 8))}
            </div>
            <ol class="path-hops">${hops}</ol>
          </div>`;
        })
        .join("");
      body.innerHTML = `<div class="path-list">${cards}</div>`;
    } catch (e) {
      body.innerHTML = `<p class="error">${escapeHtml(e.message)}</p>`;
    }
  }

  // ── 3. Scheduler Priorities ──────────────────────────────────────────────
  async function renderSchedulerPriorities() {
    const section = ensureSection("nlv-scheduler", "Smart Re-scan Queue");
    const body = section.querySelector(".innov-body");
    section.querySelector(".innov-refresh").onclick = renderSchedulerPriorities;
    body.textContent = "Loading…";
    try {
      const [budget, rows] = await Promise.all([
        api("/scheduler/budget"),
        api("/scheduler/priorities?limit=30"),
      ]);
      const stats = `
        <p class="budget-stats">
          Total: <strong>${budget.total_rows}</strong> ·
          Due now: <strong>${budget.due_now}</strong> ·
          Cooldown: <strong>${budget.in_cooldown}</strong> ·
          Avg score: <strong>${budget.avg_score ? budget.avg_score.toFixed(1) : "—"}</strong>
        </p>`;
      const tbody = rows
        .map(
          (r) => `
          <tr>
            <td>${escapeHtml(r.asset_id.slice(0, 8))}</td>
            <td>${escapeHtml(r.module)}</td>
            <td><strong>${r.score.toFixed(1)}</strong></td>
            <td>${r.last_scan_at ? escapeHtml(r.last_scan_at) : "never"}</td>
            <td>${escapeHtml(r.next_eligible_at)}</td>
          </tr>`,
        )
        .join("");
      body.innerHTML =
        stats +
        `
        <table class="innov-table">
          <thead><tr><th>Asset</th><th>Module</th><th>Score</th><th>Last scan</th><th>Eligible</th></tr></thead>
          <tbody>${tbody || "<tr><td colspan='5'>Queue empty.</td></tr>"}</tbody>
        </table>`;
    } catch (e) {
      body.innerHTML = `<p class="error">${escapeHtml(e.message)}</p>`;
    }
  }

  // ── 4. Remediation Workflow Kanban ───────────────────────────────────────
  const REM_COLUMNS = [
    "draft",
    "dry_run_pending",
    "dry_run_done",
    "awaiting_approval",
    "approved",
    "running",
    "succeeded",
    "failed",
    "rolled_back",
  ];

  async function renderRemediationKanban() {
    const section = ensureSection("nlv-remediation", "Remediation Workflow");
    const body = section.querySelector(".innov-body");
    section.querySelector(".innov-refresh").onclick = renderRemediationKanban;
    body.textContent = "Loading…";
    try {
      const rows = await api("/remediation/jobs?limit=200");
      const grouped = {};
      REM_COLUMNS.forEach((s) => (grouped[s] = []));
      rows.forEach((r) => {
        if (grouped[r.status]) grouped[r.status].push(r);
      });
      const cols = REM_COLUMNS.map((status) => {
        const cards = (grouped[status] || [])
          .map(
            (j) => `
          <div class="rem-card">
            <div class="rem-id">${escapeHtml(j.id.slice(0, 8))}</div>
            <div class="rem-cve">${escapeHtml(j.cve_id || "—")}</div>
            <div class="rem-asset">${escapeHtml(j.asset_id.slice(0, 8))}</div>
            ${j.requires_four_eyes ? '<span class="rem-4eyes">4-eyes</span>' : ""}
          </div>`,
          )
          .join("");
        return `
          <div class="rem-col" data-status="${status}">
            <h3>${escapeHtml(status)} <span class="count">${grouped[status].length}</span></h3>
            <div class="rem-cards">${cards || "<em>empty</em>"}</div>
          </div>`;
      }).join("");
      body.innerHTML = `<div class="rem-board">${cols}</div>`;
    } catch (e) {
      body.innerHTML = `<p class="error">${escapeHtml(e.message)}</p>`;
    }
  }

  // ── 5. AI Triage card ────────────────────────────────────────────────────
  async function renderAiTriage(cveId, assetId) {
    const section = ensureSection("nlv-ai-triage", "AI Triage Recommendation");
    const body = section.querySelector(".innov-body");
    section.querySelector(".innov-refresh").onclick = () => renderAiTriage(cveId, assetId);
    if (!cveId || !assetId) {
      body.innerHTML = "<p>Pass cveId and assetId to load a recommendation.</p>";
      return;
    }
    body.textContent = "Loading…";
    try {
      const rec = await api(`/triage/${encodeURIComponent(cveId)}/asset/${assetId}`);
      const factors = (rec.top_factors || [])
        .map((f) => `<li>${escapeHtml(f)}</li>`)
        .join("");
      body.innerHTML = `
        <div class="ai-triage-card urgency-${escapeHtml(rec.urgency)}">
          <header>
            <span class="urgency-badge">${escapeHtml(rec.urgency).toUpperCase()}</span>
            <span class="model">${escapeHtml(rec.model_id)}</span>
          </header>
          <p class="one-liner">${escapeHtml(rec.one_liner)}</p>
          <ul class="factor-list">${factors}</ul>
          <footer>
            <small>cached until ${escapeHtml(rec.cached_until)}</small>
            <small class="disclaimer">Suggestion automatisée — vérifiez avant action.</small>
          </footer>
        </div>`;
    } catch (e) {
      const msg = e.message.includes("503")
        ? "AI triage disabled. Set AI_TRIAGE_ENABLED=true."
        : e.message;
      body.innerHTML = `<p class="error">${escapeHtml(msg)}</p>`;
    }
  }

  // ── Public API ───────────────────────────────────────────────────────────
  window.NLV_Innovation = {
    renderCompensating,
    renderAttackPaths,
    renderSchedulerPriorities,
    renderRemediationKanban,
    renderAiTriage,
  };

  // Inject minimal styles for the new sections (scoped to .innovation-section)
  const css = `
    .innovation-section { display: none; padding: 1rem; }
    .innovation-section.active { display: block; }
    .innov-header { display: flex; justify-content: space-between; align-items: center; }
    .innov-header h2 { margin: 0; font-size: 1.1rem; }
    .innov-table { width: 100%; border-collapse: collapse; margin-top: .5rem; font-size: .85rem; }
    .innov-table th, .innov-table td { padding: .35rem .5rem; border-bottom: 1px solid var(--border, #2a3441); text-align: left; }
    .innov-table tr.downgraded td { background: rgba(80, 200, 120, 0.07); }
    .factor-list { margin: 0; padding-left: 1rem; font-size: .8rem; }
    .kev-tag { background: #b9281d; color: white; padding: 0 .3rem; border-radius: 3px; font-size: .7rem; margin-left: .3rem; }
    .path-card { border: 1px solid var(--border, #2a3441); border-radius: 6px; padding: .6rem; margin-bottom: .5rem; }
    .path-hops { font-family: monospace; font-size: .8rem; }
    .edge-cve_exploit { color: #e06c6c; }
    .edge-ssh_pivot { color: #f0b840; }
    .edge-network_reachable { color: #6ca0e0; }
    .edge-ioc_pivot { color: #b56cf0; }
    .rem-board { display: flex; gap: .5rem; overflow-x: auto; }
    .rem-col { min-width: 180px; background: rgba(255,255,255,0.02); padding: .5rem; border-radius: 6px; }
    .rem-col h3 { font-size: .85rem; margin: 0 0 .5rem; text-transform: uppercase; }
    .rem-col .count { font-weight: normal; opacity: .6; }
    .rem-card { background: var(--card-bg, #1a2230); padding: .4rem; border-radius: 4px; margin-bottom: .4rem; font-size: .75rem; }
    .rem-4eyes { background: #555; color: white; padding: 0 .3rem; border-radius: 3px; font-size: .65rem; }
    .ai-triage-card { border: 2px solid var(--border, #2a3441); border-radius: 8px; padding: 1rem; }
    .ai-triage-card.urgency-now { border-color: #c0392b; background: rgba(192,57,43,0.08); }
    .ai-triage-card.urgency-24h { border-color: #e67e22; }
    .ai-triage-card.urgency-7d { border-color: #f1c40f; }
    .urgency-badge { background: #444; padding: .2rem .5rem; border-radius: 3px; font-weight: bold; }
    .disclaimer { opacity: .6; font-style: italic; }
    .innov-refresh { background: var(--accent, #2c7be5); color: white; border: 0; padding: .25rem .6rem; border-radius: 3px; cursor: pointer; }
    .error { color: #e06c6c; }
    .budget-stats { font-size: .85rem; opacity: .8; margin-bottom: .5rem; }
  `;
  const style = document.createElement("style");
  style.textContent = css;
  document.head.appendChild(style);

  // Auto-show the attack-paths panel on URL hash, e.g. #innovation-attack-paths
  window.addEventListener("hashchange", () => {
    if (location.hash === "#innovation-attack-paths") {
      document
        .querySelectorAll(".innovation-section")
        .forEach((s) => s.classList.remove("active"));
      ensureSection("nlv-attack-paths", "Critical Attack Paths").classList.add("active");
      renderAttackPaths();
    } else if (location.hash === "#innovation-scheduler") {
      document
        .querySelectorAll(".innovation-section")
        .forEach((s) => s.classList.remove("active"));
      ensureSection("nlv-scheduler", "Smart Re-scan Queue").classList.add("active");
      renderSchedulerPriorities();
    } else if (location.hash === "#innovation-remediation") {
      document
        .querySelectorAll(".innovation-section")
        .forEach((s) => s.classList.remove("active"));
      ensureSection("nlv-remediation", "Remediation Workflow").classList.add("active");
      renderRemediationKanban();
    }
  });
})();
