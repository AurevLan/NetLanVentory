'use strict';

/* "À traiter" (todo) view — v0.16 SSVC convergence step 2.
 *
 * Standalone module rendering the unified patching-priority home view.
 * Follows the innovation.js pattern (self-contained, doesn't touch app.js
 * beyond the tiny routing tweaks made for this feature) but reuses the
 * global helpers already exposed by app.js (api(), escape(), escapeAttr(),
 * t(), cveUrl(), criticalityBadge(), switchToView(), openAssetModal()) since
 * this view is a first-class nav panel, not a floating overlay — staying in
 * app.js's visual/data language is more valuable here than isolation.
 *
 * Backend contract (fixed): GET /prioritization/todo?limit=20|100
 *   { counts: {act_open, attend_open, internet_facing_open,
 *              sla_breached, unevaluated},
 *     total_open, items: [...], generated_at }
 */
(function () {
  // ── Tier styling — mirrors app.js's _TIER_CONFIG (P1..P4 colors/labels) ──
  const TODO_TIER_CONFIG = {
    P1: { color: '#f87171', label: 'P1 — Immédiat' },
    P2: { color: '#fb923c', label: 'P2 — Urgent' },
    P3: { color: '#fbbf24', label: 'P3 — Planifié' },
    P4: { color: '#60a5fa', label: 'P4 — Backlog' },
  };

  const TODO_DECISION_LABEL = {
    act: 'Agir',
    attend: 'Attendre',
    track: 'Suivre',
    'track*': 'Suivre*',
  };

  let _todoLimit = 20;

  function _t(key, fallback) {
    return typeof t === 'function' ? t(key, fallback) : (fallback || key);
  }

  function _esc(v) {
    return typeof escape === 'function' ? escape(v) : String(v == null ? '' : v);
  }

  function _escAttr(v) {
    return typeof escapeAttr === 'function' ? escapeAttr(v) : _esc(v);
  }

  // ── Score → color, matching app.js's SEV_COLOR bands ─────────────────────
  function _scoreColor(score) {
    if (score == null) return 'var(--text-muted)';
    if (score >= 9) return 'var(--danger)';
    if (score >= 7) return '#fb923c';
    if (score >= 4) return 'var(--warning)';
    return 'var(--info)';
  }

  async function loadTodoView(limit) {
    const panel = document.getElementById('panel-todo');
    if (!panel) return;
    _todoLimit = limit || _todoLimit || 20;

    const listEl = document.getElementById('todo-list');
    const statsEl = document.getElementById('todo-stats');
    if (listEl) {
      listEl.innerHTML = `<div style="padding:24px;color:var(--text-muted);font-size:13px">${_t('common.loading', 'Chargement…')}</div>`;
    }

    try {
      const data = await api(`/prioritization/todo?limit=${encodeURIComponent(_todoLimit)}`);
      if (!data) return;
      _renderTodoStats(data.counts || {});
      _renderTodoUnevaluated(data.counts || {});
      _renderTodoList(data);
      _renderTodoLoadMore(data);

      const navCount = document.getElementById('nav-todo-count');
      if (navCount) navCount.textContent = data.total_open ? String(data.total_open) : '';
    } catch (e) {
      if (statsEl) statsEl.innerHTML = '';
      if (listEl) {
        listEl.innerHTML = `<span style="color:var(--danger);font-size:13px">${_t('common.error', 'Erreur')} : ${_esc(String(e.message || e))}</span>`;
      }
    }
  }

  function _renderTodoStats(counts) {
    const el = document.getElementById('todo-stats');
    if (!el) return;
    const act = counts.act_open || 0;
    const net = counts.internet_facing_open || 0;
    const sla = counts.sla_breached || 0;

    const tiles = [
      { label: _t('todo.stat.act_open', 'Décisions Act ouvertes'), value: act, color: act > 0 ? 'var(--danger)' : 'var(--text)' },
      { label: _t('todo.stat.internet_facing', 'Expositions Internet'), value: net, color: net > 0 ? 'var(--warning)' : 'var(--text)' },
      { label: _t('todo.stat.sla_breached', 'SLA dépassés'), value: sla, color: sla > 0 ? 'var(--danger)' : 'var(--text)' },
    ];

    el.innerHTML = tiles.map((x) =>
      `<div class="stat-card"><span class="num" style="color:${x.color}">${x.value}</span><span class="stat-lbl">${_esc(x.label)}</span></div>`
    ).join('');
  }

  function _renderTodoUnevaluated(counts) {
    const el = document.getElementById('todo-unevaluated-note');
    if (!el) return;
    const n = counts.unevaluated || 0;
    if (n <= 0) {
      el.classList.add('hidden');
      el.innerHTML = '';
      return;
    }
    el.classList.remove('hidden');
    el.innerHTML = `<strong>${n}</strong> ${_esc(_t('todo.unevaluated_suffix', 'expositions pas encore évaluées (recalcul horaire)'))}`;
  }

  function _renderSeverityChips(item) {
    const raw = item.cvss_score;
    const eff = item.effective_severity;
    if (raw == null && eff == null) return '<span style="color:var(--text-muted)">—</span>';

    if (raw != null && eff != null && Math.abs(raw - eff) >= 0.05) {
      const tooltip = _escAttr(_t('todo.effective_tooltip', 'Sévérité effective après contrôles compensatoires'));
      return `<span class="cve-cvss-chip" style="--cvss-color:var(--text-muted);text-decoration:line-through;opacity:.55">${raw.toFixed(1)}</span>` +
        `<span style="color:var(--text-muted);font-size:11px" aria-hidden="true">→</span>` +
        `<span class="cve-cvss-chip" style="--cvss-color:${_scoreColor(eff)}" title="${tooltip}">${eff.toFixed(1)}</span>`;
    }

    const val = eff != null ? eff : raw;
    return `<span class="cve-cvss-chip" style="--cvss-color:${_scoreColor(val)}">${val.toFixed(1)}</span>`;
  }

  function _renderEpssChip(item) {
    if (item.epss_percentile == null) return '';
    return `<span class="cve-cvss-chip" style="--cvss-color:#818cf8" title="EPSS percentile">${(item.epss_percentile * 100).toFixed(0)}%</span>`;
  }

  function _renderFixBadge(item) {
    if (!item.fixed_version) return '';
    const title = item.package_name ? `${item.package_name} → ${item.fixed_version}` : item.fixed_version;
    return `<span class="cve-fix-badge" title="${_escAttr(title)}">${_esc(_t('remediation.table.fix_available', 'Fix dispo'))}</span>`;
  }

  function _renderTierBadge(item) {
    const cfg = TODO_TIER_CONFIG[item.tier] || { color: 'var(--text-muted)', label: item.tier || '—' };
    const decisionLabel = TODO_DECISION_LABEL[item.decision] || item.decision || '';
    let title = cfg.label;
    if (decisionLabel) title += ' · ' + decisionLabel;
    if (item.demoted_by_controls) title += ' · ' + _t('todo.demoted_hint', 'Sévérité réduite par des contrôles compensatoires');
    return `<span class="todo-tier-badge" style="--tier-color:${cfg.color}" title="${_escAttr(title)}">${_esc(item.tier || '—')}</span>`;
  }

  function _renderReasons(item) {
    const reasons = item.reasons || [];
    if (!reasons.length) return '';
    return `<div class="todo-reasons">${reasons.map((r) => `<span class="todo-reason-chip">${_esc(r)}</span>`).join('')}</div>`;
  }

  function _renderAssetLink(item) {
    const label = item.asset_name || item.asset_ip || (item.asset_id ? item.asset_id.slice(0, 8) : '—');
    if (!item.asset_id || typeof switchToView !== 'function') return _esc(label);
    const hasModal = typeof openAssetModal === 'function';
    const onclick = hasModal
      ? `switchToView('assets');openAssetModal('${_escAttr(item.asset_id)}')`
      : `switchToView('assets')`;
    return `<span class="clickable" style="color:var(--accent)" onclick="${onclick}">${_esc(label)}</span>`;
  }

  function _renderTodoItem(item) {
    const cfg = TODO_TIER_CONFIG[item.tier] || { color: 'var(--text-muted)' };
    const critBadge = typeof criticalityBadge === 'function' ? criticalityBadge(item.asset_criticality) : '';
    const cveHref = typeof cveUrl === 'function' ? cveUrl(item.cve_id) : '#';

    return `
      <div class="cve-row todo-row" data-tier="${_esc(item.tier || '')}">
        <div class="cve-row-main todo-row-main">
          ${_renderTierBadge(item)}
          <div class="cve-row-id">
            <a class="cve-link" href="${cveHref}" target="_blank" rel="noopener">${_esc(item.cve_id)}</a>
          </div>
          <div class="cve-row-pkg">
            ${_renderAssetLink(item)}
            ${critBadge}
          </div>
          <div class="cve-row-meta">
            ${_renderSeverityChips(item)}
            ${_renderEpssChip(item)}
            ${_renderFixBadge(item)}
            <span class="todo-sla-badge" style="--tier-color:${cfg.color}">${_esc(item.sla_label || '—')}</span>
          </div>
        </div>
        ${item.action ? `<div class="todo-action-line" style="--tier-color:${cfg.color}">${_esc(item.action)}</div>` : ''}
        ${_renderReasons(item)}
      </div>`;
  }

  function _renderTodoEmptyState(allEvaluated) {
    return `
      <div class="empty-state todo-empty-state">
        <svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.5" width="40" height="40">
          <path d="M24 4L8 10v12c0 9.6 6.72 18.6 16 21 9.28-2.4 16-11.4 16-21V10L24 4z"/>
          <path d="M17 24l4 4 10-10"/>
        </svg>
        <p>${_esc(_t('todo.empty.title', "Rien d'urgent à traiter"))}</p>
        ${allEvaluated ? `<span>${_esc(_t('todo.empty.hint', 'Lancez un scan pour détecter de nouvelles expositions.'))}</span>` : ''}
      </div>`;
  }

  function _renderTodoList(data) {
    const el = document.getElementById('todo-list');
    if (!el) return;
    const items = data.items || [];
    const totalOpen = data.total_open || 0;

    if (!items.length || totalOpen === 0) {
      const allEvaluated = (data.counts && data.counts.unevaluated || 0) === 0;
      el.innerHTML = _renderTodoEmptyState(allEvaluated);
      return;
    }

    el.innerHTML = items.map(_renderTodoItem).join('');
  }

  function _renderTodoLoadMore(data) {
    const el = document.getElementById('todo-load-more');
    if (!el) return;
    const items = data.items || [];
    const totalOpen = data.total_open || 0;

    if (items.length === 20 && totalOpen > 20 && _todoLimit < 100) {
      el.innerHTML = `<button class="btn btn-sm" id="todo-load-more-btn">${_esc(_t('todo.load_more', 'Voir plus'))}</button>`;
      const btn = document.getElementById('todo-load-more-btn');
      if (btn) btn.addEventListener('click', () => loadTodoView(100));
    } else {
      el.innerHTML = '';
    }
  }

  window.loadTodoView = loadTodoView;
})();
