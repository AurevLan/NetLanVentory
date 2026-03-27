'use strict';

const API = '/api/v1';

// ── Auth state ────────────────────────────────────────────────────────────────
// NOTE: Token stored in sessionStorage (not localStorage) to limit XSS exposure.
// sessionStorage is cleared when the tab closes, reducing persistent token theft risk.
// For maximum security, migrate to httpOnly cookies with SameSite=Strict.

let _token = sessionStorage.getItem('nlv_token') || localStorage.getItem('nlv_token') || null;

// Migrate existing tokens from localStorage to sessionStorage
if (localStorage.getItem('nlv_token') && !sessionStorage.getItem('nlv_token')) {
  sessionStorage.setItem('nlv_token', localStorage.getItem('nlv_token'));
  localStorage.removeItem('nlv_token');
}
let _me = null;
let _overviewChart = null;
let _currentReportId = null;
let _assetDns = [];
let _vocabulary = { os_family: [], device_type: [] };
let _globalSettings = null;  // Loaded once on init, used for ZAP target computation
const HTTP_PORTS  = new Set([80, 8080, 8000, 3000, 8888]);
const HTTPS_PORTS = new Set([443, 8443, 4443]);

// ── ZAP auto-scan visibility helpers ─────────────────────────────────────────

/** Return list of {url, port, source} objects that the scheduler would scan for this asset. */
function _computeZapTargets(asset) {
  const openPorts = (asset.ports || []).filter(p => p.state === 'open');
  const targets = [];

  const addTargets = (port, scheme) => {
    const defaultPort = scheme === 'https' ? 443 : 80;
    const portSuffix = port === defaultPort ? '' : `:${port}`;

    if (asset.ip) {
      targets.push({ url: `${scheme}://${asset.ip}${portSuffix}`, port, source: 'IP' });
    }
    for (const dns of (asset.dns_entries || [])) {
      targets.push({ url: `${scheme}://${dns.fqdn}${portSuffix}`, port, source: dns.fqdn });
    }
  };

  for (const p of openPorts) {
    if (HTTP_PORTS.has(p.port_number))  addTargets(p.port_number, 'http');
    if (HTTPS_PORTS.has(p.port_number)) addTargets(p.port_number, 'https');
  }

  return targets;
}

/** Return minutes until next auto-scan, or null if auto-scan is not enabled. */
function _computeNextScan(asset) {
  // Determine effective interval
  const assetEnabled = asset.zap_auto_scan_enabled;
  const globalEnabled = _globalSettings?.zap_auto_scan_enabled;
  const effectiveEnabled = assetEnabled != null ? assetEnabled : globalEnabled;
  if (!effectiveEnabled) return null;

  const interval = asset.zap_scan_interval_minutes
    ?? _globalSettings?.zap_scan_interval_minutes
    ?? 60;

  if (!asset.zap_last_auto_scan_at) return 0; // never scanned → due now

  const nextAt = new Date(asset.zap_last_auto_scan_at).getTime() + interval * 60_000;
  return Math.max(0, Math.round((nextAt - Date.now()) / 60_000));
}

// ── Utilities ────────────────────────────────────────────────────────────────

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (_token) headers['Authorization'] = `Bearer ${_token}`;

  const res = await fetch(API + path, { headers, ...opts });

  if (res.status === 401) {
    _logout();
    return null;
  }
  if (res.status === 204) return null;
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

function badge(text, type = 'info') {
  return `<span class="badge badge-${type}">${text}</span>`;
}

function statusBadge(status) {
  const map = {
    completed: 'success',
    running: 'warning',
    pending: 'muted',
    error: 'error',
    completed_with_errors: 'warning',
    failed: 'error',
  };
  return badge(status, map[status] || 'info');
}

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString();
}

/**
 * HTML-escape a string to prevent XSS.
 * Handles all characters that are dangerous in HTML attribute and text contexts.
 */
function escape(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/`/g, '&#96;')
    .replace(/\//g, '&#47;');
}

/**
 * Escape a string for safe use inside JavaScript string literals in HTML attributes.
 * Use when building onclick="fn('${escapeAttr(val)}')" patterns.
 */
function escapeAttr(str) {
  return escape(str).replace(/\\/g, '\\\\');
}

// ── Toast notifications ───────────────────────────────────────────────────────

function showToast(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = message;
  container.appendChild(el);
  // Trigger transition
  requestAnimationFrame(() => requestAnimationFrame(() => el.classList.add('visible')));
  setTimeout(() => {
    el.classList.remove('visible');
    setTimeout(() => el.remove(), 300);
  }, duration);
}

// ── Navigation ────────────────────────────────────────────────────────────────

// ── Hash-based routing ────────────────────────────────────────────────────────
// Every view change updates location.hash so the browser back/forward buttons
// work and URLs are shareable (e.g. /#/assets, /#/admin, /#/topology).

let _currentView = null;

function switchToView(viewName, { pushHistory = true } = {}) {
  if (!viewName) return;
  _currentView = viewName;

  document.querySelectorAll('.nav-item').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));

  const navBtn = document.querySelector(`.nav-item[data-view="${viewName}"]`);
  if (navBtn) navBtn.classList.add('active');
  const panel = document.getElementById(`panel-${viewName}`);
  if (panel) panel.classList.add('active');

  // Update URL hash for browser navigation (back/forward)
  if (pushHistory && location.hash !== `#/${viewName}`) {
    history.pushState({ view: viewName }, '', `#/${viewName}`);
  }

  // Load data for the panel
  const loaders = {
    'admin': () => loadUsers(),
    'cves': () => loadCves(),
    'dashboard': () => loadDashboard(),
    'expositions': () => loadExpositions(),
    'topology': () => loadTopology(),
    'reports': () => loadReportsPanel(),
    'remediation': () => loadRemediation(),
    'timeline': () => loadTimeline(),
    'compliance': () => loadCompliance(),
    'executive': () => loadExecutive(),
    'threat-intel': () => loadThreatIntel(),
  };
  if (loaders[viewName]) loaders[viewName]();
}

function _getViewFromHash() {
  const hash = location.hash.replace(/^#\/?/, '');
  return hash || 'assets';
}

function initNav() {
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      switchToView(item.dataset.view);
    });
  });

  // Handle browser back/forward buttons
  window.addEventListener('popstate', (e) => {
    const view = e.state?.view || _getViewFromHash();
    switchToView(view, { pushHistory: false });
  });

  // On initial load, restore view from hash
  const initialView = _getViewFromHash();
  if (initialView !== 'assets') {
    switchToView(initialView, { pushHistory: false });
  }
}

// ── Authentication ────────────────────────────────────────────────────────────

function _showLogin() {
  document.getElementById('login-view').classList.remove('hidden');
  document.getElementById('app-view').classList.add('hidden');
}

function _showApp() {
  document.getElementById('login-view').classList.add('hidden');
  document.getElementById('app-view').classList.remove('hidden');
}

function _logout() {
  _token = null;
  _me = null;
  sessionStorage.removeItem('nlv_token');
  localStorage.removeItem('nlv_token');  // clean up legacy storage
  _showLogin();
}

function logout() { _logout(); }

async function login(username, password) {
  const form = new URLSearchParams();
  form.append('username', username);
  form.append('password', password);

  const res = await fetch(`${API}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Login failed' }));
    throw new Error(err.detail || 'Login failed');
  }

  const data = await res.json();
  _token = data.access_token;
  _me = data.user;
  sessionStorage.setItem('nlv_token', _token);
}

async function checkAuth() {
  if (!_token) { _showLogin(); return false; }
  try {
    _me = await api('/auth/me');
    if (!_me) { _showLogin(); return false; }
    return true;
  } catch {
    _showLogin();
    return false;
  }
}

function _applyUserContext() {
  if (!_me) return;

  // Sidebar user info
  const letter = (_me.email || _me.username || '?').charAt(0).toUpperCase();
  document.getElementById('nav-avatar').textContent = letter;
  document.getElementById('nav-username').textContent =
    _me.full_name || _me.username || _me.email;
  document.getElementById('nav-role').textContent = _me.role;

  // Show Admin section for admins
  if (_me.role === 'admin') {
    document.getElementById('admin-section').style.display = '';
  }
}

function _initLoginForm() {
  document.getElementById('login-form').addEventListener('submit', async e => {
    e.preventDefault();
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    const errEl = document.getElementById('login-error');
    errEl.classList.add('hidden');

    try {
      await login(username, password);
      _showApp();
      _applyUserContext();
      await _initAppData();
    } catch (err) {
      errEl.textContent = err.message;
      errEl.classList.remove('hidden');
    }
  });
}

// ── Vocabulary (OS, device type datalists) ────────────────────────────────────

async function loadVocabulary() {
  try {
    const v = await api('/assets/vocabulary');
    if (!v) return;
    _vocabulary = v;
    const dlOs = document.getElementById('dl-os-family');
    const dlDt = document.getElementById('dl-device-type');
    if (dlOs) dlOs.innerHTML = (_vocabulary.os_family || []).map(s => `<option value="${escape(s)}">`).join('');
    if (dlDt) dlDt.innerHTML = (_vocabulary.device_type || []).map(s => `<option value="${escape(s)}">`).join('');
  } catch (e) {
    console.error('Vocabulary error:', e);
  }
}

// ── Module checkboxes ─────────────────────────────────────────────────────────

async function loadModuleCheckboxes() {
  try {
    const { items } = await api('/modules');
    const container = document.getElementById('module-checkboxes');
    container.innerHTML = items.map(m => `
      <label>
        <input type="checkbox" value="${escape(m.name)}" ${m.name === 'arp_sweep' ? 'checked' : ''} />
        ${escape(m.display_name)}
      </label>
    `).join('');
  } catch (e) {
    console.error('Failed to load modules:', e);
  }
}

// ── Stats ─────────────────────────────────────────────────────────────────────

async function refreshStats() {
  try {
    const [assets, scans, mods, activeAssets] = await Promise.all([
      api('/assets?limit=1'),
      api('/scans?limit=1'),
      api('/modules'),
      api('/assets?limit=1&active_only=true'),
    ]);

    document.querySelector('#stat-assets .num').textContent = assets.total;
    document.querySelector('#stat-active .num').textContent = activeAssets.total;
    document.querySelector('#stat-scans .num').textContent = scans.total;
    document.querySelector('#stat-modules .num').textContent = mods.total;

    // Update sidebar badges
    const assetBadge = document.getElementById('nav-asset-count');
    if (assetBadge) assetBadge.textContent = assets.total;

    // Update unacknowledged CVE badge from dashboard
    try {
      const dash = await api('/dashboard');
      const expBadge = document.getElementById('nav-exp-count');
      if (expBadge) expBadge.textContent = dash.unacknowledged_cves > 0 ? dash.unacknowledged_cves : '';
    } catch (_) { /* non-critical */ }
  } catch (e) {
    console.error('Stats error:', e);
  }
}

// ── Assets ────────────────────────────────────────────────────────────────────

let _selectedAssetIds = new Set();

function openBulkScanMenu() {
  const ids = [..._selectedAssetIds];
  if (!ids.length) return;
  const action = window.prompt(
    `${ids.length} asset(s) sélectionné(s).\nChoisir le scan (ssh / trivy) :`, 'ssh'
  );
  if (!action) return;
  if (!['ssh', 'trivy'].includes(action.trim())) {
    showToast('Type de scan invalide. Utilisez "ssh" ou "trivy".', 'error');
    return;
  }
  _runBulkScan(ids, action.trim());
}

async function _runBulkScan(ids, scanType) {
  let ok = 0, fail = 0;
  const endpoint = scanType === 'trivy' ? 'trivy-docker' : 'ssh-scan';
  for (const id of ids) {
    try {
      await api(`/assets/${id}/${endpoint}`, { method: 'POST' });
      ok++;
    } catch (_) {
      fail++;
    }
  }
  showToast(`Bulk ${scanType} : ${ok} lancé(s)${fail ? `, ${fail} échec(s)` : ''}.`,
    fail ? 'warning' : 'success');
}

// ── Asset modal ───────────────────────────────────────────────────────────────

let _modalAssetId = null;

function _switchModalTab(tabName) {
  document.querySelectorAll('.modal-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.modal-tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelector(`.modal-tab[data-modaltab="${tabName}"]`)?.classList.add('active');
  document.getElementById(`mtab-${tabName}`)?.classList.add('active');
}

function _initModalTabs() {
  document.querySelectorAll('.modal-tab').forEach(tab => {
    tab.addEventListener('click', () => _switchModalTab(tab.dataset.modaltab));
  });
}

function _switchSecPanel(name, triggerBtn) {
  document.querySelectorAll('.sec-subnav-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.sec-panel').forEach(p => { p.style.display = 'none'; });
  if (triggerBtn) triggerBtn.classList.add('active');
  const panel = document.getElementById('secpanel-' + name);
  if (panel) panel.style.display = 'block';
}

// ── Overview tab renderer ─────────────────────────────────────────────────────

function _renderOverviewTab(asset) {
  const zapReports = asset.zap_reports || [];
  const cves = asset.cves || [];

  // Completed scans sorted oldest → newest for the chart
  const completed = zapReports
    .filter(r => r.status === 'completed')
    .sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

  const lastCompleted = completed.length ? completed[completed.length - 1] : null;
  const hasData = completed.length > 0;

  const risk = lastCompleted?.risk_summary || {};
  const totalAlerts = hasData
    ? (risk.high || 0) + (risk.medium || 0) + (risk.low || 0) + (risk.informational || 0)
    : '—';

  document.getElementById('ov-alerts').textContent = totalAlerts;
  document.getElementById('ov-cves').textContent = cves.length > 0 ? cves.length : '—';
  document.getElementById('ov-techs').textContent = hasData ? (lastCompleted.technologies?.length || 0) : '—';
  document.getElementById('ov-last-scan').textContent = lastCompleted?.created_at
    ? fmtDate(lastCompleted.created_at) : '—';

  const noScanEl = document.getElementById('ov-no-scan');
  const chartWrap = document.getElementById('ov-chart-wrap');

  if (!hasData) {
    if (noScanEl) noScanEl.style.display = '';
    if (chartWrap) chartWrap.style.display = 'none';
  } else {
    if (noScanEl) noScanEl.style.display = 'none';
    if (chartWrap) chartWrap.style.display = '';

    if (_overviewChart) { _overviewChart.destroy(); _overviewChart = null; }

    const ctx = document.getElementById('overview-chart')?.getContext('2d');
    if (ctx && window.Chart) {
      const labels = completed.map(r => fmtDate(r.created_at));
      const getR = (r, k) => (r.risk_summary || {})[k] || 0;

      const _OV_FONT = { family: 'Inter, sans-serif', size: 11 };
      const _OV_GRID = 'rgba(255,255,255,0.06)';
      const _OV_TICK = 'rgba(255,255,255,0.45)';
      const _OV_TOOLTIP = {
        backgroundColor: 'rgba(15,18,30,0.92)',
        titleColor: '#e2e8f0', bodyColor: '#94a3b8',
        borderColor: 'rgba(129,140,248,0.3)', borderWidth: 1, cornerRadius: 8,
      };

      if (completed.length === 1) {
        // Single scan: horizontal bar by severity
        const r = completed[0].risk_summary || {};
        _overviewChart = new Chart(ctx, {
          type: 'bar',
          data: {
            labels: ['High', 'Medium', 'Low', 'Info'],
            datasets: [{
              data: [r.high || 0, r.medium || 0, r.low || 0, r.informational || 0],
              backgroundColor: ['rgba(248,113,113,0.8)', 'rgba(251,146,60,0.8)', 'rgba(251,191,36,0.8)', 'rgba(148,163,184,0.5)'],
              borderColor:     ['#f87171', '#fb923c', '#fbbf24', '#94a3b8'],
              borderWidth: 1,
              borderRadius: 6,
            }],
          },
          options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 500, easing: 'easeOutQuart' },
            plugins: { legend: { display: false }, tooltip: _OV_TOOLTIP },
            scales: {
              x: { beginAtZero: true, ticks: { color: _OV_TICK, font: _OV_FONT, precision: 0 }, grid: { color: _OV_GRID }, border: { color: 'transparent' } },
              y: { ticks: { color: _OV_TICK, font: _OV_FONT }, grid: { display: false }, border: { color: 'transparent' } },
            },
          },
        });
      } else {
        // Multiple scans: time-series mixed chart (stacked bars + CVE line)
        _overviewChart = new Chart(ctx, {
          type: 'bar',
          data: {
            labels,
            datasets: [
              { type: 'bar', label: 'High',   data: completed.map(r => getR(r, 'high')),          backgroundColor: 'rgba(248,113,113,0.75)', stack: 'alerts', borderRadius: 3 },
              { type: 'bar', label: 'Medium', data: completed.map(r => getR(r, 'medium')),        backgroundColor: 'rgba(251,146,60,0.75)',  stack: 'alerts', borderRadius: 3 },
              { type: 'bar', label: 'Low',    data: completed.map(r => getR(r, 'low')),           backgroundColor: 'rgba(251,191,36,0.65)',  stack: 'alerts', borderRadius: 3 },
              { type: 'bar', label: 'Info',   data: completed.map(r => getR(r, 'informational')), backgroundColor: 'rgba(148,163,184,0.4)',  stack: 'alerts', borderRadius: 3 },
              {
                type: 'line', label: 'CVEs',
                data: completed.map(r => r.cve_count || 0),
                borderColor: '#a78bfa', backgroundColor: 'rgba(167,139,250,0.12)',
                pointRadius: 5, pointBackgroundColor: '#a78bfa', pointBorderColor: '#0f121e', pointBorderWidth: 2,
                tension: 0.35, yAxisID: 'yCve', fill: true,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 500, easing: 'easeOutQuart' },
            plugins: {
              legend: { labels: { color: _OV_TICK, font: _OV_FONT, boxWidth: 12, borderRadius: 3 } },
              tooltip: _OV_TOOLTIP,
            },
            scales: {
              x: { stacked: true, ticks: { color: _OV_TICK, font: _OV_FONT, maxRotation: 30 }, grid: { color: _OV_GRID }, border: { color: 'transparent' } },
              y: { stacked: true, beginAtZero: true, ticks: { color: _OV_TICK, font: _OV_FONT, precision: 0 }, grid: { color: _OV_GRID }, border: { color: 'transparent' }, title: { display: true, text: 'Alertes', color: _OV_TICK, font: _OV_FONT } },
              yCve: { position: 'right', beginAtZero: true, ticks: { color: '#a78bfa', font: _OV_FONT, precision: 0 }, grid: { drawOnChartArea: false }, border: { color: 'transparent' }, title: { display: true, text: 'CVEs', color: '#a78bfa', font: _OV_FONT } },
            },
          },
        });
      }
    }
  }

  // Technologies
  const techPillsEl = document.getElementById('ov-tech-pills');
  if (techPillsEl) {
    const techs = lastCompleted?.technologies || [];
    const catCls = { server: 'tech-server', javascript: 'tech-js', language: 'tech-lang', framework: 'tech-fw', library: 'tech-lib' };
    techPillsEl.innerHTML = techs.length
      ? techs.map(t =>
          `<span class="tech-pill ${catCls[t.category] || 'tech-lib'}" title="${escape(t.alert_name || t.category)}">
            ${escape(t.name)}${t.version ? `<span class="tech-version">${escape(t.version)}</span>` : ''}
          </span>`).join('')
      : '<span style="color:var(--text-muted);font-size:12px">Aucune technologie détectée.</span>';
  }
}

// ── CVE priority view ─────────────────────────────────────────────────────────

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'unknown'];
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', unknown: 'Unknown' };
const SEV_COLOR = { critical: 'var(--danger)', high: '#fb923c', medium: 'var(--warning)', low: '#60a5fa', unknown: 'var(--text-muted)' };

function _renderCvePriorityList(cves) {
  const container = document.getElementById('cve-priority-list');
  if (!container) return;

  // Update score bar counts
  const counts = { all: cves.length, critical: 0, high: 0, medium: 0, low: 0 };
  cves.forEach(c => { const s = (c.severity || 'unknown').toLowerCase(); if (s in counts) counts[s]++; });
  ['all', 'critical', 'high', 'medium', 'low'].forEach(k => {
    const el = document.getElementById('sev-count-' + k);
    if (el) el.textContent = counts[k] || '';
  });

  if (!cves.length) {
    container.innerHTML = `
      <div class="empty-state" style="padding:48px 20px">
        <svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.5" width="40" height="40">
          <path d="M24 4L8 10v12c0 9.6 6.72 18.6 16 21 9.28-2.4 16-11.4 16-21V10L24 4z"/>
          <path d="M17 24l4 4 10-10"/>
        </svg>
        <p>Aucune vulnérabilité détectée</p>
        <span>Lancez un scan SSH, Nuclei, ZAP ou Trivy pour analyser cet asset.</span>
      </div>`;
    return;
  }

  // Group by severity
  const groups = {};
  SEV_ORDER.forEach(s => { groups[s] = []; });
  cves.forEach(c => {
    const s = (c.severity || 'unknown').toLowerCase();
    (groups[s in groups ? s : 'unknown']).push(c);
  });
  // Sort within each group by CVSS desc
  Object.values(groups).forEach(g => g.sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0)));

  const isAdmin = _me && _me.role === 'admin';
  const ackLabels = { none: 'À traiter', in_progress: 'En cours', accepted: 'Accepté', false_positive: 'Faux +' };
  const ackColors = { none: 'var(--danger)', in_progress: 'var(--warning)', accepted: 'var(--success)', false_positive: 'var(--text-muted)' };

  container.innerHTML = SEV_ORDER.filter(s => groups[s].length > 0).map((sev, idx) => {
    const grp = groups[sev];
    const color = SEV_COLOR[sev];
    const panelId = 'cve-grp-' + sev;
    const expanded = sev === 'critical' || sev === 'high';

    const rows = grp.map(c => {
      const ackStatus = c.ack_status || 'none';
      const ackColor = ackColors[ackStatus] || 'var(--text-muted)';
      const hasFix = !!c.fixed_version;
      const hasRemediation = !!c.remediation;
      const adminEdit = isAdmin
        ? `<button class="cve-action-edit" onclick="openCveRemediationModal('${escape(c.cve_id_str)}','${escape(c.remediation || '')}')" title="Éditer le plan d'action">✎</button>`
        : '';

      const exploitBadge = c.exploit_verified === true
        ? `<span class="exploit-verified-badge exploit-confirmed" title="Exploitabilité confirmée par Nuclei">⚡ Exploitable</span>`
        : c.exploit_verified === false
          ? `<span class="exploit-verified-badge exploit-not-confirmed" title="Nuclei n'a pas confirmé l'exploitation">✓ Non confirmé</span>`
          : '';

      return `
        <div class="cve-row" data-sev="${escape(sev)}">
          <div class="cve-row-main">
            <div class="cve-row-id">
              <a class="cve-link" href="${cveUrl(c.cve_id_str)}" target="_blank" rel="noopener">${escape(c.cve_id_str)}</a>
              ${hasFix ? `<span class="cve-fix-badge">Fix dispo</span>` : ''}
              ${exploitBadge}
            </div>
            <div class="cve-row-pkg">
              ${escape(c.package_name || '—')}
              <span class="cve-row-version">${escape(c.package_version || '')}</span>
              ${hasFix ? `<span class="cve-row-fix">→ ${escape(c.fixed_version)}</span>` : ''}
            </div>
            <div class="cve-row-meta">
              ${_renderSourceBadges(c.source)}
              ${c.cvss_score != null ? `<span class="cve-cvss-chip" style="--cvss-color:${color}">${c.cvss_score.toFixed(1)}</span>` : ''}
              <span class="cve-ack-badge" style="color:${ackColor}">${ackLabels[ackStatus] || ackStatus}</span>
            </div>
          </div>
          ${c.description ? `<div class="cve-row-desc">${escape(c.description.length > 140 ? c.description.slice(0,140)+'…' : c.description)}</div>` : ''}
          ${hasRemediation || isAdmin ? `
          <div class="cve-row-plan">
            <span class="cve-plan-icon">📋</span>
            ${hasRemediation
              ? `<span class="cve-plan-text">${escape(c.remediation)}</span>${adminEdit}`
              : `<span class="cve-plan-empty">Aucun plan d'action défini.</span>${adminEdit}`}
          </div>` : ''}
          <div class="cve-row-actions">
            <button class="cve-quick-btn" onclick="quickAck('${escape(c.id)}','in_progress')" title="Marquer En cours">⏳ En cours</button>
            <button class="cve-quick-btn" onclick="quickAck('${escape(c.id)}','accepted')" title="Marquer Accepté">✓ Accepter</button>
            <button class="cve-quick-btn muted" onclick="quickAck('${escape(c.id)}','false_positive')" title="Faux positif">⊘ Faux +</button>
          </div>
        </div>`;
    }).join('');

    return `
      <div class="cve-severity-group" data-sev="${sev}">
        <button class="cve-group-header" onclick="_toggleSevGroup('${panelId}',this)" aria-expanded="${expanded}">
          <span class="cve-group-dot" style="background:${color}"></span>
          <span class="cve-group-title" style="color:${color}">${SEV_LABEL[sev]}</span>
          <span class="cve-group-count">${grp.length} faille${grp.length > 1 ? 's' : ''}</span>
          <svg class="trivy-chevron" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12" style="${expanded ? '' : 'transform:rotate(-90deg)'}">
            <polyline points="4,6 8,10 12,6"/>
          </svg>
        </button>
        <div id="${panelId}" style="${expanded ? '' : 'display:none'}">
          ${rows}
        </div>
      </div>`;
  }).join('');
}

// ── Quick ack shortcut ────────────────────────────────────────────────────────

async function quickAck(assetCveId, status) {
  if (!_modalAssetId) return;
  try {
    await api(`/assets/${_modalAssetId}/cves/${assetCveId}/ack`, {
      method: 'PATCH',
      body: JSON.stringify({ ack_status: status }),
    });
    const asset = await api(`/assets/${_modalAssetId}`);
    if (asset) _renderFlawsTab(asset);
  } catch (e) {
    showToast('Erreur : ' + e.message, 'error');
  }
}

// ── Exploit validation ────────────────────────────────────────────────────────

async function triggerExploitValidation() {
  if (!_modalAssetId) return;
  const btn = document.getElementById('exploit-validate-btn');
  const statusEl = document.getElementById('exploit-validate-status');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Validation en cours…'; }
  if (statusEl) statusEl.textContent = '';
  try {
    const res = await api(`/assets/${_modalAssetId}/exploit-validation`, { method: 'POST' });
    if (statusEl) statusEl.textContent = res.message || `${res.queued} CVE(s) en cours de vérification`;
    showToast(`Validation lancée — ${res.queued} CVE(s)`, 'success');
    // Poll once after ~10s to refresh badges
    setTimeout(async () => {
      try {
        const asset = await api(`/assets/${_modalAssetId}`);
        if (asset) _renderFlawsTab(asset);
      } catch (_) {}
      if (btn) { btn.disabled = false; btn.innerHTML = '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="12" height="12"><path d="M8 1L1 4v5c0 4 2.8 7.75 7 9 4.2-1.25 7-5 7-9V4L8 1z"/><path d="M5 8l2 2 4-4"/></svg> Vérifier exploitabilité'; }
    }, 10000);
  } catch (e) {
    showToast('Erreur : ' + e.message, 'error');
    if (btn) { btn.disabled = false; btn.innerHTML = '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="12" height="12"><path d="M8 1L1 4v5c0 4 2.8 7.75 7 9 4.2-1.25 7-5 7-9V4L8 1z"/><path d="M5 8l2 2 4-4"/></svg> Vérifier exploitabilité'; }
  }
}

// ── CVE severity filter ───────────────────────────────────────────────────────

let _cveFilter = 'all';

function _setCveFilter(level, btn) {
  _cveFilter = level;
  document.querySelectorAll('.cve-filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  _applyCveFilter();
}

function _applyCveFilter() {
  const rows = document.querySelectorAll('#cve-tbody tr[data-severity]');
  let visible = 0;
  rows.forEach(tr => {
    const sev = (tr.dataset.severity || '').toLowerCase();
    const show = _cveFilter === 'all' || sev === _cveFilter;
    tr.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  const countEl = document.getElementById('cve-filter-count');
  if (countEl) countEl.textContent = `${visible} résultat${visible !== 1 ? 's' : ''}`;
}

// ── Failles tab renderer ──────────────────────────────────────────────────────

function _renderFlawsTab(asset) {
  const cves = asset.cves || [];
  const zapReports = asset.zap_reports || [];

  // CVE count badge on Failles tab
  const badgeEl = document.getElementById('modal-cve-badge');
  if (cves.length > 0) {
    badgeEl.textContent = cves.length;
    badgeEl.style.display = '';
  } else {
    badgeEl.style.display = 'none';
  }

  // Sub-nav badges
  const cveBadge = document.getElementById('sec-badge-cves');
  if (cveBadge) { cveBadge.textContent = cves.length || ''; cveBadge.style.display = cves.length ? '' : 'none'; }
  const zapBadge = document.getElementById('sec-badge-zap');
  const completedZap = zapReports.filter(r => r.status === 'completed');
  if (zapBadge) { zapBadge.textContent = completedZap.length || ''; zapBadge.style.display = completedZap.length ? '' : 'none'; }

  // Report selector
  const completedReports = zapReports.filter(r => r.status === 'completed');
  const selectorDiv = document.getElementById('zap-report-selector');
  const selectorEl = document.getElementById('zap-report-select');

  if (completedReports.length > 1 && selectorEl && selectorDiv) {
    selectorEl.innerHTML = completedReports.map(r =>
      `<option value="${escape(r.id)}">${escape(r.target_url || '?')} — ${fmtDate(r.created_at)}</option>`
    ).join('');
    selectorDiv.style.display = '';
  } else if (selectorDiv) {
    selectorDiv.style.display = 'none';
  }

  // Load most recent completed report
  if (completedReports.length > 0) {
    loadZapReportDetail(completedReports[0].id);
  } else {
    const flawsEl = document.getElementById('flaws-list');
    if (flawsEl) flawsEl.innerHTML =
      '<p style="color:var(--text-muted);font-size:12px">Aucun rapport disponible — lancez un scan ZAP.</p>';
    const riskEl = document.getElementById('zap-risk-summary');
    if (riskEl) riskEl.classList.add('hidden');
  }

  // CVE priority view
  try {
    _renderCvePriorityList(cves);
  } catch (e) {
    console.error('CVE render error:', e);
    const el = document.getElementById('cve-priority-list');
    if (el) el.innerHTML = `<div style="padding:20px;color:var(--danger);font-size:13px">Erreur de rendu CVE : ${escape(e.message)}</div>`;
  }

  // ZAP history
  const histList = document.getElementById('zap-history-list');
  if (!zapReports.length) {
    histList.innerHTML = '<p style="color:var(--text-muted);font-size:12px">No scans run yet.</p>';
  } else {
    histList.innerHTML = zapReports.map(r => {
      const statusType = r.status === 'completed' ? 'success'
        : r.status === 'failed' ? 'error'
        : r.status === 'running' ? 'warning' : 'muted';
      const riskPills = r.risk_summary ? Object.entries(r.risk_summary)
        .filter(([, v]) => v > 0)
        .map(([k, v]) => `<span class="badge badge-${k === 'high' ? 'error' : k === 'medium' ? 'warning' : 'info'}">${v} ${k}</span>`)
        .join(' ') : '';
      const techCount = r.technologies ? r.technologies.length : 0;
      const techBadge = techCount > 0
        ? `<span class="badge badge-muted">${techCount} tech</span>` : '';
      return `
        <div class="zap-history-item">
          ${badge(r.status, statusType)}
          <span class="zap-history-url">${escape(r.target_url || '—')}</span>
          ${riskPills}
          ${techBadge}
          <span class="zap-history-date">${fmtDate(r.created_at)}</span>
        </div>`;
    }).join('');
  }
}

// ── ZAP report detail loader ──────────────────────────────────────────────────

async function loadZapReportDetail(reportId) {
  if (!_modalAssetId || !reportId) return;
  _currentReportId = reportId;
  try {
    const detail = await api(`/assets/${_modalAssetId}/zap/${reportId}`);
    if (!detail) return;
    _renderFlawsList(detail.alerts || []);
    _renderRiskSummary(detail.risk_summary);
  } catch (e) {
    console.error('ZAP report detail error:', e);
  }
}

// ── Flaws list renderer ───────────────────────────────────────────────────────

function _renderFlawsList(alerts) {
  const container = document.getElementById('flaws-list');
  if (!container) return;

  if (!alerts || !alerts.length) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:12px">Aucune alerte pour ce rapport.</p>';
    return;
  }

  const riskOrder = { high: 0, medium: 1, low: 2, informational: 3 };
  const sorted = [...alerts].sort((a, b) =>
    (riskOrder[(a.risk || '').toLowerCase()] ?? 9) - (riskOrder[(b.risk || '').toLowerCase()] ?? 9)
  );

  container.innerHTML = sorted.map(alert => {
    const risk = (alert.risk || 'informational').toLowerCase();
    const riskCls = risk === 'high' ? 'risk-high'
      : risk === 'medium' ? 'risk-medium'
      : risk === 'low' ? 'risk-low' : 'risk-info';

    const cveLinks = (alert.cve_ids || []).map(cve =>
      `<a class="cve-link" href="${cveUrl(cve)}"
         target="_blank" rel="noopener">${escape(cve)}</a>`
    ).join(' ');

    return `
      <div class="flaw-item ${riskCls}">
        <div class="flaw-header" onclick="toggleFlaw(this)">
          <span class="flaw-arrow">▶</span>
          <span class="flaw-risk-badge">${escape(alert.risk || 'Info')}</span>
          <span class="flaw-name">${escape(alert.name || alert.alert || '—')}</span>
          ${(alert.count > 1) ? `<span class="badge badge-muted" style="margin-left:auto">${alert.count}x</span>` : ''}
        </div>
        <div class="flaw-body">
          ${alert.description ? `<p style="margin-bottom:10px;font-size:12px;color:var(--text-muted)">${escape(alert.description)}</p>` : ''}
          ${alert.solution ? `<div class="flaw-solution"><strong>Solution :</strong><br>${escape(alert.solution)}</div>` : ''}
          ${cveLinks ? `<div style="margin-top:8px;font-size:12px">CVE : ${cveLinks}</div>` : ''}
          ${alert.evidence ? `<div class="flaw-evidence"><code>${escape(alert.evidence)}</code></div>` : ''}
          ${alert.url ? `<div style="margin-top:6px;font-size:11px;color:var(--text-muted)">URL : <span class="mono">${escape(alert.url)}</span></div>` : ''}
        </div>
      </div>`;
  }).join('');
}

function toggleFlaw(headerEl) {
  const item = headerEl.closest('.flaw-item');
  if (!item) return;
  item.classList.toggle('open');
}

// ── SSH Profile toggle ─────────────────────────────────────────────────────────

/**
 * When a SSH profile is selected, hide the per-asset credential fields and show
 * a banner indicating which profile is active. When cleared, show them again.
 */
function _onSshProfileChange(profileId, selectEl) {
  const credGroups = ['modal-ssh-user-group', 'modal-ssh-port-group', 'modal-ssh-password-group', 'modal-ssh-key-group'];
  const banner = document.getElementById('modal-ssh-profile-banner');

  if (profileId) {
    // Hide credential fields (password/key are provided by the profile)
    credGroups.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = 'none';
    });
    // Build banner label from the selected option text
    const label = selectEl
      ? (selectEl.options[selectEl.selectedIndex]?.text || 'Profil SSH')
      : 'Profil SSH';
    if (banner) {
      banner.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="14" height="14"
             style="flex-shrink:0;margin-top:1px" stroke-linecap="round" stroke-linejoin="round">
          <rect x="2" y="11" width="20" height="11" rx="2"/>
          <path d="M7 11V7a5 5 0 0 1 9.9-1"/><circle cx="12" cy="16" r="1"/>
        </svg>
        Credentials fournis par le profil <strong>${escape(label)}</strong>.
        Les champs mot de passe et clé privée sont désactivés.`;
      banner.style.display = 'flex';
    }
  } else {
    // Show credential fields
    credGroups.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = '';
    });
    if (banner) banner.style.display = 'none';
  }
}

// ── Auto ZAP trigger ──────────────────────────────────────────────────────────

async function _autoTriggerZap(asset) {
  const openPorts = (asset.ports || []).filter(p => p.state === 'open');
  const httpPort  = openPorts.find(p => HTTP_PORTS.has(p.port_number));
  const httpsPort = openPorts.find(p => HTTPS_PORTS.has(p.port_number));
  if (!httpPort || !httpsPort) return;

  const zapReports = asset.zap_reports || [];
  const now = Date.now();
  const hasRecent = zapReports.some(r => {
    if (['running', 'pending'].includes(r.status)) return true;
    if (r.status === 'completed' && r.created_at) {
      return (now - new Date(r.created_at).getTime()) < 3_600_000;
    }
    return false;
  });
  if (hasRecent) return;

  // Show Auto badge on Overview tab
  const autoBadge = document.getElementById('modal-auto-badge');
  if (autoBadge) autoBadge.style.display = '';

  const httpUrl  = httpPort.port_number  === 80  ? `http://${asset.ip}`  : `http://${asset.ip}:${httpPort.port_number}`;
  const httpsUrl = httpsPort.port_number === 443 ? `https://${asset.ip}` : `https://${asset.ip}:${httpsPort.port_number}`;

  _launchAutoScan(asset.id, httpUrl);
  _launchAutoScan(asset.id, httpsUrl);
}

async function _launchAutoScan(assetId, url) {
  try {
    const report = await api(`/assets/${assetId}/zap`, {
      method: 'POST',
      body: JSON.stringify({ target_url: url, spider: true }),
    });
    if (!report) return;

    let done = false;
    while (!done && _modalAssetId === assetId) {
      await new Promise(r => setTimeout(r, 5000));
      if (_modalAssetId !== assetId) break;

      const updated = await api(`/assets/${assetId}/zap/${report.id}`);
      if (!updated) break;

      const statusEl = document.getElementById('zap-status');
      if (statusEl) {
        statusEl.className = 'status-bar running';
        statusEl.textContent = `Auto ZAP (${url}) — ${updated.status}${updated.alerts_count != null ? ' — ' + updated.alerts_count + ' alertes' : ''}`;
        statusEl.classList.remove('hidden');
      }

      if (['completed', 'failed'].includes(updated.status)) {
        done = true;
        const refreshed = await api(`/assets/${assetId}`);
        if (refreshed && _modalAssetId === assetId) {
          _renderOverviewTab(refreshed);
          _renderFlawsTab(refreshed);
        }
        if (updated.status === 'completed') {
          showToast(`Auto ZAP (${url}) : ${updated.alerts_count} alertes.`, 'success');
        }
      }
    }
  } catch (e) {
    console.error('Auto ZAP error:', e);
  }
}

function closeAssetModal(event) {
  if (event && event.target !== document.getElementById('asset-modal')) return;
  document.getElementById('asset-modal').classList.add('hidden');
  _modalAssetId = null;
  _assetDns = [];
}

// ── DNS entries ───────────────────────────────────────────────────────────────

function _renderDnsTags() {
  const container = document.getElementById('dns-tags');
  if (!container) return;
  if (!_assetDns.length) {
    container.innerHTML = '<span style="color:var(--text-muted);font-size:12px">Aucun DNS associé.</span>';
    return;
  }
  container.innerHTML = _assetDns.map(d =>
    `<span class="dns-tag">
      ${escape(d.fqdn)}
      <button class="dns-tag-remove" title="Supprimer" onclick="removeDnsEntry('${d.id}')">×</button>
    </span>`
  ).join('');
}

async function addDnsEntry() {
  if (!_modalAssetId) return;
  const input = document.getElementById('dns-input');
  const fqdn = (input?.value || '').trim();
  if (!fqdn) return;

  try {
    const entry = await api(`/assets/${_modalAssetId}/dns`, {
      method: 'POST',
      body: JSON.stringify({ fqdn }),
    });
    if (!entry) return;
    _assetDns.push(entry);
    _renderDnsTags();
    if (input) input.value = '';
    // Refresh vocabulary in background
    loadVocabulary();
  } catch (e) {
    showToast(`Erreur DNS: ${e.message}`, 'error');
  }
}

async function removeDnsEntry(dnsId) {
  if (!_modalAssetId) return;
  try {
    await api(`/assets/${_modalAssetId}/dns/${dnsId}`, { method: 'DELETE' });
    _assetDns = _assetDns.filter(d => d.id !== dnsId);
    _renderDnsTags();
  } catch (e) {
    showToast(`Erreur suppression DNS: ${e.message}`, 'error');
  }
}

// ── ZAP auto-scan target visibility renderer ──────────────────────────────────

function _renderZapTargets(asset) {
  const section = document.getElementById('zap-targets-section');
  const listEl = document.getElementById('zap-targets-list');
  const nextEl = document.getElementById('zap-next-scan');
  if (!section || !listEl || !nextEl) return;

  const targets = _computeZapTargets(asset);
  if (!targets.length) {
    section.style.display = 'none';
    return;
  }

  section.style.display = '';
  listEl.innerHTML = targets.map(t =>
    `<span style="font-size:12px;font-family:monospace;color:var(--text-muted)">
      <span class="badge badge-muted" style="margin-right:6px">${escape(String(t.port))}</span>
      <a href="${escape(t.url)}" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none">${escape(t.url)}</a>
      <span style="color:var(--text-muted);margin-left:4px">${t.source === 'IP' ? '' : '· DNS'}</span>
    </span>`
  ).join('');

  const nextMin = _computeNextScan(asset);
  if (nextMin === null) {
    nextEl.textContent = 'Auto-scan désactivé pour cet asset.';
  } else if (nextMin === 0) {
    nextEl.textContent = 'Prochain scan : dû maintenant (en attente du scheduler).';
  } else {
    nextEl.textContent = `Prochain scan dans : ${nextMin} min`;
  }
}

// ── SSH CVE section renderer + scan trigger ───────────────────────────────────

function _renderSshSection(asset, sshReports) {
  const statusEl = document.getElementById('ssh-conn-status');
  const bodyEl = document.getElementById('ssh-scan-body');
  if (!bodyEl) return;

  const hasCreds = asset.has_ssh_password || asset.has_ssh_key || !!asset.ssh_profile_id;
  const credLabel = asset.has_ssh_password || asset.has_ssh_key
    ? (asset.ssh_user ? `${asset.ssh_user}@${asset.ip || '?'}` : asset.ip || '')
    : asset.ssh_profile_name
      ? `Profil : ${asset.ssh_profile_name}`
      : asset.ip || '';

  if (statusEl) {
    statusEl.textContent = hasCreds ? credLabel : 'Aucun credential SSH';
    statusEl.style.color = hasCreds ? 'var(--text-muted)' : 'var(--danger)';
  }

  if (!hasCreds) {
    bodyEl.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.5" width="40" height="40" opacity="0.4">
          <rect x="8" y="20" width="32" height="22" rx="3"/>
          <path d="M16 20v-6a8 8 0 0 1 16 0v6"/>
          <circle cx="24" cy="31" r="2" fill="currentColor" stroke="none"/>
          <line x1="24" y1="33" x2="24" y2="37"/>
        </svg>
        <p>Aucun credential SSH configuré</p>
        <span>Ajoutez un mot de passe, une clé privée ou affectez un profil SSH dans l'onglet Détails.</span>
      </div>`;
    return;
  }

  // Build history
  let histHtml = '';
  if (!sshReports.length) {
    histHtml = `<div class="scan-history-empty">Aucun scan SSH exécuté.</div>`;
  } else {
    histHtml = `<div class="scan-history-list">` + sshReports.map(r => {
      const stType = r.status === 'completed' ? 'success' : r.status === 'failed' ? 'error' : 'warning';
      const chips = r.status === 'completed' ? [
        r.packages_found != null ? `<span class="scan-stat-chip">${r.packages_found} paquets</span>` : '',
        r.cves_found > 0 ? `<span class="scan-stat-chip danger">${r.cves_found} CVE</span>` : `<span class="scan-stat-chip success">0 CVE</span>`,
        r.os_type ? `<span class="scan-stat-chip">${escape(r.os_type)}</span>` : '',
      ].filter(Boolean).join('') : (r.error_msg ? `<span style="color:var(--danger);font-size:11px">${escape(r.error_msg)}</span>` : '');
      return `<div class="scan-history-item">
        <div class="scan-history-meta">
          ${badge(r.status, stType)}
          <span class="scan-history-date">${fmtDate(r.created_at)}</span>
        </div>
        <div class="scan-history-chips">${chips}</div>
      </div>`;
    }).join('') + `</div>`;
  }

  bodyEl.innerHTML = `
    <div class="scan-action-bar">
      <button class="btn btn-primary btn-sm" id="ssh-scan-btn" onclick="runSshScan()">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="13" height="13"><polygon points="3,2 13,8 3,14" fill="currentColor" stroke="none"/></svg>
        Analyser les paquets
      </button>
      <span id="ssh-scan-status" class="scan-status-text"></span>
    </div>
    ${histHtml}`;
}

async function runSshScan() {
  if (!_modalAssetId) return;
  const assetId = _modalAssetId;
  const btn = document.getElementById('ssh-scan-btn');
  const statusEl = document.getElementById('ssh-scan-status');
  if (btn) btn.disabled = true;
  if (statusEl) statusEl.textContent = 'Démarrage du scan SSH…';

  try {
    const report = await api(`/assets/${assetId}/ssh-scan`, { method: 'POST' });
    if (!report) return;

    if (statusEl) statusEl.textContent = 'Scan en cours…';

    // Poll until done
    let done = false;
    while (!done && _modalAssetId === assetId) {
      await new Promise(r => setTimeout(r, 3000));
      if (_modalAssetId !== assetId) break;

      const updated = await api(`/assets/${assetId}/ssh-scan/${report.id}`);
      if (!updated) break;

      if (['completed', 'failed'].includes(updated.status)) {
        done = true;
        if (updated.status === 'completed') {
          if (statusEl) statusEl.textContent = `Terminé — ${updated.cves_found ?? 0} CVE trouvées.`;
          showToast(`SSH scan : ${updated.cves_found ?? 0} CVE sur ${updated.packages_found ?? 0} paquets.`, 'success');
        } else {
          if (statusEl) statusEl.textContent = `Échec : ${updated.error_msg || 'erreur inconnue'}`;
          showToast(`SSH scan échoué : ${updated.error_msg || ''}`, 'error');
        }

        // Refresh asset & SSH reports
        const [asset, reports] = await Promise.all([
          api(`/assets/${assetId}`),
          api(`/assets/${assetId}/ssh-scan`),
        ]);
        if (asset && _modalAssetId === assetId) {
          _renderFlawsTab(asset);
          _renderSshSection(asset, reports || []);
        }
      }
    }
  } catch (e) {
    if (statusEl) statusEl.textContent = `Erreur : ${e.message}`;
    showToast(`SSH scan : ${e.message}`, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ── CVE advisory URL — routes to the right source depending on ID format ──────
//   CVE-YYYY-NNNNN          → NVD NIST
//   UBUNTU-CVE-YYYY-NNNNN   → Ubuntu security tracker
//   USN-XXXX-X              → Ubuntu Security Notice
//   GHSA-XXXX-XXXX-XXXX     → GitHub Advisory Database
//   anything else           → OSV.dev (catch-all)
function cveUrl(id) {
  if (!id) return '#';
  const u = id.toUpperCase();
  if (/^CVE-\d{4}-\d+$/.test(u))
    return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (u.startsWith('UBUNTU-CVE-'))
    return `https://ubuntu.com/security/${id.slice('UBUNTU-'.length)}`;
  if (u.startsWith('USN-'))
    return `https://ubuntu.com/security/notices/${id}`;
  if (u.startsWith('GHSA-'))
    return `https://github.com/advisories/${id}`;
  return `https://osv.dev/vulnerability/${id}`;
}

// ── Source badges (multi-value support: "zap,nuclei") ─────────────────────────

function _renderSourceBadges(source) {
  if (!source) return badge('?', 'muted');
  const srcColorMap = { zap: 'info', ssh: 'success', nuclei: 'warning' };
  return source.split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map(s => badge(s, srcColorMap[s] || 'muted'))
    .join(' ');
}

// ── Nuclei target preview (computed client-side from open ports) ───────────────

const NUCLEI_WEB_HTTPS = new Set([443, 8443, 4443, 9443]);
const NUCLEI_WEB_HTTP  = new Set([80, 8080, 3000, 8000, 8888, 9090]);
const NUCLEI_SVC_MAP   = {
  21: 'ftp', 990: 'ftp', 25: 'smtp', 465: 'smtp', 587: 'smtp',
  139: 'smb', 445: 'smb', 3306: 'mysql', 5432: 'postgresql',
  6379: 'redis', 27017: 'mongodb', 3389: 'rdp', 53: 'dns', 11211: 'memcached',
};

function _computeNucleiTargets(asset) {
  const openPorts = (asset.ports || []).filter(p => p.state === 'open');
  const targets = [];
  let hasWeb = false;

  for (const p of openPorts) {
    const pn = p.port_number;
    const svc = (p.service_name || '').toLowerCase();

    if (NUCLEI_WEB_HTTPS.has(pn) || svc.includes('https') || svc.includes('ssl')) {
      targets.push({ label: `https://${asset.ip}:${pn}`, type: 'web' });
      hasWeb = true;
    } else if (NUCLEI_WEB_HTTP.has(pn) || svc === 'http' || svc === 'www') {
      targets.push({ label: `http://${asset.ip}:${pn}`, type: 'web' });
      hasWeb = true;
    } else if (pn === 53 || svc === 'domain') {
      targets.push({ label: asset.ip, type: 'dns' });
    } else if (NUCLEI_SVC_MAP[pn] || Object.values(NUCLEI_SVC_MAP).includes(svc)) {
      const tag = NUCLEI_SVC_MAP[pn] || svc;
      targets.push({ label: `${asset.ip}:${pn}`, type: tag });
    }
  }

  if (hasWeb) {
    for (const dns of (asset.dns_entries || [])) {
      targets.push({ label: dns.fqdn, type: 'fqdn' });
    }
  }

  if (!targets.length && asset.ip) {
    targets.push({ label: asset.ip, type: 'ip' });
  }

  return targets;
}

// ── Nuclei section renderer ───────────────────────────────────────────────────

function _renderNucleiSection(asset, nucleiReports) {
  const bodyEl = document.getElementById('nuclei-scan-body');
  if (!bodyEl) return;

  // Auto-detected targets preview
  const targets = _computeNucleiTargets(asset);
  const targetsHtml = targets.length
    ? `<div class="nuclei-targets-list">
        ${targets.map(t => `
          <span style="font-size:12px;font-family:monospace;color:var(--text-muted)">
            <span class="badge badge-muted" style="margin-right:6px">${escape(t.type)}</span>
            <span style="color:var(--accent)">${escape(t.label)}</span>
          </span>`).join('')}
       </div>`
    : '<p style="color:var(--text-muted);font-size:12px;margin-top:6px">Aucun port ouvert détecté — l\'IP sera utilisée comme cible.</p>';

  // History
  let histHtml = '';
  if (!nucleiReports.length) {
    histHtml = `<div class="scan-history-empty">Aucun scan Nuclei exécuté.</div>`;
  } else {
    histHtml = `<div class="scan-history-list">` + nucleiReports.map(r => {
      const stType = r.status === 'completed' ? 'success' : r.status === 'failed' ? 'error' : 'warning';
      const chips = r.status === 'completed' ? [
        `<span class="scan-stat-chip">${r.findings_count ?? 0} résultats</span>`,
        r.cve_count > 0 ? `<span class="scan-stat-chip danger">${r.cve_count} CVE</span>` : `<span class="scan-stat-chip success">0 CVE</span>`,
        ...(r.risk_summary ? Object.entries(r.risk_summary).filter(([,v]) => v > 0).map(([k, v]) => {
          const c = k === 'critical' || k === 'high' ? 'danger' : k === 'medium' ? 'warning' : '';
          return `<span class="scan-stat-chip ${c}">${v} ${k}</span>`;
        }) : []),
      ].join('') : (r.error_msg ? `<span style="color:var(--danger);font-size:11px">${escape(r.error_msg)}</span>` : '');
      const loadBtn = r.status === 'completed'
        ? `<button class="btn btn-sm" onclick="loadNucleiReportDetail('${escape(r.id)}')">Voir</button>` : '';
      return `<div class="scan-history-item">
        <div class="scan-history-meta">
          ${badge(r.status, stType)}
          <span class="scan-history-date">${fmtDate(r.created_at)}</span>
          ${loadBtn}
        </div>
        <div class="scan-history-chips">${chips}</div>
      </div>`;
    }).join('') + `</div>`;
  }

  // Build CVE exploit validation info
  const assetCves = (asset.cves || []).filter(c => c.cve_id_str && c.cve_id_str.startsWith('CVE-'));
  const verifiedCount = assetCves.filter(c => c.exploit_verified === true).length;
  const testedCount   = assetCves.filter(c => c.exploit_verified !== null && c.exploit_verified !== undefined).length;
  const cveCountLabel = assetCves.length
    ? `${assetCves.length} CVE(s) standard sur cet asset`
    : 'Aucune CVE standard';
  const testedLabel = testedCount > 0
    ? `${testedCount} testée(s) — <span style="color:${verifiedCount > 0 ? 'var(--danger)' : 'var(--success)'}">${verifiedCount} exploitable(s)</span>`
    : 'Jamais testées';

  bodyEl.innerHTML = `
    <div style="margin-bottom:14px">
      <p class="field-label" style="margin-bottom:6px">Cibles détectées automatiquement</p>
      ${targetsHtml}
    </div>
    <div class="scan-action-bar">
      <button class="btn btn-primary btn-sm" id="nuclei-scan-btn" onclick="runNucleiScan()">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="13" height="13"><polygon points="3,2 13,8 3,14" fill="currentColor" stroke="none"/></svg>
        Lancer scan Nuclei
      </button>
      <span id="nuclei-scan-status" class="scan-status-text"></span>
    </div>
    <div class="exploit-validation-section">
      <div class="exploit-validation-header">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="14" height="14"><path d="M8 1L1 4v5c0 4 2.8 7.75 7 9 4.2-1.25 7-5 7-9V4L8 1z"/><path d="M5 8l2 2 4-4"/></svg>
        <span>Validation d'exploitabilité CVE</span>
      </div>
      <p class="exploit-validation-desc">
        Lance Nuclei avec les templates correspondant exactement aux CVE de cet asset pour
        confirmer si elles sont activement exploitables.
        ${assetCves.length > 0 ? `<br><span style="color:var(--text-muted)">${cveCountLabel} — ${testedLabel}</span>` : ''}
      </p>
      ${assetCves.length === 0
        ? `<p style="color:var(--text-muted);font-size:12px">Aucune CVE standard (CVE-XXXX-NNNNN) détectée sur cet asset.</p>`
        : `<div class="scan-action-bar" style="margin-top:8px">
            <button class="btn btn-sm" id="exploit-validate-btn" onclick="triggerExploitValidation()">
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="12" height="12"><path d="M8 1L1 4v5c0 4 2.8 7.75 7 9 4.2-1.25 7-5 7-9V4L8 1z"/><path d="M5 8l2 2 4-4"/></svg>
              Vérifier exploitabilité (${assetCves.length} CVEs)
            </button>
            <span id="exploit-validate-status" class="scan-status-text"></span>
          </div>`}
      ${testedCount > 0 ? `
        <div class="exploit-results-list">
          ${assetCves.filter(c => c.exploit_verified !== null && c.exploit_verified !== undefined).map(c => `
            <div class="exploit-result-row">
              <span class="mono" style="font-size:11px;color:var(--text-subtle)">${escape(c.cve_id_str)}</span>
              ${c.exploit_verified
                ? `<span class="exploit-verified-badge exploit-confirmed">⚡ Exploitable</span>`
                : `<span class="exploit-verified-badge exploit-not-confirmed">✓ Non confirmé</span>`}
              ${c.exploit_verified_at ? `<span style="font-size:10px;color:var(--text-muted)">${fmtDate(c.exploit_verified_at)}</span>` : ''}
            </div>`).join('')}
        </div>` : ''}
    </div>
    ${histHtml}`;
}

async function runNucleiScan() {
  if (!_modalAssetId) return;
  const assetId = _modalAssetId;
  const btn = document.getElementById('nuclei-scan-btn');
  const statusEl = document.getElementById('nuclei-scan-status');
  if (btn) btn.disabled = true;
  if (statusEl) statusEl.textContent = 'Démarrage du scan Nuclei…';

  try {
    const report = await api(`/assets/${assetId}/nuclei`, { method: 'POST' });
    if (!report) return;

    if (statusEl) statusEl.textContent = 'Scan en cours…';

    let done = false;
    while (!done && _modalAssetId === assetId) {
      await new Promise(r => setTimeout(r, 3000));
      if (_modalAssetId !== assetId) break;

      const updated = await api(`/assets/${assetId}/nuclei/${report.id}`);
      if (!updated) break;

      if (['completed', 'failed'].includes(updated.status)) {
        done = true;
        if (updated.status === 'completed') {
          if (statusEl) statusEl.textContent = `Terminé — ${updated.findings_count ?? 0} résultats · ${updated.cve_count ?? 0} CVE.`;
          showToast(`Nuclei : ${updated.findings_count ?? 0} résultats, ${updated.cve_count ?? 0} CVE.`, 'success');
          _renderNucleiRiskSummary(updated.risk_summary);
          _renderNucleiFindingsList(updated.findings || []);
        } else {
          if (statusEl) statusEl.textContent = `Échec : ${updated.error_msg || 'erreur inconnue'}`;
          showToast(`Nuclei scan échoué : ${updated.error_msg || ''}`, 'error');
        }

        // Refresh asset + all sections
        const [asset, nucleiReports] = await Promise.all([
          api(`/assets/${assetId}`),
          api(`/assets/${assetId}/nuclei`),
        ]);
        if (asset && _modalAssetId === assetId) {
          _renderFlawsTab(asset);
          _renderNucleiSection(asset, nucleiReports || []);
        }
      }
    }
  } catch (e) {
    if (statusEl) statusEl.textContent = `Erreur : ${e.message}`;
    showToast(`Nuclei scan : ${e.message}`, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function loadNucleiReportDetail(reportId) {
  if (!_modalAssetId || !reportId) return;
  try {
    const detail = await api(`/assets/${_modalAssetId}/nuclei/${reportId}`);
    if (!detail) return;
    _renderNucleiRiskSummary(detail.risk_summary);
    _renderNucleiFindingsList(detail.findings || []);
  } catch (e) {
    console.error('Nuclei report detail error:', e);
  }
}

function _renderNucleiRiskSummary(riskSummary) {
  const el = document.getElementById('nuclei-risk-summary');
  if (!el) return;
  if (!riskSummary) { el.classList.add('hidden'); return; }
  const items = [
    { key: 'critical', label: 'Critical', cls: 'risk-high' },
    { key: 'high',     label: 'High',     cls: 'risk-high' },
    { key: 'medium',   label: 'Medium',   cls: 'risk-medium' },
    { key: 'low',      label: 'Low',      cls: 'risk-low' },
    { key: 'info',     label: 'Info',     cls: 'risk-info' },
  ];
  el.innerHTML = items
    .filter(i => riskSummary[i.key] > 0)
    .map(i => `
      <div class="risk-pill ${i.cls}">
        <span class="risk-pill-num">${riskSummary[i.key]}</span>
        <span class="risk-pill-label">${i.label}</span>
      </div>`).join('');
  el.classList.remove('hidden');
}

function _renderNucleiFindingsList(findings) {
  const container = document.getElementById('nuclei-findings-list');
  if (!container) return;

  if (!findings || !findings.length) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:12px">Aucun résultat pour ce rapport.</p>';
    return;
  }

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort((a, b) =>
    (sevOrder[(a.severity || 'info').toLowerCase()] ?? 9) -
    (sevOrder[(b.severity || 'info').toLowerCase()] ?? 9)
  );

  container.innerHTML = sorted.map(f => {
    const sev = (f.severity || 'info').toLowerCase();
    const riskCls = sev === 'critical' || sev === 'high' ? 'risk-high'
      : sev === 'medium' ? 'risk-medium'
      : sev === 'low' ? 'risk-low' : 'risk-info';

    const cveLinks = (f.cve_ids || []).map(cve =>
      `<a class="cve-link" href="${cveUrl(cve)}"
         target="_blank" rel="noopener">${escape(cve)}</a>`
    ).join(' ');

    const tags = (f.tags || []).map(t => badge(t, 'muted')).join(' ');

    return `
      <div class="flaw-item ${riskCls}">
        <div class="flaw-header" onclick="toggleFlaw(this)">
          <span class="flaw-arrow">▶</span>
          <span class="flaw-risk-badge">${escape(f.severity || 'info')}</span>
          <span class="flaw-name">${escape(f.name || f.template_id || '—')}</span>
          <span class="badge badge-muted" style="margin-left:auto;font-size:10px">${escape(f.type || '?')}</span>
        </div>
        <div class="flaw-body">
          ${f.description ? `<p style="margin-bottom:10px;font-size:12px;color:var(--text-muted)">${escape(f.description)}</p>` : ''}
          ${cveLinks ? `<div style="margin-top:8px;font-size:12px">CVE : ${cveLinks}</div>` : ''}
          ${f.cvss_score != null ? `<div style="margin-top:6px;font-size:11px;color:var(--text-muted)">CVSS : ${f.cvss_score.toFixed(1)}</div>` : ''}
          ${f.matched_at ? `<div style="margin-top:6px;font-size:11px;color:var(--text-muted)">Matched : <span class="mono">${escape(f.matched_at)}</span></div>` : ''}
          ${tags ? `<div style="margin-top:8px;font-size:11px">${tags}</div>` : ''}
        </div>
      </div>`;
  }).join('');
}

// ── ZAP scan ──────────────────────────────────────────────────────────────────

async function runZapScan() {
  if (!_modalAssetId) return;
  const targetUrl = document.getElementById('zap-target-url').value.trim();
  if (!targetUrl) { showToast('Enter a target URL for the ZAP scan.', 'warning'); return; }

  const btn = document.getElementById('zap-scan-btn');
  btn.disabled = true;

  const statusEl = document.getElementById('zap-status');
  statusEl.className = 'status-bar running';
  statusEl.textContent = 'ZAP scan queued — spider starting…';
  statusEl.classList.remove('hidden');
  document.getElementById('zap-risk-summary').classList.add('hidden');

  try {
    const report = await api(`/assets/${_modalAssetId}/zap`, {
      method: 'POST',
      body: JSON.stringify({ target_url: targetUrl, spider: true }),
    });
    if (!report) return;

    // Poll until done
    let done = false;
    while (!done) {
      await new Promise(r => setTimeout(r, 3000));
      const updated = await api(`/assets/${_modalAssetId}/zap/${report.id}`);
      if (!updated) break;

      statusEl.textContent = `ZAP scan ${updated.status} — ${updated.alerts_count ?? '…'} alerts`;

      if (['completed', 'failed'].includes(updated.status)) {
        done = true;
        if (updated.status === 'completed') {
          statusEl.className = 'status-bar success';
          statusEl.textContent = `ZAP scan complete — ${updated.alerts_count} alerts found.`;
          _renderRiskSummary(updated.risk_summary);
          showToast(`ZAP scan finished: ${updated.alerts_count} alerts.`, 'success');
        } else {
          statusEl.className = 'status-bar error';
          statusEl.textContent = `ZAP scan failed: ${updated.error_msg || 'unknown error'}`;
          showToast('ZAP scan failed.', 'error');
        }

        // Reload asset to get updated data
        const asset = await api(`/assets/${_modalAssetId}`);
        if (asset) { _renderOverviewTab(asset); _renderFlawsTab(asset); }
      }
    }
  } catch (e) {
    statusEl.className = 'status-bar error';
    statusEl.textContent = `ZAP error: ${e.message}`;
    showToast(`ZAP error: ${e.message}`, 'error');
  } finally {
    btn.disabled = false;
  }
}

function _renderRiskSummary(riskSummary) {
  const el = document.getElementById('zap-risk-summary');
  if (!riskSummary) { el.classList.add('hidden'); return; }
  const items = [
    { key: 'high',          label: 'High',   cls: 'risk-high' },
    { key: 'medium',        label: 'Medium', cls: 'risk-medium' },
    { key: 'low',           label: 'Low',    cls: 'risk-low' },
    { key: 'informational', label: 'Info',   cls: 'risk-info' },
  ];
  el.innerHTML = items.map(i => `
    <div class="risk-pill ${i.cls}">
      <span class="risk-pill-num">${riskSummary[i.key] ?? 0}</span>
      <span class="risk-pill-label">${i.label}</span>
    </div>`).join('');
  el.classList.remove('hidden');
}

// ── Scan modal ────────────────────────────────────────────────────────────────

function openScanModal() {
  document.getElementById('scan-modal').classList.remove('hidden');
}

function closeScanModal(event) {
  if (event && event.target !== document.getElementById('scan-modal')) return;
  document.getElementById('scan-modal').classList.add('hidden');
}

// ── Scans ─────────────────────────────────────────────────────────────────────

async function loadScans() {
  try {
    const { items } = await api('/scans?limit=50');
    const tbody = document.querySelector('#scan-table tbody');
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:32px">No scans yet — start one with "+ New scan"</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(s => {
      const assetsFound = s.summary?.modules
        ? Object.values(s.summary.modules).reduce((acc, m) => acc + (m.assets_found || 0), 0)
        : '—';
      const running = ['pending', 'running'].includes(s.status);
      const rerunBtn = `<button class="btn btn-sm" onclick="rerunScan('${s.id}')"
                          ${running ? 'disabled title="Scan in progress"' : ''}>&#8635; Re-run</button>`;
      return `
        <tr>
          <td class="mono" style="font-size:11px;color:var(--text-muted)">${s.id.slice(0, 8)}…</td>
          <td class="mono">${escape(s.target)}</td>
          <td>${(s.modules_run || []).map(m => badge(m, 'info')).join(' ')}</td>
          <td>${statusBadge(s.status)}</td>
          <td style="font-size:12px;color:var(--text-muted)">${fmtDate(s.started_at)}</td>
          <td style="font-size:12px;color:var(--text-muted)">${fmtDate(s.finished_at)}</td>
          <td>${assetsFound}</td>
          <td>${rerunBtn}</td>
        </tr>`;
    }).join('');
  } catch (e) {
    console.error('Scans error:', e);
  }
}

async function triggerScan() {
  const target = document.getElementById('scan-target').value.trim();
  if (!target) { showToast('Please enter a target CIDR or IP.', 'warning'); return; }

  const checked = [...document.querySelectorAll('#module-checkboxes input:checked')];
  const modules = checked.map(cb => cb.value);
  if (!modules.length) { showToast('Select at least one module.', 'warning'); return; }

  // Close the modal and switch to scans panel
  document.getElementById('scan-modal').classList.add('hidden');
  switchToView('scans');

  const statusEl = document.getElementById('scan-status');
  statusEl.className = 'status-bar running';
  statusEl.textContent = `Starting scan on ${target} with [${modules.join(', ')}]…`;
  statusEl.classList.remove('hidden');
  document.getElementById('scan-btn').disabled = true;

  try {
    const scan = await api('/scans', {
      method: 'POST',
      body: JSON.stringify({ target, modules }),
    });

    statusEl.textContent = `Scan ${scan.id.slice(0, 8)} created — polling…`;

    let done = false;
    while (!done) {
      await new Promise(r => setTimeout(r, 2000));
      const updated = await api(`/scans/${scan.id}`);
      statusEl.textContent = `Scan ${updated.id.slice(0, 8)} — ${updated.status}`;

      if (['completed', 'completed_with_errors', 'failed', 'error'].includes(updated.status)) {
        done = true;
        const ok = updated.status === 'completed';
        statusEl.className = 'status-bar ' + (ok ? 'success' : 'error');
        const total = updated.summary?.modules
          ? Object.values(updated.summary.modules).reduce((s, m) => s + (m.assets_found || 0), 0)
          : 0;
        statusEl.textContent = `Scan complete (${updated.status}) — ${total} assets found.`;
        showToast(`Scan finished: ${total} assets found.`, ok ? 'success' : 'warning');
        await loadAssets();
        await loadScans();
        await refreshStats();
      }
    }
  } catch (e) {
    statusEl.className = 'status-bar error';
    statusEl.textContent = `Error: ${e.message}`;
    showToast(`Scan error: ${e.message}`, 'error');
  } finally {
    document.getElementById('scan-btn').disabled = false;
  }
}

async function rerunScan(scanId) {
  // Switch to scans panel
  switchToView('scans');

  const statusEl = document.getElementById('scan-status');
  statusEl.className = 'status-bar running';
  statusEl.textContent = 'Re-running scan…';
  statusEl.classList.remove('hidden');

  document.querySelectorAll('#scan-table button').forEach(b => { b.disabled = true; });

  try {
    const scan = await api(`/scans/${scanId}/rerun`, { method: 'POST' });
    statusEl.textContent = `Re-run ${scan.id.slice(0, 8)} created — target: ${scan.target}. Polling…`;

    let done = false;
    while (!done) {
      await new Promise(r => setTimeout(r, 2000));
      await loadScans();
      const updated = await api(`/scans/${scan.id}`);
      statusEl.textContent = `Re-run ${updated.id.slice(0, 8)} — ${updated.status}`;

      if (['completed', 'completed_with_errors', 'failed', 'error'].includes(updated.status)) {
        done = true;
        const ok = updated.status === 'completed';
        statusEl.className = 'status-bar ' + (ok ? 'success' : 'error');
        const total = updated.summary?.modules
          ? Object.values(updated.summary.modules).reduce((s, m) => s + (m.assets_found || 0), 0)
          : 0;
        statusEl.textContent = `Re-run complete (${updated.status}) — ${total} assets found.`;
        showToast(`Re-run finished: ${total} assets found.`, ok ? 'success' : 'warning');
        await loadAssets();
        await refreshStats();
      }
    }
  } catch (e) {
    statusEl.className = 'status-bar error';
    statusEl.textContent = `Re-run error: ${e.message}`;
    showToast(`Re-run error: ${e.message}`, 'error');
  } finally {
    await loadScans();
  }
}

// ── Modules ───────────────────────────────────────────────────────────────────

async function loadModules() {
  try {
    const { items } = await api('/modules');
    const grid = document.getElementById('modules-grid');
    const categoryColors = {
      discovery: 'info',
      port_scan: 'warning',
      service: 'success',
      os_detect: 'error',
    };
    grid.innerHTML = items.map(m => `
      <div class="module-card">
        <div class="mod-name">${escape(m.display_name)}</div>
        <div class="mod-meta">
          ${badge(m.category, categoryColors[m.category] || 'muted')}
          ${badge('v' + m.version, 'muted')}
          ${m.requires_root ? badge('root', 'warning') : ''}
        </div>
        <div class="mod-desc">${escape(m.description)}</div>
      </div>
    `).join('');
  } catch (e) {
    console.error('Modules error:', e);
  }
}

// ── Users ─────────────────────────────────────────────────────────────────────

async function loadUsers() {
  try {
    const data = await api('/users');
    if (!data) return;
    const tbody = document.querySelector('#user-table tbody');
    if (!data.items.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:32px">No users</td></tr>';
      return;
    }
    tbody.innerHTML = data.items.map(u => {
      const isSelf = u.id === _me?.id;
      const quota = u.scan_quota_per_day != null ? u.scan_quota_per_day : '∞';
      return `
        <tr>
          <td>${escape(u.email)}</td>
          <td class="mono">${escape(u.username)}</td>
          <td>${escape(u.full_name || '—')}</td>
          <td>${badge(u.role, u.role === 'admin' ? 'warning' : 'info')}</td>
          <td>${badge(u.auth_provider, 'muted')}</td>
          <td>${u.is_active ? badge('active', 'success') : badge('disabled', 'error')}</td>
          <td style="text-align:center">${quota}</td>
          <td style="display:flex;gap:6px;flex-wrap:wrap">
            <button class="btn btn-sm" onclick="openUserModal('${u.id}')">Edit</button>
            ${!isSelf
              ? `<button class="btn btn-sm" style="color:var(--danger)"
                   onclick="deleteUser('${u.id}','${escape(u.email)}')">Delete</button>`
              : '<span style="color:var(--text-muted);font-size:12px;padding:6px 4px">you</span>'}
          </td>
        </tr>`;
    }).join('');
  } catch (e) {
    console.error('Users error:', e);
  }
}

let _userModalId = null;

async function openUserModal(userId = null) {
  _userModalId = userId;
  const isEdit = !!userId;
  document.getElementById('user-modal-title').textContent = isEdit ? 'Edit user' : 'New user';
  document.getElementById('um-save-btn').textContent = isEdit ? 'Save' : 'Create';
  document.getElementById('um-pwd-hint').style.display = isEdit ? '' : 'none';

  ['um-email','um-username','um-fullname','um-password'].forEach(id => {
    document.getElementById(id).value = '';
  });
  document.getElementById('um-role').value = 'user';
  document.getElementById('um-quota').value = '';

  if (isEdit) {
    try {
      const u = await api(`/users/${userId}`);
      if (!u) return;
      document.getElementById('um-email').value = u.email;
      document.getElementById('um-username').value = u.username;
      document.getElementById('um-fullname').value = u.full_name || '';
      document.getElementById('um-role').value = u.role;
      document.getElementById('um-quota').value = u.scan_quota_per_day != null ? u.scan_quota_per_day : '';
      const isOidc = u.auth_provider !== 'local';
      document.getElementById('um-email').disabled = isOidc;
      document.getElementById('um-username').disabled = isOidc;
    } catch (e) {
      showToast(`Error loading user: ${e.message}`, 'error');
      return;
    }
  } else {
    document.getElementById('um-email').disabled = false;
    document.getElementById('um-username').disabled = false;
  }

  document.getElementById('user-modal').classList.remove('hidden');
}

function closeUserModal(event) {
  if (event && event.target !== document.getElementById('user-modal')) return;
  document.getElementById('user-modal').classList.add('hidden');
  _userModalId = null;
}

async function saveUserModal() {
  const btn = document.getElementById('um-save-btn');
  btn.disabled = true;
  btn.textContent = 'Saving…';
  const isEdit = !!_userModalId;

  try {
    if (isEdit) {
      const pwd = document.getElementById('um-password').value;
      const quotaRaw = document.getElementById('um-quota').value;
      const payload = {
        full_name: document.getElementById('um-fullname').value.trim() || null,
        role: document.getElementById('um-role').value,
        scan_quota_per_day: quotaRaw !== '' ? parseInt(quotaRaw, 10) : null,
      };
      if (pwd) payload.password = pwd;
      await api(`/users/${_userModalId}`, { method: 'PATCH', body: JSON.stringify(payload) });
    } else {
      await api('/users', {
        method: 'POST',
        body: JSON.stringify({
          email: document.getElementById('um-email').value.trim(),
          username: document.getElementById('um-username').value.trim(),
          full_name: document.getElementById('um-fullname').value.trim() || null,
          password: document.getElementById('um-password').value,
          role: document.getElementById('um-role').value,
        }),
      });
    }
    document.getElementById('user-modal').classList.add('hidden');
    _userModalId = null;
    await loadUsers();
    showToast(isEdit ? 'User updated.' : 'User created.', 'success');
  } catch (e) {
    showToast(`Error: ${e.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = isEdit ? 'Save' : 'Create';
  }
}

async function deleteUser(id, email) {
  if (!confirm(`Delete user "${email}"? This action cannot be undone.`)) return;
  try {
    await api(`/users/${id}`, { method: 'DELETE' });
    await loadUsers();
    showToast('User deleted.', 'info');
  } catch (e) {
    showToast(`Error: ${e.message}`, 'error');
  }
}

// ── ZAP global settings (admin) ───────────────────────────────────────────────

async function loadZapSettings() {
  try {
    const s = await api('/admin/zap-settings');
    if (!s) return;
    const enabledEl = document.getElementById('zap-global-enabled');
    const intervalEl = document.getElementById('zap-global-interval');
    if (enabledEl) enabledEl.checked = s.zap_auto_scan_enabled;
    if (intervalEl) intervalEl.value = s.zap_scan_interval_minutes;
  } catch (e) {
    console.error('ZAP settings load error:', e);
  }
}

async function saveZapSettings() {
  const btn = document.querySelector('[onclick="saveZapSettings()"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Sauvegarde…'; }
  const statusEl = document.getElementById('zap-settings-status');

  try {
    const intervalVal = parseInt(document.getElementById('zap-global-interval').value, 10);
    await api('/admin/zap-settings', {
      method: 'PUT',
      body: JSON.stringify({
        zap_auto_scan_enabled: document.getElementById('zap-global-enabled').checked,
        zap_scan_interval_minutes: isNaN(intervalVal) ? 60 : intervalVal,
      }),
    });
    if (statusEl) {
      statusEl.className = 'status-bar success';
      statusEl.textContent = 'Paramètres ZAP sauvegardés.';
      statusEl.classList.remove('hidden');
    }
    showToast('Paramètres ZAP sauvegardés.', 'success');
  } catch (e) {
    if (statusEl) {
      statusEl.className = 'status-bar error';
      statusEl.textContent = `Erreur: ${e.message}`;
      statusEl.classList.remove('hidden');
    }
    showToast(`Erreur: ${e.message}`, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Sauvegarder'; }
  }
}

// ── Auth settings ─────────────────────────────────────────────────────────────

async function loadAuthSettings() {
  try {
    const s = await api('/admin/auth-settings');
    if (!s) return;
    const grid = document.getElementById('auth-settings-grid');
    const row = (k, v) =>
      `<span class="detail-key">${k}</span><span class="detail-val">${escape(String(v))}</span>`;
    grid.innerHTML = [
      row('Algorithm', s.jwt_algorithm),
      row('Token expiry', s.jwt_access_token_expire_minutes + ' minutes'),
      row('OIDC (env)', s.oidc_enabled_in_env ? 'enabled' : 'disabled'),
    ].join('');
  } catch (e) {
    console.error('Auth settings error:', e);
  }
}

// ── OIDC ──────────────────────────────────────────────────────────────────────

async function loadOidcConfig() {
  try {
    const cfg = await api('/admin/oidc');
    if (!cfg) return;
    document.getElementById('oidc-enabled').checked = cfg.enabled;
    document.getElementById('oidc-name').value = cfg.name || '';
    document.getElementById('oidc-issuer').value = cfg.issuer_url || '';
    document.getElementById('oidc-client-id').value = cfg.client_id || '';
    document.getElementById('oidc-client-secret').value = '';
    document.getElementById('oidc-client-secret').placeholder =
      cfg.client_secret_set ? '••••••••  (set — leave blank to keep)' : 'Enter client secret';
    document.getElementById('oidc-scopes').value = cfg.scopes || 'openid email profile';
    document.getElementById('oidc-auto-create').checked = cfg.auto_create_users;
    document.getElementById('oidc-default-role').value = cfg.default_role || 'user';
  } catch (e) {
    console.error('OIDC load error:', e);
  }
}

async function saveOidcConfig() {
  const btn = document.querySelector('[onclick="saveOidcConfig()"]');
  btn.disabled = true;
  btn.textContent = 'Saving…';
  try {
    const secret = document.getElementById('oidc-client-secret').value;
    await api('/admin/oidc', {
      method: 'PUT',
      body: JSON.stringify({
        enabled: document.getElementById('oidc-enabled').checked,
        name: document.getElementById('oidc-name').value.trim() || 'SSO',
        issuer_url: document.getElementById('oidc-issuer').value.trim() || null,
        client_id: document.getElementById('oidc-client-id').value.trim() || null,
        client_secret: secret || null,
        scopes: document.getElementById('oidc-scopes').value.trim() || 'openid email profile',
        auto_create_users: document.getElementById('oidc-auto-create').checked,
        default_role: document.getElementById('oidc-default-role').value,
      }),
    });
    await loadOidcConfig();
    showToast('OIDC configuration saved.', 'success');
  } catch (e) {
    showToast(`Save failed: ${e.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save';
  }
}

async function testOidcConnection() {
  const btn = document.querySelector('[onclick="testOidcConnection()"]');
  btn.disabled = true;
  btn.textContent = 'Testing…';
  const res = document.getElementById('oidc-test-result');
  res.className = 'status-bar running';
  res.textContent = 'Fetching discovery document…';
  res.classList.remove('hidden');

  try {
    const result = await api('/admin/oidc/test', { method: 'POST' });
    if (!result) return;
    if (result.success) {
      res.className = 'status-bar success';
      const eps = result.endpoints
        ? Object.entries(result.endpoints)
            .filter(([, v]) => v)
            .map(([k, v]) => `<br><span style="color:var(--text-muted)">${k}:</span> ${escape(v)}`)
            .join('')
        : '';
      res.innerHTML = `&#10003; ${escape(result.message)}${eps}`;
    } else {
      res.className = 'status-bar error';
      res.textContent = `&#10007; ${result.message}`;
    }
  } catch (e) {
    res.className = 'status-bar error';
    res.textContent = `Error: ${e.message}`;
  } finally {
    btn.disabled = false;
    btn.textContent = '▶ Test connection';
  }
}

// ── Trivy helpers ─────────────────────────────────────────────────────────────

/** Extract docker image from AssetCve.package_name = "{image}:{pkg}" */
function _trivyImage(packageName) {
  if (!packageName) return '(image inconnue)';
  const parts = packageName.split(':');
  // image could be "nginx:latest" (2 parts) or "registry/img:tag" — pkg is always last segment
  if (parts.length >= 3) return parts.slice(0, parts.length - 1).join(':');
  if (parts.length === 2) return parts[0]; // "image:pkg" with no tag
  return packageName;
}

function _trivyPkg(packageName) {
  if (!packageName) return '';
  const parts = packageName.split(':');
  return parts.length >= 2 ? parts[parts.length - 1] : packageName;
}

function _renderTrivyCvesByImage(cves) {
  const trivyCves = cves.filter(c => (c.source || '').includes('trivy'));
  if (!trivyCves.length) {
    return `<div class="scan-history-empty" style="margin-top:12px">Aucune CVE Trivy — lancez un scan pour les obtenir.</div>`;
  }

  // Group by image
  const byImage = {};
  trivyCves.forEach(c => {
    const img = _trivyImage(c.package_name);
    if (!byImage[img]) byImage[img] = [];
    byImage[img].push(c);
  });

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
  const sevType = s => s === 'critical' || s === 'high' ? 'error' : s === 'medium' ? 'warning' : s === 'low' ? 'info' : 'muted';

  return Object.entries(byImage).map(([img, imgCves], idx) => {
    const sorted = [...imgCves].sort((a, b) =>
      (sevOrder[(a.severity || '').toLowerCase()] ?? 9) - (sevOrder[(b.severity || '').toLowerCase()] ?? 9)
    );
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    sorted.forEach(c => { const s = (c.severity || '').toLowerCase(); if (s in counts) counts[s]++; });
    const countPills = Object.entries(counts).filter(([,v]) => v > 0)
      .map(([k, v]) => `<span class="scan-stat-chip ${k === 'critical' || k === 'high' ? 'danger' : k === 'medium' ? 'warning' : ''}">${v} ${k}</span>`).join('');

    const rows = sorted.map(c => {
      const sev = (c.severity || '').toLowerCase();
      const pkg = _trivyPkg(c.package_name);
      return `<tr>
        <td><a class="cve-link" href="${cveUrl(c.cve_id_str)}" target="_blank" rel="noopener" title="${escape(c.description || '')}">${escape(c.cve_id_str)}</a></td>
        <td>${escape(pkg || '—')}</td>
        <td class="mono" style="font-size:11px">${escape(c.package_version || '—')}</td>
        <td class="mono" style="font-size:11px">${c.fixed_version ? `<span style="color:var(--success)">${escape(c.fixed_version)}</span>` : '<span style="color:var(--text-muted)">—</span>'}</td>
        <td>${c.severity ? badge(c.severity, sevType(sev)) : '—'}</td>
        <td>${c.cvss_score != null ? c.cvss_score.toFixed(1) : '—'}</td>
      </tr>`;
    }).join('');

    const panelId = `trivy-img-panel-${idx}`;
    return `
      <div class="trivy-image-group">
        <button class="trivy-image-header" onclick="_toggleTrivyGroup('${panelId}',this)" aria-expanded="true">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="14" height="14">
            <rect x="1" y="4" width="14" height="9" rx="2"/>
            <path d="M4 4V3a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v1"/>
          </svg>
          <span class="trivy-image-name">${escape(img)}</span>
          <span class="trivy-image-chips">${countPills}</span>
          <svg class="trivy-chevron" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12">
            <polyline points="4,6 8,10 12,6"/>
          </svg>
        </button>
        <div class="trivy-image-body" id="${panelId}">
          <div class="table-wrap">
            <table>
              <thead><tr><th>CVE</th><th>Paquet</th><th>Version</th><th>Fix</th><th>Sévérité</th><th>CVSS</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </div>
      </div>`;
  }).join('');
}

function _toggleTrivyGroup(panelId, btn) {
  const panel = document.getElementById(panelId);
  if (!panel) return;
  const open = panel.style.display !== 'none';
  panel.style.display = open ? 'none' : '';
  if (btn) btn.setAttribute('aria-expanded', String(!open));
}

// ── Trivy Docker section renderer + scan trigger ──────────────────────────────

function _renderTrivyDockerSection(asset, trivyReports) {
  const statusEl = document.getElementById('trivy-docker-status');
  const bodyEl = document.getElementById('trivy-docker-body');
  if (!bodyEl) return;

  const hasCreds = asset.has_ssh_password || asset.has_ssh_key || asset.ssh_profile_id;

  if (statusEl) {
    statusEl.textContent = hasCreds
      ? (asset.ssh_user ? `${asset.ssh_user}@${asset.ip || '?'}` : asset.ip || '')
      : 'Aucun credential SSH';
    statusEl.style.color = hasCreds ? 'var(--text-muted)' : 'var(--danger)';
  }

  if (!hasCreds) {
    bodyEl.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.5" width="40" height="40" opacity="0.4">
          <rect x="8" y="20" width="32" height="22" rx="3"/>
          <path d="M16 20v-6a8 8 0 0 1 16 0v6"/>
          <circle cx="24" cy="31" r="2" fill="currentColor" stroke="none"/>
        </svg>
        <p>Aucun credential SSH configuré</p>
        <span>Ajoutez des credentials ou un profil SSH pour activer le scan Trivy.</span>
      </div>`;
    return;
  }

  let histHtml = '';
  if (!trivyReports.length) {
    histHtml = `<div class="scan-history-empty">Aucun scan Trivy exécuté.</div>`;
  } else {
    histHtml = `<div class="scan-history-list">` + trivyReports.map(r => {
      const stType = r.status === 'completed' ? 'success' : r.status === 'failed' ? 'error' : 'warning';
      const chips = r.status === 'completed' ? [
        `<span class="scan-stat-chip">${r.containers_found} conteneur${r.containers_found !== 1 ? 's' : ''}</span>`,
        `<span class="scan-stat-chip">${r.images_scanned} image${r.images_scanned !== 1 ? 's' : ''}</span>`,
        r.cves_found > 0 ? `<span class="scan-stat-chip danger">${r.cves_found} CVE</span>` : `<span class="scan-stat-chip success">0 CVE</span>`,
      ].join('') : (r.error_msg ? `<span style="color:var(--danger);font-size:11px">${escape(r.error_msg)}</span>` : '');
      return `<div class="scan-history-item">
        <div class="scan-history-meta">
          ${badge(r.status, stType)}
          <span class="scan-history-date">${fmtDate(r.created_at)}</span>
        </div>
        <div class="scan-history-chips">${chips}</div>
      </div>`;
    }).join('') + `</div>`;
  }

  const cvesByImage = _renderTrivyCvesByImage(asset.cves || []);

  bodyEl.innerHTML = `
    <div class="scan-action-bar">
      <button class="btn btn-primary btn-sm" id="trivy-docker-btn" onclick="runTrivyDockerScan()">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="13" height="13"><polygon points="3,2 13,8 3,14" fill="currentColor" stroke="none"/></svg>
        Scanner les conteneurs Docker
      </button>
      <span id="trivy-docker-scan-status" class="scan-status-text"></span>
    </div>
    <p class="scan-hint">Requiert Docker sur la machine distante et un accès au socket Docker (groupe <code>docker</code> ou <code>root</code>).</p>
    <div style="margin-top:16px">
      <p class="field-label" style="margin-bottom:10px">CVE par conteneur</p>
      ${cvesByImage}
    </div>
    ${histHtml}`;
}

async function runTrivyDockerScan() {
  if (!_modalAssetId) return;
  const assetId = _modalAssetId;
  const btn = document.getElementById('trivy-docker-btn');
  const statusEl = document.getElementById('trivy-docker-scan-status');
  if (btn) btn.disabled = true;
  if (statusEl) statusEl.textContent = 'Démarrage du scan Trivy…';

  try {
    const report = await api(`/assets/${assetId}/trivy-docker`, { method: 'POST' });
    if (!report) return;
    if (statusEl) statusEl.textContent = 'Connexion SSH + forwarding socket Docker…';

    let done = false;
    while (!done && _modalAssetId === assetId) {
      await new Promise(r => setTimeout(r, 4000));
      if (_modalAssetId !== assetId) break;

      const updated = await api(`/assets/${assetId}/trivy-docker/${report.id}`);
      if (!updated) break;

      if (updated.status === 'running' && updated.containers_found > 0 && statusEl) {
        statusEl.textContent = `Scan Trivy en cours — ${updated.containers_found} conteneur(s) détecté(s)…`;
      }

      if (['completed', 'failed'].includes(updated.status)) {
        done = true;
        if (updated.status === 'completed') {
          if (statusEl) statusEl.textContent = `Terminé — ${updated.cves_found} CVE sur ${updated.images_scanned} image(s).`;
          showToast(`Trivy : ${updated.cves_found} CVE sur ${updated.images_scanned} image(s) Docker.`, 'success');
        } else {
          if (statusEl) statusEl.textContent = `Échec : ${updated.error_msg || 'erreur inconnue'}`;
          showToast(`Trivy échoué : ${updated.error_msg || ''}`, 'error');
        }

        const [asset, reports] = await Promise.all([
          api(`/assets/${assetId}`),
          api(`/assets/${assetId}/trivy-docker`),
        ]);
        if (asset && _modalAssetId === assetId) {
          _renderFlawsTab(asset);
          _renderTrivyDockerSection(asset, reports || []);
        }
      }
    }
  } catch (e) {
    if (statusEl) statusEl.textContent = `Erreur : ${e.message}`;
    showToast(`Trivy : ${e.message}`, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ── SSH Profiles (admin) ──────────────────────────────────────────────────────

let _sshProfiles = [];
let _editingSshProfileId = null;

function openSshProfileModal(id) {
  _editingSshProfileId = id || null;
  const modal = document.getElementById('ssh-profile-modal');
  modal.classList.remove('hidden');
  document.getElementById('ssh-profile-modal-title').textContent =
    id ? 'Edit SSH Profile' : 'New SSH Profile';
  document.getElementById('sshp-name').value = '';
  document.getElementById('sshp-user').value = '';
  document.getElementById('sshp-port').value = '';
  document.getElementById('sshp-password').value = '';
  document.getElementById('sshp-key').value = '';
  document.getElementById('sshp-password-hint').textContent = '';
  document.getElementById('sshp-key-hint').textContent = '';

  if (id) {
    const p = _sshProfiles.find(x => x.id === id);
    if (p) {
      document.getElementById('sshp-name').value = p.name;
      document.getElementById('sshp-user').value = p.ssh_user;
      document.getElementById('sshp-port').value = p.ssh_port || '';
      document.getElementById('sshp-password-hint').textContent =
        p.has_password ? 'Mot de passe enregistré — laisser vide pour conserver' : '';
      document.getElementById('sshp-key-hint').textContent =
        p.has_key ? 'Clef privée enregistrée — laisser vide pour conserver' : '';
    }
  }
}

function closeSshProfileModal(event) {
  if (event && event.target !== document.getElementById('ssh-profile-modal')) return;
  document.getElementById('ssh-profile-modal').classList.add('hidden');
  _editingSshProfileId = null;
}

async function saveSshProfile() {
  const name = document.getElementById('sshp-name').value.trim();
  const user = document.getElementById('sshp-user').value.trim();
  if (!name || !user) { showToast('Name and SSH user are required.', 'error'); return; }

  const payload = { name, ssh_user: user };
  const portVal = document.getElementById('sshp-port').value;
  if (portVal) payload.ssh_port = parseInt(portVal, 10);
  const pw = document.getElementById('sshp-password').value;
  const key = document.getElementById('sshp-key').value.trim();
  if (pw) payload.ssh_password = pw;
  if (key) payload.ssh_private_key = key;

  try {
    if (_editingSshProfileId) {
      await api(`/admin/ssh-profiles/${_editingSshProfileId}`, {
        method: 'PATCH', body: JSON.stringify(payload),
      });
    } else {
      await api('/admin/ssh-profiles', { method: 'POST', body: JSON.stringify(payload) });
    }
    document.getElementById('ssh-profile-modal').classList.add('hidden');
    _editingSshProfileId = null;
    await loadSshProfiles();
    showToast('SSH profile saved.', 'success');
  } catch (e) {
    showToast(`Save failed: ${e.message}`, 'error');
  }
}

async function deleteSshProfile(id, name) {
  if (!confirm(`Delete SSH profile "${name}"? Assets using it will fall back to per-asset credentials.`)) return;
  try {
    await api(`/admin/ssh-profiles/${id}`, { method: 'DELETE' });
    await loadSshProfiles();
    showToast('SSH profile deleted.', 'success');
  } catch (e) {
    showToast(`Delete failed: ${e.message}`, 'error');
  }
}

// ── Dashboard ────────────────────────────────────────────────────────────────

let _dashSeverityChart = null;
let _dashTopAssetsChart = null;
let _dashTrendChart = null;
let _quotaChart = null;

// ── Dashboard action required + trends (#1, #2) ───────────────────────────────

function _renderActionRequired(data) {
  const el = document.getElementById('dashboard-action-required');
  if (!el) return;

  const card = (cls, icon, count, label, onclick) =>
    `<div class="action-required-card action-card-${cls}" onclick="${onclick}" title="${label}">
       <div class="action-card-icon">${icon}</div>
       <div>
         <div class="action-card-count">${count}</div>
         <div class="action-card-label">${label}</div>
       </div>
     </div>`;

  const notScanned = data.assets_not_scanned_30d || 0;
  const noRemediation = data.critical_cves_without_remediation || 0;

  if (notScanned === 0 && noRemediation === 0) {
    el.innerHTML = card('ok', '✓', '0', 'Aucune action requise', '');
    return;
  }

  let html = '';
  if (notScanned > 0) {
    html += card('warning', '⏰', notScanned,
      `asset${notScanned > 1 ? 's' : ''} non scannés depuis >30 jours`,
      `document.getElementById('active-only').checked=false;document.getElementById('asset-filter-severity').value='';switchToView('assets');loadAssets()`);
  }
  if (noRemediation > 0) {
    html += card('danger', '🚨', noRemediation,
      `CVE Critical${noRemediation > 1 ? 's' : ''} sans plan de remédiation`,
      `document.getElementById('cve-severity-filter').value='Critical';switchToView('cves');loadCves(true)`);
  }
  el.innerHTML = html;
}

async function _loadDashboardTrends() {
  try {
    const data = await api('/dashboard/trends');
    if (!data) return;

    // Active assets count
    const activeEl = document.getElementById('dash-active-assets-trend');
    if (activeEl) activeEl.textContent = data.active_assets;

    // CVE trend chart
    const ctx = document.getElementById('dash-trend-cve-chart')?.getContext('2d');
    if (!ctx || !window.Chart) return;
    if (_dashTrendChart) _dashTrendChart.destroy();

    const CHART_FONT = { family: 'Inter, sans-serif', size: 11 };
    const GRID_COLOR = 'rgba(255,255,255,0.06)';
    const TICK_COLOR = 'rgba(255,255,255,0.45)';

    const labels = data.points.map(p => p.date.slice(5)); // MM-DD
    _dashTrendChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Découvertes',
            data: data.points.map(p => p.cves_discovered),
            borderColor: '#f87171',
            backgroundColor: 'rgba(248,113,113,0.1)',
            fill: true,
            tension: 0.35,
            pointRadius: 3,
          },
          {
            label: 'Acquittées',
            data: data.points.map(p => p.cves_acknowledged),
            borderColor: '#34d399',
            backgroundColor: 'rgba(52,211,153,0.1)',
            fill: true,
            tension: 0.35,
            pointRadius: 3,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 400 },
        plugins: {
          legend: { labels: { color: TICK_COLOR, font: CHART_FONT, boxWidth: 12 } },
          tooltip: {
            backgroundColor: 'rgba(15,18,30,0.92)',
            titleColor: '#e2e8f0', bodyColor: '#94a3b8',
            borderColor: 'rgba(129,140,248,0.3)', borderWidth: 1, cornerRadius: 8,
          },
        },
        scales: {
          x: { ticks: { color: TICK_COLOR, font: CHART_FONT, maxTicksLimit: 10 }, grid: { color: GRID_COLOR }, border: { color: 'transparent' } },
          y: { beginAtZero: true, ticks: { color: TICK_COLOR, font: CHART_FONT, precision: 0 }, grid: { color: GRID_COLOR }, border: { color: 'transparent' } },
        },
      },
    });
  } catch (e) {
    console.warn('Trends load error:', e);
  }
}

// ── Expositions ───────────────────────────────────────────────────────────────

let _expOffset = 0;
const _EXP_LIMIT = 100;
let _expData = [];  // flat list of {asset, cve_link}

async function loadExpositions() {
  _expOffset = 0;
  const tbody = document.getElementById('expositions-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="10" style="color:var(--text-muted);text-align:center;padding:24px">Chargement…</td></tr>';

  try {
    // Fetch all assets with their CVEs (limit 500)
    const { items } = await api('/assets?limit=500');
    _expData = [];
    for (const asset of items) {
      for (const cve of (asset.cves || [])) {
        _expData.push({ asset, cve });
      }
    }
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="9" style="color:var(--danger);text-align:center;padding:24px">Erreur : ${escape(String(e))}</td></tr>`;
    return;
  }

  _renderExpositions();
}

function _ackBadge(status) {
  const map = {
    none:          ['Non-ack.', 'muted'],
    accepted:      ['Accepté', 'success'],
    false_positive:['Faux positif', 'info'],
    in_progress:   ['En cours', 'warning'],
  };
  const [label, type] = map[status] || ['—', 'muted'];
  return badge(label, type);
}

function _ackActions(assetId, linkId, currentStatus) {
  const buttons = [];
  if (currentStatus !== 'accepted')
    buttons.push(`<button class="btn btn-sm" onclick="ackCve('${assetId}','${linkId}','accepted')">Accepter</button>`);
  if (currentStatus !== 'false_positive')
    buttons.push(`<button class="btn btn-sm" onclick="ackCve('${assetId}','${linkId}','false_positive')">Faux positif</button>`);
  if (currentStatus !== 'in_progress')
    buttons.push(`<button class="btn btn-sm" onclick="ackCve('${assetId}','${linkId}','in_progress')">En cours</button>`);
  if (currentStatus !== 'none')
    buttons.push(`<button class="btn btn-sm btn-danger" onclick="ackCve('${assetId}','${linkId}','none')">Réinitialiser</button>`);
  return buttons.join(' ');
}

async function ackCve(assetId, linkId, status) {
  try {
    await api(`/assets/${assetId}/cves/${linkId}/ack`, {
      method: 'PATCH',
      body: JSON.stringify({ ack_status: status }),
    });
    // Update in-memory data
    const entry = _expData.find(e => e.cve.id === linkId && e.asset.id === assetId);
    if (entry) entry.cve.ack_status = status;
    _renderExpositions();
    // Refresh dashboard badge if visible
    const dashPanel = document.getElementById('panel-dashboard');
    if (dashPanel?.classList.contains('active')) loadDashboard();
    // Update nav badge
    const unacked = _expData.filter(e => e.cve.ack_status === 'none').length;
    const expBadge = document.getElementById('nav-exp-count');
    if (expBadge) expBadge.textContent = unacked > 0 ? unacked : '';
  } catch (e) {
    showToast(`Erreur : ${e.message}`, 'error');
  }
}

function _renderExpPagination(total) {
  const container = document.getElementById('exp-pagination');
  if (!container) return;
  const pages = Math.ceil(total / _EXP_LIMIT);
  const current = Math.floor(_expOffset / _EXP_LIMIT);
  if (pages <= 1) { container.innerHTML = ''; return; }
  let html = '';
  if (current > 0)
    html += `<button class="btn btn-sm" onclick="_expPage(${current - 1})">← Préc.</button>`;
  html += `<span style="padding:6px 12px;font-size:13px;color:var(--text-muted)">Page ${current + 1} / ${pages}</span>`;
  if (current < pages - 1)
    html += `<button class="btn btn-sm" onclick="_expPage(${current + 1})">Suiv. →</button>`;
  container.innerHTML = html;
}

function _expPage(page) {
  _expOffset = page * _EXP_LIMIT;
  _renderExpositions();
}

// ── Tags management (asset modal) ─────────────────────────────────────────────

let _assetTags = [];   // current asset's tag names

function _renderAssetTags() {
  const container = document.getElementById('asset-tags-list');
  if (!container) return;
  if (!_assetTags.length) {
    container.innerHTML = '<span style="color:var(--text-muted);font-size:12px">Aucun tag.</span>';
    return;
  }
  container.innerHTML = _assetTags.map(t =>
    `<span class="dns-tag">
      ${escape(t)}
      <button class="dns-tag-remove" title="Supprimer" onclick="removeAssetTag('${escape(t)}')">×</button>
    </span>`
  ).join('');
}

async function addAssetTag() {
  if (!_modalAssetId) return;
  const input = document.getElementById('asset-tag-input');
  const name = (input?.value || '').trim();
  if (!name) return;
  if (_assetTags.includes(name)) {
    showToast('Tag déjà présent.', 'error');
    return;
  }
  try {
    await api(`/assets/${_modalAssetId}/tags/${encodeURIComponent(name)}`, { method: 'POST' });
    _assetTags.push(name);
    _renderAssetTags();
    if (input) input.value = '';
    await loadAssets();
  } catch (e) {
    showToast(`Erreur tag : ${e.message}`, 'error');
  }
}

async function removeAssetTag(name) {
  if (!_modalAssetId) return;
  try {
    await api(`/assets/${_modalAssetId}/tags/${encodeURIComponent(name)}`, { method: 'DELETE' });
    _assetTags = _assetTags.filter(t => t !== name);
    _renderAssetTags();
    await loadAssets();
  } catch (e) {
    showToast(`Erreur suppression tag : ${e.message}`, 'error');
  }
}

// ── Import / Export CSV ───────────────────────────────────────────────────────

async function exportAssetsCsv() {
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (_token) headers['Authorization'] = `Bearer ${_token}`;
    const res = await fetch(`${API}/assets/export/csv`, { headers });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || res.statusText);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'assets.csv';
    a.click();
    URL.revokeObjectURL(url);
    showToast('Export CSV téléchargé.', 'success');
  } catch (e) {
    showToast(`Export échoué : ${e.message}`, 'error');
  }
}

async function importAssetsCsv(file) {
  if (!file) return;
  try {
    const form = new FormData();
    form.append('file', file);
    const headers = {};
    if (_token) headers['Authorization'] = `Bearer ${_token}`;
    const res = await fetch(`${API}/assets/import/csv`, {
      method: 'POST',
      headers,
      body: form,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || res.statusText);
    }
    const data = await res.json();
    const msg = `Import CSV : ${data.imported} créés, ${data.updated} mis à jour${data.errors.length ? `, ${data.errors.length} erreur(s)` : ''}.`;
    showToast(msg, data.errors.length ? 'warning' : 'success', 6000);
    if (data.errors.length) {
      console.warn('CSV import errors:', data.errors);
    }
    await loadAssets();
  } catch (e) {
    showToast(`Import échoué : ${e.message}`, 'error');
  }
}

// ── SSH Scan Diff ─────────────────────────────────────────────────────────────

let _sshScanHistory = [];

function _renderSshScanHistory(reports) {
  _sshScanHistory = reports || [];
  const tbody = document.getElementById('ssh-scan-history-tbody');
  const selectA = document.getElementById('diff-scan-a');
  const selectB = document.getElementById('diff-scan-b');
  if (!tbody) return;

  if (!_sshScanHistory.length) {
    tbody.innerHTML = '<tr><td colspan="4" style="color:var(--text-muted);text-align:center;padding:12px">Aucun historique.</td></tr>';
    if (selectA) selectA.innerHTML = '<option value="">— Choisir —</option>';
    if (selectB) selectB.innerHTML = '<option value="">— Choisir —</option>';
    return;
  }

  tbody.innerHTML = _sshScanHistory.map(r => `
    <tr>
      <td style="font-size:12px">${fmtDate(r.created_at)}</td>
      <td>${statusBadge(r.status)}</td>
      <td>${r.cves_found != null ? r.cves_found : '—'}</td>
      <td style="font-size:12px">${escape(r.os_type || '—')}</td>
    </tr>`).join('');

  const opts = _sshScanHistory.map(r =>
    `<option value="${r.id}">${fmtDate(r.created_at)} — ${r.status} (${r.cves_found ?? '?'} CVEs)</option>`
  ).join('');
  const placeholder = '<option value="">— Choisir —</option>';
  if (selectA) selectA.innerHTML = placeholder + opts;
  if (selectB) selectB.innerHTML = placeholder + opts;

  // Pre-select A = second scan (older), B = first scan (newer) if available
  if (_sshScanHistory.length >= 2) {
    if (selectA) selectA.value = _sshScanHistory[1].id;
    if (selectB) selectB.value = _sshScanHistory[0].id;
  }

  // Clear previous diff results
  const diffResults = document.getElementById('diff-results');
  if (diffResults) diffResults.innerHTML = '';
}

async function runScanDiff() {
  if (!_modalAssetId) return;
  const scanA = document.getElementById('diff-scan-a')?.value;
  const scanB = document.getElementById('diff-scan-b')?.value;
  if (!scanA || !scanB) {
    showToast('Veuillez sélectionner deux scans à comparer.', 'error');
    return;
  }
  if (scanA === scanB) {
    showToast('Veuillez sélectionner deux scans différents.', 'error');
    return;
  }

  const diffResults = document.getElementById('diff-results');
  if (diffResults) diffResults.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Comparaison en cours…</p>';

  try {
    const diff = await api(`/assets/${_modalAssetId}/ssh-scans/diff?scan_a=${scanA}&scan_b=${scanB}`);
    if (!diff) return;
    _renderDiffResults(diff);
  } catch (e) {
    if (diffResults) diffResults.innerHTML = `<p style="color:var(--danger);font-size:13px">Erreur : ${escape(e.message)}</p>`;
  }
}

function _renderDiffResults(diff) {
  const el = document.getElementById('diff-results');
  if (!el) return;

  const cveRow = (cve, rowClass) => `
    <tr class="${rowClass}">
      <td><a class="cve-link" href="${cveUrl(cve.cve_id)}" target="_blank" rel="noopener">${escape(cve.cve_id)}</a></td>
      <td>${cve.severity ? badge(cve.severity, cve.severity.toLowerCase() === 'critical' || cve.severity.toLowerCase() === 'high' ? 'error' : cve.severity.toLowerCase() === 'medium' ? 'warning' : 'info') : '—'}</td>
      <td>${cve.cvss_score != null ? cve.cvss_score.toFixed(1) : '—'}</td>
      <td style="font-size:12px">${escape(cve.package_name || '—')}</td>
      <td style="font-size:12px">${escape(cve.package_version || '—')}</td>
    </tr>`;

  const section = (title, items, color, rowClass) => {
    if (!items.length) return `<p style="color:var(--text-muted);font-size:12px;margin-bottom:8px">${title} : aucune.</p>`;
    return `
      <p class="field-label" style="color:${color};margin-bottom:6px">${title} (${items.length})</p>
      <div class="table-wrap" style="margin-bottom:14px">
        <table>
          <thead><tr><th>CVE</th><th>Sévérité</th><th>CVSS</th><th>Composant</th><th>Version</th></tr></thead>
          <tbody>${items.map(c => cveRow(c, rowClass)).join('')}</tbody>
        </table>
      </div>`;
  };

  el.innerHTML =
    section('Nouvelles CVEs (B)', diff.new_cves, 'var(--danger)', 'diff-new') +
    section('CVEs résolues (A)', diff.resolved_cves, 'var(--success)', 'diff-resolved') +
    section('CVEs communes', diff.common_cves, 'var(--text-muted)', '');
}

async function init() {
  _initLoginForm();

  const authenticated = await checkAuth();
  if (!authenticated) return;

  _showApp();
  _applyUserContext();
  await _initAppData();
}

document.addEventListener('DOMContentLoaded', init);

// ── CVE Library ───────────────────────────────────────────────────────────────

let _cveOffset = 0;
const _CVE_LIMIT = 100;

function _renderCvePagination(total) {
  const container = document.getElementById('cve-pagination');
  if (!container) return;

  const pages = Math.ceil(total / _CVE_LIMIT);
  const current = Math.floor(_cveOffset / _CVE_LIMIT);

  if (pages <= 1) { container.innerHTML = ''; return; }

  let html = '';
  if (current > 0) {
    html += `<button class="btn btn-sm" onclick="_cvePage(${current - 1})">← Préc.</button>`;
  }
  html += `<span style="padding:6px 12px;font-size:13px;color:var(--text-muted)">Page ${current + 1} / ${pages}</span>`;
  if (current < pages - 1) {
    html += `<button class="btn btn-sm" onclick="_cvePage(${current + 1})">Suiv. →</button>`;
  }
  container.innerHTML = html;
}

function _cvePage(page) {
  _cveOffset = page * _CVE_LIMIT;
  loadCves(false);
}

// ── CVE Remediation modal ──────────────────────────────────────────────────────

function openCveRemediationModal(cveId, currentPlan) {
  const modal = document.getElementById('cve-remediation-modal');
  if (!modal) return;
  document.getElementById('cve-remediation-cve-id').textContent = cveId;
  document.getElementById('cve-remediation-input').value = currentPlan || '';
  modal.classList.remove('hidden');
}

function closeCveRemediationModal() {
  const modal = document.getElementById('cve-remediation-modal');
  if (modal) modal.classList.add('hidden');
}

async function saveCveRemediation() {
  const cveId = document.getElementById('cve-remediation-cve-id').textContent;
  const plan  = document.getElementById('cve-remediation-input').value.trim();
  try {
    await api(`/cves/${encodeURIComponent(cveId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ remediation: plan || null }),
    });
    closeCveRemediationModal();
    showToast('Plan d\'action enregistré', 'success');
    // Refresh current view
    const cvePanel = document.getElementById('panel-cves');
    if (cvePanel?.classList.contains('active')) loadCves(false);
    const expPanel = document.getElementById('panel-expositions');
    if (expPanel?.classList.contains('active')) loadExpositions();
  } catch (e) {
    showToast(`Erreur : ${e.message}`, 'error');
  }
}

async function triggerCveEnrichment() {
  const btn = document.getElementById('cve-enrich-btn');
  const status = document.getElementById('cve-enrich-status');
  btn.disabled = true;
  btn.textContent = 'En cours…';
  status.textContent = 'Enrichissement lancé en arrière-plan (OSV + NVD). Actualisez dans quelques instants.';
  status.classList.remove('hidden');
  try {
    await api('/cves/enrich', { method: 'POST' });
  } catch (e) {
    status.textContent = `Erreur : ${e}`;
  }
  setTimeout(() => {
    btn.disabled = false;
    btn.textContent = 'Enrichir';
    loadCves(false);
  }, 5000);
}

// ── Audit Log (admin) ─────────────────────────────────────────────────────────

let _auditSkip = 0;
const _auditLimit = 100;

async function loadAuditLog(reset = true) {
  if (reset) _auditSkip = 0;
  try {
    const user = (document.getElementById('audit-filter-user')?.value || '').trim();
    const action = (document.getElementById('audit-filter-action')?.value || '').trim();
    const resource_type = (document.getElementById('audit-filter-resource')?.value || '').trim();

    const params = new URLSearchParams({
      skip: _auditSkip,
      limit: _auditLimit,
      user,
      action,
      resource_type,
    });

    const data = await api(`/admin/audit-logs?${params}`);
    if (!data) return;

    const tbody = document.querySelector('#audit-table tbody');
    if (!data.items.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:32px">No audit entries found.</td></tr>';
      document.getElementById('audit-pagination').textContent = '';
      return;
    }

    tbody.innerHTML = data.items.map(entry => {
      const ts = entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '—';
      const detail = entry.detail
        ? `<code style="font-size:11px;word-break:break-all">${escape(entry.detail)}</code>`
        : '—';
      return `<tr>
        <td style="white-space:nowrap">${ts}</td>
        <td>${escape(entry.user)}</td>
        <td>${badge(entry.action, 'info')}</td>
        <td>${escape(entry.resource_type)}</td>
        <td class="mono" style="font-size:11px">${escape(entry.resource_id || '—')}</td>
        <td>${detail}</td>
      </tr>`;
    }).join('');

    const pgEl = document.getElementById('audit-pagination');
    const showing = _auditSkip + data.items.length;
    pgEl.innerHTML = `Showing ${_auditSkip + 1}–${showing} of ${data.total}
      ${_auditSkip > 0 ? `<button class="btn btn-sm" style="margin-left:8px" onclick="auditPage(-1)">← Prev</button>` : ''}
      ${showing < data.total ? `<button class="btn btn-sm" style="margin-left:4px" onclick="auditPage(1)">Next →</button>` : ''}`;
  } catch (e) {
    console.error('Audit log error:', e);
  }
}

function auditPage(direction) {
  _auditSkip = Math.max(0, _auditSkip + direction * _auditLimit);
  loadAuditLog(false);
}

// ── Session management ────────────────────────────────────────────────────────

async function loadMySessions() {
  try {
    const sessions = await api('/users/me/sessions');
    if (!sessions) return;
    return sessions;
  } catch (e) {
    console.error('Sessions error:', e);
    return [];
  }
}

async function revokeSession(sessionId) {
  if (!confirm('Revoke this session? The associated token will no longer be valid.')) return;
  try {
    await api(`/users/me/sessions/${sessionId}`, { method: 'DELETE' });
    showToast('Session revoked.', 'info');
  } catch (e) {
    showToast(`Error: ${e.message}`, 'error');
  }
}

async function revokeAllSessions() {
  if (!confirm('Revoke all sessions? You will be logged out everywhere.')) return;
  try {
    await api('/users/me/sessions', { method: 'DELETE' });
    showToast('All sessions revoked.', 'info');
  } catch (e) {
    showToast(`Error: ${e.message}`, 'error');
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ── UX IMPROVEMENTS ── Sprint Mars 2026 ────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

// ── #3 — Scan age badge ────────────────────────────────────────────────────────

function scanAgeBadge(isoDate) {
  if (!isoDate) return '<span class="scan-age-badge scan-age-never">Jamais</span>';
  const days = Math.floor((Date.now() - new Date(isoDate).getTime()) / 86_400_000);
  if (days < 7)  return `<span class="scan-age-badge scan-age-fresh">${days}j</span>`;
  if (days < 30) return `<span class="scan-age-badge scan-age-ok">${days}j</span>`;
  return `<span class="scan-age-badge scan-age-stale">${days}j</span>`;
}

// ── #5 — Group by subnet ──────────────────────────────────────────────────────

let _groupBySubnet = false;

function toggleGroupBySubnet() {
  _groupBySubnet = !_groupBySubnet;
  const btn = document.getElementById('group-subnet-btn');
  if (btn) {
    btn.style.background = _groupBySubnet ? 'var(--accent-dim)' : '';
    btn.style.color = _groupBySubnet ? 'var(--accent)' : '';
    btn.style.borderColor = _groupBySubnet ? 'var(--accent)' : '';
  }
  loadAssets();
}

// ── #4 — Inline editing ────────────────────────────────────────────────────────

function _initInlineEdit(td, assetId, field) {
  td.addEventListener('dblclick', () => {
    if (td.querySelector('input')) return; // already editing
    const current = td.textContent.trim();
    const input = document.createElement('input');
    input.value = current === '—' ? '' : current;
    input.style.cssText = 'width:100%;background:var(--surface3);color:var(--text);border:1px solid var(--accent);border-radius:4px;padding:2px 6px;font-size:13px;font-family:inherit';
    td.textContent = '';
    td.appendChild(input);
    input.focus();

    const save = async () => {
      const val = input.value.trim();
      if (val === (current === '—' ? '' : current)) {
        td.textContent = current;
        return;
      }
      try {
        await api(`/assets/${assetId}`, {
          method: 'PATCH',
          body: JSON.stringify({ [field]: val || null }),
        });
        td.textContent = val || '—';
        showToast('Modifié.', 'success');
      } catch (e) {
        td.textContent = current;
        showToast('Erreur: ' + e.message, 'error');
      }
    };

    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); save(); }
      if (e.key === 'Escape') { td.textContent = current; }
    });
    input.addEventListener('blur', save);
  });
  td.title = 'Double-clic pour éditer';
  td.style.cursor = 'default';
}

// ── #6 — Context menu ─────────────────────────────────────────────────────────

let _ctxAsset = null;

function _initContextMenu() {
  const menu = document.getElementById('ctx-menu');
  if (!menu) return;

  document.getElementById('asset-table').addEventListener('contextmenu', e => {
    const tr = e.target.closest('tr');
    if (!tr || !tr.parentElement || tr.parentElement.tagName !== 'TBODY') return;
    e.preventDefault();
    const assetId = tr.querySelector('.asset-checkbox')?.value;
    if (!assetId) return;
    _ctxAsset = assetId;
    // Find IP from row
    _ctxAssetIp = tr.querySelector('td.mono')?.textContent?.trim() || '';
    menu.style.left = Math.min(e.clientX, window.innerWidth - 200) + 'px';
    menu.style.top = Math.min(e.clientY, window.innerHeight - 180) + 'px';
    menu.classList.add('visible');
  });

  document.addEventListener('click', () => menu.classList.remove('visible'));
  document.addEventListener('keydown', e => { if (e.key === 'Escape') menu.classList.remove('visible'); });

  document.getElementById('ctx-ssh').onclick = () => {
    if (_ctxAsset) { api(`/assets/${_ctxAsset}/ssh-scan`, { method: 'POST' }).then(() => showToast('SSH scan lancé.', 'success')).catch(e => showToast(e.message, 'error')); }
    menu.classList.remove('visible');
  };
  document.getElementById('ctx-nuclei').onclick = () => {
    if (_ctxAsset) { api(`/assets/${_ctxAsset}/nuclei`, { method: 'POST' }).then(() => showToast('Nuclei lancé.', 'success')).catch(e => showToast(e.message, 'error')); }
    menu.classList.remove('visible');
  };
  document.getElementById('ctx-copy-ip').onclick = () => {
    if (_ctxAssetIp) navigator.clipboard.writeText(_ctxAssetIp).then(() => showToast('IP copiée.', 'success'));
    menu.classList.remove('visible');
  };
  document.getElementById('ctx-details').onclick = () => {
    if (_ctxAsset) openAssetModal(_ctxAsset);
    menu.classList.remove('visible');
  };
}

let _ctxAssetIp = '';

// ── #12 — Command palette (Ctrl+K) ────────────────────────────────────────────

let _paletteOpen = false;
let _paletteIdx = 0;
let _paletteItems = [];

function openCommandPalette() {
  if (_paletteOpen) return;
  _paletteOpen = true;
  document.getElementById('cmd-palette-overlay').classList.remove('hidden');
  const input = document.getElementById('cmd-input');
  input.value = '';
  _renderPaletteResults('');
  setTimeout(() => input.focus(), 50);
}

function closeCommandPalette() {
  _paletteOpen = false;
  document.getElementById('cmd-palette-overlay').classList.add('hidden');
}

function _renderPaletteResults(query) {
  const q = query.toLowerCase();
  _paletteItems = [];

  // Navigation sections
  const navSections = [
    { label: 'Dashboard', view: 'dashboard', icon: '◻' },
    { label: 'Assets', view: 'assets', icon: '◼' },
    { label: 'Scans', view: 'scans', icon: '⊙' },
    { label: 'Modules', view: 'modules', icon: '⬡' },
    { label: 'Expositions', view: 'expositions', icon: '⚑' },
    { label: 'CVEs', view: 'cves', icon: '⚠' },
    { label: 'Admin', view: 'admin', icon: '⚙' },
  ];

  const navMatches = navSections.filter(s => !q || s.label.toLowerCase().includes(q));

  // Asset matches (from loaded table rows)
  const assetMatches = [];
  if (q.length >= 2) {
    document.querySelectorAll('#asset-table tbody tr').forEach(tr => {
      const cells = tr.querySelectorAll('td');
      if (cells.length < 4) return;
      const name = cells[1]?.querySelector('strong')?.textContent || '';
      const ip = cells[2]?.textContent?.trim() || '';
      const hostname = cells[4]?.textContent?.trim() || '';
      const assetId = tr.querySelector('.asset-checkbox')?.value;
      if (!assetId) return;
      const text = [name, ip, hostname].join(' ').toLowerCase();
      if (text.includes(q)) {
        assetMatches.push({ label: name || ip, sub: ip, assetId });
      }
    });
  }

  // Build items
  if (navMatches.length) {
    _paletteItems.push({ type: 'category', label: 'Navigation' });
    navMatches.forEach(s => _paletteItems.push({ type: 'nav', ...s }));
  }
  if (assetMatches.length) {
    _paletteItems.push({ type: 'category', label: 'Assets' });
    assetMatches.slice(0, 8).forEach(a => _paletteItems.push({ type: 'asset', ...a }));
  }

  const results = document.getElementById('cmd-results');
  const actionItems = _paletteItems.filter(i => i.type !== 'category');
  _paletteIdx = 0;

  if (!actionItems.length) {
    results.innerHTML = `<div class="cmd-empty">Aucun résultat pour « ${escape(query)} »</div>`;
    return;
  }

  results.innerHTML = _paletteItems.map((item, i) => {
    if (item.type === 'category') return `<div class="cmd-category">${escape(item.label)}</div>`;
    const isFirst = actionItems.indexOf(item) === 0;
    return `<div class="cmd-item${isFirst ? ' active' : ''}" data-idx="${i}" onclick="_paletteSelect(${i})">
      <span style="font-size:14px;opacity:.7">${item.icon || '→'}</span>
      ${escape(item.label)}
      ${item.sub ? `<span class="cmd-item-sub">${escape(item.sub)}</span>` : ''}
    </div>`;
  }).join('');
}

function _paletteSelect(idx) {
  const item = _paletteItems[idx];
  if (!item || item.type === 'category') return;
  closeCommandPalette();
  if (item.type === 'nav') switchToView(item.view);
  if (item.type === 'asset') openAssetModal(item.assetId);
}

function _initCommandPalette() {
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      _paletteOpen ? closeCommandPalette() : openCommandPalette();
    }
    if (!_paletteOpen) return;
    if (e.key === 'Escape') { closeCommandPalette(); return; }

    const actionItems = _paletteItems.filter(i => i.type !== 'category');
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      _paletteIdx = Math.min(_paletteIdx + 1, actionItems.length - 1);
      _updatePaletteHighlight();
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      _paletteIdx = Math.max(_paletteIdx - 1, 0);
      _updatePaletteHighlight();
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      const item = actionItems[_paletteIdx];
      if (item) {
        const idx = _paletteItems.indexOf(item);
        _paletteSelect(idx);
      }
    }
  });

  document.getElementById('cmd-input')?.addEventListener('input', e => {
    _renderPaletteResults(e.target.value);
  });

  document.getElementById('cmd-palette-overlay')?.addEventListener('click', e => {
    if (e.target === document.getElementById('cmd-palette-overlay')) closeCommandPalette();
  });
}

function _updatePaletteHighlight() {
  const actionItems = _paletteItems.filter(i => i.type !== 'category');
  document.querySelectorAll('.cmd-item').forEach((el, i) => {
    el.classList.toggle('active', i === _paletteIdx);
    if (i === _paletteIdx) el.scrollIntoView({ block: 'nearest' });
  });
}

// ── #8 — Kanban board ─────────────────────────────────────────────────────────

let _expKanbanMode = false;
let _kanbanDragItem = null;

function toggleExpKanban() {
  _expKanbanMode = !_expKanbanMode;
  const tableView = document.getElementById('exp-table-view');
  const kanbanView = document.getElementById('exp-kanban-view');
  const btn = document.getElementById('exp-kanban-btn');
  if (tableView) tableView.style.display = _expKanbanMode ? 'none' : '';
  if (kanbanView) kanbanView.style.display = _expKanbanMode ? '' : 'none';
  if (btn) {
    btn.style.background = _expKanbanMode ? 'var(--accent-dim)' : '';
    btn.style.color = _expKanbanMode ? 'var(--accent)' : '';
  }
  if (_expKanbanMode) _renderKanban();
}

function _renderKanban() {
  const cols = { none: [], in_progress: [], accepted: [], false_positive: [] };
  _expData.forEach(({ asset, cve }) => {
    const status = cve.ack_status || 'none';
    if (cols[status]) cols[status].push({ asset, cve });
  });

  Object.entries(cols).forEach(([status, items]) => {
    const countEl = document.getElementById('kanban-count-' + status);
    const cardsEl = document.getElementById('kanban-cards-' + status);
    if (!cardsEl) return;
    if (countEl) countEl.textContent = items.length;

    if (!items.length) {
      cardsEl.innerHTML = '<div class="kanban-empty">Aucune</div>';
      return;
    }

    const sev = s => s === 'critical' || s === 'high' ? 'error' : s === 'medium' ? 'warning' : 'info';
    cardsEl.innerHTML = items.map(({ asset, cve }) => `
      <div class="kanban-card"
           draggable="true"
           data-link-id="${cve.id}"
           data-asset-id="${asset.id}"
           ondragstart="_onKanbanDragStart(event,'${cve.id}','${asset.id}')"
           ondragend="this.classList.remove('dragging')">
        <div style="display:flex;align-items:center;gap:6px">
          <span class="kanban-card-id">${escape(cve.cve_id_str)}</span>
          ${cve.severity ? badge(cve.severity, sev((cve.severity || '').toLowerCase())) : ''}
        </div>
        <div class="kanban-card-asset">${escape(asset.name || asset.ip || '')}</div>
        ${cve.package_name ? `<div style="color:var(--text-muted);font-size:10px;margin-top:2px">${escape(cve.package_name)}</div>` : ''}
      </div>`).join('');
  });
}

function _onKanbanDragStart(event, linkId, assetId) {
  _kanbanDragItem = { linkId, assetId };
  event.target.classList.add('dragging');
  event.dataTransfer.effectAllowed = 'move';
}

async function onKanbanDrop(event, newStatus) {
  event.preventDefault();
  event.currentTarget.classList.remove('drag-over');
  if (!_kanbanDragItem) return;
  const { linkId, assetId } = _kanbanDragItem;
  _kanbanDragItem = null;

  try {
    await api(`/assets/${assetId}/cves/${linkId}/ack`, {
      method: 'PATCH',
      body: JSON.stringify({ ack_status: newStatus }),
    });
    const entry = _expData.find(e => e.cve.id === linkId && e.asset.id === assetId);
    if (entry) entry.cve.ack_status = newStatus;
    _renderKanban();
    showToast('Statut mis à jour.', 'success');
  } catch (e) {
    showToast('Erreur: ' + e.message, 'error');
  }
}

// ── #10 — Side panel (CVE affected assets) ────────────────────────────────────

function openSidePanel(title, renderFn) {
  const panel = document.getElementById('side-panel');
  const titleEl = document.getElementById('side-panel-title');
  const bodyEl = document.getElementById('side-panel-body');
  if (!panel) return;
  titleEl.textContent = title;
  bodyEl.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Chargement…</p>';
  panel.classList.add('open');
  renderFn(bodyEl);
}

function closeSidePanel() {
  document.getElementById('side-panel')?.classList.remove('open');
}

// ── #13 — Saved filters ──────────────────────────────────────────────────────

const _FILTER_PREFIX = 'nlv_filter_';

function _loadSavedFiltersSelect() {
  const sel = document.getElementById('saved-filters-select');
  if (!sel) return;
  const keys = Object.keys(localStorage).filter(k => k.startsWith(_FILTER_PREFIX));
  if (!keys.length) { sel.style.display = 'none'; return; }
  sel.style.display = '';
  sel.innerHTML = '<option value="">— Filtres sauvegardés —</option>' +
    keys.map(k => {
      const name = k.slice(_FILTER_PREFIX.length);
      return `<option value="${escape(k)}">${escape(name)}</option>`;
    }).join('');
}

function saveCurrentFilter() {
  const search = document.getElementById('asset-search')?.value || '';
  const severity = document.getElementById('asset-filter-severity')?.value || '';
  const activeOnly = document.getElementById('active-only')?.checked || false;
  if (!search && !severity && !activeOnly) {
    showToast('Aucun filtre actif à sauvegarder.', 'warning');
    return;
  }
  const name = window.prompt('Nom du filtre :');
  if (!name) return;
  localStorage.setItem(_FILTER_PREFIX + name, JSON.stringify({ search, severity, activeOnly }));
  showToast(`Filtre « ${name} » sauvegardé.`, 'success');
  _loadSavedFiltersSelect();
}

function applySavedFilter(key) {
  if (!key) return;
  try {
    const f = JSON.parse(localStorage.getItem(key) || '{}');
    const searchEl = document.getElementById('asset-search');
    const sevEl = document.getElementById('asset-filter-severity');
    const activeEl = document.getElementById('active-only');
    if (searchEl) searchEl.value = f.search || '';
    if (sevEl) sevEl.value = f.severity || '';
    if (activeEl) activeEl.checked = !!f.activeOnly;
    loadAssets();
    document.getElementById('saved-filters-select').value = '';
  } catch (e) {
    showToast('Erreur lecture filtre.', 'error');
  }
}

// ── #11 — Export CSV depuis Expositions ─────────────────────────────────────

function exportExpositionsCsv() {
  if (!_expData.length) { showToast('Aucune donnée à exporter.', 'warning'); return; }

  const search   = (document.getElementById('exp-search')?.value || '').toLowerCase();
  const severity = document.getElementById('exp-severity')?.value || '';
  const source   = document.getElementById('exp-source')?.value || '';
  const ack      = document.getElementById('exp-ack')?.value;

  let filtered = _expData.filter(({ asset, cve }) => {
    if (severity && cve.severity !== severity) return false;
    if (source && !(cve.source || '').includes(source)) return false;
    if (ack !== '' && ack !== undefined && ack !== null && cve.ack_status !== ack) return false;
    if (search) {
      const hay = [cve.cve_id_str, asset.name, asset.ip, asset.hostname, cve.package_name].filter(Boolean).join(' ').toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  const headers = ['CVE', 'Sévérité', 'CVSS', 'Asset', 'IP', 'Source', 'Paquet', 'Version', 'Fix dispo', 'Plan d\'action', 'Ack'];
  const rows = filtered.map(({ asset, cve }) => [
    cve.cve_id_str || '',
    cve.severity || '',
    cve.cvss_score != null ? cve.cvss_score.toFixed(1) : '',
    asset.name || asset.ip || '',
    asset.ip || '',
    cve.source || '',
    cve.package_name || '',
    cve.package_version || '',
    cve.fixed_version || '',
    (cve.remediation || '').replace(/\n/g, ' '),
    cve.ack_status || 'none',
  ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));

  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `expositions_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`Export CSV : ${filtered.length} entrées.`, 'success');
}

// ── #9 — Bulk CVE acknowledgment ─────────────────────────────────────────────

let _selectedExpIds = new Set(); // set of link IDs

function toggleSelectAllExp(checkbox) {
  document.querySelectorAll('.exp-checkbox').forEach(cb => {
    cb.checked = checkbox.checked;
    const linkId = cb.value;
    if (checkbox.checked) _selectedExpIds.add(linkId);
    else _selectedExpIds.delete(linkId);
  });
  _updateExpSelectBar();
}

function toggleExpSelect(checkbox) {
  if (checkbox.checked) _selectedExpIds.add(checkbox.value);
  else _selectedExpIds.delete(checkbox.value);
  _updateExpSelectBar();
}

function _updateExpSelectBar() {
  const bar = document.getElementById('exp-select-bar');
  const countEl = document.getElementById('exp-selected-count');
  if (!bar) return;
  const n = _selectedExpIds.size;
  bar.style.display = n > 0 ? '' : 'none';
  if (countEl) countEl.textContent = `${n} exposition${n > 1 ? 's' : ''} sélectionnée${n > 1 ? 's' : ''}`;
}

function clearExpSelection() {
  _selectedExpIds.clear();
  document.querySelectorAll('.exp-checkbox').forEach(cb => { cb.checked = false; });
  const allCb = document.getElementById('select-all-exp');
  if (allCb) allCb.checked = false;
  _updateExpSelectBar();
}

function openBulkAckModal() {
  if (!_selectedExpIds.size) return;
  const modal = document.getElementById('bulk-ack-modal');
  const descEl = document.getElementById('bulk-ack-desc');
  if (descEl) descEl.textContent = `${_selectedExpIds.size} CVE${_selectedExpIds.size > 1 ? 's' : ''} sélectionné${_selectedExpIds.size > 1 ? 's' : ''}.`;
  document.getElementById('bulk-ack-note').value = '';
  modal.classList.remove('hidden');
}

function closeBulkAckModal() {
  document.getElementById('bulk-ack-modal').classList.add('hidden');
}

async function saveBulkAck() {
  const status = document.getElementById('bulk-ack-status').value;
  const note = document.getElementById('bulk-ack-note').value.trim() || null;
  const linkIds = [..._selectedExpIds];

  try {
    const result = await api('/cves/bulk-ack', {
      method: 'POST',
      body: JSON.stringify({ link_ids: linkIds, ack_status: status, ack_note: note }),
    });
    closeBulkAckModal();
    showToast(`${result.updated} CVE(s) mis à jour.`, 'success');
    clearExpSelection();
    await loadExpositions();
  } catch (e) {
    showToast('Erreur: ' + e.message, 'error');
  }
}

// ── #7 — Bulk edit assets ─────────────────────────────────────────────────────

function openBulkEditModal() {
  const n = _selectedAssetIds.size;
  if (!n) return;
  const descEl = document.getElementById('bulk-edit-desc');
  if (descEl) descEl.textContent = `${n} asset${n > 1 ? 's' : ''} sélectionné${n > 1 ? 's' : ''}.`;
  document.getElementById('bulk-os-family').value = '';
  document.getElementById('bulk-device-type').value = '';
  document.getElementById('bulk-edit-modal').classList.remove('hidden');
}

function closeBulkEditModal() {
  document.getElementById('bulk-edit-modal').classList.add('hidden');
}

async function saveBulkEdit() {
  const os = document.getElementById('bulk-os-family').value.trim() || null;
  const dt = document.getElementById('bulk-device-type').value.trim() || null;
  if (!os && !dt) { showToast('Renseignez au moins un champ.', 'warning'); return; }

  const ids = [..._selectedAssetIds];
  try {
    const result = await api('/assets/bulk-update', {
      method: 'POST',
      body: JSON.stringify({ ids, os_family: os, device_type: dt }),
    });
    closeBulkEditModal();
    showToast(`${result.updated} asset(s) mis à jour.`, 'success');
    await loadAssets();
  } catch (e) {
    showToast('Erreur: ' + e.message, 'error');
  }
}

// ── #17 — SSH profile test ────────────────────────────────────────────────────

async function testSshProfile(profileId) {
  const host = window.prompt('IP ou hostname de la machine à tester :');
  if (!host) return;
  showToast('Test SSH en cours…', 'info');
  try {
    const result = await api(`/admin/ssh-profiles/${profileId}/test`, {
      method: 'POST',
      body: JSON.stringify({ host }),
    });
    if (result.success) {
      showToast(`✓ Connexion SSH réussie (${result.latency_ms}ms)`, 'success');
    } else {
      showToast(`✗ Échec : ${result.error || 'Erreur inconnue'}`, 'error');
    }
  } catch (e) {
    showToast(`Erreur : ${e.message}`, 'error');
  }
}

// ── #18 — Quota usage chart ───────────────────────────────────────────────────

async function loadQuotaUsage() {
  try {
    const data = await api('/admin/quota-usage');
    if (!data) return;

    const tableWrap = document.getElementById('quota-table-wrap');

    if (!data.users.length) {
      if (tableWrap) tableWrap.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Aucune donnée de quota.</p>';
      return;
    }

    // Chart
    const ctx = document.getElementById('quota-chart')?.getContext('2d');
    if (ctx && window.Chart) {
      if (_quotaChart) _quotaChart.destroy();
      const CHART_FONT = { family: 'Inter, sans-serif', size: 11 };
      const GRID_COLOR = 'rgba(255,255,255,0.06)';
      const TICK_COLOR = 'rgba(255,255,255,0.45)';
      const colors = ['#818cf8', '#f87171', '#34d399', '#fbbf24', '#60a5fa', '#a78bfa'];

      _quotaChart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: data.dates.map(d => d.slice(5)),
          datasets: data.users.slice(0, 5).map((u, i) => ({
            label: u.username,
            data: u.days.map(d => d.count),
            backgroundColor: colors[i % colors.length] + 'bb',
            borderColor: colors[i % colors.length],
            borderWidth: 1,
            borderRadius: 3,
            stack: 'quota',
          })),
        },
        options: {
          responsive: true,
          plugins: {
            legend: { labels: { color: TICK_COLOR, font: CHART_FONT, boxWidth: 12 } },
            tooltip: {
              backgroundColor: 'rgba(15,18,30,0.92)',
              titleColor: '#e2e8f0', bodyColor: '#94a3b8',
              borderColor: 'rgba(129,140,248,0.3)', borderWidth: 1, cornerRadius: 8,
            },
          },
          scales: {
            x: { stacked: true, ticks: { color: TICK_COLOR, font: CHART_FONT, maxTicksLimit: 15 }, grid: { color: GRID_COLOR }, border: { color: 'transparent' } },
            y: { stacked: true, beginAtZero: true, ticks: { color: TICK_COLOR, font: CHART_FONT, precision: 0 }, grid: { color: GRID_COLOR }, border: { color: 'transparent' } },
          },
        },
      });
    }

    // Summary table
    if (tableWrap) {
      tableWrap.innerHTML = `
        <table>
          <thead><tr><th>Utilisateur</th><th>Email</th><th>Total (30j)</th></tr></thead>
          <tbody>
            ${data.users.map(u => `<tr>
              <td class="mono">${escape(u.username)}</td>
              <td>${escape(u.email)}</td>
              <td style="font-weight:600;color:var(--accent)">${u.total}</td>
            </tr>`).join('')}
          </tbody>
        </table>`;
    }
  } catch (e) {
    console.error('Quota usage error:', e);
  }
}

// ── #14 — Modal navigation history ────────────────────────────────────────────

let _modalHistory = [];

function openAssetModalWithHistory(id, fromContext) {
  if (fromContext) _modalHistory.push(fromContext);
  _openAssetModalWithBreadcrumb(id);
}

async function _openAssetModalWithBreadcrumb(id) {
  await openAssetModal(id);
  _renderModalBreadcrumb();
}

function _renderModalBreadcrumb() {
  const existing = document.getElementById('modal-breadcrumb');
  if (existing) existing.remove();
  if (!_modalHistory.length) return;

  const header = document.querySelector('#asset-modal .modal-header');
  if (!header) return;

  const bc = document.createElement('div');
  bc.id = 'modal-breadcrumb';
  bc.className = 'modal-breadcrumb';
  bc.innerHTML = _modalHistory.map((ctx, i) =>
    `<button onclick="_modalGoBack(${i})" title="Retour">${escape(ctx.label)}</button>`
  ).join(' › ') + ' › <span>Actuel</span>';
  header.after(bc);
}

function _modalGoBack(idx) {
  const ctx = _modalHistory[idx];
  _modalHistory = _modalHistory.slice(0, idx);
  if (ctx && ctx.assetId) openAssetModal(ctx.assetId);
  else if (ctx && ctx.view) switchToView(ctx.view);
}

// Make the CVE side panel open asset from history context
function openAssetFromPanel(assetId, assetLabel) {
  openAssetModalWithHistory(assetId, { label: 'Liste CVE', view: null, assetId: null });
}

// ── loadSshProfiles — replacement with Test button (#17) ─────────────────────

async function loadSshProfiles() {
  try {
    _sshProfiles = await api('/admin/ssh-profiles') || [];
    const tbody = document.querySelector('#ssh-profiles-table tbody');
    if (!_sshProfiles.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:32px">No SSH profiles yet</td></tr>';
      return;
    }
    tbody.innerHTML = _sshProfiles.map(p => `
      <tr>
        <td>${escape(p.name)}</td>
        <td class="mono">${escape(p.ssh_user)}</td>
        <td>${p.ssh_port || 22}</td>
        <td>${p.has_password ? badge('set', 'success') : badge('—', 'muted')}</td>
        <td>${p.has_key ? badge('set', 'success') : badge('—', 'muted')}</td>
        <td style="color:var(--text-muted);font-size:12px">${new Date(p.created_at).toLocaleDateString()}</td>
        <td style="display:flex;gap:6px">
          <button class="btn btn-sm" onclick="openSshProfileModal('${p.id}')">Edit</button>
          <button class="btn btn-sm" onclick="testSshProfile('${p.id}')">Tester</button>
          <button class="btn btn-sm" style="color:var(--danger)"
                  onclick="deleteSshProfile('${p.id}','${escape(p.name)}')">Delete</button>
        </td>
      </tr>`).join('');
  } catch (e) {
    console.error('SSH profiles error:', e);
  }
};

async function showCveAffectedAssets(cveId, count) {
  openSidePanel(`Assets affectés par ${cveId} (${count})`, async (bodyEl) => {
    try {
      // Find matching assets from current _expData or load from assets endpoint
      const matching = _expData.filter(e => e.cve.cve_id_str === cveId);
      if (matching.length) {
        bodyEl.innerHTML = matching.map(({ asset, cve }) => `
          <div class="side-panel-asset-item" onclick="openAssetModal('${asset.id}');closeSidePanel()">
            <div>
              <div class="side-panel-asset-name">${escape(asset.name || asset.ip || '—')}</div>
              <div class="side-panel-asset-ip">${escape(asset.ip || '')} ${escape(asset.hostname || '')}</div>
            </div>
            <div style="margin-left:auto">${_ackBadge(cve.ack_status)}</div>
          </div>`).join('');
      } else {
        // Load from CVE detail endpoint
        const detail = await api(`/cves/${encodeURIComponent(cveId)}`);
        if (detail && detail.asset_ids) {
          bodyEl.innerHTML = detail.asset_ids.map(aid =>
            `<div class="side-panel-asset-item" onclick="openAssetModal('${aid}');closeSidePanel()">
              <div class="side-panel-asset-name" style="font-family:monospace;font-size:12px">${aid}</div>
             </div>`
          ).join('');
        } else {
          bodyEl.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Aucun asset trouvé.</p>';
        }
      }
    } catch (e) {
      bodyEl.innerHTML = `<p style="color:var(--danger);font-size:13px">Erreur : ${escape(e.message)}</p>`;
    }
  });
}

// ── toggleAssetSelect / toggleSelectAllAssets — patched for bulk edit btn (#7) ─

function toggleAssetSelect(checkbox) {
  if (checkbox.checked) _selectedAssetIds.add(checkbox.value);
  else _selectedAssetIds.delete(checkbox.value);
  const bulkBtn = document.getElementById('bulk-scan-btn');
  const bulkEditBtn = document.getElementById('bulk-edit-btn');
  if (bulkBtn) bulkBtn.style.display = _selectedAssetIds.size > 0 ? '' : 'none';
  if (bulkEditBtn) bulkEditBtn.style.display = _selectedAssetIds.size > 0 ? '' : 'none';
}

function toggleSelectAllAssets(checkbox) {
  document.querySelectorAll('.asset-checkbox').forEach(cb => {
    cb.checked = checkbox.checked;
    if (checkbox.checked) _selectedAssetIds.add(cb.value);
    else _selectedAssetIds.delete(cb.value);
  });
  const bulkBtn = document.getElementById('bulk-scan-btn');
  const bulkEditBtn = document.getElementById('bulk-edit-btn');
  if (bulkBtn) bulkBtn.style.display = _selectedAssetIds.size > 0 ? '' : 'none';
  if (bulkEditBtn) bulkEditBtn.style.display = _selectedAssetIds.size > 0 ? '' : 'none';
}

// Also add close listener for side panel (click outside)
document.addEventListener('DOMContentLoaded', () => {
  // Side panel keyboard close
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeSidePanel();
  });
});

// ── #15 — Port scan diff ──────────────────────────────────────────────────────

let _portsDiffEnabled = false;

/** Save current open ports snapshot to localStorage for this asset. */
function _savePortsSnapshot(assetId, ports) {
  try {
    localStorage.setItem(`nlv_ports_${assetId}`, JSON.stringify(ports));
  } catch (_) {}
}

/** Load the previously saved ports snapshot from localStorage. */
function _loadPortsSnapshot(assetId) {
  try {
    const raw = localStorage.getItem(`nlv_ports_${assetId}`);
    return raw ? JSON.parse(raw) : null;
  } catch (_) { return null; }
}

/** Render the Ports tab, optionally as a diff against the previous snapshot. */
function _renderPortsTab(asset) {
  const openPorts = (asset.ports || []).filter(p => p.state === 'open');
  const portsTbody = document.querySelector('#modal-ports-table tbody');
  const diffBtn    = document.getElementById('ports-diff-btn');
  const diffInfo   = document.getElementById('ports-diff-info');

  const assetId   = asset.id;
  const prevPorts = _loadPortsSnapshot(assetId);

  // Show diff button only when a previous snapshot exists
  if (diffBtn) diffBtn.style.display = prevPorts ? '' : 'none';

  // Save current as the new snapshot (so next open shows diff vs today)
  _savePortsSnapshot(assetId, openPorts);

  if (!openPorts.length && !prevPorts?.length) {
    if (portsTbody) portsTbody.innerHTML =
      '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;padding:20px">No open ports detected</td></tr>';
    if (diffInfo) diffInfo.textContent = '';
    return;
  }

  if (_portsDiffEnabled && prevPorts) {
    // ── Diff mode ────────────────────────────────────────────────────────
    const prevKeys = new Set(prevPorts.map(p => `${p.port_number}/${p.protocol}`));
    const currKeys = new Set(openPorts.map(p  => `${p.port_number}/${p.protocol}`));

    const added   = openPorts.filter(p => !prevKeys.has(`${p.port_number}/${p.protocol}`));
    const removed = prevPorts.filter(p => !currKeys.has(`${p.port_number}/${p.protocol}`));
    const common  = openPorts.filter(p =>  prevKeys.has(`${p.port_number}/${p.protocol}`));

    if (diffBtn) diffBtn.textContent = 'Vue normale';
    if (diffInfo) diffInfo.textContent =
      `+${added.length} nouveau${added.length !== 1 ? 'x' : ''} · −${removed.length} fermé${removed.length !== 1 ? 's' : ''} · ${common.length} inchangé${common.length !== 1 ? 's' : ''}`;

    const rowFor = (p, cls, symbol) => `
      <tr style="background:${cls === 'added' ? 'rgba(74,222,128,.08)' : cls === 'removed' ? 'rgba(248,113,113,.08)' : ''}">
        <td style="color:${cls === 'added' ? 'var(--green)' : cls === 'removed' ? 'var(--red)' : 'var(--text-muted)'};font-weight:700;width:24px;text-align:center">${symbol}</td>
        <td class="mono">${p.port_number}</td>
        <td>${escape(p.protocol)}</td>
        <td>${badge(p.state || 'closed', p.state === 'open' ? 'success' : 'muted')}</td>
        <td>${escape(p.service_name || '—')}</td>
        <td style="color:var(--text-muted);font-size:12px">${escape(p.version || '—')}</td>
      </tr>`;

    portsTbody.innerHTML =
      added.map(p   => rowFor(p, 'added',   '+')).join('') +
      removed.map(p => rowFor(p, 'removed', '−')).join('') +
      common.map(p  => rowFor(p, 'common',  ' ')).join('');

    if (!portsTbody.innerHTML.trim()) {
      portsTbody.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;padding:20px">Aucune différence détectée</td></tr>';
    }
  } else {
    // ── Normal mode ───────────────────────────────────────────────────────
    if (diffBtn) diffBtn.textContent = 'Comparer avec snapshot précédent';
    if (diffInfo) {
      const ts = new Date().toLocaleDateString('fr-FR');
      diffInfo.textContent = prevPorts
        ? `Snapshot précédent disponible · ${openPorts.length} port${openPorts.length !== 1 ? 's' : ''} ouvert${openPorts.length !== 1 ? 's' : ''}`
        : `Snapshot sauvegardé — revenez plus tard pour comparer`;
    }

    if (!openPorts.length) {
      portsTbody.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;padding:20px">No open ports detected</td></tr>';
    } else {
      portsTbody.innerHTML = openPorts.map(p => `
        <tr>
          <td></td>
          <td class="mono">${p.port_number}</td>
          <td>${escape(p.protocol)}</td>
          <td>${badge(p.state, p.state === 'open' ? 'success' : 'muted')}</td>
          <td>${escape(p.service_name || '—')}</td>
          <td style="color:var(--text-muted);font-size:12px">${escape(p.version || '—')}</td>
        </tr>`).join('');
    }
  }
}

/** Toggle the ports diff view on/off. */
function togglePortsDiff() {
  _portsDiffEnabled = !_portsDiffEnabled;
  // Re-render with current asset data — reload from API so we have fresh data
  if (_modalAssetId) {
    api(`/assets/${_modalAssetId}`).then(asset => {
      if (asset) _renderPortsTab(asset);
    }).catch(() => {});
  }
}

// ── #16 — Schedule builder helpers ───────────────────────────────────────────
// The <select> elements replace <input type="number"> for interval fields.
// .value on a <select> works identically to .value on <input>, so no JS
// changes are needed beyond the HTML replacements already done in index.html.
// When a stored value doesn't match any option (e.g. a custom number), the
// select shows the empty/default option, which is safe behaviour.

// ═══════════════════════════════════════════════════════════════════════════════
// ── SPRINT UX MARS 2026 — Features 1-10 ────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

// ── Feature 1 — Criticité asset ──────────────────────────────────────────────

function criticalityBadge(criticality) {
  if (!criticality) return '<span style="color:var(--text-muted)">—</span>';
  const map = {
    critical: ['Critical', 'crit-critical'],
    high:     ['High',     'crit-high'],
    medium:   ['Medium',   'crit-medium'],
    low:      ['Low',      'crit-low'],
  };
  const [label, cls] = map[criticality.toLowerCase()] || [criticality, 'crit-low'];
  return `<span class="criticality-badge ${cls}">${label}</span>`;
}

// ── Feature 2 — Risk score badge ─────────────────────────────────────────────

function riskScoreBadge(score) {
  if (score == null) return '<span style="color:var(--text-muted)">—</span>';
  const s = Number(score);
  let cls, label;
  if (s >= 75) { cls = 'risk-critical'; label = `Critique (${s})`; }
  else if (s >= 50) { cls = 'risk-elevated'; label = `Élevé (${s})`; }
  else if (s >= 25) { cls = 'risk-medium-r'; label = `Moyen (${s})`; }
  else { cls = 'risk-low-r'; label = `Faible (${s})`; }
  return `<span class="risk-score-badge ${cls}">${label}</span>`;
}

// ── Feature 3 — EPSS badge ───────────────────────────────────────────────────

function epssBadge(epssScore) {
  if (epssScore == null) return '<span style="color:var(--text-muted)">—</span>';
  const pct = (epssScore * 100).toFixed(1);
  let cls;
  if (epssScore > 0.5) cls = 'epss-high';
  else if (epssScore > 0.25) cls = 'epss-medium';
  else cls = 'epss-low';
  return `<span class="epss-badge ${cls}">${pct}%</span>`;
}

async function triggerEpssEnrichment() {
  const btn = document.getElementById('cve-epss-enrich-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'En cours…'; }
  const status = document.getElementById('cve-enrich-status');
  if (status) {
    status.textContent = 'Enrichissement EPSS lancé en arrière-plan. Actualisez dans quelques instants.';
    status.classList.remove('hidden');
  }
  try {
    await api('/admin/epss/enrich', { method: 'POST' });
    showToast('Enrichissement EPSS lancé.', 'success');
  } catch (e) {
    showToast('Erreur EPSS : ' + e.message, 'error');
    if (status) status.textContent = `Erreur : ${e.message}`;
  }
  setTimeout(() => {
    if (btn) { btn.disabled = false; btn.textContent = 'Enrichir EPSS'; }
    loadCves(false);
  }, 5000);
}

// ── Feature 4 — SSL/TLS scanning ─────────────────────────────────────────────

async function runSslScan() {
  if (!_modalAssetId) return;
  const assetId = _modalAssetId;
  const btn = document.getElementById('ssl-scan-btn');
  const statusEl = document.getElementById('ssl-scan-status');
  if (btn) btn.disabled = true;
  if (statusEl) statusEl.textContent = 'Démarrage du scan SSL…';

  try {
    const report = await api(`/assets/${assetId}/ssl-scan`, { method: 'POST' });
    if (!report) throw new Error('Pas de réponse');
    if (statusEl) statusEl.textContent = 'Scan SSL en cours…';

    // Poll for completion
    let done = false;
    let attempts = 0;
    while (!done && _modalAssetId === assetId && attempts < 30) {
      await new Promise(r => setTimeout(r, 3000));
      attempts++;
      if (_modalAssetId !== assetId) break;
      try {
        const updated = await api(`/assets/${assetId}/ssl-scan`);
        if (Array.isArray(updated)) {
          done = true;
          if (statusEl) statusEl.textContent = `Terminé — ${updated.length} rapport(s).`;
          showToast(`SSL scan : ${updated.length} rapport(s).`, 'success');
          _renderSslReports(updated);
        }
      } catch (_) { /* keep polling */ }
    }
    if (!done && _modalAssetId === assetId) {
      if (statusEl) statusEl.textContent = 'Scan SSL terminé.';
      const reports = await api(`/assets/${assetId}/ssl-scan`).catch(() => []);
      _renderSslReports(reports || []);
    }
  } catch (e) {
    if (statusEl) statusEl.textContent = `Erreur : ${e.message}`;
    showToast(`SSL scan : ${e.message}`, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function loadSslReports(assetId) {
  try {
    const reports = await api(`/assets/${assetId}/ssl-scan`);
    _renderSslReports(reports || []);
  } catch (_) {
    _renderSslReports([]);
  }
}

function _sslStatusBadge(status) {
  const map = {
    valid:    ['Valide', 'ssl-valid'],
    expiring: ['Expire bientôt', 'ssl-expiring'],
    expired:  ['Expiré', 'ssl-expired'],
    error:    ['Erreur', 'ssl-error'],
  };
  const [label, cls] = map[status] || [status || '?', 'ssl-error'];
  return `<span class="ssl-status-badge ${cls}">${label}</span>`;
}

function _renderSslReports(reports) {
  const container = document.getElementById('ssl-reports-body');
  if (!container) return;
  if (!reports || !reports.length) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Aucun rapport SSL disponible. Lancez un scan.</p>';
    return;
  }
  container.innerHTML = reports.map((r, idx) => {
    const issues = (r.issues || []).map(i => `<div class="ssl-issue">⚠ ${escape(i)}</div>`).join('');
    const daysLeft = r.days_until_expiry != null
      ? `<span style="color:${r.days_until_expiry < 30 ? 'var(--danger)' : 'var(--text-muted)'}">${r.days_until_expiry}j</span>`
      : '—';
    const detailId = `ssl-detail-${idx}`;
    const certDetail = r.certificate ? `
      <div class="detail-grid" style="font-size:11px;max-width:460px">
        <span class="detail-key">Sujet</span><span class="detail-val">${escape(r.certificate.subject || '—')}</span>
        <span class="detail-key">Émetteur</span><span class="detail-val">${escape(r.certificate.issuer || '—')}</span>
        <span class="detail-key">Expire le</span><span class="detail-val">${escape(r.certificate.not_after || '—')}</span>
        <span class="detail-key">SANs</span><span class="detail-val">${escape((r.certificate.san || []).join(', ') || '—')}</span>
        <span class="detail-key">Version TLS</span><span class="detail-val">${escape(r.tls_version || '—')}</span>
        <span class="detail-key">Cipher</span><span class="detail-val">${escape(r.cipher_suite || '—')}</span>
      </div>` : '';
    return `
      <div class="ssl-report-card">
        <div class="ssl-report-header" onclick="document.getElementById('${detailId}').style.display=document.getElementById('${detailId}').style.display==='none'?'':'none'">
          <strong class="mono" style="font-size:13px">${escape(r.host || '?')}:${r.port || 443}</strong>
          ${_sslStatusBadge(r.status)}
          <span style="color:var(--text-muted);font-size:12px">${escape(r.subject || '')}</span>
          <span style="margin-left:auto;font-size:12px;color:var(--text-muted)">Expire dans ${daysLeft}</span>
          <span style="font-size:11px;color:var(--text-muted);margin-left:8px">Score: ${r.score != null ? r.score : '—'}</span>
        </div>
        <div class="ssl-report-detail" id="${detailId}" style="display:none">
          ${certDetail}
          ${issues ? `<div style="margin-top:8px">${issues}</div>` : ''}
        </div>
      </div>`;
  }).join('');
}

// ── Feature 5 — Baseline / Drift detection ────────────────────────────────────

async function createBaseline() {
  if (!_modalAssetId) return;
  const statusEl = document.getElementById('baseline-status');
  if (statusEl) statusEl.textContent = 'Création du snapshot…';
  try {
    await api(`/assets/${_modalAssetId}/baseline`, { method: 'POST' });
    showToast('Baseline créé.', 'success');
    if (statusEl) statusEl.textContent = 'Baseline créé.';
    await loadBaselines(_modalAssetId);
  } catch (e) {
    if (statusEl) statusEl.textContent = `Erreur : ${e.message}`;
    showToast('Erreur baseline : ' + e.message, 'error');
  }
}

async function loadBaselines(assetId) {
  try {
    const baselines = await api(`/assets/${assetId}/baseline`);
    _renderBaselineList(baselines || []);
  } catch (_) {
    _renderBaselineList([]);
  }
}

function _renderBaselineList(baselines) {
  const container = document.getElementById('baseline-list');
  if (!container) return;
  if (!baselines.length) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Aucun baseline disponible. Créez un snapshot pour démarrer.</p>';
    return;
  }
  container.innerHTML = baselines.map(b => `
    <div class="baseline-item">
      <div>
        <div class="baseline-item-date">${fmtDate(b.created_at)}</div>
        <div style="font-size:11px;color:var(--text-muted)">${b.ports_count != null ? b.ports_count + ' ports' : ''} ${b.cves_count != null ? '· ' + b.cves_count + ' CVEs' : ''}</div>
      </div>
      <button class="btn btn-sm" onclick="compareBaseline('${b.id}')">Comparer avec maintenant</button>
    </div>`).join('');
}

async function compareBaseline(baselineId) {
  if (!_modalAssetId) return;
  const diffEl = document.getElementById('baseline-diff-result');
  if (diffEl) diffEl.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Comparaison en cours…</p>';
  try {
    const diff = await api(`/assets/${_modalAssetId}/baseline/${baselineId}/diff`);
    _renderBaselineDiff(diff);
  } catch (e) {
    if (diffEl) diffEl.innerHTML = `<p style="color:var(--danger);font-size:13px">Erreur : ${escape(e.message)}</p>`;
  }
}

function _renderBaselineDiff(diff) {
  const container = document.getElementById('baseline-diff-result');
  if (!container || !diff) return;

  const portRow = (port, cls, symbol) =>
    `<div class="${cls}" style="font-size:12px;padding:2px 0">${symbol} ${escape(String(port.port_number || port))}${port.protocol ? '/' + port.protocol : ''} ${escape(port.service_name || '')}</div>`;

  const cveRow = (cve, cls, symbol) =>
    `<div class="${cls}" style="font-size:12px;padding:2px 0">${symbol} <a class="cve-link" href="${cveUrl(cve.cve_id || cve)}" target="_blank">${escape(cve.cve_id || cve)}</a>${cve.severity ? ` — ${cve.severity}` : ''}</div>`;

  const portAdded   = (diff.ports?.added   || []).map(p => portRow(p, 'diff-added',   '+')).join('');
  const portRemoved = (diff.ports?.removed || []).map(p => portRow(p, 'diff-removed', '−')).join('');
  const cveAdded    = (diff.cves?.added    || []).map(c => cveRow(c,  'diff-removed', '⚠')).join('');
  const cveResolved = (diff.cves?.resolved || []).map(c => cveRow(c,  'diff-added',   '✓')).join('');

  const section = (title, content) =>
    content ? `<div style="margin-bottom:12px"><p class="field-label" style="margin-bottom:6px">${title}</p>${content}</div>` : '';

  container.innerHTML = `
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px;margin-top:4px">
      <p class="field-label" style="margin-bottom:10px">Résultat de la comparaison</p>
      ${section('Ports — Nouveaux', portAdded)}
      ${section('Ports — Fermés', portRemoved)}
      ${section('CVEs — Nouvelles', cveAdded)}
      ${section('CVEs — Résolues', cveResolved)}
      ${(!portAdded && !portRemoved && !cveAdded && !cveResolved)
        ? '<p style="color:var(--success);font-size:13px">✓ Aucun changement détecté.</p>' : ''}
    </div>`;
}

// ── Feature 6 — SLA Dashboard widget ─────────────────────────────────────────

async function _loadDashboardSlaBreaches() {
  const container = document.getElementById('dash-sla-breaches');
  if (!container) return;
  try {
    const data = await api('/sla/breaches');
    if (!data || !data.items || !data.items.length) {
      container.innerHTML = '<p style="color:var(--success);font-size:13px">✓ Aucune SLA en retard.</p>';
      return;
    }
    container.innerHTML = `
      <table class="reports-sla-table">
        <thead><tr><th>Asset</th><th>CVE</th><th>Sévérité</th><th>Deadline</th><th>Retard</th></tr></thead>
        <tbody>
          ${data.items.slice(0, 10).map(b => `
            <tr class="sla-breach-row">
              <td><span class="clickable" style="color:var(--accent);cursor:pointer" onclick="openAssetModal('${b.asset_id}')">${escape(b.asset_name || b.asset_ip || b.asset_id.slice(0,8))}</span></td>
              <td><a class="cve-link" href="${cveUrl(b.cve_id)}" target="_blank">${escape(b.cve_id)}</a></td>
              <td>${b.severity ? badge(b.severity, b.severity.toLowerCase() === 'critical' || b.severity.toLowerCase() === 'high' ? 'error' : 'warning') : '—'}</td>
              <td style="font-size:11px">${b.deadline ? new Date(b.deadline).toLocaleDateString('fr-FR') : '—'}</td>
              <td style="color:var(--danger);font-weight:600">${b.overdue_days != null ? b.overdue_days + 'j' : '—'}</td>
            </tr>`).join('')}
        </tbody>
      </table>
      ${data.total > 10 ? `<p style="color:var(--text-muted);font-size:11px;margin-top:6px">+${data.total - 10} autres — voir le panel Rapports</p>` : ''}`;
  } catch (_) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:13px">SLA indisponible.</p>';
  }
}

async function _loadDashboardTopRisk() {
  const container = document.getElementById('dash-top-risk-list');
  if (!container) return;
  try {
    const { items } = await api('/assets?limit=500');
    const sorted = (items || [])
      .filter(a => a.risk_score != null)
      .sort((a, b) => b.risk_score - a.risk_score)
      .slice(0, 5);
    if (!sorted.length) {
      container.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Aucun score de risque calculé.</p>';
      return;
    }
    container.innerHTML = sorted.map(a => {
      const s = a.risk_score;
      let color = s >= 75 ? '#f87171' : s >= 50 ? '#fb923c' : s >= 25 ? '#fbbf24' : '#34d399';
      return `<div class="top-risk-item" onclick="openAssetModal('${a.id}')">
        <div class="top-risk-score" style="color:${color}">${Math.round(s)}</div>
        <div class="top-risk-info">
          <div class="top-risk-name">${escape(a.name || a.hostname || a.ip || '—')}</div>
          <div class="top-risk-ip">${escape(a.ip || '')}</div>
        </div>
        ${criticalityBadge(a.criticality)}
      </div>`;
    }).join('');
  } catch (_) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Erreur chargement.</p>';
  }
}

// ── Feature 7 — Admin: Notifications / Webhooks ───────────────────────────────

let _notifModalId = null;

async function loadNotifications() {
  try {
    const data = await api('/admin/notifications');
    const tbody = document.getElementById('notif-tbody');
    if (!tbody) return;
    const items = data?.items || data || [];
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;padding:24px">Aucun webhook configuré.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(n => {
      const events = (n.events || []).map(e => `<span class="notif-event-tag">${escape(e)}</span>`).join(' ');
      return `<tr>
        <td>${escape(n.name)}</td>
        <td>${badge(n.webhook_type || 'webhook', 'info')}</td>
        <td class="mono" style="font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis">${escape(n.url || '—')}</td>
        <td style="font-size:11px">${events || '—'}</td>
        <td>
          <label style="cursor:pointer">
            <input type="checkbox" ${n.is_active ? 'checked' : ''} onchange="toggleNotifActive('${n.id}', this.checked)" />
          </label>
        </td>
        <td style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="btn btn-sm" onclick="openNotifModal('${n.id}')">Éditer</button>
          <button class="btn btn-sm" onclick="testNotifWebhookById('${n.id}')">Tester</button>
          <button class="btn btn-sm" style="color:var(--danger)" onclick="deleteNotif('${n.id}','${escape(n.name)}')">Supprimer</button>
        </td>
      </tr>`;
    }).join('');
  } catch (e) {
    console.error('Notifications error:', e);
  }
}

async function openNotifModal(id = null) {
  _notifModalId = id;
  const modal = document.getElementById('notif-modal');
  if (!modal) return;
  document.getElementById('notif-modal-title').textContent = id ? 'Modifier le webhook' : 'Nouveau webhook';
  document.getElementById('notif-name').value = '';
  document.getElementById('notif-url').value = '';
  document.getElementById('notif-secret').value = '';
  document.getElementById('notif-active').checked = true;
  document.querySelectorAll('input[name="notif-event"]').forEach(cb => { cb.checked = false; });
  const testBtn = document.getElementById('notif-test-btn');
  if (testBtn) testBtn.style.display = id ? '' : 'none';

  if (id) {
    try {
      const n = await api(`/admin/notifications/${id}`);
      if (n) {
        document.getElementById('notif-name').value = n.name || '';
        document.getElementById('notif-url').value = n.url || '';
        document.getElementById('notif-active').checked = n.is_active !== false;
        document.querySelectorAll('input[name="notif-event"]').forEach(cb => {
          cb.checked = (n.events || []).includes(cb.value);
        });
      }
    } catch (_) {}
  }
  modal.classList.remove('hidden');
}

function closeNotifModal() {
  const modal = document.getElementById('notif-modal');
  if (modal) modal.classList.add('hidden');
  _notifModalId = null;
}

async function saveNotif() {
  const name = document.getElementById('notif-name').value.trim();
  const url = document.getElementById('notif-url').value.trim();
  if (!name || !url) { showToast('Nom et URL requis.', 'error'); return; }

  const events = [...document.querySelectorAll('input[name="notif-event"]:checked')].map(cb => cb.value);
  const secret = document.getElementById('notif-secret').value.trim();
  const is_active = document.getElementById('notif-active').checked;

  const payload = { name, url, events, is_active, webhook_type: 'webhook' };
  if (secret) payload.secret = secret;

  try {
    if (_notifModalId) {
      await api(`/admin/notifications/${_notifModalId}`, { method: 'PUT', body: JSON.stringify(payload) });
    } else {
      await api('/admin/notifications', { method: 'POST', body: JSON.stringify(payload) });
    }
    closeNotifModal();
    await loadNotifications();
    showToast('Webhook enregistré.', 'success');
  } catch (e) {
    showToast('Erreur : ' + e.message, 'error');
  }
}

async function deleteNotif(id, name) {
  if (!confirm(`Supprimer le webhook "${name}" ?`)) return;
  try {
    await api(`/admin/notifications/${id}`, { method: 'DELETE' });
    await loadNotifications();
    showToast('Webhook supprimé.', 'info');
  } catch (e) {
    showToast('Erreur : ' + e.message, 'error');
  }
}

async function toggleNotifActive(id, active) {
  try {
    await api(`/admin/notifications/${id}`, { method: 'PUT', body: JSON.stringify({ is_active: active }) });
    showToast(active ? 'Webhook activé.' : 'Webhook désactivé.', 'success');
  } catch (e) {
    showToast('Erreur : ' + e.message, 'error');
    await loadNotifications();
  }
}

async function testNotifWebhook() {
  if (!_notifModalId) { showToast('Enregistrez d\'abord le webhook.', 'warning'); return; }
  await testNotifWebhookById(_notifModalId);
}

async function testNotifWebhookById(id) {
  try {
    await api(`/admin/notifications/${id}/test`, { method: 'POST' });
    showToast('Webhook de test envoyé.', 'success');
  } catch (e) {
    showToast('Erreur test webhook : ' + e.message, 'error');
  }
}

// ── Feature 8 — Rapport exécutif ─────────────────────────────────────────────

let _reportsTrendChart = null;

function openExecutiveReport() {
  const headers = { 'Authorization': `Bearer ${_token}` };
  window.open(`${API}/reports/executive`, '_blank');
}

function _renderReportsStats(data) {
  const el = document.getElementById('reports-stats');
  if (!el) return;
  const statCard = (label, value, color, icon) =>
    `<div class="dash-stat-card" style="--card-accent:${color || 'var(--accent)'}">
       <div class="dash-stat-icon" style="color:${color}">${icon}</div>
       <div class="dash-stat-value" style="color:${color}">${value != null ? value : '—'}</div>
       <div class="dash-stat-label">${label}</div>
     </div>`;
  el.innerHTML = [
    statCard('Score sécurité global', data.security_score != null ? data.security_score + '/100' : '—', 'var(--accent)',
      '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" width="22" height="22"><path d="M10 2l8 14H2L10 2z"/></svg>'),
    statCard('Assets critiques', data.critical_assets || 0, 'var(--danger)',
      '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" width="22" height="22"><rect x="2" y="3" width="16" height="12" rx="2"/></svg>'),
    statCard('CVEs critiques non traitées', data.critical_unacked_cves || 0, 'var(--danger)',
      '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" width="22" height="22"><path d="M10 18s7-3 7-9V4l-7-2-7 2v5c0 6 7 9 7 9z"/></svg>'),
    statCard('SLA Breaches', data.sla_breaches_count || 0, (data.sla_breaches_count || 0) > 0 ? 'var(--warning)' : 'var(--success)',
      '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" width="22" height="22"><circle cx="10" cy="10" r="8"/><polyline points="10 6 10 10 13 12"/></svg>'),
  ].join('');
}

function _renderReportsSlaBreaches(breaches) {
  const el = document.getElementById('reports-sla-list');
  if (!el) return;
  if (!breaches.length) {
    el.innerHTML = '<p style="color:var(--success);font-size:13px">✓ Aucune SLA en retard.</p>';
    return;
  }
  el.innerHTML = `
    <table class="reports-sla-table">
      <thead><tr><th>Asset</th><th>CVE</th><th>Sévérité</th><th>Deadline</th><th>Retard</th></tr></thead>
      <tbody>
        ${breaches.slice(0, 8).map(b => `
          <tr class="sla-breach-row">
            <td><span class="clickable" style="color:var(--accent);cursor:pointer" onclick="switchToView('assets');openAssetModal('${b.asset_id}')">${escape(b.asset_name || b.asset_ip || b.asset_id.slice(0,8))}</span></td>
            <td><a class="cve-link" href="${cveUrl(b.cve_id)}" target="_blank">${escape(b.cve_id)}</a></td>
            <td>${badge(b.severity || '?', b.severity?.toLowerCase() === 'critical' || b.severity?.toLowerCase() === 'high' ? 'error' : 'warning')}</td>
            <td style="font-size:11px">${b.deadline ? new Date(b.deadline).toLocaleDateString('fr-FR') : '—'}</td>
            <td style="color:var(--danger);font-weight:600">${b.overdue_days != null ? b.overdue_days + 'j' : '—'}</td>
          </tr>`).join('')}
      </tbody>
    </table>`;
}

function _renderReportsTopRisk(assets) {
  const el = document.getElementById('reports-top-risk-list');
  if (!el) return;
  if (!assets.length) {
    el.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Aucun score de risque calculé.</p>';
    return;
  }
  el.innerHTML = assets.map(a => {
    const s = a.risk_score || 0;
    const color = s >= 75 ? '#f87171' : s >= 50 ? '#fb923c' : s >= 25 ? '#fbbf24' : '#34d399';
    return `<div class="top-risk-item" onclick="switchToView('assets');openAssetModal('${a.asset_id || a.id}')">
      <div class="top-risk-score" style="color:${color}">${Math.round(s)}</div>
      <div class="top-risk-info">
        <div class="top-risk-name">${escape(a.name || a.hostname || a.ip || '—')}</div>
        <div class="top-risk-ip">${escape(a.ip || '')}</div>
      </div>
    </div>`;
  }).join('');
}

function _renderReportsTrend(trend) {
  const ctx = document.getElementById('reports-trend-chart')?.getContext('2d');
  if (!ctx || !window.Chart) return;
  if (_reportsTrendChart) _reportsTrendChart.destroy();
  const points = trend.points || [];
  const CHART_FONT = { family: 'Inter, sans-serif', size: 11 };
  const GRID_COLOR = 'rgba(255,255,255,0.06)';
  const TICK_COLOR = 'rgba(255,255,255,0.45)';
  _reportsTrendChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: points.map(p => (p.date || '').slice(5)),
      datasets: [
        { label: 'CVEs découvertes', data: points.map(p => p.cves_discovered || 0), borderColor: '#f87171', backgroundColor: 'rgba(248,113,113,0.1)', fill: true, tension: 0.35, pointRadius: 3 },
        { label: 'CVEs résolues',    data: points.map(p => p.cves_acknowledged || 0), borderColor: '#34d399', backgroundColor: 'rgba(52,211,153,0.1)', fill: true, tension: 0.35, pointRadius: 3 },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: TICK_COLOR, font: CHART_FONT, boxWidth: 12 } },
        tooltip: { backgroundColor: 'rgba(15,18,30,0.92)', titleColor: '#e2e8f0', bodyColor: '#94a3b8', borderColor: 'rgba(129,140,248,0.3)', borderWidth: 1, cornerRadius: 8 },
      },
      scales: {
        x: { ticks: { color: TICK_COLOR, font: CHART_FONT, maxTicksLimit: 10 }, grid: { color: GRID_COLOR }, border: { color: 'transparent' } },
        y: { beginAtZero: true, ticks: { color: TICK_COLOR, font: CHART_FONT, precision: 0 }, grid: { color: GRID_COLOR }, border: { color: 'transparent' } },
      },
    },
  });
}

// ── Feature 9 — Topologie réseau D3.js ───────────────────────────────────────

let _topoGrouping = 'subnet'; // 'subnet' | 'criticality'
let _topoAssets = [];

function toggleTopoGrouping() {
  _topoGrouping = _topoGrouping === 'subnet' ? 'criticality' : 'subnet';
  const btn = document.getElementById('topo-group-btn');
  if (btn) btn.textContent = _topoGrouping === 'subnet' ? 'Par criticité' : 'Par subnet';
  _renderTopology(_topoAssets);
}

function _topoNodeColor(asset) {
  const crit = (asset.criticality || '').toLowerCase();
  if (crit === 'critical') return '#f87171';
  const cves = asset.cves || [];
  const hasCritical = cves.some(c => (c.severity || '').toLowerCase() === 'critical');
  const hasHigh = cves.some(c => (c.severity || '').toLowerCase() === 'high');
  if (hasCritical) return '#f87171';
  if (hasHigh) return '#fb923c';
  const hasMedium = cves.some(c => (c.severity || '').toLowerCase() === 'medium');
  if (hasMedium) return '#fbbf24';
  return '#34d399';
}

function _renderTopology(assets) {
  const container = document.getElementById('topology-container');
  if (!container || !window.d3) {
    if (container) container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-muted);font-size:13px">D3.js non chargé.</div>';
    return;
  }
  container.innerHTML = '';
  if (!assets.length) {
    container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-muted);font-size:13px">Aucun asset à afficher.</div>';
    return;
  }

  const W = container.clientWidth || 800;
  const H = container.clientHeight || 560;

  // Build nodes and links
  const nodes = [];
  const links = [];

  if (_topoGrouping === 'subnet') {
    // Group nodes by /24 subnet — create group nodes
    const subnets = {};
    assets.forEach(a => {
      const ip = a.ip || '';
      const sub = ip.split('.').slice(0, 3).join('.') + '.0/24';
      if (!subnets[sub]) subnets[sub] = { id: 'sub_' + sub, label: sub, type: 'subnet', x: 0, y: 0 };
    });
    Object.values(subnets).forEach(s => nodes.push(s));
    assets.forEach(a => {
      const ip = a.ip || '';
      const sub = ip.split('.').slice(0, 3).join('.') + '.0/24';
      const nodeId = 'asset_' + a.id;
      nodes.push({ id: nodeId, label: a.name || a.ip || '?', ip: a.ip || '', asset: a, type: 'asset', x: 0, y: 0 });
      if (subnets[sub]) links.push({ source: 'sub_' + sub, target: nodeId });
    });
  } else {
    // Group by criticality — create criticality group nodes
    const groups = { critical: null, high: null, medium: null, low: null, none: null };
    Object.keys(groups).forEach(k => {
      groups[k] = { id: 'grp_' + k, label: k === 'none' ? 'Sans CVE' : k, type: 'group', x: 0, y: 0 };
      nodes.push(groups[k]);
    });
    assets.forEach(a => {
      const color = _topoNodeColor(a);
      let grp = 'none';
      if (color === '#f87171') grp = 'critical';
      else if (color === '#fb923c') grp = 'high';
      else if (color === '#fbbf24') grp = 'medium';
      else grp = 'low';
      const nodeId = 'asset_' + a.id;
      nodes.push({ id: nodeId, label: a.name || a.ip || '?', ip: a.ip || '', asset: a, type: 'asset', x: 0, y: 0 });
      links.push({ source: 'grp_' + grp, target: nodeId });
    });
  }

  const svg = d3.select(container).append('svg')
    .attr('width', W).attr('height', H)
    .style('background', 'transparent');

  // Arrow marker
  svg.append('defs').append('marker')
    .attr('id', 'arrow').attr('viewBox', '0 -3 6 6').attr('refX', 14).attr('refY', 0)
    .attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
    .append('path').attr('d', 'M0,-3L6,0L0,3').attr('fill', '#1c2d44');

  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d.id).distance(80).strength(0.6))
    .force('charge', d3.forceManyBody().strength(-180))
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('collision', d3.forceCollide(28));

  const link = svg.append('g').selectAll('line')
    .data(links).join('line')
    .attr('stroke', '#1c2d44').attr('stroke-width', 1.2);

  const nodeG = svg.append('g').selectAll('g')
    .data(nodes).join('g')
    .call(d3.drag()
      .on('start', (ev, d) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag',  (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
      .on('end',   (ev, d) => { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
    )
    .on('click', (ev, d) => { if (d.asset) openAssetModal(d.asset.id); });

  // Tooltip
  const tooltip = d3.select('body').append('div').attr('class', 'topo-tooltip').style('display', 'none');

  nodeG.filter(d => d.type === 'asset')
    .on('mouseover', (ev, d) => {
      const a = d.asset;
      const cveCount = (a.cves || []).length;
      tooltip.style('display', 'block')
        .html(`<strong>${escape(a.name || a.ip || '?')}</strong>
          IP: ${escape(a.ip || '—')}<br>
          Hostname: ${escape(a.hostname || '—')}<br>
          CVEs: ${cveCount}<br>
          Risk score: ${a.risk_score != null ? a.risk_score : '—'}<br>
          Criticité: ${a.criticality || '—'}`);
    })
    .on('mousemove', ev => {
      tooltip.style('left', (ev.clientX + 14) + 'px').style('top', (ev.clientY - 10) + 'px');
    })
    .on('mouseout', () => tooltip.style('display', 'none'));

  // Group/subnet nodes
  nodeG.filter(d => d.type === 'subnet' || d.type === 'group').append('rect')
    .attr('x', -36).attr('y', -12).attr('width', 72).attr('height', 24).attr('rx', 6)
    .attr('fill', 'var(--surface3)').attr('stroke', 'var(--border)').attr('stroke-width', 1.5);
  nodeG.filter(d => d.type === 'subnet' || d.type === 'group').append('text')
    .attr('text-anchor', 'middle').attr('dy', '0.35em')
    .attr('fill', 'var(--text-muted)').attr('font-size', 10).attr('font-family', 'monospace')
    .text(d => d.label);

  // Asset nodes
  const riskRadius = d => {
    const s = d.asset?.risk_score;
    if (s == null) return 8;
    return Math.max(7, Math.min(18, 7 + s / 12));
  };
  nodeG.filter(d => d.type === 'asset').append('circle')
    .attr('r', riskRadius)
    .attr('fill', d => _topoNodeColor(d.asset))
    .attr('fill-opacity', 0.85)
    .attr('stroke', '#0c1120').attr('stroke-width', 1.5)
    .style('cursor', 'pointer');
  nodeG.filter(d => d.type === 'asset').append('text')
    .attr('dy', d => riskRadius(d) + 10)
    .attr('text-anchor', 'middle')
    .attr('fill', 'var(--text-muted)').attr('font-size', 9).attr('font-family', 'Inter, sans-serif')
    .text(d => (d.label || '').slice(0, 12));

  sim.on('tick', () => {
    link
      .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
    nodeG.attr('transform', d => `translate(${d.x},${d.y})`);
  });

  // Cleanup tooltip on panel exit
  const obs = new MutationObserver(() => {
    if (!document.contains(container)) { tooltip.remove(); obs.disconnect(); }
  });
  obs.observe(document.body, { childList: true, subtree: true });
}

// ── Feature — SLA Config admin ────────────────────────────────────────────────

async function loadSlaConfig() {
  try {
    const cfg = await api('/sla/config');
    if (!cfg) return;
    const f = (id, val) => { const el = document.getElementById(id); if (el) el.value = val != null ? val : ''; };
    f('sla-critical', cfg.critical_days);
    f('sla-high', cfg.high_days);
    f('sla-medium', cfg.medium_days);
    f('sla-low', cfg.low_days);
  } catch (_) { /* endpoint might not exist yet */ }
}

async function saveSlaConfig() {
  const v = id => { const el = document.getElementById(id); return el && el.value ? parseInt(el.value, 10) : null; };
  const payload = {
    critical_days: v('sla-critical'),
    high_days:     v('sla-high'),
    medium_days:   v('sla-medium'),
    low_days:      v('sla-low'),
  };
  const statusEl = document.getElementById('sla-config-status');
  try {
    await api('/sla/config', { method: 'PUT', body: JSON.stringify(payload) });
    if (statusEl) { statusEl.className = 'status-bar success'; statusEl.textContent = 'Configuration SLA sauvegardée.'; statusEl.classList.remove('hidden'); }
    showToast('Configuration SLA sauvegardée.', 'success');
  } catch (e) {
    if (statusEl) { statusEl.className = 'status-bar error'; statusEl.textContent = `Erreur : ${e.message}`; statusEl.classList.remove('hidden'); }
    showToast('Erreur : ' + e.message, 'error');
  }
}

async function recomputeAllSlas() {
  try {
    await api('/sla/compute', { method: 'POST' });
    showToast('Recalcul SLA lancé.', 'success');
  } catch (e) {
    showToast('Erreur SLA : ' + e.message, 'error');
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ── OVERRIDES — Functions redeclared here (last declaration wins) ───────────────
// ═══════════════════════════════════════════════════════════════════════════════

// ── loadAssets — adds Criticité + Risque columns ─────────────────────────────

async function loadAssets() {
  const search = document.getElementById('asset-search').value.toLowerCase();
  const activeOnly = document.getElementById('active-only').checked;
  const filterSeverity = document.getElementById('asset-filter-severity')?.value || '';

  try {
    const { items } = await api(`/assets?limit=500${activeOnly ? '&active_only=true' : ''}`);
    let filtered = items.filter(a => {
      if (search) {
        const tags = (a.tags || []).join(' ').toLowerCase();
        const match = (a.name || '').toLowerCase().includes(search) ||
          (a.ip || '').includes(search) ||
          (a.mac || '').toLowerCase().includes(search) ||
          (a.hostname || '').toLowerCase().includes(search) ||
          tags.includes(search);
        if (!match) return false;
      }
      if (filterSeverity) {
        const hasSeverity = (a.cves || []).some(c => c.severity === filterSeverity);
        if (!hasSeverity) return false;
      }
      return true;
    });

    const tbody = document.querySelector('#asset-table tbody');
    const bulkBtn = document.getElementById('bulk-scan-btn');
    const bulkEditBtn = document.getElementById('bulk-edit-btn');
    if (!filtered.length) {
      tbody.innerHTML = '<tr><td colspan="15" style="text-align:center;color:var(--text-muted);padding:32px">No assets found</td></tr>';
      if (bulkBtn) bulkBtn.style.display = 'none';
      if (bulkEditBtn) bulkEditBtn.style.display = 'none';
      return;
    }

    const critCount = (a) => (a.cves || []).filter(c => c.severity === 'Critical' && c.ack_status === 'none').length;

    let rows;
    if (_groupBySubnet) {
      const groups = {};
      filtered.forEach(a => {
        const subnet = (a.ip || '').split('.').slice(0, 3).join('.') + '.0/24';
        if (!groups[subnet]) groups[subnet] = [];
        groups[subnet].push(a);
      });
      rows = '';
      Object.entries(groups).sort().forEach(([subnet, assets]) => {
        rows += `<tr class="subnet-header"><td colspan="15">${escape(subnet)} — ${assets.length} host${assets.length > 1 ? 's' : ''}</td></tr>`;
        rows += assets.map(a => _renderAssetRow(a, critCount(a))).join('');
      });
    } else {
      rows = filtered.map(a => _renderAssetRow(a, critCount(a))).join('');
    }

    tbody.innerHTML = rows;

    if (bulkBtn) bulkBtn.style.display = _selectedAssetIds.size > 0 ? '' : 'none';
    if (bulkEditBtn) bulkEditBtn.style.display = _selectedAssetIds.size > 0 ? '' : 'none';

    tbody.querySelectorAll('[data-inline-field]').forEach(td => {
      const assetId = td.closest('tr')?.querySelector('.asset-checkbox')?.value;
      if (assetId) _initInlineEdit(td, assetId, td.dataset.inlineField);
    });
  } catch (e) {
    console.error('Assets error:', e);
  }
}

function _renderAssetRow(a, critCnt) {
  const openPorts = (a.ports || []).filter(p => p.state === 'open');
  const portList = openPorts.slice(0, 5)
    .map(p => `<span class="mono">${p.port_number}/${p.protocol}</span>`).join(' ');
  const morePorts = openPorts.length > 5
    ? `<span class="badge badge-muted">+${openPorts.length - 5}</span>` : '';
  const cves = a.cves || [];
  const unacked = cves.filter(c => c.ack_status === 'none');
  const cveBadge = unacked.length
    ? `<span class="badge badge-${critCnt > 0 ? 'error' : 'warning'}">${unacked.length}</span>`
    : '<span style="color:var(--text-muted)">—</span>';
  const tagHtml = (a.tags || []).map(t =>
    `<span style="font-size:10px;background:var(--surface3);border:1px solid var(--border);border-radius:4px;padding:1px 5px;color:var(--text-muted)">${escape(t)}</span>`
  ).join(' ');
  const checked = _selectedAssetIds.has(a.id) ? 'checked' : '';

  // SSL icon
  const has443 = openPorts.some(p => p.port_number === 443);
  let sslIcon = '';
  if (has443) {
    // We don't load SSL status per row (perf), just show the lock icon
    sslIcon = '<span title="Port 443 ouvert" style="font-size:12px;margin-left:4px">🔒</span>';
  }

  return `
    <tr>
      <td onclick="event.stopPropagation()">
        <input type="checkbox" class="asset-checkbox" value="${a.id}" ${checked}
          onchange="toggleAssetSelect(this)" />
      </td>
      <td class="clickable" onclick="openAssetModal('${a.id}')">
        ${a.name ? `<strong>${escape(a.name)}</strong>` : '<span style="color:var(--text-muted)">—</span>'}
        ${sslIcon}
        ${tagHtml ? `<div style="margin-top:3px;display:flex;flex-wrap:wrap;gap:3px">${tagHtml}</div>` : ''}
      </td>
      <td class="mono clickable" onclick="openAssetModal('${a.id}')">${escape(a.ip || '—')}</td>
      <td class="mono">${escape(a.mac || '—')}</td>
      <td data-inline-field="hostname">${escape(a.hostname || '—')}</td>
      <td>${escape(a.vendor || '—')}</td>
      <td data-inline-field="os_family">${escape(a.os_family || '—')}${a.os_version ? ` <small style="color:var(--text-muted)">${escape(a.os_version)}</small>` : ''}</td>
      <td>${portList}${morePorts}</td>
      <td>${cveBadge}</td>
      <td>${criticalityBadge(a.criticality)}</td>
      <td>${riskScoreBadge(a.risk_score)}</td>
      <td>${a.is_active ? badge('yes', 'success') : badge('no', 'muted')}</td>
      <td style="color:var(--text-muted);font-size:12px">${fmtDate(a.last_seen)}</td>
      <td>${scanAgeBadge(a.last_seen)}</td>
    </tr>`;
}

// ── openAssetModal — adds criticality pre-fill + SSL/Baseline tab loading ─────

async function openAssetModal(id) {
  _modalAssetId = id;
  const overlay = document.getElementById('asset-modal');
  overlay.classList.remove('hidden');
  _switchModalTab('details');
  _switchSecPanel('cves', document.querySelector('.sec-subnav .sec-subnav-btn'));

  const saveBtn = document.getElementById('modal-save-btn');
  saveBtn.disabled = false;
  saveBtn.textContent = 'Save';

  document.getElementById('zap-status').classList.add('hidden');
  document.getElementById('zap-risk-summary').classList.add('hidden');
  const autoBadge = document.getElementById('modal-auto-badge');
  if (autoBadge) autoBadge.style.display = 'none';

  // Reset SSL and Baseline tabs
  const sslBody = document.getElementById('ssl-reports-body');
  if (sslBody) sslBody.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Chargement…</p>';
  const baselineList = document.getElementById('baseline-list');
  if (baselineList) baselineList.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Chargement…</p>';
  const baselineDiff = document.getElementById('baseline-diff-result');
  if (baselineDiff) baselineDiff.innerHTML = '';

  try {
    const a = await api(`/assets/${id}`);
    document.getElementById('modal-title').textContent =
      a.name || a.hostname || a.ip || 'Asset';

    const infoEl = document.getElementById('modal-info');
    const row = (k, v) =>
      `<span class="detail-key">${k}</span><span class="detail-val">${escape(v || '—')}</span>`;
    infoEl.innerHTML = [
      row('IP', a.ip),
      row('MAC', a.mac),
      row('Vendor', a.vendor),
      row('Last seen', a.last_seen ? new Date(a.last_seen).toLocaleString() : null),
    ].join('');

    document.getElementById('modal-name').value = a.name || '';
    document.getElementById('modal-hostname').value = a.hostname || '';
    document.getElementById('modal-device-type').value = a.device_type || '';
    document.getElementById('modal-os-family').value = a.os_family || '';
    document.getElementById('modal-os-version').value = a.os_version || '';

    // Criticality
    const critSelect = document.getElementById('modal-criticality');
    if (critSelect) critSelect.value = a.criticality || '';

    const profileSelect = document.getElementById('modal-ssh-profile');
    if (profileSelect) {
      if (_me && _me.role === 'admin') {
        document.getElementById('modal-ssh-profile-group').style.display = '';
        try {
          const profiles = await api('/admin/ssh-profiles') || [];
          profileSelect.innerHTML =
            '<option value="">— No profile (use per-asset credentials) —</option>' +
            profiles.map(p => `<option value="${p.id}">${escape(p.name)} (${escape(p.ssh_user)})</option>`).join('');
        } catch (_) {
          profileSelect.innerHTML = '<option value="">— No profile —</option>';
        }
        profileSelect.value = a.ssh_profile_id || '';
        _onSshProfileChange(profileSelect.value, profileSelect);
      } else {
        document.getElementById('modal-ssh-profile-group').style.display = 'none';
        _onSshProfileChange('');
      }
    }
    document.getElementById('modal-ssh-user').value = a.ssh_user || '';
    document.getElementById('modal-ssh-port').value = a.ssh_port || '';
    document.getElementById('modal-ssh-password').value = '';
    document.getElementById('modal-ssh-key').value = '';
    const pwHint = document.getElementById('modal-ssh-password-hint');
    const keyHint = document.getElementById('modal-ssh-key-hint');
    if (pwHint) pwHint.textContent = a.has_ssh_password ? 'Mot de passe enregistré — laisser vide pour conserver' : '';
    if (keyHint) keyHint.textContent = a.has_ssh_key ? 'Clé privée enregistrée — laisser vide pour conserver' : '';
    document.getElementById('modal-notes').value = a.notes || '';

    _assetDns = a.dns_entries || [];
    _renderDnsTags();
    _assetTags = a.tags || [];
    _renderAssetTags();

    const zapAutoEl = document.getElementById('modal-zap-auto');
    const zapIntervalEl = document.getElementById('modal-zap-interval');
    if (zapAutoEl) zapAutoEl.checked = a.zap_auto_scan_enabled === true;
    if (zapIntervalEl) zapIntervalEl.value = a.zap_scan_interval_minutes || '';

    const sshAutoEl = document.getElementById('modal-ssh-auto');
    const sshIntervalEl = document.getElementById('modal-ssh-interval');
    if (sshAutoEl) sshAutoEl.checked = a.ssh_auto_scan_enabled === true;
    if (sshIntervalEl) sshIntervalEl.value = a.ssh_scan_interval_minutes || '';

    const trivyAutoEl = document.getElementById('modal-trivy-auto');
    const trivyIntervalEl = document.getElementById('modal-trivy-interval');
    if (trivyAutoEl) trivyAutoEl.checked = a.trivy_auto_scan_enabled === true;
    if (trivyIntervalEl) trivyIntervalEl.value = a.trivy_scan_interval_minutes || '';

    document.getElementById('zap-target-url').value = a.ip ? `http://${a.ip}` : '';

    _portsDiffEnabled = false;
    _renderPortsTab(a);
    _renderZapTargets(a);
    _renderOverviewTab(a);
    _renderFlawsTab(a);
    _autoTriggerZap(a);

    let sshReports = [];
    try { sshReports = await api(`/assets/${id}/ssh-scan`) || []; } catch (_) {}
    _renderSshSection(a, sshReports);

    try {
      const sshHistory = await api(`/assets/${id}/ssh-scans`) || [];
      _renderSshScanHistory(sshHistory);
    } catch (_) {}

    let nucleiReports = [];
    try { nucleiReports = await api(`/assets/${id}/nuclei`) || []; } catch (_) {}
    _renderNucleiSection(a, nucleiReports);

    let trivyReports = [];
    try { trivyReports = await api(`/assets/${id}/trivy-docker`) || []; } catch (_) {}
    _renderTrivyDockerSection(a, trivyReports);

    // SSL tab
    await loadSslReports(id);

    // Baseline tab
    await loadBaselines(id);

    // Full Audit jobs
    loadFullAuditJobs(id);

  } catch (e) {
    document.getElementById('modal-info').innerHTML =
      `<span class="detail-key">Error</span><span class="detail-val" style="color:var(--danger)">${escape(e.message)}</span>`;
  }
}

// ── saveAssetModal — includes criticality ────────────────────────────────────

async function saveAssetModal() {
  if (!_modalAssetId) return;
  const saveBtn = document.getElementById('modal-save-btn');
  saveBtn.disabled = true;
  saveBtn.textContent = 'Saving…';

  const sshPort = document.getElementById('modal-ssh-port').value;
  const zapIntervalRaw = document.getElementById('modal-zap-interval').value;
  const sshIntervalRaw = document.getElementById('modal-ssh-interval').value;
  const trivyIntervalRaw = document.getElementById('modal-trivy-interval').value;
  const payload = {
    name:       document.getElementById('modal-name').value.trim() || null,
    hostname:   document.getElementById('modal-hostname').value.trim() || null,
    device_type: document.getElementById('modal-device-type').value.trim() || null,
    os_family:  document.getElementById('modal-os-family').value.trim() || null,
    os_version: document.getElementById('modal-os-version').value.trim() || null,
    criticality: document.getElementById('modal-criticality')?.value || null,
    ssh_profile_id: document.getElementById('modal-ssh-profile')?.value || null,
    ssh_user:   document.getElementById('modal-ssh-user').value.trim() || null,
    ssh_port:   sshPort ? parseInt(sshPort, 10) : null,
    zap_auto_scan_enabled: document.getElementById('modal-zap-auto').checked,
    zap_scan_interval_minutes: zapIntervalRaw ? parseInt(zapIntervalRaw, 10) : null,
    ssh_auto_scan_enabled: document.getElementById('modal-ssh-auto')?.checked ?? false,
    ssh_scan_interval_minutes: sshIntervalRaw ? parseInt(sshIntervalRaw, 10) : null,
    trivy_auto_scan_enabled: document.getElementById('modal-trivy-auto')?.checked ?? false,
    trivy_scan_interval_minutes: trivyIntervalRaw ? parseInt(trivyIntervalRaw, 10) : null,
    notes: document.getElementById('modal-notes').value.trim() || null,
  };
  const sshPwd = document.getElementById('modal-ssh-password').value;
  const sshKey = document.getElementById('modal-ssh-key').value.trim();
  if (sshPwd) payload.ssh_password = sshPwd;
  if (sshKey) payload.ssh_private_key = sshKey;

  try {
    await api(`/assets/${_modalAssetId}`, { method: 'PATCH', body: JSON.stringify(payload) });
    document.getElementById('asset-modal').classList.add('hidden');
    _modalAssetId = null;
    await loadAssets();
    showToast('Asset saved successfully.', 'success');
  } catch (e) {
    saveBtn.disabled = false;
    saveBtn.textContent = 'Save';
    showToast(`Save failed: ${e.message}`, 'error');
  }
}

// ── _renderExpositions — adds EPSS column ────────────────────────────────────

function _renderExpositions() {
  const tbody = document.getElementById('expositions-tbody');
  if (!tbody) return;

  const search   = (document.getElementById('exp-search')?.value || '').toLowerCase();
  const severity = document.getElementById('exp-severity')?.value || '';
  const source   = document.getElementById('exp-source')?.value || '';
  const ack      = document.getElementById('exp-ack')?.value;

  let filtered = _expData.filter(({ asset, cve }) => {
    if (severity && cve.severity !== severity) return false;
    if (source && !(cve.source || '').includes(source)) return false;
    if (ack !== '' && ack !== undefined && ack !== null && cve.ack_status !== ack) return false;
    if (search) {
      const hay = [cve.cve_id_str, asset.name, asset.ip, asset.hostname, cve.package_name, cve.package_version]
        .filter(Boolean).join(' ').toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  const total = filtered.length;
  const page = filtered.slice(_expOffset, _expOffset + _EXP_LIMIT);

  if (!page.length) {
    tbody.innerHTML = '<tr><td colspan="12" style="color:var(--text-muted);text-align:center;padding:24px">Aucune exposition trouvée.</td></tr>';
    _renderExpPagination(total);
    return;
  }

  tbody.innerHTML = page.map(({ asset, cve }) => {
    const sev = (cve.severity || '').toLowerCase();
    const sevType = sev === 'critical' || sev === 'high' ? 'error'
      : sev === 'medium' ? 'warning' : sev === 'low' ? 'info' : 'muted';
    const ackBadge = _ackBadge(cve.ack_status);
    const assetLabel = escape(asset.name || asset.ip || asset.hostname || asset.id.slice(0, 8));
    const fixAvail = cve.fixed_version
      ? `<span style="color:var(--success);font-size:11px">✓ ${escape(cve.fixed_version)}</span>`
      : '<span style="color:var(--text-muted);font-size:11px">—</span>';
    const planCell = cve.remediation
      ? `<span class="plan-snippet" title="${escape(cve.remediation)}" onclick="openCveRemediationModal('${escape(cve.cve_id_str)}','${escape(cve.remediation || '')}')" style="cursor:pointer">${escape(cve.remediation.length > 50 ? cve.remediation.slice(0, 50) + '…' : cve.remediation)}</span>`
      : (_me && _me.role === 'admin'
          ? `<button class="btn btn-sm" onclick="openCveRemediationModal('${escape(cve.cve_id_str)}','')">+ Plan</button>`
          : '<span style="color:var(--text-muted);font-size:11px">—</span>');
    const isSelected = _selectedExpIds.has(cve.id);
    return `
      <tr>
        <td onclick="event.stopPropagation()">
          <input type="checkbox" class="exp-checkbox" value="${cve.id}" ${isSelected ? 'checked' : ''}
            onchange="toggleExpSelect(this)" />
        </td>
        <td><a class="cve-link" href="${cveUrl(cve.cve_id_str)}" target="_blank" rel="noopener"
               title="${escape(cve.description || '')}">${escape(cve.cve_id_str)}</a></td>
        <td>${cve.severity ? badge(cve.severity, sevType) : '—'}</td>
        <td>${cve.cvss_score != null ? cve.cvss_score.toFixed(1) : '—'}</td>
        <td>${epssBadge(cve.epss_score)}</td>
        <td><span class="clickable" onclick="openAssetModal('${asset.id}')" style="color:var(--accent);cursor:pointer">${assetLabel}</span></td>
        <td style="font-size:11px">${_renderSourceBadges(cve.source)}</td>
        <td style="font-size:11px">${cve.package_name ? escape(cve.package_name + (cve.package_version ? ' ' + cve.package_version : '')) : '—'}</td>
        <td>${fixAvail}</td>
        <td style="max-width:180px;font-size:12px">${planCell}</td>
        <td>${ackBadge}</td>
        <td style="white-space:nowrap">
          ${_ackActions(asset.id, cve.id, cve.ack_status)}
        </td>
      </tr>`;
  }).join('');

  _renderExpPagination(total);
  if (_expKanbanMode) _renderKanban();
}

// ── switchToView — duplicate removed (defined at top of file with hash routing) ──

// ── initSubTabs — handle new sub-tabs ────────────────────────────────────────

function initSubTabs() {
  document.querySelectorAll('.subnav-item').forEach(tab => {
    tab.addEventListener('click', () => {
      const panel = document.getElementById('panel-admin');
      panel.querySelectorAll('.subnav-item').forEach(t => t.classList.remove('active'));
      panel.querySelectorAll('.sub-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('sub-' + tab.dataset.subtab)?.classList.add('active');

      if (tab.dataset.subtab === 'admin-auth') loadAuthSettings();
      if (tab.dataset.subtab === 'admin-oidc') loadOidcConfig();
      if (tab.dataset.subtab === 'admin-users') loadUsers();
      if (tab.dataset.subtab === 'admin-zap') loadZapSettings();
      if (tab.dataset.subtab === 'admin-ssh-profiles') loadSshProfiles();
      if (tab.dataset.subtab === 'admin-audit') loadAuditLog();
      if (tab.dataset.subtab === 'admin-quota') loadQuotaUsage();
      if (tab.dataset.subtab === 'admin-sla') loadSlaConfig();
      if (tab.dataset.subtab === 'admin-notif') loadNotifications();
    });
  });
}

// ── loadDashboard — adds SLA breaches + top risk widgets ─────────────────────

async function loadDashboard() {
  const grid = document.getElementById('dashboard-stats');
  if (!grid) return;

  grid.innerHTML = '<span style="color:var(--text-muted);font-size:13px">Chargement…</span>';

  let data;
  try {
    data = await api('/dashboard');
  } catch (e) {
    grid.innerHTML = `<span style="color:var(--danger)">Erreur : ${escape(String(e))}</span>`;
    return;
  }

  const expBadge = document.getElementById('nav-exp-count');
  if (expBadge) expBadge.textContent = data.unacknowledged_cves > 0 ? data.unacknowledged_cves : '';

  const statCard = (label, value, color, icon) =>
    `<div class="dash-stat-card" style="--card-accent:${color || 'var(--accent)'}">
       <div class="dash-stat-icon" style="color:${color || 'var(--accent)'}">${icon || ''}</div>
       <div class="dash-stat-value" style="color:${color || 'var(--accent)'}">${value}</div>
       <div class="dash-stat-label">${label}</div>
     </div>`;

  grid.innerHTML = [
    statCard('Total assets', data.total_assets, 'var(--accent)',
      '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" width="22" height="22"><rect x="2" y="3" width="16" height="12" rx="2"/><path d="M6 19h8M10 15v4"/></svg>'),
    statCard('Assets actifs', data.active_assets, 'var(--success)',
      '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" width="22" height="22"><circle cx="10" cy="10" r="7"/><path d="M7 10l2 2 4-4"/></svg>'),
    statCard('CVEs totaux', data.total_cves, data.total_cves > 0 ? 'var(--warning)' : 'var(--success)',
      '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" width="22" height="22"><path d="M10 18s7-3 7-9V4l-7-2-7 2v5c0 6 7 9 7 9z"/><path d="M10 8v3M10 14h.01"/></svg>'),
    statCard('CVEs non-acknowled.', data.unacknowledged_cves, data.unacknowledged_cves > 0 ? 'var(--danger)' : 'var(--success)',
      '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" width="22" height="22"><path d="M10 2l8 14H2L10 2z"/><path d="M10 8v4M10 15h.01"/></svg>'),
  ].join('');

  const SEV_COLORS = { Critical: '#f87171', High: '#fb923c', Medium: '#fbbf24', Low: '#60a5fa', Unknown: '#6b7280' };
  const CHART_FONT = { family: 'Inter, sans-serif', size: 12 };
  const GRID_COLOR = 'rgba(255,255,255,0.06)';
  const TICK_COLOR = 'rgba(255,255,255,0.45)';

  const sevCtx = document.getElementById('dash-severity-chart')?.getContext('2d');
  if (sevCtx) {
    if (_dashSeverityChart) _dashSeverityChart.destroy();
    const labels = data.cves_by_severity.map(s => s.severity);
    const counts = data.cves_by_severity.map(s => s.count);
    const colors = labels.map(l => SEV_COLORS[l] || '#6b7280');
    _dashSeverityChart = new Chart(sevCtx, {
      type: 'doughnut',
      data: { labels, datasets: [{ data: counts, backgroundColor: colors, borderColor: 'rgba(15,18,30,0.8)', borderWidth: 3, hoverOffset: 6 }] },
      options: {
        responsive: true, cutout: '68%',
        animation: { animateScale: true, duration: 600, easing: 'easeOutQuart' },
        plugins: {
          legend: { position: 'right', labels: { color: TICK_COLOR, font: CHART_FONT, padding: 14, boxWidth: 12, borderRadius: 4 } },
          tooltip: { backgroundColor: 'rgba(15,18,30,0.92)', titleColor: '#e2e8f0', bodyColor: '#94a3b8', borderColor: 'rgba(129,140,248,0.3)', borderWidth: 1, cornerRadius: 8 },
        },
      },
    });
  }

  const topCtx = document.getElementById('dash-top-assets-chart')?.getContext('2d');
  if (topCtx) {
    if (_dashTopAssetsChart) _dashTopAssetsChart.destroy();
    const topLabels = data.top_vulnerable_assets.map(a => a.name || a.ip || a.asset_id.slice(0, 8));
    const topCounts = data.top_vulnerable_assets.map(a => a.cve_count);
    const topCritical = data.top_vulnerable_assets.map(a => a.critical_count);
    _dashTopAssetsChart = new Chart(topCtx, {
      type: 'bar',
      data: {
        labels: topLabels,
        datasets: [
          { label: 'CVEs totaux', data: topCounts, backgroundColor: 'rgba(99,102,241,0.75)', borderColor: 'rgba(129,140,248,0.9)', borderWidth: 1, borderRadius: 5 },
          { label: 'Critical', data: topCritical, backgroundColor: 'rgba(248,113,113,0.75)', borderColor: 'rgba(248,113,113,0.9)', borderWidth: 1, borderRadius: 5 },
        ],
      },
      options: {
        indexAxis: 'y', responsive: true,
        animation: { duration: 500, easing: 'easeOutQuart' },
        plugins: {
          legend: { labels: { color: TICK_COLOR, font: CHART_FONT, boxWidth: 12, borderRadius: 4 } },
          tooltip: { backgroundColor: 'rgba(15,18,30,0.92)', titleColor: '#e2e8f0', bodyColor: '#94a3b8', borderColor: 'rgba(129,140,248,0.3)', borderWidth: 1, cornerRadius: 8 },
        },
        scales: {
          x: { ticks: { color: TICK_COLOR, font: CHART_FONT }, grid: { color: GRID_COLOR }, border: { color: 'transparent' } },
          y: { ticks: { color: TICK_COLOR, font: CHART_FONT }, grid: { color: 'transparent' }, border: { color: 'transparent' } },
        },
      },
    });
  }

  _renderActionRequired(data);
  _loadDashboardTrends();
  _loadDashboardSlaBreaches();
  _loadDashboardTopRisk();
}

// ── _initAppData — final override with all new feature wiring ─────────────────

async function _initAppData() {
  initNav();
  initSubTabs();
  _initModalTabs();

  try {
    _globalSettings = await api('/admin/zap-settings');
  } catch (_) {}

  await loadModuleCheckboxes();
  await loadVocabulary();
  await refreshStats();
  await loadAssets();
  await loadScans();
  await loadScheduledScans();
  await loadModules();

  document.getElementById('open-scan-modal-btn').addEventListener('click', openScanModal);
  document.getElementById('scan-btn').addEventListener('click', triggerScan);

  document.getElementById('refresh-assets').addEventListener('click', loadAssets);
  document.getElementById('asset-search').addEventListener('input', loadAssets);
  document.getElementById('active-only').addEventListener('change', loadAssets);
  document.getElementById('asset-filter-severity')?.addEventListener('change', loadAssets);

  document.getElementById('exp-search')?.addEventListener('input', loadExpositions);
  document.getElementById('exp-severity')?.addEventListener('change', loadExpositions);
  document.getElementById('exp-source')?.addEventListener('change', loadExpositions);
  document.getElementById('exp-ack')?.addEventListener('change', loadExpositions);

  document.getElementById('refresh-scans').addEventListener('click', loadScans);

  document.getElementById('refresh-cves').addEventListener('click', () => loadCves(true));
  document.getElementById('cve-search').addEventListener('input', () => loadCves(true));
  document.getElementById('cve-severity-filter').addEventListener('change', () => loadCves(true));
  document.getElementById('cve-epss-filter')?.addEventListener('change', () => loadCves(true));
  document.getElementById('cve-enrich-btn').addEventListener('click', triggerCveEnrichment);
  document.getElementById('cve-epss-enrich-btn')?.addEventListener('click', triggerEpssEnrichment);

  _initContextMenu();
  _initCommandPalette();
  _loadSavedFiltersSelect();

  setInterval(() => { refreshStats(); loadScans(); }, 30_000);
}

document.addEventListener('DOMContentLoaded', () => {
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeSidePanel();
  });
});

// ── v2.1 — Topology canvas (no D3 dependency) + Reports fixes ────────────────

// Rewrite loadTopology to use Canvas API instead of D3
async function loadTopology() {
  const container = document.getElementById('topology-container');
  if (!container) return;
  container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-muted);font-size:13px">Chargement des assets…</div>';

  let assets = [];
  try {
    const resp = await api('/assets?limit=500');
    assets = (resp && resp.items) ? resp.items : [];
    _topoAssets = assets;
  } catch (e) {
    container.innerHTML = `<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--danger);font-size:13px">Erreur : ${escape(String(e.message))}</div>`;
    return;
  }

  if (!assets.length) {
    container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-muted);font-size:13px">Aucun asset à afficher.</div>';
    return;
  }

  // Build canvas-based topology (no external dependency)
  container.innerHTML = '';
  const W = container.clientWidth || container.offsetWidth || 800;
  const H = 540;

  const canvas = document.createElement('canvas');
  canvas.width = W;
  canvas.height = H;
  canvas.style.cssText = 'width:100%;height:100%;display:block;cursor:pointer;';
  container.appendChild(canvas);

  const ctx2d = canvas.getContext('2d');

  // Group by /24 subnet
  const subnets = {};
  assets.forEach(a => {
    const sub = (a.ip || '0.0.0.0').split('.').slice(0, 3).join('.') + '.x';
    if (!subnets[sub]) subnets[sub] = [];
    subnets[sub].push(a);
  });

  const subnetKeys = Object.keys(subnets).sort();
  const cols = Math.min(subnetKeys.length, 4);
  const colW = W / (cols + 1);

  // Assign positions
  const nodePositions = new Map();
  subnetKeys.forEach((sub, si) => {
    const cx = colW * ((si % cols) + 1);
    const cy = 60 + Math.floor(si / cols) * 180;
    nodePositions.set('sub_' + sub, { x: cx, y: cy, label: sub, type: 'subnet' });
    subnets[sub].forEach((a, ai) => {
      const angle = (2 * Math.PI * ai) / Math.max(subnets[sub].length, 1);
      const r = Math.min(70, 20 + subnets[sub].length * 8);
      nodePositions.set(a.id, {
        x: cx + r * Math.cos(angle),
        y: cy + r * Math.sin(angle) + 40,
        label: a.name || a.ip || '?',
        asset: a,
        type: 'asset',
      });
    });
  });

  const nodeColor = (a) => {
    const crit = (a.criticality || '').toLowerCase();
    if (crit === 'critical') return '#f87171';
    if (crit === 'high') return '#fb923c';
    const cves = a.cves || [];
    if (cves.some(c => (c.severity || '').toLowerCase() === 'critical')) return '#f87171';
    if (cves.some(c => (c.severity || '').toLowerCase() === 'high')) return '#fb923c';
    if (cves.some(c => (c.severity || '').toLowerCase() === 'medium')) return '#fbbf24';
    return '#34d399';
  };

  const draw = () => {
    ctx2d.clearRect(0, 0, W, H);
    ctx2d.fillStyle = 'var(--surface)' in document.documentElement.style ? '#0c1120' : '#0c1120';
    ctx2d.fillRect(0, 0, W, H);

    // Draw edges
    ctx2d.strokeStyle = 'rgba(129,140,248,0.2)';
    ctx2d.lineWidth = 1;
    assets.forEach(a => {
      const sub = (a.ip || '0.0.0.0').split('.').slice(0, 3).join('.') + '.x';
      const sPos = nodePositions.get('sub_' + sub);
      const aPos = nodePositions.get(a.id);
      if (sPos && aPos) {
        ctx2d.beginPath();
        ctx2d.moveTo(sPos.x, sPos.y);
        ctx2d.lineTo(aPos.x, aPos.y);
        ctx2d.stroke();
      }
    });

    // Draw subnet nodes
    subnetKeys.forEach(sub => {
      const pos = nodePositions.get('sub_' + sub);
      if (!pos) return;
      ctx2d.fillStyle = 'rgba(30,41,59,0.9)';
      ctx2d.strokeStyle = 'rgba(129,140,248,0.5)';
      ctx2d.lineWidth = 1.5;
      const tw = ctx2d.measureText(sub).width + 16;
      const rr = 6;
      const bx = pos.x - tw / 2, by = pos.y - 11;
      ctx2d.beginPath();
      ctx2d.moveTo(bx + rr, by);
      ctx2d.lineTo(bx + tw - rr, by);
      ctx2d.arcTo(bx + tw, by, bx + tw, by + 22, rr);
      ctx2d.lineTo(bx + tw, by + 22 - rr);
      ctx2d.arcTo(bx + tw, by + 22, bx + tw - rr, by + 22, rr);
      ctx2d.lineTo(bx + rr, by + 22);
      ctx2d.arcTo(bx, by + 22, bx, by + 22 - rr, rr);
      ctx2d.lineTo(bx, by + rr);
      ctx2d.arcTo(bx, by, bx + rr, by, rr);
      ctx2d.closePath();
      ctx2d.fill();
      ctx2d.stroke();
      ctx2d.fillStyle = 'rgba(148,163,184,0.9)';
      ctx2d.font = '10px monospace';
      ctx2d.textAlign = 'center';
      ctx2d.fillText(sub, pos.x, pos.y + 4);
    });

    // Draw asset nodes
    assets.forEach(a => {
      const pos = nodePositions.get(a.id);
      if (!pos) return;
      const r = a.risk_score != null ? Math.max(7, Math.min(16, 6 + a.risk_score / 8)) : 8;
      ctx2d.beginPath();
      ctx2d.arc(pos.x, pos.y, r, 0, 2 * Math.PI);
      ctx2d.fillStyle = nodeColor(a);
      ctx2d.globalAlpha = 0.85;
      ctx2d.fill();
      ctx2d.globalAlpha = 1;
      ctx2d.strokeStyle = '#0c1120';
      ctx2d.lineWidth = 1.5;
      ctx2d.stroke();
      ctx2d.fillStyle = 'rgba(148,163,184,0.8)';
      ctx2d.font = '9px Inter, sans-serif';
      ctx2d.textAlign = 'center';
      const lbl = (pos.label || '').slice(0, 14);
      ctx2d.fillText(lbl, pos.x, pos.y + r + 11);
    });
  };

  draw();

  // Tooltip on hover
  const tip = document.createElement('div');
  tip.style.cssText = 'position:fixed;background:rgba(12,17,32,.95);border:1px solid rgba(129,140,248,.3);border-radius:6px;padding:10px 14px;font-size:12px;pointer-events:none;z-index:9999;display:none;color:#e2e8f0;max-width:240px;line-height:1.6;box-shadow:0 4px 16px rgba(0,0,0,.4)';
  document.body.appendChild(tip);

  canvas.addEventListener('mousemove', ev => {
    const rect = canvas.getBoundingClientRect();
    const mx = (ev.clientX - rect.left) * (W / rect.width);
    const my = (ev.clientY - rect.top) * (H / rect.height);
    let found = null;
    assets.forEach(a => {
      const pos = nodePositions.get(a.id);
      if (!pos) return;
      const r = 16;
      if ((mx - pos.x) ** 2 + (my - pos.y) ** 2 < r * r) found = a;
    });
    if (found) {
      const cveCount = (found.cves || []).filter(c => c.ack_status === 'none').length;
      tip.style.display = 'block';
      tip.style.left = (ev.clientX + 14) + 'px';
      tip.style.top = (ev.clientY - 10) + 'px';
      tip.innerHTML = `<strong style="color:var(--accent,#818cf8)">${escape(found.name || found.ip || '?')}</strong>
        IP: ${escape(found.ip || '—')}<br>Hostname: ${escape(found.hostname || '—')}<br>
        CVEs actives: ${cveCount}<br>Risk score: ${found.risk_score != null ? Math.round(found.risk_score) : '—'}<br>
        Criticité: ${found.criticality || 'medium'}`;
      canvas.style.cursor = 'pointer';
    } else {
      tip.style.display = 'none';
      canvas.style.cursor = 'default';
    }
  });
  canvas.addEventListener('mouseleave', () => { tip.style.display = 'none'; });
  canvas.addEventListener('click', ev => {
    const rect = canvas.getBoundingClientRect();
    const mx = (ev.clientX - rect.left) * (W / rect.width);
    const my = (ev.clientY - rect.top) * (H / rect.height);
    assets.forEach(a => {
      const pos = nodePositions.get(a.id);
      if (!pos) return;
      if ((mx - pos.x) ** 2 + (my - pos.y) ** 2 < 16 * 16) openAssetModal(a.id);
    });
  });

  // Cleanup tip when leaving panel
  const cleanupTip = () => { if (tip.parentNode) tip.remove(); };
  document.querySelectorAll('.nav-item').forEach(b => b.addEventListener('click', cleanupTip, { once: false }));
}

// Rewrite loadReportsPanel to be simpler and more robust
async function loadReportsPanel() {
  const statsEl = document.getElementById('reports-stats');
  const slaEl = document.getElementById('reports-sla-list');
  const riskEl = document.getElementById('reports-top-risk-list');

  if (statsEl) statsEl.innerHTML = '<span style="color:var(--text-muted);font-size:13px">Chargement…</span>';
  if (slaEl) slaEl.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Chargement…</p>';
  if (riskEl) riskEl.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Chargement…</p>';

  try {
    const data = await api('/reports/executive/data');
    if (!data) { throw new Error('Réponse vide'); }

    // Stats cards
    if (statsEl) {
      const by_crit = data.assets?.by_criticality || {};
      const critAssets = (by_crit.critical || 0) + (by_crit.high || 0);
      const critCves = data.cves?.critical_count || 0;
      const slaBr = data.sla?.breaches || 0;

      const card = (label, value, color) =>
        `<div class="dash-stat-card" style="--card-accent:${color}">
           <div class="dash-stat-value" style="color:${color}">${value}</div>
           <div class="dash-stat-label">${label}</div>
         </div>`;

      statsEl.innerHTML =
        card('Total assets', data.assets?.total ?? '—', 'var(--accent)') +
        card('Assets critiques/élevés', critAssets, critAssets > 0 ? 'var(--danger)' : 'var(--success)') +
        card('CVEs critiques', critCves, critCves > 0 ? 'var(--danger)' : 'var(--success)') +
        card('SLA Breaches', slaBr, slaBr > 0 ? 'var(--warning)' : 'var(--success)');
    }

    // SLA breaches — API only gives count for now
    if (slaEl) {
      const n = data.sla?.breaches || 0;
      slaEl.innerHTML = n === 0
        ? '<p style="color:var(--success);font-size:13px">✓ Aucune SLA en retard.</p>'
        : `<p style="color:var(--warning);font-size:13px">⚠ ${n} CVE(s) en breach SLA. Consultez le panel Admin → SLA pour le détail.</p>`;
    }

    // Top risky assets
    if (riskEl) {
      const topAssets = data.top_risky_assets || [];
      if (!topAssets.length) {
        riskEl.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Aucun score de risque calculé. Lancez Admin → EPSS → Enrichir pour calculer les scores.</p>';
      } else {
        riskEl.innerHTML = topAssets.slice(0, 5).map(a => {
          const s = a.risk_score || 0;
          const color = s >= 75 ? '#f87171' : s >= 50 ? '#fb923c' : s >= 25 ? '#fbbf24' : '#34d399';
          return `<div class="top-risk-item" onclick="switchToView('assets');openAssetModal('${a.id || a.asset_id}')">
            <div class="top-risk-score" style="color:${color}">${Math.round(s)}</div>
            <div class="top-risk-info">
              <div class="top-risk-name">${escape(a.name || a.hostname || a.ip || '—')}</div>
              <div class="top-risk-ip">${escape(a.ip || '')}</div>
            </div>
          </div>`;
        }).join('');
      }
    }

    // Trend chart via dashboard/trends
    try {
      const trend = await api('/dashboard/trends');
      if (trend && trend.points) _renderReportsTrend(trend);
    } catch (_) { /* trend skipped */ }

  } catch (e) {
    const msg = `<span style="color:var(--danger);font-size:13px">Erreur : ${escape(String(e.message))}</span>`;
    if (statsEl) statsEl.innerHTML = msg;
    if (slaEl) slaEl.innerHTML = '';
    if (riskEl) riskEl.innerHTML = '';
  }
}

// ═══════════════════════════════════════════════════════════════════
// THREAT INTEL — KEV + ExploitDB + PoC badges & sync  (v2.2)
// ═══════════════════════════════════════════════════════════════════

// ── Maturity badge ────────────────────────────────────────────────
function maturityBadge(maturity, kevRansomware) {
  if (!maturity || maturity === 'none') return '<span style="color:var(--text-muted);font-size:11px">—</span>';
  if (maturity === 'weaponized') {
    const extra = kevRansomware ? ' 🎰' : '';
    return `<span class="maturity-badge weaponized" title="Dans CISA KEV — exploité activement${kevRansomware ? ' + ransomware' : ''}">KEV${extra}</span>`;
  }
  if (maturity === 'exploit') {
    return `<span class="maturity-badge exploit" title="Exploit disponible sur ExploitDB">EDB</span>`;
  }
  if (maturity === 'poc') {
    return `<span class="maturity-badge poc" title="PoC public disponible sur GitHub">PoC</span>`;
  }
  return '—';
}

// ── KEV sync ──────────────────────────────────────────────────────
async function triggerKevSync() {
  const btn = document.getElementById('cve-kev-sync-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'KEV…'; }
  const statusEl = document.getElementById('cve-enrich-status');
  if (statusEl) { statusEl.textContent = 'Synchronisation CISA KEV…'; statusEl.classList.remove('hidden'); }
  try {
    const r = await api('/admin/kev/sync', { method: 'POST' });
    if (statusEl) statusEl.textContent = `KEV sync : ${r.matched} CVEs weaponized (catalogue CISA : ${r.kev_total})`;
    loadCves(true);
  } catch (e) {
    if (statusEl) statusEl.textContent = `Erreur KEV : ${String(e.message)}`;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'KEV'; }
    setTimeout(() => statusEl?.classList.add('hidden'), 8000);
  }
}

// ── Exploit sync ──────────────────────────────────────────────────
async function triggerExploitSync() {
  const btn = document.getElementById('cve-exploit-sync-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Exploits…'; }
  const statusEl = document.getElementById('cve-enrich-status');
  if (statusEl) { statusEl.textContent = 'Sync ExploitDB + PoC GitHub (peut prendre ~30s)…'; statusEl.classList.remove('hidden'); }
  try {
    const r = await api('/admin/exploits/sync', { method: 'POST' });
    if (statusEl) statusEl.textContent = `Exploits sync : EDB=${r.edb_matched} | PoC=${r.poc_matched} | ${r.total_updated} CVEs mis à jour`;
    loadCves(true);
  } catch (e) {
    if (statusEl) statusEl.textContent = `Erreur exploits : ${String(e.message)}`;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Exploits'; }
    setTimeout(() => statusEl?.classList.add('hidden'), 8000);
  }
}

// ── loadCves override with threat-intel filters ───────────────────
async function loadCves(reset = false) {
  if (reset) _cveOffset = 0;

  const search    = (document.getElementById('cve-search')?.value || '').trim();
  const severity  = document.getElementById('cve-severity-filter')?.value || '';
  const epssMin   = document.getElementById('cve-epss-filter')?.value || '';
  const maturity  = document.getElementById('cve-maturity-filter')?.value || '';
  const kevOnly   = document.getElementById('cve-kev-filter')?.checked || false;

  const params = new URLSearchParams({ skip: _cveOffset, limit: _CVE_LIMIT });
  if (search)   params.set('search', search);
  if (severity) params.set('severity', severity);
  if (epssMin)  params.set('epss_min', Number(epssMin) / 100);
  if (maturity) params.set('maturity', maturity);
  if (kevOnly)  params.set('kev_only', 'true');

  const tbody = document.getElementById('cve-global-tbody');
  tbody.innerHTML = '<tr><td colspan="9" style="color:var(--text-muted);text-align:center;padding:24px">Chargement…</td></tr>';

  let data;
  try {
    data = await api(`/cves?${params}`);
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="9" style="color:var(--danger);text-align:center;padding:24px">Erreur : ${escape(String(e))}</td></tr>`;
    return;
  }

  const countEl = document.getElementById('nav-cve-count');
  if (countEl) countEl.textContent = data.total > 0 ? data.total : '';

  if (!data.items.length) {
    tbody.innerHTML = '<tr><td colspan="9" style="color:var(--text-muted);text-align:center;padding:24px">Aucun CVE trouvé.</td></tr>';
    _renderCvePagination(data.total);
    return;
  }

  const isAdmin = _me && _me.role === 'admin';
  tbody.innerHTML = data.items.map(c => {
    const sev = (c.severity || '').toLowerCase();
    const sevType = sev === 'critical' || sev === 'high' ? 'error'
      : sev === 'medium' ? 'warning' : sev === 'low' ? 'info' : 'muted';
    const desc = c.description
      ? escape(c.description.length > 100 ? c.description.slice(0, 100) + '…' : c.description)
      : '—';
    const pub = c.published_at ? new Date(c.published_at).toLocaleDateString('fr-FR') : '—';
    const planCell = c.remediation
      ? `<span class="plan-snippet clickable" title="${escape(c.remediation)}"
             onclick="openCveRemediationModal('${escape(c.cve_id)}','${escape(c.remediation || '')}')"
             >${escape(c.remediation.length > 50 ? c.remediation.slice(0, 50) + '…' : c.remediation)}</span>`
      : (isAdmin
          ? `<button class="btn btn-sm" onclick="openCveRemediationModal('${escape(c.cve_id)}','')">+ Plan</button>`
          : '<span style="color:var(--text-muted);font-size:11px">—</span>');
    const affectedCell = c.asset_count > 0
      ? `<span class="clickable" style="font-weight:600;color:var(--danger);cursor:pointer"
             onclick="showCveAffectedAssets('${escape(c.cve_id)}',${c.asset_count})">${c.asset_count}</span>`
      : '0';

    // Threat intel cell: maturity badge + optional EDB link
    let threatCell = maturityBadge(c.exploit_maturity, c.kev_ransomware_use);
    if (c.exploit_db_id) {
      threatCell += ` <a href="https://www.exploit-db.com/exploits/${c.exploit_db_id}" target="_blank" rel="noopener"
        style="font-size:10px;color:var(--text-muted)" title="Voir exploit EDB #${c.exploit_db_id}">#${c.exploit_db_id}</a>`;
    }
    if (c.poc_count > 0) {
      threatCell += ` <a href="https://github.com/nomi-sec/PoC-in-GitHub/tree/master/${(c.cve_id.match(/CVE-(\d{4})/)||['',''])[1]}/${c.cve_id}"
        target="_blank" rel="noopener" style="font-size:10px;color:var(--text-muted)" title="${c.poc_count} PoC(s) public(s)">${c.poc_count}×PoC</a>`;
    }

    return `
      <tr${c.exploit_maturity === 'weaponized' ? ' style="background:rgba(239,68,68,0.06)"' : c.exploit_maturity === 'exploit' ? ' style="background:rgba(251,146,60,0.06)"' : ''}>
        <td><a class="cve-link" href="${cveUrl(c.cve_id)}" target="_blank" rel="noopener"
             title="${escape(c.description || '')}">${escape(c.cve_id)}</a></td>
        <td>${c.severity ? badge(c.severity, sevType) : '—'}</td>
        <td>${c.cvss_score != null ? c.cvss_score.toFixed(1) : '—'}</td>
        <td>${epssBadge(c.epss_score)}</td>
        <td style="white-space:nowrap">${threatCell}</td>
        <td style="text-align:center">${affectedCell}</td>
        <td style="font-size:12px;color:var(--text-muted);max-width:240px" title="${escape(c.description || '')}">${desc}</td>
        <td style="max-width:180px;font-size:12px">${planCell}</td>
        <td style="font-size:12px">${pub}</td>
      </tr>`;
  }).join('');

  _renderCvePagination(data.total);
}

// ── Full Audit ────────────────────────────────────────────────────────────────

const _FULL_AUDIT_STEPS = [
  { key: 'port_scan',         label: 'Port scan' },
  { key: 'testssl',           label: 'testssl.sh' },
  { key: 'ssh_audit',         label: 'ssh-audit' },
  { key: 'default_creds',     label: 'Default creds' },
  { key: 'ssh_scan',          label: 'SSH CVE scan' },
  { key: 'nuclei',            label: 'Nuclei' },
  { key: 'exploit_validation',label: 'Exploit validation' },
  { key: 'risk_score',        label: 'Risk score' },
];

async function loadFullAuditJobs(assetId) {
  try {
    const jobs = await api(`/assets/${assetId}/full-audit`).catch(() => []);
    _renderFullAuditJobs(jobs || []);
  } catch (_) {
    _renderFullAuditJobs([]);
  }
}

async function runFullAudit() {
  if (!_modalAssetId) return;
  const assetId = _modalAssetId;
  const btn = document.getElementById('fullaudit-run-btn');
  const statusEl = document.getElementById('fullaudit-status');
  if (btn) btn.disabled = true;
  if (statusEl) statusEl.textContent = 'Démarrage…';

  try {
    const job = await api(`/assets/${assetId}/full-audit`, { method: 'POST' });
    if (!job) throw new Error('Pas de réponse');
    showToast('Full audit démarré', 'success');
    if (statusEl) statusEl.textContent = 'En cours…';
    _renderFullAuditJobs([job]);
    _pollFullAuditJob(assetId, job.id);
  } catch (e) {
    if (statusEl) statusEl.textContent = `Erreur : ${e.message}`;
    showToast(`Full audit : ${e.message}`, 'error');
    if (btn) btn.disabled = false;
  }
}

async function _pollFullAuditJob(assetId, jobId) {
  const btn = document.getElementById('fullaudit-run-btn');
  const statusEl = document.getElementById('fullaudit-status');
  let attempts = 0;
  let errors = 0;
  const maxAttempts = 144; // 12 min max (poll every 5s)

  try {
    while (_modalAssetId === assetId && attempts < maxAttempts) {
      await new Promise(r => setTimeout(r, 5000));
      attempts++;
      if (_modalAssetId !== assetId) break;

      try {
        const job = await api(`/assets/${assetId}/full-audit/${jobId}`);
        errors = 0;
        _renderFullAuditJobs([job]);

        const completedSteps = Object.values(job.steps || {}).filter(s => s.status === 'completed').length;
        if (statusEl) statusEl.textContent = `${job.status} — ${completedSteps}/${_FULL_AUDIT_STEPS.length} étapes`;

        if (job.status === 'completed' || job.status === 'failed') {
          const msg = job.status === 'completed' ? 'Full audit terminé ✓' : `Full audit échoué : ${job.error_msg || ''}`;
          if (statusEl) statusEl.textContent = msg;
          showToast(msg, job.status === 'completed' ? 'success' : 'error');
          break;
        }
      } catch (_) {
        if (++errors >= 5) break; // Stop after 5 consecutive API errors
      }
    }

    if (attempts >= maxAttempts && statusEl) statusEl.textContent = 'Timeout — vérifier manuellement';
  } finally {
    if (btn) btn.disabled = false;
  }
}

function _fullAuditStepBadge(step) {
  const s = step?.status;
  if (!s || s === 'pending') return '<span style="color:var(--text-muted);font-size:11px">—</span>';
  if (s === 'running')   return '<span style="color:var(--accent);font-size:11px;font-weight:600">↻ en cours</span>';
  if (s === 'completed') return '<span style="color:#27ae60;font-size:11px;font-weight:600">✓</span>';
  if (s === 'skipped')   return '<span style="color:var(--text-muted);font-size:11px">⊘ ignoré</span>';
  if (s === 'failed')    return '<span style="color:var(--danger);font-size:11px;font-weight:600">✗ échec</span>';
  return `<span style="font-size:11px">${escape(s)}</span>`;
}

function _renderFullAuditJobs(jobs) {
  const container = document.getElementById('fullaudit-jobs-body');
  const badge = document.getElementById('fullaudit-badge');
  if (!container) return;

  if (!Array.isArray(jobs) || !jobs.length) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Aucun audit lancé.</p>';
    if (badge) badge.style.display = 'none';
    return;
  }

  const running = jobs.filter(j => j.status === 'running' || j.status === 'pending').length;
  if (badge) {
    if (running > 0) {
      badge.style.display = '';
      badge.textContent = '↻';
    } else {
      badge.style.display = 'none';
    }
  }

  container.innerHTML = jobs.map((job, idx) => {
    const statusColor = {
      pending: 'var(--text-muted)', running: 'var(--accent)',
      completed: '#27ae60', failed: 'var(--danger)',
    }[job.status] || '#333';

    const stepsHtml = _FULL_AUDIT_STEPS.map(s => {
      const step = (job.steps || {})[s.key];
      const detail = step?.detail ? ` — <span style="font-size:10px;color:#888">${escape(String(step.detail).slice(0,80))}</span>` : '';
      return `<div style="display:flex;align-items:center;gap:8px;padding:3px 0;border-bottom:1px solid #f5f5f5">
        <span style="width:140px;font-size:12px;color:#555">${s.label}</span>
        ${_fullAuditStepBadge(step)}${detail}
      </div>`;
    }).join('');

    const duration = (job.started_at && job.finished_at)
      ? ` — ${Math.round((new Date(job.finished_at) - new Date(job.started_at)) / 1000)}s`
      : '';

    const detailId = `fa-detail-${idx}`;
    return `<div style="border:1px solid #eee;border-radius:6px;margin-bottom:10px;overflow:hidden">
      <div style="display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer;background:#fafafa"
           onclick="document.getElementById('${detailId}').style.display=document.getElementById('${detailId}').style.display==='none'?'':'none'">
        <span style="font-size:12px;color:var(--text-muted)">${fmtDate(job.created_at)}</span>
        <span style="font-weight:600;font-size:13px;color:${statusColor}">${job.status}${duration}</span>
        ${job.error_msg ? `<span style="font-size:11px;color:var(--danger)">${escape(job.error_msg.slice(0,80))}</span>` : ''}
        <span style="margin-left:auto;font-size:11px;color:var(--text-muted)">▼</span>
      </div>
      <div id="${detailId}" style="display:${idx === 0 ? '' : 'none'};padding:10px 14px;background:#fff">
        ${stepsHtml}
      </div>
    </div>`;
  }).join('');
}

function openAssetReport() {
  if (!_modalAssetId) return;
  window.open(`/api/v1/reports/assets/${_modalAssetId}`, '_blank');
}

// ── Wire new buttons ──────────────────────────────────────────────
(function _wireThreatIntelButtons() {
  document.getElementById('cve-kev-sync-btn')?.addEventListener('click', triggerKevSync);
  document.getElementById('cve-exploit-sync-btn')?.addEventListener('click', triggerExploitSync);
  document.getElementById('cve-maturity-filter')?.addEventListener('change', () => loadCves(true));
  document.getElementById('cve-kev-filter')?.addEventListener('change', () => loadCves(true));
})();

// ── Remediation plan ──────────────────────────────────────────────────────────

const _SEV_COLOR = { Critical: '#f87171', High: '#fb923c', Medium: '#fbbf24', Low: '#34d399', Unknown: '#94a3b8' };
const _CRIT_LABEL = { critical: '🔴 Critique', high: '🟠 Élevé', medium: '🟡 Moyen', low: '🟢 Faible', Unknown: '⚪ Inconnu' };

function _remScoreColor(s) {
  if (s >= 75) return '#f87171';
  if (s >= 50) return '#fb923c';
  if (s >= 25) return '#fbbf24';
  return '#34d399';
}

function _remSevBreakdown(breakdown) {
  return Object.entries(breakdown)
    .sort(([a], [b]) => {
      const ord = { Critical: 4, High: 3, Medium: 2, Low: 1 };
      return (ord[b] || 0) - (ord[a] || 0);
    })
    .map(([sev, cnt]) => `<span style="display:inline-flex;align-items:center;gap:3px;margin-right:6px;font-size:12px">
      <span style="width:8px;height:8px;border-radius:50%;background:${_SEV_COLOR[sev] || '#94a3b8'};display:inline-block"></span>
      ${cnt} ${sev}
    </span>`)
    .join('');
}

async function loadRemediation() {
  const summaryEl = document.getElementById('remediation-summary');
  const listEl    = document.getElementById('remediation-list');
  if (!listEl) return;

  listEl.innerHTML = '<p style="color:var(--text-muted);font-size:13px;padding:16px">Chargement…</p>';
  if (summaryEl) summaryEl.innerHTML = '';

  const source    = document.getElementById('remediation-source-filter')?.value || '';
  const onlyKev   = document.getElementById('remediation-kev-only')?.checked ? 'true' : 'false';
  const onlySla   = document.getElementById('remediation-sla-only')?.checked ? 'true' : 'false';

  const params = new URLSearchParams({ limit: '100', only_kev: onlyKev, only_sla_breached: onlySla });
  if (source) params.set('source', source);

  try {
    const data = await api(`/remediation-plan?${params}`);
    if (!data) throw new Error('Réponse vide');

    const groups = data.groups || [];
    const kevCount = groups.filter(g => g.in_kev).length;
    const slaCount = groups.reduce((s, g) => s + g.sla_breached_count, 0);
    const verCount = groups.filter(g => g.exploit_verified).length;

    if (summaryEl) {
      const card = (label, value, color) =>
        `<div class="dash-stat-card" style="--card-accent:${color}">
           <div class="dash-stat-value" style="color:${color}">${value}</div>
           <div class="dash-stat-label">${label}</div>
         </div>`;
      summaryEl.innerHTML =
        card('Groupes', data.total_groups, 'var(--accent)') +
        card('Dans KEV', kevCount, kevCount > 0 ? 'var(--danger)' : 'var(--success)') +
        card('SLA dépassé', slaCount, slaCount > 0 ? 'var(--warning)' : 'var(--success)') +
        card('Exploits vérifiés', verCount, verCount > 0 ? '#f97316' : 'var(--success)');
    }

    if (!groups.length) {
      listEl.innerHTML = '<p style="color:var(--success);font-size:14px;padding:16px">✓ Aucune action requise avec les filtres actuels.</p>';
      return;
    }

    listEl.innerHTML = groups.map((g, idx) => {
      const scoreColor = _remScoreColor(g.risk_score);
      const kevBadge   = g.in_kev ? '<span class="badge" style="background:#dc2626;color:#fff;font-size:10px;padding:1px 5px;border-radius:3px;margin-left:4px">KEV</span>' : '';
      const expBadge   = g.exploit_verified ? '<span class="badge" style="background:#7c3aed;color:#fff;font-size:10px;padding:1px 5px;border-radius:3px;margin-left:4px">PoC vérifié</span>' : '';
      const slaBadge   = g.sla_breached_count > 0 ? `<span class="badge" style="background:#d97706;color:#fff;font-size:10px;padding:1px 5px;border-radius:3px;margin-left:4px">${g.sla_breached_count} SLA !</span>` : '';

      const cveLinks = g.cve_ids.slice(0, 5).map(id =>
        `<span style="font-family:monospace;font-size:11px;background:var(--bg);padding:1px 5px;border-radius:3px;margin-right:3px">${escape(id)}</span>`
      ).join('') + (g.cve_ids.length > 5 ? `<span style="font-size:11px;color:var(--text-muted)">+${g.cve_ids.length - 5}</span>` : '');

      const detailId = `rem-detail-${idx}`;
      const sources  = g.sources.length ? g.sources.join(', ') : '—';
      const critLabel = _CRIT_LABEL[g.criticality_max?.toLowerCase()] || g.criticality_max;
      const epssLabel = g.epss_max > 0 ? `${(g.epss_max * 100).toFixed(1)}%` : '—';

      return `<div class="settings-card" style="margin-bottom:10px;border-left:4px solid ${scoreColor}">
        <div style="display:flex;align-items:center;gap:12px;cursor:pointer" onclick="document.getElementById('${detailId}').style.display=document.getElementById('${detailId}').style.display==='none'?'':'none'">
          <div style="min-width:48px;text-align:center">
            <div style="font-size:22px;font-weight:700;color:${scoreColor};line-height:1">${g.risk_score}</div>
            <div style="font-size:10px;color:var(--text-muted)">#${g.rank}</div>
          </div>
          <div style="flex:1;min-width:0">
            <div style="font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
              ${escape(g.action)}${kevBadge}${expBadge}${slaBadge}
            </div>
            <div style="margin-top:4px">${_remSevBreakdown(g.severity_breakdown)}</div>
          </div>
          <div style="text-align:right;min-width:80px;font-size:12px;color:var(--text-muted)">
            ${g.affected_assets} asset${g.affected_assets > 1 ? 's' : ''}
          </div>
        </div>
        <div id="${detailId}" style="display:none;margin-top:10px;padding-top:10px;border-top:1px solid var(--border);font-size:12px">
          <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:8px">
            <div><span style="color:var(--text-muted)">Criticité max</span><br><strong>${escape(critLabel)}</strong></div>
            <div><span style="color:var(--text-muted)">EPSS max</span><br><strong>${epssLabel}</strong></div>
            <div><span style="color:var(--text-muted)">Sources</span><br><strong>${escape(sources)}</strong></div>
          </div>
          <div style="margin-bottom:6px"><span style="color:var(--text-muted)">CVEs :</span> ${cveLinks}</div>
          ${g.package_name ? `<div><span style="color:var(--text-muted)">Paquet :</span> <code>${escape(g.package_name)}</code>${g.fixed_version ? ` → <code>${escape(g.fixed_version)}</code>` : ''}</div>` : ''}
        </div>
      </div>`;
    }).join('');

  } catch (e) {
    listEl.innerHTML = `<span style="color:var(--danger);font-size:13px">Erreur : ${escape(String(e.message))}</span>`;
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
// ── SSE (Server-Sent Events) — real-time updates ─────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

let _sseSource = null;

function initSSE() {
  const token = sessionStorage.getItem('nlv_token') || localStorage.getItem('nlv_token');
  if (!token || _sseSource) return;
  try {
    _sseSource = new EventSource(`/api/v1/events/stream?token=${encodeURIComponent(token)}`);
    _sseSource.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.event === 'scan_update') {
          // Refresh scans list if visible
          const scanPanel = document.getElementById('panel-scans');
          if (scanPanel && scanPanel.classList.contains('active')) loadScans();
        } else if (data.event === 'notification') {
          const level = data.level === 'critical' ? 'error' : 'info';
          showToast(data.message || 'Nouvelle notification', level, data.level === 'critical' ? 10000 : 4000);
        } else if (data.event === 'new_asset') {
          showToast(data.message || 'Nouvel asset détecté', 'info');
        } else if (data.event === 'cve_alert') {
          showToast(`CVE ${data.cve_id || ''} sur ${data.asset_ip || ''}`, 'error', 8000);
        }
      } catch (_) { /* ignore parse errors */ }
    };
    _sseSource.addEventListener('error', () => {
      // Reconnect after 5s on error
      if (_sseSource) { _sseSource.close(); _sseSource = null; }
      setTimeout(initSSE, 5000);
    });
  } catch (_) { /* EventSource not supported */ }
}

// Init SSE after login
document.addEventListener('DOMContentLoaded', () => { setTimeout(initSSE, 2000); });


// ═══════════════════════════════════════════════════════════════════════════════
// ── Global Search ────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

let _searchTimer = null;

function initGlobalSearch() {
  const input = document.getElementById('global-search-input');
  const dropdown = document.getElementById('global-search-results');
  if (!input || !dropdown) return;

  input.addEventListener('input', () => {
    clearTimeout(_searchTimer);
    const q = input.value.trim();
    if (q.length < 2) { dropdown.classList.add('hidden'); return; }
    _searchTimer = setTimeout(async () => {
      try {
        const resp = await api(`/search?q=${encodeURIComponent(q)}&limit=15`);
        const data = await resp.json();
        if (!data.results || data.results.length === 0) {
          dropdown.innerHTML = '<div style="padding:12px;color:var(--text-muted);font-size:13px">Aucun résultat</div>';
        } else {
          dropdown.innerHTML = data.results.map(r => `
            <div class="search-result-item" onclick="navigateSearchResult('${escape(r.type)}','${escape(r.id)}')" style="padding:8px 12px;cursor:pointer;border-bottom:1px solid var(--border)">
              <span class="badge" style="font-size:10px;margin-right:6px">${escape(r.type)}</span>
              <strong>${escape(r.title)}</strong>
              ${r.subtitle ? `<span style="color:var(--text-muted);font-size:12px;margin-left:6px">${escape(r.subtitle)}</span>` : ''}
              ${r.severity ? `<span class="badge badge-${r.severity.toLowerCase()}" style="margin-left:6px;font-size:10px">${escape(r.severity)}</span>` : ''}
            </div>
          `).join('');
        }
        dropdown.classList.remove('hidden');
      } catch (_) { dropdown.classList.add('hidden'); }
    }, 300);
  });

  input.addEventListener('blur', () => { setTimeout(() => dropdown.classList.add('hidden'), 200); });
  input.addEventListener('focus', () => { if (input.value.trim().length >= 2) input.dispatchEvent(new Event('input')); });

  // Ctrl+K shortcut
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); input.focus(); input.select(); }
  });
}

function navigateSearchResult(type, id) {
  document.getElementById('global-search-results').classList.add('hidden');
  if (type === 'asset') {
    switchToView('assets');
    setTimeout(() => { if (typeof openAssetModal === 'function') openAssetModal(id); }, 300);
  } else if (type === 'cve') {
    switchToView('cves');
  }
}

document.addEventListener('DOMContentLoaded', initGlobalSearch);


// ═══════════════════════════════════════════════════════════════════════════════
// ── Timeline ─────────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

async function loadTimeline() {
  const el = document.getElementById('timeline-list');
  if (!el) return;
  el.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Chargement…</p>';
  try {
    const resp = await api('/timeline?limit=200');
    const events = await resp.json();
    if (!events.length) { el.innerHTML = '<p style="color:var(--text-muted)">Aucun événement</p>'; return; }

    const typeColors = { asset_discovered: '#818cf8', cve_found: '#f87171', port_opened: '#fbbf24', scan_completed: '#34d399' };
    const typeIcons = { asset_discovered: '&#x1f4bb;', cve_found: '&#x26a0;', port_opened: '&#x1f513;', scan_completed: '&#x2705;' };

    el.innerHTML = events.map(ev => {
      const color = typeColors[ev.event_type] || '#94a3b8';
      const icon = typeIcons[ev.event_type] || '&#x2022;';
      const ts = new Date(ev.timestamp).toLocaleString('fr-FR');
      const sevBadge = ev.severity && ev.severity !== 'info'
        ? `<span class="badge badge-${ev.severity.toLowerCase()}" style="font-size:10px;margin-left:6px">${escape(ev.severity)}</span>` : '';
      return `<div class="timeline-event" style="display:flex;gap:12px;padding:10px 0;border-bottom:1px solid var(--border)">
        <div style="min-width:4px;background:${color};border-radius:2px"></div>
        <div style="flex:1">
          <div style="font-size:13px;font-weight:600">${icon} ${escape(ev.detail)}${sevBadge}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:2px">${ts}${ev.asset_ip ? ` — ${escape(ev.asset_ip)}` : ''}</div>
        </div>
      </div>`;
    }).join('');
  } catch (e) {
    el.innerHTML = `<p style="color:var(--danger)">Erreur : ${escape(String(e.message))}</p>`;
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
// ── Compliance ───────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

async function loadCompliance() {
  const fwEl = document.getElementById('compliance-frameworks');
  const listEl = document.getElementById('compliance-reports-list');
  if (!fwEl || !listEl) return;

  try {
    const [fwResp, repResp] = await Promise.all([
      api('/compliance/frameworks'),
      api('/compliance/reports?limit=20'),
    ]);
    const frameworks = await fwResp.json();
    const reports = await repResp.json();

    fwEl.innerHTML = frameworks.map(fw => `
      <div class="settings-card" style="text-align:center">
        <h3 style="font-size:14px;margin-bottom:4px">${escape(fw.name)}</h3>
        <p style="font-size:11px;color:var(--text-muted);margin-bottom:8px">${escape(fw.description).substring(0, 80)}</p>
        <div style="font-size:11px;color:var(--text-muted)">${fw.controls_count} contrôles</div>
        <button class="btn btn-primary btn-sm" style="margin-top:8px" onclick="runComplianceEval('${escape(fw.id)}')">Évaluer</button>
      </div>
    `).join('');

    if (!reports.length) { listEl.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Aucun rapport</p>'; return; }
    listEl.innerHTML = `<table class="data-table"><thead><tr><th>Framework</th><th>Score</th><th>Statut</th><th>Date</th><th>Findings</th></tr></thead><tbody>
      ${reports.map(r => `<tr>
        <td>${escape(r.framework_name)}</td>
        <td><strong style="color:${r.score >= 70 ? 'var(--success)' : r.score >= 40 ? 'var(--warning)' : 'var(--danger)'}">${r.score != null ? r.score + '%' : '—'}</strong></td>
        <td><span class="badge">${escape(r.status)}</span></td>
        <td style="font-size:12px">${r.generated_at ? new Date(r.generated_at).toLocaleDateString('fr-FR') : '—'}</td>
        <td>${r.findings_count}</td>
      </tr>`).join('')}
    </tbody></table>`;
  } catch (e) {
    fwEl.innerHTML = `<p style="color:var(--danger)">Erreur : ${escape(String(e.message))}</p>`;
  }
}

async function runComplianceEval(framework) {
  try {
    showToast(`Évaluation ${framework} lancée…`, 'info');
    await api(`/compliance/evaluate/${framework}`, { method: 'POST' });
    setTimeout(loadCompliance, 3000);
  } catch (e) {
    showToast(`Erreur : ${e.message}`, 'error');
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
// ── Executive RSSI Dashboard ─────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

async function loadExecutive() {
  const kpisEl = document.getElementById('exec-kpis');
  const gaugeEl = document.getElementById('exec-risk-gauge');
  const coverageEl = document.getElementById('exec-coverage');
  const topEl = document.getElementById('exec-top-assets');
  if (!kpisEl) return;

  try {
    const resp = await api('/executive/summary');
    const d = await resp.json();

    kpisEl.innerHTML = [
      { label: 'Score risque', value: d.global_risk_score, color: d.global_risk_score > 60 ? 'var(--danger)' : d.global_risk_score > 30 ? 'var(--warning)' : 'var(--success)' },
      { label: 'CVEs critiques', value: d.critical_cves, color: 'var(--danger)' },
      { label: 'Taux remédiation', value: d.remediation_rate_pct + '%', color: 'var(--success)' },
      { label: 'Tendance', value: d.risk_trend === 'improving' ? 'En amélioration' : d.risk_trend === 'worsening' ? 'En dégradation' : 'Stable', color: d.risk_trend === 'improving' ? 'var(--success)' : d.risk_trend === 'worsening' ? 'var(--danger)' : 'var(--text-muted)' },
    ].map(k => `<div class="stat-card"><span class="num" style="color:${k.color}">${k.value}</span><span class="stat-lbl">${k.label}</span></div>`).join('');

    // Risk gauge
    if (gaugeEl) {
      const pct = d.global_risk_score;
      const gaugeColor = pct > 60 ? '#ef4444' : pct > 30 ? '#f59e0b' : '#22c55e';
      gaugeEl.innerHTML = `
        <div style="position:relative;width:160px;height:160px;margin:0 auto">
          <svg viewBox="0 0 36 36" style="transform:rotate(-90deg)">
            <circle cx="18" cy="18" r="15.9" fill="none" stroke="var(--border)" stroke-width="3"/>
            <circle cx="18" cy="18" r="15.9" fill="none" stroke="${gaugeColor}" stroke-width="3" stroke-dasharray="${pct} ${100 - pct}" stroke-linecap="round"/>
          </svg>
          <div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column">
            <span style="font-size:28px;font-weight:700;color:${gaugeColor}">${pct}</span>
            <span style="font-size:11px;color:var(--text-muted)">/100</span>
          </div>
        </div>`;
    }

    // Coverage
    if (coverageEl) {
      const c = d.coverage;
      coverageEl.innerHTML = [
        { label: 'Scan récent', pct: c.scan_coverage_pct, count: `${c.assets_with_recent_scan}/${c.total_assets}` },
        { label: 'Hardening', pct: c.hardening_coverage_pct, count: `${c.assets_with_hardening}/${c.total_assets}` },
        { label: 'SSL valide', pct: 0, count: `${c.assets_with_ssl_ok}/${c.total_assets}` },
      ].map(m => `<div style="margin-bottom:12px">
        <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px"><span>${m.label}</span><span>${m.count}</span></div>
        <div style="height:8px;background:var(--border);border-radius:4px;overflow:hidden"><div style="height:100%;width:${Math.min(m.pct, 100)}%;background:var(--primary);border-radius:4px"></div></div>
      </div>`).join('');
    }

    // Top risky assets
    if (topEl) {
      topEl.innerHTML = d.top_risky_assets.slice(0, 5).map(a => `
        <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:13px">
          <span>${escape(a.ip || a.name || a.asset_id.substring(0, 8))}</span>
          <span><span class="badge badge-critical" style="font-size:10px">${a.critical_cve_count} crit</span> ${a.cve_count} CVEs</span>
        </div>
      `).join('') || '<p style="color:var(--text-muted);font-size:13px">Aucun asset à risque</p>';
    }

    // Trend chart
    const canvas = document.getElementById('exec-trend-chart');
    if (canvas && d.trend_30d && d.trend_30d.length > 0 && typeof Chart !== 'undefined') {
      const ctx = canvas.getContext('2d');
      if (canvas._chartInstance) canvas._chartInstance.destroy();
      canvas._chartInstance = new Chart(ctx, {
        type: 'line',
        data: {
          labels: d.trend_30d.map(p => p.date.substring(5)),
          datasets: [
            { label: 'Nouvelles CVEs', data: d.trend_30d.map(p => p.new_cves), borderColor: '#f87171', backgroundColor: 'rgba(248,113,113,0.1)', fill: true, tension: 0.3 },
            { label: 'CVEs résolues', data: d.trend_30d.map(p => p.resolved_cves), borderColor: '#34d399', backgroundColor: 'rgba(52,211,153,0.1)', fill: true, tension: 0.3 },
            { label: 'Non acquittées', data: d.trend_30d.map(p => p.cumulative_unacked), borderColor: '#818cf8', borderDash: [5, 3], fill: false, tension: 0.3 },
          ],
        },
        options: { responsive: true, plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } }, scales: { x: { ticks: { color: '#64748b', font: { size: 10 } } }, y: { ticks: { color: '#64748b' }, beginAtZero: true } } },
      });
    }
  } catch (e) {
    kpisEl.innerHTML = `<p style="color:var(--danger)">Erreur : ${escape(String(e.message))}</p>`;
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
// ── Threat Intelligence ──────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

async function loadThreatIntel() {
  const statsEl = document.getElementById('threat-intel-stats');
  const listEl = document.getElementById('threat-ioc-list');
  if (!listEl) return;

  try {
    const resp = await api('/threat-intel/iocs?limit=100');
    const iocs = await resp.json();

    if (statsEl) {
      const ipCount = iocs.filter(i => i.ioc_type === 'ip').length;
      const domainCount = iocs.filter(i => i.ioc_type === 'domain').length;
      const urlCount = iocs.filter(i => i.ioc_type === 'url').length;
      statsEl.innerHTML = [
        { label: 'IPs', value: ipCount },
        { label: 'Domaines', value: domainCount },
        { label: 'URLs', value: urlCount },
      ].map(s => `<div class="stat-card"><span class="num">${s.value}</span><span class="stat-lbl">${s.label}</span></div>`).join('');
    }

    if (!iocs.length) { listEl.innerHTML = '<p style="color:var(--text-muted);font-size:13px">Aucun IOC. Rafraîchissez les feeds.</p>'; return; }
    listEl.innerHTML = `<table class="data-table"><thead><tr><th>Indicateur</th><th>Type</th><th>Source</th><th>Sévérité</th><th>Dernière vue</th></tr></thead><tbody>
      ${iocs.slice(0, 50).map(i => `<tr>
        <td style="font-family:monospace;font-size:12px">${escape(i.indicator)}</td>
        <td><span class="badge">${escape(i.ioc_type)}</span></td>
        <td>${escape(i.source)}</td>
        <td>${i.severity ? `<span class="badge badge-${i.severity.toLowerCase()}">${escape(i.severity)}</span>` : '—'}</td>
        <td style="font-size:12px">${i.last_seen ? new Date(i.last_seen).toLocaleDateString('fr-FR') : '—'}</td>
      </tr>`).join('')}
    </tbody></table>`;
  } catch (e) {
    listEl.innerHTML = `<p style="color:var(--danger)">Erreur : ${escape(String(e.message))}</p>`;
  }
}

async function refreshThreatFeeds() {
  try {
    showToast('Rafraîchissement des feeds en cours…', 'info');
    await api('/threat-intel/refresh', { method: 'POST' });
    showToast('Feeds en cours de mise à jour', 'info');
    setTimeout(loadThreatIntel, 5000);
  } catch (e) {
    showToast(`Erreur : ${e.message}`, 'error');
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
// ── Export helpers ────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

async function exportExecutivePDF() {
  try {
    showToast('Génération du PDF…', 'info');
    const resp = await api('/reports/export/pdf/executive');
    if (!resp.ok) { const err = await resp.json().catch(() => ({})); throw new Error(err.detail || 'Erreur PDF'); }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'executive_report.pdf'; a.click();
    URL.revokeObjectURL(url);
    showToast('PDF téléchargé', 'info');
  } catch (e) { showToast(`Erreur PDF : ${e.message}`, 'error'); }
}

async function exportXLSX() {
  try {
    showToast('Génération Excel…', 'info');
    const resp = await api('/reports/export/xlsx');
    if (!resp.ok) { const err = await resp.json().catch(() => ({})); throw new Error(err.detail || 'Erreur Excel'); }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'netlanventory_export.xlsx'; a.click();
    URL.revokeObjectURL(url);
    showToast('Excel téléchargé', 'info');
  } catch (e) { showToast(`Erreur Excel : ${e.message}`, 'error'); }
}

// ── Scheduled Scans (recurring network rescans) ─────────────────────────────

async function loadScheduledScans() {
  const tbody = document.getElementById('scheduled-scans-tbody');
  if (!tbody) return;
  try {
    const scans = await api('/scheduled-scans');
    if (!scans || scans.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="color:var(--text-muted);text-align:center;padding:32px">Aucun scan planifié. Cliquez sur "+ Nouveau scan planifié" pour commencer.</td></tr>';
      return;
    }
    tbody.innerHTML = scans.map(s => {
      const modules = escape(s.modules).split(',').map(m =>
        `<span class="badge badge-info" style="font-size:9px;margin:1px">${m.trim()}</span>`
      ).join(' ');
      const interval = s.interval_hours >= 24
        ? `${Math.round(s.interval_hours / 24)}j`
        : `${s.interval_hours}h`;
      const lastRun = s.last_run_at ? fmtDate(s.last_run_at) : '—';
      const statusBdg = s.last_status
        ? statusBadge(s.last_status)
        : '<span class="badge badge-muted">jamais</span>';
      const enabledBdg = s.enabled
        ? '<span class="badge badge-success">actif</span>'
        : '<span class="badge badge-muted">inactif</span>';
      return `<tr>
        <td><strong>${escape(s.name)}</strong><br>${enabledBdg}</td>
        <td class="mono">${escape(s.target)}</td>
        <td>${modules}</td>
        <td class="mono">${interval}</td>
        <td style="font-size:12px">${lastRun}</td>
        <td>${statusBdg}</td>
        <td class="mono">${s.run_count || 0}</td>
        <td>
          <button class="btn btn-sm" onclick="triggerScheduledScan('${escape(s.id)}')">Lancer</button>
          <button class="btn btn-sm" onclick="toggleScheduledScan('${escape(s.id)}', ${!s.enabled})">${s.enabled ? 'Désactiver' : 'Activer'}</button>
          <button class="btn btn-danger btn-sm" onclick="deleteScheduledScan('${escape(s.id)}', '${escape(s.name)}')">Suppr.</button>
        </td>
      </tr>`;
    }).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" style="color:var(--danger);padding:16px">Erreur: ${escape(e.message)}</td></tr>`;
  }
}

async function openScheduledScanModal() {
  const name = prompt('Nom du scan planifié (ex: "Rescan LAN quotidien"):');
  if (!name) return;
  const target = prompt('Plage cible (CIDR, ex: "192.168.1.0/24"):');
  if (!target) return;
  const intervalStr = prompt('Intervalle en heures (ex: 24 pour quotidien, 168 pour hebdo):', '24');
  const interval = parseInt(intervalStr, 10);
  if (!interval || interval < 1) { showToast('Intervalle invalide', 'error'); return; }

  const modulesStr = prompt(
    'Modules (séparés par des virgules):',
    'arp_sweep,port_scanner,service_detector,os_fingerprint'
  );
  if (!modulesStr) return;

  try {
    await api('/scheduled-scans', {
      method: 'POST',
      body: JSON.stringify({
        name,
        target,
        modules: modulesStr,
        interval_hours: interval,
        enabled: true,
      }),
    });
    showToast(`Scan planifié "${name}" créé`, 'success');
    loadScheduledScans();
  } catch (e) {
    showToast(`Erreur: ${e.message}`, 'error');
  }
}

async function triggerScheduledScan(id) {
  try {
    const result = await api(`/scheduled-scans/${id}/trigger`, { method: 'POST' });
    showToast(`Scan lancé (${result.target}) — ID: ${result.scan_id.slice(0,8)}`, 'success');
    loadScheduledScans();
  } catch (e) {
    showToast(`Erreur: ${e.message}`, 'error');
  }
}

async function toggleScheduledScan(id, enabled) {
  try {
    await api(`/scheduled-scans/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    });
    showToast(enabled ? 'Scan activé' : 'Scan désactivé', 'info');
    loadScheduledScans();
  } catch (e) {
    showToast(`Erreur: ${e.message}`, 'error');
  }
}

async function deleteScheduledScan(id, name) {
  if (!confirm(`Supprimer le scan planifié "${name}" ?`)) return;
  try {
    await api(`/scheduled-scans/${id}`, { method: 'DELETE' });
    showToast(`Scan "${name}" supprimé`, 'info');
    loadScheduledScans();
  } catch (e) {
    showToast(`Erreur: ${e.message}`, 'error');
  }
}
