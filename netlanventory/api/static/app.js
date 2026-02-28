'use strict';

const API = '/api/v1';

// ── Auth state ────────────────────────────────────────────────────────────────

let _token = localStorage.getItem('nlv_token') || null;
let _me = null;
let _overviewChart = null;
let _currentReportId = null;
let _assetDns = [];
let _vocabulary = { os_family: [], device_type: [] };
const HTTP_PORTS  = new Set([80, 8080, 8000, 3000, 8888]);
const HTTPS_PORTS = new Set([443, 8443, 4443]);

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

function escape(str) {
  return String(str ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );
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

function switchToView(viewName) {
  document.querySelectorAll('.nav-item').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));

  const navBtn = document.querySelector(`.nav-item[data-view="${viewName}"]`);
  if (navBtn) navBtn.classList.add('active');
  const panel = document.getElementById(`panel-${viewName}`);
  if (panel) panel.classList.add('active');

  // Load data for the panel if needed
  if (viewName === 'admin') loadUsers();
}

function initNav() {
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      switchToView(item.dataset.view);
    });
  });
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
  localStorage.removeItem('nlv_token');
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
  localStorage.setItem('nlv_token', _token);
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

    // Update sidebar badge
    const badge = document.getElementById('nav-asset-count');
    if (badge) badge.textContent = assets.total;
  } catch (e) {
    console.error('Stats error:', e);
  }
}

// ── Assets ────────────────────────────────────────────────────────────────────

async function loadAssets() {
  const search = document.getElementById('asset-search').value.toLowerCase();
  const activeOnly = document.getElementById('active-only').checked;

  try {
    const { items } = await api(`/assets?limit=500${activeOnly ? '&active_only=true' : ''}`);
    const filtered = items.filter(a =>
      !search ||
      (a.name || '').toLowerCase().includes(search) ||
      (a.ip || '').includes(search) ||
      (a.mac || '').toLowerCase().includes(search) ||
      (a.hostname || '').toLowerCase().includes(search)
    );

    const tbody = document.querySelector('#asset-table tbody');
    if (!filtered.length) {
      tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-muted);padding:32px">No assets found</td></tr>';
      return;
    }

    tbody.innerHTML = filtered.map(a => {
      const openPorts = (a.ports || []).filter(p => p.state === 'open');
      const portList = openPorts.slice(0, 6)
        .map(p => `<span class="mono">${p.port_number}/${p.protocol}</span>`).join(' ');
      const morePorts = openPorts.length > 6
        ? `<span class="badge badge-muted">+${openPorts.length - 6}</span>` : '';
      return `
        <tr class="clickable" onclick="openAssetModal('${a.id}')">
          <td>${a.name ? `<strong>${escape(a.name)}</strong>` : '<span style="color:var(--text-muted)">—</span>'}</td>
          <td class="mono">${escape(a.ip || '—')}</td>
          <td class="mono">${escape(a.mac || '—')}</td>
          <td>${escape(a.hostname || '—')}</td>
          <td>${escape(a.vendor || '—')}</td>
          <td>${escape(a.os_family || '—')}${a.os_version ? ` <small style="color:var(--text-muted)">${escape(a.os_version)}</small>` : ''}</td>
          <td>${portList}${morePorts}</td>
          <td>${a.is_active ? badge('yes', 'success') : badge('no', 'muted')}</td>
          <td style="color:var(--text-muted);font-size:12px">${fmtDate(a.last_seen)}</td>
        </tr>`;
    }).join('');
  } catch (e) {
    console.error('Assets error:', e);
  }
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

async function openAssetModal(id) {
  _modalAssetId = id;
  const overlay = document.getElementById('asset-modal');
  overlay.classList.remove('hidden');
  _switchModalTab('details');

  const saveBtn = document.getElementById('modal-save-btn');
  saveBtn.disabled = false;
  saveBtn.textContent = 'Save';

  // Reset ZAP status & auto badge
  document.getElementById('zap-status').classList.add('hidden');
  document.getElementById('zap-risk-summary').classList.add('hidden');
  const autoBadge = document.getElementById('modal-auto-badge');
  if (autoBadge) autoBadge.style.display = 'none';

  try {
    const a = await api(`/assets/${id}`);
    document.getElementById('modal-title').textContent =
      a.name || a.hostname || a.ip || 'Asset';

    // ── Details tab ──────────────────────────────────────────────────────
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
    document.getElementById('modal-ssh-user').value = a.ssh_user || '';
    document.getElementById('modal-ssh-port').value = a.ssh_port || '';
    document.getElementById('modal-notes').value = a.notes || '';

    // DNS entries
    _assetDns = a.dns_entries || [];
    _renderDnsTags();

    // ZAP auto-scan per-asset settings
    const zapAutoEl = document.getElementById('modal-zap-auto');
    const zapIntervalEl = document.getElementById('modal-zap-interval');
    if (zapAutoEl) zapAutoEl.checked = a.zap_auto_scan_enabled === true;
    if (zapIntervalEl) zapIntervalEl.value = a.zap_scan_interval_minutes || '';

    // Pre-fill ZAP URL
    document.getElementById('zap-target-url').value = a.ip ? `http://${a.ip}` : '';

    // ── Ports tab ────────────────────────────────────────────────────────
    const openPorts = (a.ports || []).filter(p => p.state === 'open');
    const portsTbody = document.querySelector('#modal-ports-table tbody');
    if (!openPorts.length) {
      portsTbody.innerHTML = '<tr><td colspan="5" style="color:var(--text-muted);text-align:center;padding:20px">No open ports detected</td></tr>';
    } else {
      portsTbody.innerHTML = openPorts.map(p => `
        <tr>
          <td class="mono">${p.port_number}</td>
          <td>${escape(p.protocol)}</td>
          <td>${badge(p.state, p.state === 'open' ? 'success' : 'muted')}</td>
          <td>${escape(p.service_name || '—')}</td>
          <td style="color:var(--text-muted);font-size:12px">${escape(p.version || '—')}</td>
        </tr>`).join('');
    }

    // ── Overview + Failles tabs ───────────────────────────────────────
    _renderOverviewTab(a);
    _renderFlawsTab(a);
    _autoTriggerZap(a);

  } catch (e) {
    document.getElementById('modal-info').innerHTML =
      `<span class="detail-key">Error</span><span class="detail-val" style="color:var(--danger)">${escape(e.message)}</span>`;
  }
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

      if (completed.length === 1) {
        // Single scan: horizontal bar by severity (original view)
        const r = completed[0].risk_summary || {};
        _overviewChart = new Chart(ctx, {
          type: 'bar',
          data: {
            labels: ['High', 'Medium', 'Low', 'Info'],
            datasets: [{
              data: [r.high || 0, r.medium || 0, r.low || 0, r.informational || 0],
              backgroundColor: ['#e53935', '#fb8c00', '#fdd835', '#90a4ae'],
              borderRadius: 4,
            }],
          },
          options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              x: { beginAtZero: true, ticks: { color: '#8b949e', font: { size: 11 }, precision: 0 }, grid: { color: '#30363d' } },
              y: { ticks: { color: '#8b949e', font: { size: 12 } }, grid: { display: false } },
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
              {
                type: 'bar', label: 'High',
                data: completed.map(r => getR(r, 'high')),
                backgroundColor: '#e53935', stack: 'alerts', borderRadius: 2,
              },
              {
                type: 'bar', label: 'Medium',
                data: completed.map(r => getR(r, 'medium')),
                backgroundColor: '#fb8c00', stack: 'alerts', borderRadius: 2,
              },
              {
                type: 'bar', label: 'Low',
                data: completed.map(r => getR(r, 'low')),
                backgroundColor: '#fdd835', stack: 'alerts', borderRadius: 2,
              },
              {
                type: 'bar', label: 'Info',
                data: completed.map(r => getR(r, 'informational')),
                backgroundColor: '#90a4ae', stack: 'alerts', borderRadius: 2,
              },
              {
                type: 'line', label: 'CVEs',
                data: completed.map(r => r.cve_count || 0),
                borderColor: '#7c4dff', backgroundColor: 'rgba(124,77,255,0.15)',
                pointRadius: 4, pointBackgroundColor: '#7c4dff',
                tension: 0.3, yAxisID: 'yCve', fill: false,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                display: true,
                labels: { color: '#8b949e', font: { size: 11 }, boxWidth: 12 },
              },
            },
            scales: {
              x: {
                stacked: true,
                ticks: { color: '#8b949e', font: { size: 10 }, maxRotation: 30 },
                grid: { color: '#30363d' },
              },
              y: {
                stacked: true, beginAtZero: true,
                ticks: { color: '#8b949e', font: { size: 11 }, precision: 0 },
                grid: { color: '#30363d' },
                title: { display: true, text: 'Alertes', color: '#8b949e', font: { size: 11 } },
              },
              yCve: {
                position: 'right', beginAtZero: true,
                ticks: { color: '#7c4dff', font: { size: 11 }, precision: 0 },
                grid: { drawOnChartArea: false },
                title: { display: true, text: 'CVEs', color: '#7c4dff', font: { size: 11 } },
              },
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

  // CVE table
  const tbody = document.getElementById('cve-tbody');
  if (!cves.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;padding:24px">No vulnerabilities detected yet</td></tr>';
  } else {
    tbody.innerHTML = cves.map(c => {
      const sev = (c.severity || '').toLowerCase();
      const sevType = sev === 'high' || sev === 'critical' ? 'error'
        : sev === 'medium' ? 'warning' : sev === 'low' ? 'info' : 'muted';
      return `
        <tr>
          <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${escape(c.cve_id_str)}"
               target="_blank" rel="noopener">${escape(c.cve_id_str)}</a></td>
          <td>${escape(c.package_name || '—')}</td>
          <td class="mono">${escape(c.package_version || '—')}</td>
          <td>${c.severity ? badge(c.severity, sevType) : '—'}</td>
          <td>${c.cvss_score != null ? c.cvss_score.toFixed(1) : '—'}</td>
          <td>${badge(c.source || '?', 'muted')}</td>
        </tr>`;
    }).join('');
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
      `<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${escape(cve)}"
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

async function saveAssetModal() {
  if (!_modalAssetId) return;
  const saveBtn = document.getElementById('modal-save-btn');
  saveBtn.disabled = true;
  saveBtn.textContent = 'Saving…';

  const sshPort = document.getElementById('modal-ssh-port').value;
  const zapIntervalRaw = document.getElementById('modal-zap-interval').value;
  const payload = {
    name: document.getElementById('modal-name').value.trim() || null,
    hostname: document.getElementById('modal-hostname').value.trim() || null,
    device_type: document.getElementById('modal-device-type').value.trim() || null,
    os_family: document.getElementById('modal-os-family').value.trim() || null,
    os_version: document.getElementById('modal-os-version').value.trim() || null,
    ssh_user: document.getElementById('modal-ssh-user').value.trim() || null,
    ssh_port: sshPort ? parseInt(sshPort, 10) : null,
    zap_auto_scan_enabled: document.getElementById('modal-zap-auto').checked,
    zap_scan_interval_minutes: zapIntervalRaw ? parseInt(zapIntervalRaw, 10) : null,
    notes: document.getElementById('modal-notes').value.trim() || null,
  };

  try {
    await api(`/assets/${_modalAssetId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
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

// ── Admin — sub-tab switching ─────────────────────────────────────────────────

function initSubTabs() {
  document.querySelectorAll('.subnav-item').forEach(tab => {
    tab.addEventListener('click', () => {
      const panel = document.getElementById('panel-admin');
      panel.querySelectorAll('.subnav-item').forEach(t => t.classList.remove('active'));
      panel.querySelectorAll('.sub-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('sub-' + tab.dataset.subtab).classList.add('active');

      if (tab.dataset.subtab === 'admin-auth') loadAuthSettings();
      if (tab.dataset.subtab === 'admin-oidc') loadOidcConfig();
      if (tab.dataset.subtab === 'admin-users') loadUsers();
      if (tab.dataset.subtab === 'admin-zap') loadZapSettings();
    });
  });
}

// ── Users ─────────────────────────────────────────────────────────────────────

async function loadUsers() {
  try {
    const data = await api('/users');
    if (!data) return;
    const tbody = document.querySelector('#user-table tbody');
    if (!data.items.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:32px">No users</td></tr>';
      return;
    }
    tbody.innerHTML = data.items.map(u => {
      const isSelf = u.id === _me?.id;
      return `
        <tr>
          <td>${escape(u.email)}</td>
          <td class="mono">${escape(u.username)}</td>
          <td>${escape(u.full_name || '—')}</td>
          <td>${badge(u.role, u.role === 'admin' ? 'warning' : 'info')}</td>
          <td>${badge(u.auth_provider, 'muted')}</td>
          <td>${u.is_active ? badge('active', 'success') : badge('disabled', 'error')}</td>
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

  if (isEdit) {
    try {
      const u = await api(`/users/${userId}`);
      if (!u) return;
      document.getElementById('um-email').value = u.email;
      document.getElementById('um-username').value = u.username;
      document.getElementById('um-fullname').value = u.full_name || '';
      document.getElementById('um-role').value = u.role;
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
      const payload = {
        full_name: document.getElementById('um-fullname').value.trim() || null,
        role: document.getElementById('um-role').value,
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

// ── App init ──────────────────────────────────────────────────────────────────

async function _initAppData() {
  initNav();
  initSubTabs();
  _initModalTabs();

  await loadModuleCheckboxes();
  await loadVocabulary();
  await refreshStats();
  await loadAssets();
  await loadScans();
  await loadModules();

  // Scan modal button
  document.getElementById('open-scan-modal-btn').addEventListener('click', openScanModal);
  document.getElementById('scan-btn').addEventListener('click', triggerScan);

  // Assets panel
  document.getElementById('refresh-assets').addEventListener('click', loadAssets);
  document.getElementById('asset-search').addEventListener('input', loadAssets);
  document.getElementById('active-only').addEventListener('change', loadAssets);

  // Scans panel
  document.getElementById('refresh-scans').addEventListener('click', loadScans);

  // Auto-refresh every 30 s
  setInterval(() => { refreshStats(); loadScans(); }, 30_000);
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
