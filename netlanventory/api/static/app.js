'use strict';

const API = '/api/v1';

// ── Utilities ────────────────────────────────────────────────────────────────

async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
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
  const d = new Date(iso);
  return d.toLocaleString();
}

function escape(str) {
  return String(str ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );
}

// ── Module checkboxes in scan form ───────────────────────────────────────────

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

// ── Stats ────────────────────────────────────────────────────────────────────

async function refreshStats() {
  try {
    const [assets, scans, mods] = await Promise.all([
      api('/assets?limit=1'),
      api('/scans?limit=1'),
      api('/modules'),
    ]);
    const activeAssets = await api('/assets?limit=1&active_only=true');

    document.querySelector('#stat-assets .num').textContent = assets.total;
    document.querySelector('#stat-active .num').textContent = activeAssets.total;
    document.querySelector('#stat-scans .num').textContent = scans.total;
    document.querySelector('#stat-modules .num').textContent = mods.total;
  } catch (e) {
    console.error('Stats error:', e);
  }
}

// ── Assets ───────────────────────────────────────────────────────────────────

async function loadAssets() {
  const search = document.getElementById('asset-search').value.toLowerCase();
  const activeOnly = document.getElementById('active-only').checked;

  try {
    const { items } = await api(`/assets?limit=500${activeOnly ? '&active_only=true' : ''}`);
    const filtered = items.filter(a =>
      !search ||
      (a.ip || '').includes(search) ||
      (a.mac || '').toLowerCase().includes(search) ||
      (a.hostname || '').toLowerCase().includes(search)
    );

    const tbody = document.querySelector('#asset-table tbody');
    if (!filtered.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:30px">No assets found</td></tr>';
      return;
    }

    tbody.innerHTML = filtered.map(a => {
      const openPorts = (a.ports || []).filter(p => p.state === 'open');
      const portList = openPorts.slice(0, 8).map(p => `<span class="mono">${p.port_number}/${p.protocol}</span>`).join(' ');
      const morePorts = openPorts.length > 8 ? `<span class="badge badge-muted">+${openPorts.length - 8}</span>` : '';
      return `
        <tr>
          <td class="mono">${escape(a.ip || '—')}</td>
          <td class="mono">${escape(a.mac || '—')}</td>
          <td>${escape(a.hostname || '—')}</td>
          <td>${escape(a.vendor || '—')}</td>
          <td>${escape(a.os_family || '—')}${a.os_version ? ` <small style="color:var(--muted)">${escape(a.os_version)}</small>` : ''}</td>
          <td>${portList}${morePorts}</td>
          <td>${a.is_active ? badge('yes', 'success') : badge('no', 'muted')}</td>
          <td style="color:var(--muted);font-size:12px">${fmtDate(a.last_seen)}</td>
        </tr>`;
    }).join('');
  } catch (e) {
    console.error('Assets error:', e);
  }
}

// ── Scans ────────────────────────────────────────────────────────────────────

async function loadScans() {
  try {
    const { items } = await api('/scans?limit=50');
    const tbody = document.querySelector('#scan-table tbody');
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:30px">No scans yet</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(s => {
      const assetsFound = (s.summary?.modules
        ? Object.values(s.summary.modules).reduce((acc, m) => acc + (m.assets_found || 0), 0)
        : '—');
      return `
        <tr>
          <td class="mono" style="font-size:11px;color:var(--muted)">${s.id.slice(0, 8)}…</td>
          <td class="mono">${escape(s.target)}</td>
          <td>${(s.modules_run || []).map(m => badge(m, 'info')).join(' ')}</td>
          <td>${statusBadge(s.status)}</td>
          <td style="font-size:12px;color:var(--muted)">${fmtDate(s.started_at)}</td>
          <td style="font-size:12px;color:var(--muted)">${fmtDate(s.finished_at)}</td>
          <td>${assetsFound}</td>
        </tr>`;
    }).join('');
  } catch (e) {
    console.error('Scans error:', e);
  }
}

// ── Modules ──────────────────────────────────────────────────────────────────

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

// ── Scan trigger ─────────────────────────────────────────────────────────────

async function triggerScan() {
  const target = document.getElementById('scan-target').value.trim();
  if (!target) { alert('Please enter a target CIDR or IP.'); return; }

  const checked = [...document.querySelectorAll('#module-checkboxes input:checked')];
  const modules = checked.map(cb => cb.value);
  if (!modules.length) { alert('Select at least one module.'); return; }

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

    statusEl.textContent = `Scan ${scan.id.slice(0, 8)} created — status: ${scan.status}. Polling…`;

    // Poll until finished
    let done = false;
    while (!done) {
      await new Promise(r => setTimeout(r, 2000));
      const updated = await api(`/scans/${scan.id}`);
      statusEl.textContent = `Scan ${updated.id.slice(0, 8)} — status: ${updated.status}`;

      if (['completed', 'completed_with_errors', 'failed', 'error'].includes(updated.status)) {
        done = true;
        statusEl.className = 'status-bar ' + (updated.status === 'completed' ? 'success' : 'error');
        const total = updated.summary?.modules
          ? Object.values(updated.summary.modules).reduce((s, m) => s + (m.assets_found || 0), 0)
          : 0;
        statusEl.textContent = `Scan complete (${updated.status}) — ${total} assets found.`;
        await loadAssets();
        await loadScans();
        await refreshStats();
      }
    }
  } catch (e) {
    statusEl.className = 'status-bar error';
    statusEl.textContent = `Error: ${e.message}`;
  } finally {
    document.getElementById('scan-btn').disabled = false;
  }
}

// ── Tab switching ────────────────────────────────────────────────────────────

function initTabs() {
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
    });
  });
}

// ── Init ─────────────────────────────────────────────────────────────────────

async function init() {
  initTabs();
  await loadModuleCheckboxes();
  await refreshStats();
  await loadAssets();
  await loadScans();
  await loadModules();

  document.getElementById('scan-btn').addEventListener('click', triggerScan);
  document.getElementById('refresh-assets').addEventListener('click', loadAssets);
  document.getElementById('refresh-scans').addEventListener('click', loadScans);
  document.getElementById('asset-search').addEventListener('input', loadAssets);
  document.getElementById('active-only').addEventListener('change', loadAssets);

  // Auto-refresh every 30 seconds
  setInterval(() => { refreshStats(); loadScans(); }, 30_000);
}

document.addEventListener('DOMContentLoaded', init);
