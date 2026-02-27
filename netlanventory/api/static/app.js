'use strict';

const API = '/api/v1';

// ── Auth state ────────────────────────────────────────────────────────────────

let _token = localStorage.getItem('nlv_token') || null;
let _me = null;  // current user object from /auth/me

// ── Utilities ────────────────────────────────────────────────────────────────

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (_token) headers['Authorization'] = `Bearer ${_token}`;

  const res = await fetch(API + path, { headers, ...opts });

  if (res.status === 401) {
    // Token expired or invalid — go back to login
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
  const d = new Date(iso);
  return d.toLocaleString();
}

function escape(str) {
  return String(str ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );
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
  document.getElementById('nav-username').textContent = _me.email;
  document.getElementById('nav-role').textContent = _me.role;

  // Show Admin tab only for admins
  if (_me.role === 'admin') {
    document.getElementById('tab-admin-btn').style.display = '';
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
      (a.name || '').toLowerCase().includes(search) ||
      (a.ip || '').includes(search) ||
      (a.mac || '').toLowerCase().includes(search) ||
      (a.hostname || '').toLowerCase().includes(search)
    );

    const tbody = document.querySelector('#asset-table tbody');
    if (!filtered.length) {
      tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--muted);padding:30px">No assets found</td></tr>';
      return;
    }

    tbody.innerHTML = filtered.map(a => {
      const openPorts = (a.ports || []).filter(p => p.state === 'open');
      const portList = openPorts.slice(0, 6).map(p => `<span class="mono">${p.port_number}/${p.protocol}</span>`).join(' ');
      const morePorts = openPorts.length > 6 ? `<span class="badge badge-muted">+${openPorts.length - 6}</span>` : '';
      return `
        <tr class="clickable" onclick="openAssetModal('${a.id}')">
          <td>${a.name ? `<strong>${escape(a.name)}</strong>` : '<span style="color:var(--muted)">—</span>'}</td>
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

// ── Asset detail / edit modal ─────────────────────────────────────────────────

let _modalAssetId = null;

async function openAssetModal(id) {
  _modalAssetId = id;
  const overlay = document.getElementById('asset-modal');
  overlay.classList.remove('hidden');

  // Reset save button
  const saveBtn = document.getElementById('modal-save-btn');
  saveBtn.disabled = false;
  saveBtn.textContent = 'Save';

  try {
    const a = await api(`/assets/${id}`);
    document.getElementById('modal-title').textContent =
      a.name || a.hostname || a.ip || 'Asset';

    // Read-only info grid
    const infoEl = document.getElementById('modal-info');
    const row = (k, v) =>
      `<span class="detail-key">${k}</span><span class="detail-val">${escape(v || '—')}</span>`;
    infoEl.innerHTML = [
      row('IP', a.ip),
      row('MAC', a.mac),
      row('Hostname', a.hostname),
      row('Vendor', a.vendor),
      row('Device type', a.device_type),
      row('OS', a.os_family ? `${a.os_family}${a.os_version ? ' ' + a.os_version : ''}` : null),
      row('Last seen', a.last_seen ? new Date(a.last_seen).toLocaleString() : null),
    ].join('');

    // Editable fields
    document.getElementById('modal-name').value = a.name || '';
    document.getElementById('modal-ssh-user').value = a.ssh_user || '';
    document.getElementById('modal-ssh-port').value = a.ssh_port || '';
    document.getElementById('modal-notes').value = a.notes || '';

    // Ports table
    const openPorts = (a.ports || []).filter(p => p.state === 'open');
    const portsTbody = document.querySelector('#modal-ports-table tbody');
    if (!openPorts.length) {
      portsTbody.innerHTML = '<tr><td colspan="5" style="color:var(--muted)">No open ports detected</td></tr>';
    } else {
      portsTbody.innerHTML = openPorts.map(p => `
        <tr>
          <td class="mono">${p.port_number}</td>
          <td>${escape(p.protocol)}</td>
          <td>${badge(p.state, p.state === 'open' ? 'success' : 'muted')}</td>
          <td>${escape(p.service_name || '—')}</td>
          <td style="color:var(--muted);font-size:12px">${escape(p.version || '—')}</td>
        </tr>`).join('');
    }
  } catch (e) {
    document.getElementById('modal-info').innerHTML =
      `<span class="detail-key">Error</span><span class="detail-val" style="color:var(--danger)">${escape(e.message)}</span>`;
  }
}

function closeAssetModal(event) {
  // Close only when clicking the overlay background or the close/cancel buttons
  if (event && event.target !== document.getElementById('asset-modal')) return;
  document.getElementById('asset-modal').classList.add('hidden');
  _modalAssetId = null;
}

async function saveAssetModal() {
  if (!_modalAssetId) return;
  const saveBtn = document.getElementById('modal-save-btn');
  saveBtn.disabled = true;
  saveBtn.textContent = 'Saving…';

  const sshPort = document.getElementById('modal-ssh-port').value;
  const payload = {
    name: document.getElementById('modal-name').value.trim() || null,
    ssh_user: document.getElementById('modal-ssh-user').value.trim() || null,
    ssh_port: sshPort ? parseInt(sshPort, 10) : null,
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
  } catch (e) {
    saveBtn.disabled = false;
    saveBtn.textContent = 'Save';
    alert(`Save failed: ${e.message}`);
  }
}

// ── Scans ────────────────────────────────────────────────────────────────────

async function loadScans() {
  try {
    const { items } = await api('/scans?limit=50');
    const tbody = document.querySelector('#scan-table tbody');
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:30px">No scans yet</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(s => {
      const assetsFound = (s.summary?.modules
        ? Object.values(s.summary.modules).reduce((acc, m) => acc + (m.assets_found || 0), 0)
        : '—');
      const running = ['pending', 'running'].includes(s.status);
      const rerunBtn = `<button class="btn btn-sm" onclick="rerunScan('${s.id}')" ${running ? 'disabled title="Scan in progress"' : ''}>&#8635; Re-run</button>`;
      return `
        <tr>
          <td class="mono" style="font-size:11px;color:var(--muted)">${s.id.slice(0, 8)}…</td>
          <td class="mono">${escape(s.target)}</td>
          <td>${(s.modules_run || []).map(m => badge(m, 'info')).join(' ')}</td>
          <td>${statusBadge(s.status)}</td>
          <td style="font-size:12px;color:var(--muted)">${fmtDate(s.started_at)}</td>
          <td style="font-size:12px;color:var(--muted)">${fmtDate(s.finished_at)}</td>
          <td>${assetsFound}</td>
          <td>${rerunBtn}</td>
        </tr>`;
    }).join('');
  } catch (e) {
    console.error('Scans error:', e);
  }
}

async function rerunScan(scanId) {
  const statusEl = document.getElementById('scan-status');
  statusEl.className = 'status-bar running';
  statusEl.textContent = 'Re-running scan…';
  statusEl.classList.remove('hidden');

  // Disable all re-run buttons while polling
  document.querySelectorAll('#scan-table button').forEach(b => { b.disabled = true; });

  try {
    const scan = await api(`/scans/${scanId}/rerun`, { method: 'POST' });
    statusEl.textContent = `Re-run ${scan.id.slice(0, 8)} created — target: ${scan.target}. Polling…`;

    // Switch to Scans tab so the user can follow progress
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    const scansTab = document.querySelector('.tab[data-tab="scans"]');
    if (scansTab) scansTab.classList.add('active');
    document.getElementById('tab-scans').classList.add('active');

    let done = false;
    while (!done) {
      await new Promise(r => setTimeout(r, 2000));
      await loadScans();
      const updated = await api(`/scans/${scan.id}`);
      statusEl.textContent = `Re-run ${updated.id.slice(0, 8)} — status: ${updated.status}`;

      if (['completed', 'completed_with_errors', 'failed', 'error'].includes(updated.status)) {
        done = true;
        statusEl.className = 'status-bar ' + (updated.status === 'completed' ? 'success' : 'error');
        const total = updated.summary?.modules
          ? Object.values(updated.summary.modules).reduce((s, m) => s + (m.assets_found || 0), 0)
          : 0;
        statusEl.textContent = `Re-run complete (${updated.status}) — ${total} assets found.`;
        await loadAssets();
        await refreshStats();
      }
    }
  } catch (e) {
    statusEl.className = 'status-bar error';
    statusEl.textContent = `Re-run error: ${e.message}`;
  } finally {
    await loadScans(); // re-enable buttons via fresh render
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

// ── Admin panel ───────────────────────────────────────────────────────────────

function initSubTabs() {
  document.querySelectorAll('.sub-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const panel = document.getElementById('tab-admin');
      panel.querySelectorAll('.sub-tab').forEach(t => t.classList.remove('active'));
      panel.querySelectorAll('.sub-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('sub-' + tab.dataset.subtab).classList.add('active');
      if (tab.dataset.subtab === 'admin-auth') loadAuthSettings();
      if (tab.dataset.subtab === 'admin-oidc') loadOidcConfig();
      if (tab.dataset.subtab === 'admin-users') loadUsers();
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
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:30px">No users</td></tr>';
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
              : '<span style="color:var(--muted);font-size:12px;padding:6px 4px">you</span>'}
          </td>
        </tr>`;
    }).join('');
  } catch (e) { console.error('Users error:', e); }
}

// user modal handles both create and edit
let _userModalId = null;

async function openUserModal(userId = null) {
  _userModalId = userId;
  const isEdit = !!userId;
  document.getElementById('user-modal-title').textContent = isEdit ? 'Edit user' : 'New user';
  document.getElementById('um-save-btn').textContent = isEdit ? 'Save' : 'Create';

  // Reset
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
      // Disable email/username for OIDC users
      const isOidc = u.auth_provider !== 'local';
      document.getElementById('um-email').disabled = isOidc;
      document.getElementById('um-username').disabled = isOidc;
    } catch (e) { alert(`Error loading user: ${e.message}`); return; }
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
      await api(`/users/${_userModalId}`, {
        method: 'PATCH',
        body: JSON.stringify(payload),
      });
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
  } catch (e) {
    alert(`Error: ${e.message}`);
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
  } catch (e) { alert(`Error: ${e.message}`); }
}

// ── Authentication settings ───────────────────────────────────────────────────

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
  } catch (e) { console.error('Auth settings error:', e); }
}

// ── OIDC connector ────────────────────────────────────────────────────────────

async function loadOidcConfig() {
  try {
    const cfg = await api('/admin/oidc');
    if (!cfg) return;
    document.getElementById('oidc-enabled').checked = cfg.enabled;
    document.getElementById('oidc-name').value = cfg.name || '';
    document.getElementById('oidc-issuer').value = cfg.issuer_url || '';
    document.getElementById('oidc-client-id').value = cfg.client_id || '';
    document.getElementById('oidc-client-secret').value = '';  // never prefill secret
    document.getElementById('oidc-client-secret').placeholder =
      cfg.client_secret_set ? '••••••••  (set — leave blank to keep)' : 'Enter client secret';
    document.getElementById('oidc-scopes').value = cfg.scopes || 'openid email profile';
    document.getElementById('oidc-auto-create').checked = cfg.auto_create_users;
    document.getElementById('oidc-default-role').value = cfg.default_role || 'user';
  } catch (e) { console.error('OIDC load error:', e); }
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
        client_secret: secret || null,   // null = keep existing
        scopes: document.getElementById('oidc-scopes').value.trim() || 'openid email profile',
        auto_create_users: document.getElementById('oidc-auto-create').checked,
        default_role: document.getElementById('oidc-default-role').value,
      }),
    });
    await loadOidcConfig();  // refresh (shows secret_set status)
    const res = document.getElementById('oidc-test-result');
    res.className = 'status-bar success';
    res.textContent = 'Configuration saved.';
    res.classList.remove('hidden');
    setTimeout(() => res.classList.add('hidden'), 3000);
  } catch (e) {
    alert(`Save failed: ${e.message}`);
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
            .map(([k, v]) => `<br><span style="color:var(--muted)">${k}:</span> ${escape(v)}`)
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

// ── Tab switching ────────────────────────────────────────────────────────────

function initTabs() {
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
      if (tab.dataset.tab === 'admin') loadUsers();
    });
  });
}

// ── App data init ─────────────────────────────────────────────────────────────

async function _initAppData() {
  initTabs();
  initSubTabs();
  await loadModuleCheckboxes();
  await refreshStats();
  await loadAssets();
  await loadScans();
  await loadModules();

  document.getElementById('scan-btn').addEventListener('click', triggerScan);
  document.getElementById('refresh-assets').addEventListener('click', loadAssets);
  document.getElementById('refresh-scans').addEventListener('click', loadScans);
  // refresh-users removed (now inline onclick in sub-panel)
  document.getElementById('asset-search').addEventListener('input', loadAssets);
  document.getElementById('active-only').addEventListener('change', loadAssets);

  // Auto-refresh every 30 seconds
  setInterval(() => { refreshStats(); loadScans(); }, 30_000);
}

// ── Init ─────────────────────────────────────────────────────────────────────

async function init() {
  _initLoginForm();

  const authenticated = await checkAuth();
  if (!authenticated) return;

  _showApp();
  _applyUserContext();
  await _initAppData();
}

document.addEventListener('DOMContentLoaded', init);
