/**
 * admin.js — Security Admin Console
 * Real-time alert queue with human-in-the-loop approval/rejection.
 */

let adminWs = null;
let alerts = [];
let auditLog = [];
let adminStats = {};
let selectedAlertId = null;
let activeContainerId = 'admin-content';
let adminToken = sessionStorage.getItem('admin_jwt') || null;
let adminUser = sessionStorage.getItem('admin_user') || 'admin';

function getAuthHeaders() {
  return adminToken 
    ? { 'Authorization': `Bearer ${adminToken}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' };
}

function isAdminLoggedIn() {
  if (!adminToken) return false;
  try {
    const payload = JSON.parse(atob(adminToken.split('.')[1]));
    return payload.exp * 1000 > Date.now();
  } catch (e) {
    return false;
  }
}

async function adminFetch(url, options = {}) {
  options.headers = {
    ...options.headers,
    ...getAuthHeaders()
  };
  try {
    const res = await fetch(url, options);
    if (res.status === 401) {
      console.warn('[ADMIN] Unauthorized request (401), logging out...');
      logoutAdmin();
      return null;
    }
    return res;
  } catch (e) {
    console.error(`[ADMIN] Fetch error for ${url}:`, e);
    throw e;
  }
}

function logoutAdmin() {
  adminToken = null;
  adminUser = 'admin';
  sessionStorage.removeItem('admin_jwt');
  sessionStorage.removeItem('admin_user');
  if (adminWs) {
    try { adminWs.close(); } catch (e) {}
    adminWs = null;
  }
  renderAdminDashboard(activeContainerId);
}

window._logoutAdmin = function() {
  logoutAdmin();
};

async function handleAdminLogin() {
  const userEl = document.getElementById('admin-login-user');
  const passEl = document.getElementById('admin-login-pass');
  const errorEl = document.getElementById('admin-login-error');
  const btnEl = document.getElementById('admin-login-btn');
  
  if (!userEl || !passEl) return;
  const username = userEl.value.trim();
  const password = passEl.value;
  
  if (!username || !password) {
    if (errorEl) errorEl.textContent = 'Please enter both username and password.';
    return;
  }
  
  if (btnEl) {
    btnEl.disabled = true;
    btnEl.textContent = 'Authenticating...';
  }
  if (errorEl) errorEl.textContent = '';

  try {
    const res = await fetch('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    
    if (res.status === 401) {
      if (errorEl) errorEl.textContent = 'Invalid credentials.';
    } else if (res.status === 403) {
      const data = await res.json();
      if (errorEl) errorEl.textContent = data.detail || 'Security department role required.';
    } else if (!res.ok) {
      if (errorEl) errorEl.textContent = 'Authentication failed. Please try again.';
    } else {
      const data = await res.json();
      adminToken = data.token;
      adminUser = data.username || username;
      sessionStorage.setItem('admin_jwt', adminToken);
      sessionStorage.setItem('admin_user', adminUser);
      renderAdminDashboard(activeContainerId);
      connectAdminWebSocket();
    }
  } catch (e) {
    if (errorEl) errorEl.textContent = 'Network error. Please try again later.';
  } finally {
    if (btnEl) {
      btnEl.disabled = false;
      btnEl.textContent = 'Authenticate';
    }
  }
}

window._requestReset = async function() {
  if (!confirm("⚠️ WARNING: This will wipe alerts, infra leases, credential rotations, and Elasticsearch indices.\n\nAudit logs and Kafka topics will be preserved.\n\nAre you sure you want to request a pipeline reset?")) {
    return;
  }

  try {
    const res = await adminFetch('/api/admin/reset/request', { method: 'POST' });
    if (!res || !res.ok) {
      showToast('❌ Reset Failed', 'Could not request a reset token.');
      return;
    }
    const data = await res.json();
    const token = data.confirm_token;
    
    const secondConfirmation = confirm(
      `⚠️ CRITICAL CONFIRMATION REQUIRED.\n\n` +
      `A one-time reset token has been issued (Expires in 60s).\n` +
      `Click OK to execute the pipeline reset now, or Cancel to abort.`
    );
    
    if (secondConfirmation) {
      const confirmRes = await adminFetch('/api/admin/reset/confirm', {
        method: 'POST',
        body: JSON.stringify({ confirm_token: token })
      });
      if (confirmRes && confirmRes.ok) {
        showToast('🔥 Pipeline Reset Complete', 'All data wiped successfully.');
        loadAlerts();
        loadAdminStats();
        loadAuditLog();
        loadRegistrations();
      } else {
        const errData = confirmRes ? await confirmRes.json() : {};
        showToast('❌ Reset Failed', errData.detail || 'Confirmation failed or expired.');
      }
    }
  } catch (e) {
    showToast('❌ Reset Error', 'An error occurred during reset.');
  }
};

/**
 * Render the Admin Dashboard layout
 */
export function renderAdminDashboard(containerId) {
  activeContainerId = containerId;
  const container = document.getElementById(containerId);
  if (!container) return;

  if (!isAdminLoggedIn()) {
    container.innerHTML = `
      <div class="admin-login-overlay">
        <div class="admin-login-card">
          <div class="admin-login-icon">🔒</div>
          <h3>Admin Authentication Required</h3>
          <p style="color: var(--text-secondary); margin-bottom: 24px;">Enter Security department credentials to access the admin console.</p>
          <input type="text" id="admin-login-user" placeholder="Username" style="width: 100%; box-sizing: border-box;" />
          <input type="password" id="admin-login-pass" placeholder="Password" style="width: 100%; box-sizing: border-box;" />
          <button id="admin-login-btn">Authenticate</button>
          <div id="admin-login-error" class="admin-login-error"></div>
        </div>
      </div>
    `;

    document.getElementById('admin-login-btn')?.addEventListener('click', handleAdminLogin);
    const enterHandler = (e) => { if (e.key === 'Enter') handleAdminLogin(); };
    document.getElementById('admin-login-user')?.addEventListener('keyup', enterHandler);
    document.getElementById('admin-login-pass')?.addEventListener('keyup', enterHandler);
    return;
  }

  container.innerHTML = `
    <!-- Admin Console Header with Logout -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 12px; border-bottom: 1px solid var(--glass-border);">
      <div style="color: var(--text-muted); font-size: 13px; font-family: var(--font-mono);">
        Logged in as: <strong style="color: var(--cyan);">${adminUser}</strong>
      </div>
      <button class="admin-btn-action reject" style="background: rgba(255,255,255,0.05); border: 1px solid var(--glass-border); color: var(--text-primary); padding: 6px 16px; border-radius: 6px; cursor: pointer; font-size: 12px;" onclick="window._logoutAdmin()">Sign Out</button>
    </div>

    <!-- Admin Stats Row -->
    <div class="admin-stats-row">
      <div class="admin-stat-card critical-glow">
        <div class="admin-stat-icon">🚨</div>
        <div class="admin-stat-value" id="admin-pending-count">0</div>
        <div class="admin-stat-label">Pending Alerts</div>
      </div>
      <div class="admin-stat-card">
        <div class="admin-stat-icon">⚡</div>
        <div class="admin-stat-value" id="admin-critical-count">0</div>
        <div class="admin-stat-label">Critical Pending</div>
      </div>
      <div class="admin-stat-card">
        <div class="admin-stat-icon">✅</div>
        <div class="admin-stat-value" id="admin-approved-count">0</div>
        <div class="admin-stat-label">Approved</div>
      </div>
      <div class="admin-stat-card">
        <div class="admin-stat-icon">❌</div>
        <div class="admin-stat-value" id="admin-rejected-count">0</div>
        <div class="admin-stat-label">Rejected</div>
      </div>
      <div class="admin-stat-card">
        <div class="admin-stat-icon">📊</div>
        <div class="admin-stat-value" id="admin-total-count">0</div>
        <div class="admin-stat-label">Total Alerts</div>
      </div>
    </div>

    <!-- Main Admin Layout: Alert Queue + Detail -->
    <div class="admin-main-layout">
      <!-- Left: Alert Queue -->
      <div class="admin-alert-queue">
        <div class="admin-panel-header">
          <span class="admin-panel-title">🔔 Alert Queue</span>
          <div class="admin-filter-row">
            <select id="admin-source-filter" class="admin-filter-select">
              <option value="">All Sources</option>
              <option value="live_portal">🌐 Live Portal</option>
              <option value="replayed_dataset">📊 Replayed Dataset</option>
            </select>
            <select id="admin-status-filter" class="admin-filter-select">
              <option value="">All Status</option>
              <option value="pending" selected>Pending</option>
              <option value="approved">Approved</option>
              <option value="rejected">Rejected</option>
            </select>
            <select id="admin-severity-filter" class="admin-filter-select">
              <option value="">All Severity</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
            </select>
          </div>
        </div>
        <div class="admin-alert-list" id="admin-alert-list">
          <div class="admin-loading">Loading alerts...</div>
        </div>
      </div>

      <!-- Right: Alert Detail / Forensics -->
      <div class="admin-alert-detail" id="admin-alert-detail">
        <div class="admin-detail-placeholder">
          <div class="admin-detail-placeholder-icon">🔍</div>
          <div class="admin-detail-placeholder-text">Select an alert to view forensic details</div>
        </div>
      </div>
    </div>

    <!-- Pending Registrations -->
    <div class="admin-audit-section">
      <div class="admin-panel-header">
        <span class="admin-panel-title">👤 Pending Access Requests</span>
        <span class="admin-audit-count" id="admin-reg-count">0 requests</span>
      </div>
      <div class="admin-audit-table-wrapper">
        <table class="admin-audit-table">
          <thead>
            <tr>
              <th>Username</th>
              <th>Department</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="admin-reg-tbody">
            <tr><td colspan="4" class="admin-empty">No pending registrations</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Audit Log -->
    <div class="admin-audit-section">
      <div class="admin-panel-header">
        <span class="admin-panel-title">📋 Admin Audit Log</span>
        <span class="admin-audit-count" id="admin-audit-count">0 entries</span>
      </div>
      <div class="admin-audit-table-wrapper">
        <table class="admin-audit-table" id="admin-audit-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Action</th>
              <th>Alert ID</th>
              <th>User</th>
              <th>Score</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody id="admin-audit-tbody">
            <tr><td colspan="6" class="admin-empty">No admin actions yet</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Alert Notification Toast -->
    <div class="admin-toast" id="admin-toast" style="display: none;">
      <div class="admin-toast-icon">🚨</div>
      <div class="admin-toast-content">
        <div class="admin-toast-title" id="admin-toast-title">CRITICAL ALERT</div>
        <div class="admin-toast-message" id="admin-toast-message">New threat detected</div>
      </div>
      <button class="admin-toast-close" id="admin-toast-close">×</button>
    </div>

    <!-- Danger Zone -->
    <div class="admin-audit-section danger-zone-section" style="border: 1px solid var(--magenta); margin-top: 32px; background: rgba(255, 0, 92, 0.05); border-radius: 12px; padding: 24px;">
      <div class="admin-panel-header" style="border-bottom: 1px solid rgba(255, 0, 92, 0.2); padding-bottom: 12px; margin-bottom: 16px;">
        <span class="admin-panel-title" style="color: var(--magenta); font-weight: bold;">⚠️ Danger Zone</span>
      </div>
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <h4 style="margin: 0 0 8px 0; color: var(--text-primary);">Reset Pipeline State</h4>
          <p style="margin: 0; color: var(--text-muted); font-size: 13px;">Wipe all Postgres database records, Kafka topics, and Elasticsearch indices to start fresh.</p>
        </div>
        <button class="admin-btn-action reject" style="background: var(--magenta); color: #fff; padding: 12px 24px; font-weight: bold; border-radius: 8px; border: none; cursor: pointer;" onclick="window._requestReset()">Reset Pipeline</button>
      </div>
    </div>
  `;

  // Setup filter listeners
  document.getElementById('admin-source-filter')?.addEventListener('change', renderAlertList);
  document.getElementById('admin-status-filter')?.addEventListener('change', loadAlerts);
  document.getElementById('admin-severity-filter')?.addEventListener('change', loadAlerts);
  document.getElementById('admin-toast-close')?.addEventListener('click', hideToast);

  // Initial load
  loadAlerts();
  loadAdminStats();
  loadAuditLog();
  loadRegistrations();

  // Poll for updates
  setInterval(loadAlerts, 5000);
  setInterval(loadAdminStats, 5000);
  setInterval(loadAuditLog, 10000);
  setInterval(loadRegistrations, 10000);
}


/**
 * Load pending user registrations
 */
async function loadRegistrations() {
  try {
    const res = await adminFetch('/api/admin/registrations');
    if (!res || !res.ok) return;
    const data = await res.json();
    const registrations = data.registrations || [];

    updateEl('admin-reg-count', `${registrations.length} requests`);

    const tbody = document.getElementById('admin-reg-tbody');
    if (!tbody) return;

    if (registrations.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="admin-empty">No pending registrations</td></tr>';
      return;
    }

    tbody.innerHTML = registrations.map(reg => {
      const vpnBadgeHtml = reg.is_vpn
        ? `<span class="badge-vpn-warn">⚠️ VPN IP Endpoint</span>`
        : '';
      return `
        <tr>
          <td><strong>${reg.username}</strong></td>
          <td>${reg.department || '--'}${vpnBadgeHtml}</td>
          <td><span class="admin-stage-status pending">PENDING</span></td>
          <td>
            <div style="display: flex; gap: 8px;">
              <button class="admin-btn-action approve" onclick="window._approveReg('${reg.username}')">Approve</button>
              <button class="admin-btn-action reject" onclick="window._rejectReg('${reg.username}')">Reject</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  } catch (e) { /* Ignore */ }
}


window._approveReg = async function (username) {
  const password = prompt(`Enter temporary password for ${username}:`);
  if (!password) return;

  try {
    const res = await adminFetch(`/api/admin/registrations/${username}/approve`, {
      method: 'POST',
      body: JSON.stringify({ password: password })
    });
    if (!res) return;
    const data = await res.json();
    if (data.success) {
      showToast('✅ User Approved', `${username} is now active with the provided credentials.`);
      loadRegistrations();
    } else {
      showToast('❌ Error', data.message || 'Failed to approve registration');
    }
  } catch (e) {
    showToast('❌ Error', 'Failed to approve registration');
  }
};



window._rejectReg = async function (username) {
  if (!confirm(`Are you sure you want to reject registration for ${username}?`)) return;
  try {
    const res = await adminFetch(`/api/admin/registrations/${username}/reject`, { method: 'POST' });
    if (!res) return;
    const data = await res.json();
    if (data.success) {
      showToast('❌ User Rejected', `Registration for ${username} deleted.`);
      loadRegistrations();
    }
  } catch (e) {
    showToast('❌ Error', 'Failed to reject registration');
  }
}



/**
 * Connect admin WebSocket for real-time notifications
 */
export function connectAdminWebSocket() {
  if (!isAdminLoggedIn()) {
    console.log('[ADMIN] WebSocket connection deferred: admin not logged in');
    return;
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/api/admin/ws?token=${adminToken}`;

  try {
    adminWs = new WebSocket(wsUrl);

    adminWs.onopen = () => {
      console.log('[ADMIN] WebSocket connected');
    };

    adminWs.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleAdminMessage(data);
      } catch (e) {
        console.error('[ADMIN] Failed to parse message:', e);
      }
    };

    adminWs.onclose = () => {
      console.log('[ADMIN] WebSocket disconnected');
      if (isAdminLoggedIn()) {
        setTimeout(connectAdminWebSocket, 5000);
      }
    };

    adminWs.onerror = () => {
      console.error('[ADMIN] WebSocket error');
    };
  } catch (e) {
    console.error('[ADMIN] WebSocket connection failed:', e);
  }
}


function handleAdminMessage(message) {
  switch (message.type) {
    case 'new_alert':
      // A new threat alert was created
      showNewAlertToast(message.data);
      loadAlerts();
      loadAdminStats();
      break;

    case 'alert_resolved':
      // An alert was approved or rejected
      loadAlerts();
      loadAdminStats();
      loadAuditLog();
      break;

    case 'new_registration':
      // A live user submitted a registration request
      showToast('👤 New Access Request', `User ${message.data.username} (${message.data.department}) has requested access.`);
      loadRegistrations();
      break;

    case 'vpn_login_alert':
      // VPN login detected — show toast in admin console
      const vpn = message.data;
      const vpnStatus = vpn.login_success ? '✓ Login OK' : '✗ Login Failed';
      showToast(
        '🛡️ VPN LOGIN DETECTED',
        `${vpn.username} from ${vpn.source_ip} (${vpn.vpn_provider}, ${vpn.city}, ${vpn.country}) — ${vpnStatus}`
      );
      break;

    case 'admin_connected':
      console.log('[ADMIN] Connected with stats:', message.data);
      break;
  }
}


/**
 * Load alerts from API
 */
async function loadAlerts() {
  try {
    const statusFilter = document.getElementById('admin-status-filter')?.value || '';
    const severityFilter = document.getElementById('admin-severity-filter')?.value || '';

    let url = '/api/admin/alerts?limit=100';
    if (statusFilter) url += `&status=${statusFilter}`;
    if (severityFilter) url += `&severity=${severityFilter}`;

    const res = await adminFetch(url);
    if (!res || !res.ok) return;
    const data = await res.json();
    alerts = data.alerts || [];
    renderAlertList();
  } catch (e) {
    console.warn('[ADMIN] Could not load alerts');
  }
}


function renderAlertList() {
  const list = document.getElementById('admin-alert-list');
  if (!list) return;

  const sourceFilter = document.getElementById('admin-source-filter')?.value || '';
  let filteredAlerts = alerts;

  if (sourceFilter) {
    filteredAlerts = alerts.filter(alert => {
      const source = alert.event_data?.event_source || 'replayed_dataset';
      return source === sourceFilter;
    });
  }

  if (filteredAlerts.length === 0) {
    list.innerHTML = '<div class="admin-empty">No alerts match current filters</div>';
    return;
  }

  list.innerHTML = filteredAlerts.map(alert => {
    const isCritical = alert.threat_action === 'CRITICAL_ALERT';
    const isBlock = alert.threat_action === 'BLOCK';
    const severityClass = isCritical ? 'severity-critical' : isBlock ? 'severity-high' : 'severity-medium';
    const statusClass = alert.status === 'pending' ? 'status-pending'
      : alert.status === 'approved' ? 'status-approved' : 'status-rejected';
    const isSelected = alert.alert_id === selectedAlertId ? 'selected' : '';

    const scorePercent = ((alert.threat_score || 0) * 100).toFixed(1);
    const timeStr = alert.created_at ? new Date(alert.created_at).toLocaleTimeString() : '--';

    const source = alert.event_data?.event_source || 'replayed_dataset';
    const sourceBadgeHtml = source === 'live_portal'
      ? `<span class="badge-live" style="margin-left: 8px;">🌐 Live</span>`
      : `<span class="badge-replayed" style="margin-left: 8px;">📊 Replayed</span>`;

    return `
      <div class="admin-alert-card ${severityClass} ${statusClass} ${isSelected}"
           data-alert-id="${alert.alert_id}"
           onclick="window._selectAdminAlert('${alert.alert_id}')">
        <div class="admin-alert-card-header">
          <span class="admin-severity-badge ${severityClass}">
            ${isCritical ? '🔴 CRITICAL' : isBlock ? '🟠 BLOCK' : '🟡 MONITOR'}
          </span>
          ${sourceBadgeHtml}
          <span class="admin-alert-status ${statusClass}">
            ${alert.status.toUpperCase()}
          </span>
        </div>
        <div class="admin-alert-card-body">
          <div class="admin-alert-user">${alert.user_id || 'unknown'}</div>
          <div class="admin-alert-meta">
            <span>Score: <strong>${scorePercent}%</strong></span>
            <span>IP: ${alert.event_data?.source_ip || '--'}</span>
            <span>${timeStr}</span>
          </div>
          <div class="admin-alert-type">${alert.event_data?.anomaly_type || 'Unknown'}</div>
        </div>
        <div class="admin-alert-id">${alert.alert_id}</div>
      </div>
    `;
  }).join('');
}


/**
 * Select and show full detail for an alert
 */
window._selectAdminAlert = async function (alertId) {
  selectedAlertId = alertId;
  renderAlertList(); // Update selection highlight

  const detail = document.getElementById('admin-alert-detail');
  if (!detail) return;

  detail.innerHTML = '<div class="admin-loading">Loading forensic data...</div>';

  try {
    const res = await adminFetch(`/api/admin/alerts/${alertId}`);
    if (!res || !res.ok) throw new Error('Failed to load');
    const alert = await res.json();
    renderAlertDetail(alert);
  } catch (e) {
    detail.innerHTML = '<div class="admin-empty">Failed to load alert details</div>';
  }
};


function renderAlertDetail(alert) {
  const detail = document.getElementById('admin-alert-detail');
  if (!detail) return;

  const isCritical = alert.threat_action === 'CRITICAL_ALERT';
  const scorePercent = ((alert.threat_score || 0) * 100).toFixed(1);
  const event = alert.event_data || {};
  const isPending = alert.status === 'pending';

  // Build pipeline stages table
  const stagesHtml = (alert.pipeline_stages || []).map((s, i) => `
    <tr>
      <td style="color: var(--text-muted);">${s.stage_number || i + 1}</td>
      <td>${s.stage_name || '--'}</td>
      <td><span class="admin-stage-status ${s.status === 'pending_approval' ? 'pending' : ''}">${s.status || '--'}</span></td>
      <td style="color: var(--amber);">${(s.latency_ms || 0).toFixed(1)}ms</td>
      <td>${s.is_real_tool ? '✅ Real' : '⚙️ Sim'}</td>
    </tr>
  `).join('');

  detail.innerHTML = `
    <div class="admin-detail-content">
      <!-- Alert Header -->
      <div class="admin-detail-header ${isCritical ? 'critical' : 'high'}">
        <div class="admin-detail-severity">
          ${isCritical ? '🔴 CRITICAL ALERT' : '🟠 HIGH SEVERITY ALERT'}
        </div>
        <div class="admin-detail-id">${alert.alert_id}</div>
      </div>

      <!-- Threat Score Section -->
      <div class="admin-score-section">
        <div class="admin-score-main">
          <div class="admin-score-label">Threat Score</div>
          <div class="admin-score-value ${isCritical ? 'critical' : 'high'}">${scorePercent}%</div>
          <div class="admin-score-bar">
            <div class="admin-score-fill" style="width: ${scorePercent}%; background: ${isCritical ? 'var(--magenta)' : 'var(--amber)'};"></div>
          </div>
        </div>
        <div class="admin-model-scores">
          <div class="admin-model-score">
            <span class="admin-model-label">XGBoost</span>
            <span class="admin-model-value">${(alert.xgb_score || 0).toFixed(4)}</span>
          </div>
          <div class="admin-model-score">
            <span class="admin-model-label">LightGBM</span>
            <span class="admin-model-value">${(alert.lgb_score || 0).toFixed(4)}</span>
          </div>
          <div class="admin-model-score">
            <span class="admin-model-label">Ensemble</span>
            <span class="admin-model-value">${(alert.ensemble_score || 0).toFixed(4)}</span>
          </div>
          <div class="admin-model-score">
            <span class="admin-model-label">Threshold</span>
            <span class="admin-model-value" style="color: var(--amber);">${(alert.threshold || 0).toFixed(4)}</span>
          </div>
        </div>
      </div>

      <!-- Event Facts -->
      <div class="admin-facts-section">
        <div class="admin-section-label">📋 Event Facts</div>
        <div class="admin-facts-grid">
          <div class="admin-fact"><span class="admin-fact-key">User</span><span class="admin-fact-val">${event.user || '--'}</span></div>
          <div class="admin-fact"><span class="admin-fact-key">Source IP</span><span class="admin-fact-val">${event.source_ip || '--'}</span></div>
          <div class="admin-fact"><span class="admin-fact-key">Region</span><span class="admin-fact-val">${event.ip_region || '--'}</span></div>
          <div class="admin-fact"><span class="admin-fact-key">Action</span><span class="admin-fact-val">${event.action || '--'}</span></div>
          <div class="admin-fact"><span class="admin-fact-key">Anomaly Type</span><span class="admin-fact-val admin-anomaly-type">${event.anomaly_type || 'None'}</span></div>
          <div class="admin-fact"><span class="admin-fact-key">Geo Mismatch</span><span class="admin-fact-val ${event.geo_mismatch ? 'danger' : ''}">${event.geo_mismatch ? '⚠ YES' : 'No'}</span></div>
          <div class="admin-fact"><span class="admin-fact-key">Impossible Travel</span><span class="admin-fact-val ${event.impossible_travel ? 'danger' : ''}">${event.impossible_travel ? '⚠ YES' : 'No'}</span></div>
          <div class="admin-fact"><span class="admin-fact-key">Login Hour</span><span class="admin-fact-val">${event.login_hour ?? '--'}</span></div>
          <div class="admin-fact"><span class="admin-fact-key">Failed Attempts (15m)</span><span class="admin-fact-val ${(event.failed_attempts_last_15m || 0) >= 5 ? 'danger' : ''}">${event.failed_attempts_last_15m ?? 0}</span></div>
          <div class="admin-fact"><span class="admin-fact-key">Data Downloaded</span><span class="admin-fact-val">${(event.data_downloaded_mb || 0).toFixed(1)} MB</span></div>
          <div class="admin-fact"><span class="admin-fact-key">Pipeline Latency</span><span class="admin-fact-val">${(alert.total_latency_ms || 0).toFixed(1)}ms</span></div>
          <div class="admin-fact"><span class="admin-fact-key">Created</span><span class="admin-fact-val">${alert.created_at ? new Date(alert.created_at).toLocaleString() : '--'}</span></div>
          <div class="admin-fact">
            <span class="admin-fact-key">Event Source</span>
            <span class="admin-fact-val badge-${(event.event_source || 'replayed_dataset') === 'live_portal' ? 'live' : 'replayed'}">
              ${(event.event_source || 'replayed_dataset') === 'live_portal' ? '🌐 Live Portal' : '📊 Replayed Dataset'}
            </span>
          </div>
        </div>
      </div>

      <!-- Threat Trigger Reasons -->
      <div class="admin-facts-section">
        <div class="admin-section-label">⚠️ Threat Trigger Reasons</div>
        ${event.threat_reasons && event.threat_reasons.length > 0
      ? `<ul class="admin-reasons-list">${event.threat_reasons.map(r => `<li>${r}</li>`).join('')}</ul>`
      : `<div style="color: var(--text-muted); font-size: 12px; margin-top: 8px; font-family: var(--font-mono); padding-left: 8px;">No explicit anomalous factors detected (ensemble probability model match)</div>`
    }
      </div>

      <!-- Geo Info -->
      <div class="admin-facts-section">
        <div class="admin-section-label">🌐 Geographic Data</div>
        <div class="admin-geo-row">
          <div class="admin-geo-card">
            <div class="admin-geo-label">Source</div>
            <div class="admin-geo-city">${alert.source_geo?.city || 'Unknown'}</div>
            <div class="admin-geo-coords">${alert.source_geo?.lat?.toFixed(2) || 0}°, ${alert.source_geo?.lng?.toFixed(2) || 0}°</div>
          </div>
          <div class="admin-geo-arrow">→</div>
          <div class="admin-geo-card">
            <div class="admin-geo-label">Destination</div>
            <div class="admin-geo-city">${alert.destination_geo?.city || 'Unknown'}</div>
            <div class="admin-geo-coords">${alert.destination_geo?.lat?.toFixed(2) || 0}°, ${alert.destination_geo?.lng?.toFixed(2) || 0}°</div>
          </div>
        </div>
      </div>

      <!-- Pipeline Stages -->
      <div class="admin-facts-section">
        <div class="admin-section-label">⚡ Pipeline Stages</div>
        <div class="admin-stages-table-wrapper">
          <table class="admin-stages-table">
            <thead>
              <tr><th>#</th><th>Stage</th><th>Status</th><th>Latency</th><th>Type</th></tr>
            </thead>
            <tbody>${stagesHtml}</tbody>
          </table>
        </div>
      </div>

      ${alert.rotation_result && alert.rotation_result.user_rotation ? `
      <!-- Rotation Result -->
      <div class="admin-facts-section">
        <div class="admin-section-label">🔐 Vault Rotation Result</div>
        <div class="admin-rotation-result">
          <div class="admin-fact"><span class="admin-fact-key">Success</span><span class="admin-fact-val ${alert.rotation_result.user_rotation.success ? 'success' : 'danger'}">${alert.rotation_result.user_rotation.success ? '✅ YES' : '❌ FAILED'}</span></div>
          <div class="admin-fact"><span class="admin-fact-key">Rotation #</span><span class="admin-fact-val">${alert.rotation_result.user_rotation.rotation_number || '--'}</span></div>
          <div class="admin-fact"><span class="admin-fact-key">Rotation ID</span><span class="admin-fact-val" style="font-size: 10px;">${alert.rotation_result.user_rotation.rotation_id || '--'}</span></div>
        </div>
      </div>
      ` : ''}

      ${alert.admin_notes ? `
      <div class="admin-facts-section">
        <div class="admin-section-label">📝 Admin Notes</div>
        <div class="admin-notes-text">${alert.admin_notes}</div>
      </div>
      ` : ''}

      <!-- Action Buttons -->
      ${isPending ? `
      <div class="admin-action-section">
        <textarea id="admin-notes-input" class="admin-notes-input" placeholder="Add notes (optional)..." rows="2"></textarea>
        <div class="admin-action-buttons">
          <button class="admin-btn admin-btn-approve" onclick="window._approveAlert('${alert.alert_id}')">
            ✅ Approve Credential Rotation
          </button>
          <button class="admin-btn admin-btn-reject" onclick="window._rejectAlert('${alert.alert_id}')">
            ❌ Reject (False Positive)
          </button>
        </div>
      </div>
      ` : `
      <div class="admin-resolved-banner ${alert.status}">
        ${alert.status === 'approved' ? '✅ APPROVED' : '❌ REJECTED'} — ${alert.resolved_at ? new Date(alert.resolved_at).toLocaleString() : ''}
      </div>
      `}
    </div>
  `;
}


/**
 * Approve credential rotation
 */
window._approveAlert = async function (alertId) {
  const notes = document.getElementById('admin-notes-input')?.value || '';
  const btn = document.querySelector('.admin-btn-approve');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Rotating credentials...'; }

  try {
    const res = await adminFetch(`/api/admin/alerts/${alertId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ admin_notes: notes }),
    });
    if (!res) return;
    const data = await res.json();

    if (data.success) {
      showToast('✅ Rotation Approved', `Credentials rotated for ${data.rotation_result?.user_id || 'user'}`);
    } else {
      showToast('⚠ Error', data.message || 'Approval failed');
    }

    // Refresh everything
    loadAlerts();
    loadAdminStats();
    loadAuditLog();
    window._selectAdminAlert(alertId);
  } catch (e) {
    showToast('❌ Error', 'Network error during approval');
    if (btn) { btn.disabled = false; btn.textContent = '✅ Approve Credential Rotation'; }
  }
};


/**
 * Reject alert (false positive)
 */
window._rejectAlert = async function (alertId) {
  const notes = document.getElementById('admin-notes-input')?.value || '';

  try {
    const res = await adminFetch(`/api/admin/alerts/${alertId}/reject`, {
      method: 'POST',
      body: JSON.stringify({ admin_notes: notes }),
    });
    if (!res) return;
    const data = await res.json();

    if (data.success) {
      showToast('❌ Alert Rejected', 'Marked as false positive');
    }

    loadAlerts();
    loadAdminStats();
    loadAuditLog();
    window._selectAdminAlert(alertId);
  } catch (e) {
    showToast('❌ Error', 'Network error during rejection');
  }
};


/**
 * Load admin stats
 */
async function loadAdminStats() {
  try {
    const res = await adminFetch('/api/admin/stats');
    if (!res || !res.ok) return;
    adminStats = await res.json();

    updateEl('admin-pending-count', adminStats.pending_count || 0);
    updateEl('admin-critical-count', adminStats.critical_pending || 0);
    updateEl('admin-approved-count', adminStats.total_approved || 0);
    updateEl('admin-rejected-count', adminStats.total_rejected || 0);
    updateEl('admin-total-count', adminStats.total_alerts || 0);

    // Pulse effect on pending count if > 0
    const pendingCard = document.querySelector('.admin-stat-card.critical-glow');
    if (pendingCard) {
      pendingCard.classList.toggle('has-pending', (adminStats.pending_count || 0) > 0);
    }
  } catch (e) { /* Ignore */ }
}


/**
 * Load audit log
 */
async function loadAuditLog() {
  try {
    const res = await adminFetch('/api/admin/audit-log?limit=50');
    if (!res || !res.ok) return;
    const data = await res.json();
    auditLog = data.entries || [];

    updateEl('admin-audit-count', `${auditLog.length} entries`);

    const tbody = document.getElementById('admin-audit-tbody');
    if (!tbody) return;

    if (auditLog.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="admin-empty">No admin actions yet</td></tr>';
      return;
    }

    tbody.innerHTML = auditLog.map(entry => {
      const time = entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '--';
      const actionClass = entry.action === 'approve' ? 'action-approve' : 'action-reject';
      return `
        <tr>
          <td>${time}</td>
          <td><span class="admin-action-badge ${actionClass}">${entry.action?.toUpperCase()}</span></td>
          <td style="font-family: var(--font-mono); font-size: 11px;">${entry.alert_id || '--'}</td>
          <td>${entry.user_id || '--'}</td>
          <td style="color: var(--magenta);">${((entry.threat_score || 0) * 100).toFixed(1)}%</td>
          <td style="color: var(--text-muted); max-width: 200px; overflow: hidden; text-overflow: ellipsis;">${entry.admin_notes || '--'}</td>
        </tr>
      `;
    }).join('');
  } catch (e) { /* Ignore */ }
}


/**
 * Toast notifications
 */
function showNewAlertToast(alertData) {
  const isCritical = alertData.threat_action === 'CRITICAL_ALERT';
  const title = isCritical ? '🚨 CRITICAL ALERT' : '⚠ New Threat Alert';
  const msg = `${alertData.user_id} — Score: ${((alertData.threat_score || 0) * 100).toFixed(1)}%`;
  showToast(title, msg);
}

function showToast(title, message) {
  const toast = document.getElementById('admin-toast');
  const titleEl = document.getElementById('admin-toast-title');
  const msgEl = document.getElementById('admin-toast-message');
  if (!toast || !titleEl || !msgEl) return;

  titleEl.textContent = title;
  msgEl.textContent = message;
  toast.style.display = 'flex';
  toast.classList.add('show');

  setTimeout(() => {
    hideToast();
  }, 6000);
}

function hideToast() {
  const toast = document.getElementById('admin-toast');
  if (toast) {
    toast.classList.remove('show');
    setTimeout(() => { toast.style.display = 'none'; }, 300);
  }
}


function updateEl(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}
