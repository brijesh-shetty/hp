/**
 * main.js — HPE Threat Detection Pipeline — Application Entry Point
 * Orchestrates globe, pipeline, dashboard, and WebSocket simulation.
 */

import './styles/index.css';
import { initGlobe, addArc } from './globe.js';
import { renderPipeline, animatePipelineEvent, updateStageLatencies } from './pipeline.js';
import { renderDashboard, updateDashboard, updateHealth, updateModelMetrics, showVpnAlert } from './dashboard.js';
import { initStarField } from './effects.js';
import { renderAdminDashboard, connectAdminWebSocket } from './admin.js';

// ── State ─────────────────────────────────────────────────────────────────────
let ws = null;
let isSimulating = false;
let eventQueue = [];
let processingEvent = false;

// ── Initialize Application ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  console.log('[HPE] Initializing Threat Detection Pipeline...');

  // Init star field background
  initStarField('globe-section');

  // Init 3D Globe
  initGlobe('globe-container');

  // Render pipeline structure
  renderPipeline('pipeline-content');

  // Render dashboard
  renderDashboard('dashboard-content');

  // Render admin dashboard
  renderAdminDashboard('admin-content');

  // Initialize HUD from backend metrics (persisted across reloads)
  initHUDFromBackend();

  // Start health polling
  updateHealth();
  updateModelMetrics();
  setInterval(updateHealth, 10000);
  setInterval(updateModelMetrics, 30000);

  // Section navigation
  setupSectionNav();

  // Connect WebSocket for simulation
  connectSimulation();

  // Connect admin WebSocket for real-time alerts
  connectAdminWebSocket();

  // Start processing event queue
  processEventQueue();

  console.log('[HPE] Initialization complete');
});

// ── WebSocket Simulation ──────────────────────────────────────────────────────
function connectSimulation() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/simulate`;

  console.log(`[HPE] Connecting to WebSocket: ${wsUrl}`);

  try {
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log('[HPE] WebSocket connected — simulation started');
      isSimulating = true;
      updateConnectionStatus(true);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleSimulationMessage(data);
      } catch (e) {
        console.error('[HPE] Failed to parse message:', e);
      }
    };

    ws.onclose = () => {
      console.log('[HPE] WebSocket disconnected');
      isSimulating = false;
      updateConnectionStatus(false);

      // Reconnect after 5 seconds
      setTimeout(connectSimulation, 5000);
    };

    ws.onerror = (err) => {
      console.error('[HPE] WebSocket error:', err);
      updateConnectionStatus(false);

      // Fallback: load sample events and simulate locally
      setTimeout(() => {
        if (!isSimulating) {
          loadAndSimulateLocally();
        }
      }, 3000);
    };
  } catch (e) {
    console.error('[HPE] WebSocket connection failed:', e);
    // Fallback
    setTimeout(loadAndSimulateLocally, 2000);
  }
}

function handleSimulationMessage(message) {
  switch (message.type) {
    case 'server_info':
      console.log('[HPE] Server info:', message.data);
      break;

    case 'pipeline_result':
      eventQueue.push(message.data);
      break;

    case 'vpn_login_alert':
      // Instant VPN login detection — show banner immediately
      console.log('[HPE] 🛡️ VPN Login Alert received via WebSocket:', message.data);
      showVpnAlert(message.data);
      break;

    case 'error':
      console.error('[HPE] Simulation error:', message.data);
      break;
  }
}

// ── Event Queue Processing ───────────────────────────────────────────────────
async function processEventQueue() {
  while (true) {
    if (eventQueue.length > 0 && !processingEvent) {
      processingEvent = true;
      const data = eventQueue.shift();

      try {
        const event = data.event;
        const prediction = data.prediction;

        const isLivePortal = (prediction.event_summary?.event_source === 'live_portal');

        // Draw globe arcs and animate pipeline for events
        // If the queue is growing, skip the slow animations to prevent lagging behind
        const shouldAnimate = isLivePortal || (eventQueue.length < 3);

        if (shouldAnimate) {
          // Update globe with arc
          addArc(event, prediction);

          // Animate pipeline
          await animatePipelineEvent(prediction);
        } else {
          // Skip slow animation, just update latencies directly
          updateStageLatencies(prediction.pipeline_stages);
          // Add a visual delay to prevent super-fast scrolling of dashboard/logs
          await sleep(800);
        }

        // Always update dashboard (populates threat feeds & logs for both sources)
        updateDashboard(prediction);

        // Update HUD
        updateGlobeHUD(prediction);

      } catch (e) {
        console.error('[HPE] Event processing error:', e);
      }

      processingEvent = false;
    }

    await sleep(100);
  }
}

// ── Local Simulation Fallback ─────────────────────────────────────────────────
async function loadAndSimulateLocally() {
  console.log('[HPE] Loading sample events for local simulation...');

  try {
    const res = await fetch('/api/sample-events');
    if (!res.ok) {
      console.error('[HPE] Failed to load sample events, using internal demo');
      startInternalDemo();
      return;
    }

    const data = await res.json();
    const normal = data.sample_normal || [];
    const attack = data.sample_attack || [];
    const allEvents = [...normal, ...attack];

    if (allEvents.length === 0) {
      startInternalDemo();
      return;
    }

    console.log(`[HPE] Local simulation with ${allEvents.length} events`);

    // Simulate by posting to predict endpoint
    let idx = 0;
    isSimulating = true;

    const simulate = async () => {
      if (!isSimulating) return;

      const event = allEvents[idx % allEvents.length];
      idx++;

      try {
        const res = await fetch('/api/predict', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(event),
        });

        if (res.ok) {
          const prediction = await res.json();
          eventQueue.push({ event, prediction });
        }
      } catch (e) {
        console.error('[HPE] Local sim error:', e);
      }

      setTimeout(simulate, Math.random() * 2000 + 1000);
    };

    simulate();
  } catch (e) {
    console.error('[HPE] Local simulation failed:', e);
    startInternalDemo();
  }
}

// ── Internal Demo (no backend) ────────────────────────────────────────────────
function startInternalDemo() {
  console.log('[HPE] Starting internal demo mode (no backend)');

  const demoEvents = [
    { user_id: 'USR-0175', source_ip: '109.223.221.101', ip_region: 'Asia-Pacific', user_region: 'Asia-Pacific', action: 'write', anomaly_type: 'None', geo_mismatch: false },
    { user_id: 'USR-0080', source_ip: '129.74.149.115', ip_region: 'Asia-Pacific', user_region: 'Asia-Pacific', action: 'read', anomaly_type: 'data_exfiltration', geo_mismatch: false },
    { user_id: 'USR-0057', source_ip: '140.56.194.153', ip_region: 'EU-Central', user_region: 'US-East', action: 'read', anomaly_type: 'impossible_travel', geo_mismatch: true },
    { user_id: 'USR-0032', source_ip: '162.245.203.53', ip_region: 'US-East', user_region: 'US-East', action: 'admin', anomaly_type: 'brute_force', geo_mismatch: false },
  ];

  const geoMap = {
    'US-East': { lat: 40.71, lng: -74.01, city: 'New York' },
    'US-West': { lat: 37.77, lng: -122.42, city: 'San Francisco' },
    'EU-Central': { lat: 50.11, lng: 8.68, city: 'Frankfurt' },
    'Asia-Pacific': { lat: 1.35, lng: 103.82, city: 'Singapore' },
    'South-America': { lat: -23.55, lng: -46.63, city: 'São Paulo' },
  };

  function regionToGeo(region) {
    return geoMap[region] || { lat: 0, lng: 0, city: 'Unknown' };
  }

  let idx = 0;
  const runDemo = () => {
    const event = demoEvents[idx % demoEvents.length];
    const isThreat = event.anomaly_type && event.anomaly_type !== 'None';

    const prediction = {
      event_id: `demo-${idx}`,
      is_threat: isThreat,
      threat_score: isThreat ? 0.85 + Math.random() * 0.15 : Math.random() * 0.1,
      threat_action: isThreat ? 'BLOCK' : 'ALLOW',
      xgb_score: isThreat ? 0.90 : Math.random() * 0.05,
      lgb_score: isThreat ? 0.88 : Math.random() * 0.08,
      ensemble_score: isThreat ? 0.89 : Math.random() * 0.06,
      threshold: 0.5455,
      source_geo: regionToGeo(event.ip_region),
      destination_geo: { lat: 12.97, lng: 77.59, city: 'Bangalore' },
      pipeline_stages: Array.from({ length: 10 }, (_, i) => ({
        stage_name: `Stage ${i + 1}`,
        latency_ms: Math.random() * 5 + 0.5,
        status: 'completed',
      })),
      total_latency_ms: Math.random() * 30 + 10,
      timestamp: new Date().toISOString(),
      event_summary: event,
    };

    eventQueue.push({ event, prediction });
    idx++;
    setTimeout(runDemo, Math.random() * 3000 + 1500);
  };

  runDemo();
}

// ── Globe HUD Updates ─────────────────────────────────────────────────────────
let hudTotalEvents = 0;
let hudTotalThreats = 0;

async function initHUDFromBackend() {
  try {
    const res = await fetch('/api/health');
    if (!res.ok) return;
    const data = await res.json();
    hudTotalEvents = data.total_requests || 0;
    hudTotalThreats = data.total_threats_blocked || 0;

    const totalEl = document.getElementById('hud-event-count');
    const threatEl = document.getElementById('hud-threat-count');
    if (totalEl) totalEl.textContent = hudTotalEvents.toLocaleString();
    if (threatEl) threatEl.textContent = hudTotalThreats.toLocaleString();
    console.log(`[HPE] HUD initialized: ${hudTotalEvents} events, ${hudTotalThreats} threats`);
  } catch (e) {
    console.warn('[HPE] Could not fetch backend metrics for HUD init');
  }
}

function updateGlobeHUD(prediction) {
  hudTotalEvents++;
  if (prediction.is_threat) hudTotalThreats++;

  const totalEl = document.getElementById('hud-event-count');
  const threatEl = document.getElementById('hud-threat-count');
  const levelEl = document.getElementById('hud-threat-level');
  const levelFill = document.getElementById('threat-level-fill');

  if (totalEl) totalEl.textContent = hudTotalEvents.toLocaleString();
  if (threatEl) threatEl.textContent = hudTotalThreats.toLocaleString();

  const threatPercent = hudTotalEvents > 0 ? (hudTotalThreats / hudTotalEvents * 100) : 0;
  if (levelEl) {
    if (threatPercent > 10) {
      levelEl.textContent = 'CRITICAL';
      levelEl.className = 'hud-value danger';
    } else if (threatPercent > 5) {
      levelEl.textContent = 'ELEVATED';
      levelEl.className = 'hud-value';
      levelEl.style.color = 'var(--amber)';
    } else {
      levelEl.textContent = 'NOMINAL';
      levelEl.className = 'hud-value success';
    }
  }
  if (levelFill) {
    levelFill.style.width = `${Math.min(threatPercent * 5, 100)}%`;
  }
}

function updateConnectionStatus(connected) {
  const dot = document.getElementById('status-ws-dot');
  const text = document.getElementById('status-ws-text');
  if (dot) dot.className = `status-dot ${connected ? '' : 'warning'}`;
  if (text) text.textContent = connected ? 'SYSTEM LIVE' : 'LOCAL SIMULATION';
}

// ── Section Navigation ───────────────────────────────────────────────────────
function setupSectionNav() {
  const dots = document.querySelectorAll('.section-nav-dot');
  const sections = ['globe-section', 'pipeline-section', 'dashboard-section', 'admin-section'];

  dots.forEach((dot, idx) => {
    dot.addEventListener('click', () => {
      const section = document.getElementById(sections[idx]);
      if (section) section.scrollIntoView({ behavior: 'smooth' });
    });
  });

  // Intersection observer for active dot
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const idx = sections.indexOf(entry.target.id);
          dots.forEach((d, i) => d.classList.toggle('active', i === idx));
        }
      });
    },
    { threshold: 0.5 }
  );

  sections.forEach(id => {
    const section = document.getElementById(id);
    if (section) observer.observe(section);
  });
}

// ── Utility ──────────────────────────────────────────────────────────────────
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
