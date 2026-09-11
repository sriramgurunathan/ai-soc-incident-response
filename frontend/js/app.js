/**
 * ApexShield AI-SOC & Enterprise Incident Response Platform
 * UI UX Pro Max Cyberpunk / SOC HUD Client Engine
 */

let currentUser = null;
let currentIncident = null;
let socket = null;
const BASE_API = "";

// Initialize application on DOM load
document.addEventListener("DOMContentLoaded", () => {
  if (window.lucide) {
    lucide.createIcons();
  }
  checkExistingSession();
  connectWebSocket();
  fetchSOCData();
  fetchAnnouncements();
});

// Tab Switcher
function switchTab(tabId) {
  const tabs = ["portal", "soc", "simulator", "docs"];
  tabs.forEach(t => {
    const el = document.getElementById(`tab-${t}`);
    const btn = document.getElementById(`nav-${t}`);
    if (t === tabId) {
      el.classList.remove("hidden");
      btn.className = "cursor-pointer px-3 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-all bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5";
    } else {
      el.classList.add("hidden");
      btn.className = "cursor-pointer px-3 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-all text-gray-400 hover:text-gray-200 border border-transparent hover:border-gray-800 flex items-center gap-1.5";
    }
  });

  if (tabId === "soc") {
    fetchSOCData();
  } else if (tabId === "portal" && currentUser) {
    fetchDocuments();
  }

  if (window.lucide) {
    lucide.createIcons();
  }
}

// Session Check
async function checkExistingSession() {
  const token = localStorage.getItem("apex_token");
  if (!token) return;

  try {
    const res = await fetch(`${BASE_API}/api/v1/auth/me`, {
      headers: { "Authorization": `Bearer ${token}` }
    });
    if (res.ok) {
      currentUser = await res.json();
      renderDashboard();
    } else {
      localStorage.removeItem("apex_token");
    }
  } catch (err) {
    console.warn("Session restore failed:", err);
  }
}

// WebSocket Connection to Real-Time SOC Event Bus
function connectWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/soc-stream`;

  socket = new WebSocket(wsUrl);

  socket.onopen = () => {
    const ind = document.getElementById("live-indicator");
    const txt = document.getElementById("ws-status-text");
    if (ind) ind.className = "pulse-live";
    if (txt) txt.textContent = "WEBSOCKET: CONNECTED";
  };

  socket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handleIncomingTelemetry(data);
    } catch (e) {
      console.error("WS Parse error", e);
    }
  };

  socket.onclose = () => {
    const ind = document.getElementById("live-indicator");
    const txt = document.getElementById("ws-status-text");
    if (ind) ind.className = "pulse-alert";
    if (txt) txt.textContent = "WEBSOCKET: RECONNECTING...";
    setTimeout(connectWebSocket, 3000);
  };
}

function handleIncomingTelemetry(data) {
  if (data.type === "NEW_SECURITY_EVENT") {
    appendTelemetryLog(data.event);
    incrementKPICounter("kpi-total-events");
  } else if (data.type === "NEW_SECURITY_INCIDENT") {
    appendIncidentRow(data.incident, true);
    incrementKPICounter("kpi-active-incidents");
    appendTelemetryLog({
      timestamp: new Date().toISOString(),
      event_type: "INCIDENT_ALERT_BROADCAST",
      username: data.incident.username,
      source_ip: data.incident.source_ip,
      severity: data.incident.severity,
      details: { title: data.incident.title, mitre: data.incident.mitre_technique }
    });
  }
}

// Login Handler
async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;
  const frictionBanner = document.getElementById("friction-banner");
  const frictionText = document.getElementById("friction-text");
  const quarantineBanner = document.getElementById("quarantine-banner");

  frictionBanner.classList.add("hidden");
  quarantineBanner.classList.add("hidden");

  try {
    const res = await fetch(`${BASE_API}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });

    const data = await res.json();

    if (res.ok) {
      if (data.is_locked || data.must_reset_password) {
        quarantineBanner.classList.remove("hidden");
        document.getElementById("reset-username").value = username;
      } else {
        localStorage.setItem("apex_token", data.access_token);
        currentUser = data.user;
        renderDashboard();
      }
    } else {
      if (data.detail && (data.detail.includes("friction") || data.detail.includes("Invalid password"))) {
        frictionBanner.classList.remove("hidden");
        frictionText.textContent = data.detail;
      } else if (res.status === 403 || (data.detail && data.detail.includes("QUARANTINED"))) {
        quarantineBanner.classList.remove("hidden");
        document.getElementById("reset-username").value = username;
      } else {
        alert(data.detail || "Authentication failed.");
      }
    }
  } catch (err) {
    alert("Connection error: " + err.message);
  }
}

function handleLogout() {
  localStorage.removeItem("apex_token");
  currentUser = null;
  document.getElementById("portal-dashboard").classList.add("hidden");
  document.getElementById("portal-auth-container").classList.remove("hidden");
  if (window.lucide) lucide.createIcons();
}

function renderDashboard() {
  document.getElementById("portal-auth-container").classList.add("hidden");
  document.getElementById("portal-dashboard").classList.remove("hidden");

  document.getElementById("user-display-name").textContent = currentUser.full_name;
  document.getElementById("user-avatar-initials").textContent = currentUser.full_name.split(" ").map(n => n[0]).join("");
  document.getElementById("user-clearance-badge").textContent = currentUser.clearance_level;
  document.getElementById("user-meta").textContent = `${currentUser.department} | ${currentUser.role} | ${currentUser.email}`;

  fetchDocuments();
  if (window.lucide) lucide.createIcons();
}

// Documents
async function fetchDocuments() {
  const container = document.getElementById("documents-container");
  if (!container) return;

  try {
    const token = localStorage.getItem("apex_token");
    const headers = token ? { "Authorization": `Bearer ${token}` } : {};
    const res = await fetch(`${BASE_API}/api/v1/portal/documents`, { headers });
    const docs = await res.json();

    container.innerHTML = docs.map(d => `
      <div class="hud-card p-4 flex flex-col justify-between space-y-3">
        <div class="space-y-1.5">
          <div class="flex items-center justify-between">
            <span class="px-2 py-0.5 text-[10px] font-mono rounded ${d.classification === 'Top Secret' ? 'bg-red-500/20 text-red-400 border border-red-500/40' : (d.classification === 'Secret' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40')}">
              ${d.classification}
            </span>
            <span class="text-[11px] text-gray-500 font-mono">${d.department}</span>
          </div>
          <h4 class="text-xs font-bold text-white leading-tight">${d.title}</h4>
          <p class="text-[11px] text-gray-400 line-clamp-2">${d.description || ''}</p>
        </div>
        <button onclick="downloadDocument('${d.id}', '${d.title}')" class="btn-secondary text-[11px] py-1.5 justify-center w-full">
          <i data-lucide="download" class="w-3.5 h-3.5"></i> Download File
        </button>
      </div>
    `).join("");

    if (window.lucide) lucide.createIcons();
  } catch (err) {
    console.error("Fetch docs error", err);
  }
}

async function downloadDocument(docId, docTitle) {
  const token = localStorage.getItem("apex_token");
  const headers = token ? { "Authorization": `Bearer ${token}` } : {};

  try {
    const res = await fetch(`${BASE_API}/api/v1/portal/documents/${docId}/download`, { headers });
    const data = await res.json();

    if (res.ok) {
      alert(`[AUTHORIZED ACCESS: ${data.file_name}]

${data.content_preview}`);
    } else {
      alert(`SECURITY ALERT: ${data.detail}`);
      fetchSOCData();
    }
  } catch (e) {
    alert("Download error: " + e.message);
  }
}

async function fetchAnnouncements() {
  const container = document.getElementById("announcements-container");
  if (!container) return;

  try {
    const res = await fetch(`${BASE_API}/api/v1/portal/announcements`);
    const list = await res.json();

    container.innerHTML = list.map(a => `
      <div class="p-3 rounded-lg bg-gray-950/70 border border-gray-800 flex items-start justify-between gap-3 text-xs">
        <div class="space-y-1">
          <div class="flex items-center gap-2">
            <span class="font-bold text-white">${a.title}</span>
            <span class="text-[10px] font-mono px-1.5 py-0.2 rounded ${a.priority === 'HIGH' ? 'bg-red-500/20 text-red-400' : 'bg-gray-800 text-gray-400'}">${a.priority}</span>
          </div>
          <p class="text-gray-400 text-[11px]">${a.summary}</p>
        </div>
        <span class="text-[10px] text-gray-500 font-mono shrink-0">${a.date}</span>
      </div>
    `).join("");
  } catch (err) {}
}

// Password Reset Modal (3-History Policy)
function openPasswordResetModal(username) {
  const modal = document.getElementById("password-reset-modal");
  const alertEl = document.getElementById("reset-alert");
  alertEl.className = "hidden";
  alertEl.textContent = "";

  if (username) {
    document.getElementById("reset-username").value = username;
  } else if (currentUser) {
    document.getElementById("reset-username").value = currentUser.username;
  }
  modal.classList.remove("hidden");
  if (window.lucide) lucide.createIcons();
}

function closePasswordResetModal() {
  document.getElementById("password-reset-modal").classList.add("hidden");
}

async function handlePasswordReset(e) {
  e.preventDefault();
  const username = document.getElementById("reset-username").value.trim();
  const new_password = document.getElementById("reset-new-password").value;
  const confirm_password = document.getElementById("reset-confirm-password").value;
  const alertEl = document.getElementById("reset-alert");

  alertEl.className = "hidden";

  try {
    const res = await fetch(`${BASE_API}/api/v1/auth/reset-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, new_password, confirm_password })
    });

    const data = await res.json();

    if (res.ok) {
      alertEl.className = "p-3 rounded-lg text-xs font-mono bg-emerald-950/80 border border-emerald-500/60 text-emerald-300 block";
      alertEl.textContent = data.message;
      document.getElementById("quarantine-banner").classList.add("hidden");
      setTimeout(() => {
        closePasswordResetModal();
      }, 2500);
      fetchSOCData();
    } else {
      alertEl.className = "p-3 rounded-lg text-xs font-mono bg-red-950/80 border border-red-500/60 text-red-300 block";
      alertEl.textContent = data.detail || "Password policy violation.";
    }
  } catch (err) {
    alertEl.className = "p-3 rounded-lg text-xs font-mono bg-red-950/80 border border-red-500/60 text-red-300 block";
    alertEl.textContent = "Error: " + err.message;
  }
}

// SOC Console Data
async function fetchSOCData() {
  try {
    const statsRes = await fetch(`${BASE_API}/api/v1/soc/stats`);
    const stats = await statsRes.json();
    document.getElementById("kpi-total-events").textContent = stats.total_security_events;
    document.getElementById("kpi-active-incidents").textContent = stats.active_incidents;
    document.getElementById("kpi-locked-accounts").textContent = stats.quarantined_accounts;
    document.getElementById("kpi-blocked-ips").textContent = stats.blocked_perimeter_ips;

    const incRes = await fetch(`${BASE_API}/api/v1/soc/incidents?limit=50`);
    const incidents = await incRes.json();
    renderIncidents(incidents);

    const evRes = await fetch(`${BASE_API}/api/v1/soc/events?limit=30`);
    const events = await evRes.json();
    renderInitialTelemetry(events);
  } catch (err) {
    console.error("SOC Data load error", err);
  }
}

function renderIncidents(incidents) {
  const tbody = document.getElementById("incidents-table-body");
  document.getElementById("incidents-count").textContent = `${incidents.length} INCIDENTS`;

  tbody.innerHTML = incidents.map(inc => `
    <tr class="hover:bg-gray-900/50 transition-colors cursor-pointer" onclick="openIncidentModal('${inc.id}')">
      <td class="p-3 font-bold text-white flex items-center gap-1.5">
        <span class="w-1.5 h-1.5 rounded-full ${inc.severity === 'CRITICAL' ? 'bg-red-400' : 'bg-amber-400'}"></span>
        ${inc.incident_number}
      </td>
      <td class="p-3 text-gray-300">${inc.attack_type}</td>
      <td class="p-3">
        <span class="px-2 py-0.5 rounded text-[10px] font-bold ${inc.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/40' : (inc.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' : 'bg-yellow-500/20 text-yellow-300')}">
          ${inc.severity}
        </span>
      </td>
      <td class="p-3 text-gray-300">${inc.username || 'System'}</td>
      <td class="p-3 text-gray-400 font-mono text-[11px]">${inc.source_ip || 'Internal'}</td>
      <td class="p-3 text-right">
        <button onclick="event.stopPropagation(); openIncidentModal('${inc.id}')" class="px-2 py-1 text-[11px] rounded bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700">
          Triage
        </button>
      </td>
    </tr>
  `).join("");
}

function appendIncidentRow(inc, prepend = false) {
  const tbody = document.getElementById("incidents-table-body");
  const rowHtml = `
    <tr class="hover:bg-gray-900/50 transition-colors cursor-pointer bg-red-950/30" onclick="openIncidentModal('${inc.id}')">
      <td class="p-3 font-bold text-white flex items-center gap-1.5">
        <span class="w-1.5 h-1.5 rounded-full bg-red-400 animate-ping"></span>
        ${inc.incident_number}
      </td>
      <td class="p-3 text-gray-300">${inc.attack_type || inc.title}</td>
      <td class="p-3">
        <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/40">
          ${inc.severity}
        </span>
      </td>
      <td class="p-3 text-gray-300">${inc.username || 'System'}</td>
      <td class="p-3 text-gray-400 font-mono text-[11px]">${inc.source_ip || 'Internal'}</td>
      <td class="p-3 text-right">
        <button onclick="event.stopPropagation(); openIncidentModal('${inc.id}')" class="px-2 py-1 text-[11px] rounded bg-red-600 hover:bg-red-500 text-white font-bold">
          Review
        </button>
      </td>
    </tr>
  `;
  if (prepend) {
    tbody.insertAdjacentHTML("afterbegin", rowHtml);
  } else {
    tbody.insertAdjacentHTML("beforeend", rowHtml);
  }
}

function renderInitialTelemetry(events) {
  const container = document.getElementById("telemetry-log-stream");
  container.innerHTML = "";
  events.reverse().forEach(ev => appendTelemetryLog(ev));
}

function appendTelemetryLog(ev) {
  const container = document.getElementById("telemetry-log-stream");
  const timeStr = ev.timestamp ? ev.timestamp.split("T")[1]?.substring(0, 8) : new Date().toTimeString().split(" ")[0];
  const sevColor = ev.severity === "CRITICAL" ? "text-red-400 font-bold" : (ev.severity === "HIGH" ? "text-orange-400" : (ev.severity === "MEDIUM" ? "text-yellow-400" : "text-emerald-400"));

  const line = document.createElement("div");
  line.className = "hover:bg-gray-900/60 p-1 rounded transition-colors";
  line.innerHTML = `
    <span class="text-gray-500">[${timeStr}]</span>
    <span class="${sevColor}">[${ev.severity}]</span>
    <span class="text-white">${ev.event_type}</span>
    ${ev.username ? `<span class="text-cyan-400">usr=${ev.username}</span>` : ''}
    <span class="text-gray-400">ip=${ev.source_ip}</span>
  `;
  container.appendChild(line);
  container.scrollTop = container.scrollHeight;
}

function clearEventLogs() {
  document.getElementById("telemetry-log-stream").innerHTML = '<div class="text-gray-500">[SYS] Log buffer cleared by analyst.</div>';
}

function incrementKPICounter(id) {
  const el = document.getElementById(id);
  if (el) {
    const val = parseInt(el.textContent) || 0;
    el.textContent = val + 1;
  }
}

// Incident Modal
async function openIncidentModal(incidentId) {
  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/incidents/${incidentId}`);
    const inc = await res.json();
    currentIncident = inc;

    document.getElementById("modal-incident-title").textContent = inc.title;
    document.getElementById("modal-incident-badge").textContent = inc.severity;
    document.getElementById("modal-incident-meta").textContent = `${inc.incident_number} | Target: ${inc.username || 'N/A'} | Source: ${inc.source_ip || 'Internal'}`;

    const ai = inc.ai_summary || {};
    document.getElementById("modal-ai-summary").textContent = ai.executive_summary || "Automated AI triage summary generated.";
    document.getElementById("modal-detection-reason").textContent = ai.detection_reason || "Cadence anomaly detected exceeding rate limit.";

    const mitre = ai.mitre_attack || {};
    document.getElementById("modal-mitre-container").innerHTML = `
      <div class="p-3 rounded-lg bg-gray-900/80 border border-gray-800 space-y-1">
        <span class="text-[10px] text-gray-500 font-mono">TACTIC</span>
        <div class="text-white font-bold">${mitre.tactic || 'Credential Access'}</div>
      </div>
      <div class="p-3 rounded-lg bg-gray-900/80 border border-gray-800 space-y-1">
        <span class="text-[10px] text-gray-500 font-mono">TECHNIQUE</span>
        <div class="text-emerald-400 font-bold">${mitre.technique || inc.mitre_technique || 'T1110.001'}</div>
      </div>
    `;

    const actions = ai.recommended_response_actions || [
      "Keep account quarantined and require 3-history excluded password reset.",
      "Add source IP to border firewall drop list."
    ];
    document.getElementById("modal-actions-list").innerHTML = actions.map(act => `
      <li class="flex items-start gap-2">
        <span class="text-emerald-400">▹</span>
        <span>${act}</span>
      </li>
    `).join("");

    document.getElementById("modal-evidence-raw").textContent = JSON.stringify(inc.evidence_data || {}, null, 2);

    document.getElementById("incident-modal").classList.remove("hidden");
    if (window.lucide) lucide.createIcons();
  } catch (err) {
    alert("Load incident error: " + err.message);
  }
}

function closeIncidentModal() {
  document.getElementById("incident-modal").classList.add("hidden");
}

async function executeActionOnCurrentIncident(actionType) {
  if (!currentIncident) return;
  const target = (actionType === "block_ip" || actionType === "unblock_ip") ? currentIncident.source_ip : currentIncident.username;
  
  if (!target) {
    alert("No target available for this containment action.");
    return;
  }

  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/containment`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: actionType,
        target: target,
        reason: `SOC Containment on ${currentIncident.incident_number}`
      })
    });
    const result = await res.json();
    alert(result.message);
    fetchSOCData();
  } catch (err) {
    alert("Action failed: " + err.message);
  }
}

async function updateIncidentStatus(newStatus) {
  if (!currentIncident) return;
  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/incidents/${currentIncident.id}/status?new_status=${newStatus}`, {
      method: "PATCH"
    });
    if (res.ok) {
      alert(`Incident status updated to ${newStatus}.`);
      closeIncidentModal();
      fetchSOCData();
    }
  } catch (err) {
    alert("Status update failed: " + err.message);
  }
}

// Threat Hunt Search
async function handleThreatHunt(e) {
  const query = e.target.value.trim();
  if (e.key === "Enter" && query.length > 1) {
    try {
      const res = await fetch(`${BASE_API}/api/v1/soc/threat-hunt?query=${encodeURIComponent(query)}`);
      const events = await res.json();
      renderInitialTelemetry(events);
    } catch (err) {
      console.error(err);
    }
  }
}

// Attack Simulator
async function runSimulation(scenario) {
  const consoleEl = document.getElementById("sim-console");
  const logLine = (txt) => {
    consoleEl.innerHTML += `<div>${txt}</div>`;
    consoleEl.scrollTop = consoleEl.scrollHeight;
  };

  logLine(`\n[SIMULATOR] Launching scenario: ${scenario}...`);

  try {
    let endpoint = "";
    if (scenario === "human-friction") endpoint = "/api/v1/simulate/human-login-friction?target_user=john.doe";
    else if (scenario === "malware-burst") endpoint = "/api/v1/simulate/malware-brute-force?target_user=john.doe";
    else if (scenario === "sqli") endpoint = "/api/v1/simulate/sqli";
    else if (scenario === "xss") endpoint = "/api/v1/simulate/xss";
    else if (scenario === "port-scan") endpoint = "/api/v1/simulate/port-scan";

    const res = await fetch(`${BASE_API}${endpoint}`, { method: "POST" });
    const data = await res.json();

    logLine(`[STATUS ${res.status}] ${JSON.stringify(data, null, 2)}`);

    if (scenario === "malware-burst") {
      logLine(`[ALERT] HIGH VELOCITY BURST DETECTED -> Account Quarantined! Incident generated: ${data.incident_number}`);
    } else if (scenario === "human-friction") {
      logLine(`[BENIGN] Human friction tolerated. Account remains active.`);
    }

    fetchSOCData();
  } catch (err) {
    logLine(`[ERROR] Simulation failed: ${err.message}`);
  }
}

function clearSimConsole() {
  document.getElementById("sim-console").innerHTML = "<div>[SIM-CONSOLE READY] Buffer cleared.</div>";
}

// DFIR Report Export
function exportDFIRReport() {
  const report = `# ApexShield SOC Forensic Incident Investigation Report
Generated: ${new Date().toUTCString()}
System: ApexShield AI-SOC v2.0
Detection Engine: Active Defense (Sliding Window Velocity Analyzer)

## Executive Summary
This report documents security telemetry, automated brute-force burst detections, password history policy enforcement, and AI incident triage investigations.

## Detection Rules & Policies
1. **High-Velocity Brute Force (Malware / Automated)**: Triggered upon >= 5 failed logins within 15 seconds. Account is immediately quarantined, flagged for mandatory password reset, and mapped to MITRE T1110.001.
2. **Benign User Friction Baseline**: Tolerates 3-4 failed logins over 180 seconds with human typing jitter. No incident raised.
3. **Password History Hygiene**: Cryptographically prevents password reuse against the active password and the user's last 3 previous passwords using bcrypt salted hashes.

## Recommended SOC Next Steps
- Validate target account integrity via out-of-band identity check.
- Maintain source IP in perimeter firewall drop filter.
- Retain audit logs for forensics.
`;

  const blob = new Blob([report], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `ApexShield_DFIR_Incident_Report_${Date.now()}.md`;
  a.click();
}
