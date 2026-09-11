
let currentSocUser = null;
let currentIncident = null;
let socket = null;
const BASE_API = "";

document.addEventListener("DOMContentLoaded", () => {
  if (window.lucide) lucide.createIcons();
  checkSocSession();
});

async function checkSocSession() {
  const token = localStorage.getItem("soc_token");
  if (!token) {
    showLoginView();
    return;
  }

  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/auth/me`, {
      headers: { "Authorization": `Bearer ${token}` }
    });
    if (res.ok) {
      currentSocUser = await res.json();
      renderSocConsole();
    } else {
      localStorage.removeItem("soc_token");
      showLoginView();
    }
  } catch (err) {
    showLoginView();
  }
}

function showLoginView() {
  document.getElementById("soc-auth-view").classList.remove("hidden");
  document.getElementById("soc-console-view").classList.add("hidden");
  if (window.lucide) lucide.createIcons();
}

async function handleSocLogin(e) {
  e.preventDefault();
  const username = document.getElementById("soc-username").value.trim();
  const password = document.getElementById("soc-password").value;
  const alertEl = document.getElementById("soc-login-alert");

  alertEl.classList.add("hidden");

  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (res.ok) {
      localStorage.setItem("soc_token", data.access_token);
      currentSocUser = data.user;
      renderSocConsole();
    } else {
      alertEl.classList.remove("hidden");
      alertEl.textContent = data.detail || "SOC Authentication Denied.";
    }
  } catch (err) {
    alertEl.classList.remove("hidden");
    alertEl.textContent = "Gateway Connection Error: " + err.message;
  }
}

function handleSocLogout() {
  localStorage.removeItem("soc_token");
  currentSocUser = null;
  showLoginView();
}

function renderSocConsole() {
  document.getElementById("soc-auth-view").classList.add("hidden");
  document.getElementById("soc-console-view").classList.remove("hidden");

  document.getElementById("soc-user-name").textContent = currentSocUser.full_name;
  document.getElementById("soc-user-role").textContent = currentSocUser.role;

  const adminBadge = document.getElementById("soc-admin-badge");
  const adminTabBtn = document.getElementById("tab-btn-coworkers");
  const lockdownCard = document.getElementById("emergency-lockdown-card");

  if (currentSocUser.is_admin) {
    adminBadge.classList.remove("hidden");
    adminTabBtn.classList.remove("hidden");
    lockdownCard.classList.remove("hidden");
  } else {
    adminBadge.classList.add("hidden");
    adminTabBtn.classList.add("hidden");
    lockdownCard.classList.add("hidden");
  }

  connectWebSocket();
  fetchSocStats();
  fetchIncidents();
  fetchPasswordRequests();
  fetchCoworkers();
  if (window.lucide) lucide.createIcons();
}

// Tab switcher inside SOC console
function switchSocSubTab(tabName) {
  const tabs = ["incidents", "approvals", "coworkers", "simulator"];
  tabs.forEach(t => {
    const section = document.getElementById(`subtab-${t}`);
    const btn = document.getElementById(`tab-btn-${t}`);
    if (section && btn) {
      if (t === tabName) {
        section.classList.remove("hidden");
        btn.className = "px-3 py-1.5 rounded-lg text-xs font-mono font-medium bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center gap-1.5 cursor-pointer";
      } else {
        section.classList.add("hidden");
        btn.className = "px-3 py-1.5 rounded-lg text-xs font-mono font-medium text-gray-400 hover:text-white border border-transparent flex items-center gap-1.5 cursor-pointer";
      }
    }
  });
  if (tabName === "coworkers") fetchCoworkers();
  if (tabName === "approvals") fetchPasswordRequests();
  if (window.lucide) lucide.createIcons();
}

// WebSocket Live Feeds
function connectWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/soc-stream`;

  socket = new WebSocket(wsUrl);

  socket.onopen = () => {
    document.getElementById("ws-status-badge").className = "pulse-green";
    document.getElementById("ws-status-label").textContent = "LIVE";
  };

  socket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === "NEW_SECURITY_EVENT") {
        appendTelemetryLog(data.event);
        incrementCounter("stat-events");
      } else if (data.type === "NEW_SECURITY_INCIDENT") {
        showLiveAlertBanner(data.incident);
        fetchIncidents();
        fetchSocStats();
      } else if (data.type === "NEW_PASSWORD_RESET_REQUEST" || data.type === "PASSWORD_RESET_RESOLVED") {
        fetchPasswordRequests();
        fetchSocStats();
      }
    } catch (e) {}
  };

  socket.onclose = () => {
    document.getElementById("ws-status-badge").className = "pulse-red";
    document.getElementById("ws-status-label").textContent = "DISCONNECTED";
    setTimeout(connectWebSocket, 3000);
  };
}

function showLiveAlertBanner(inc) {
  const banner = document.getElementById("live-threat-banner");
  banner.classList.remove("hidden");
  document.getElementById("alert-banner-text").textContent = 
    `[CRITICAL ALERT] High-Velocity Brute Force detected on employee '${inc.username}' from IP ${inc.source_ip}! Risk: ${inc.risk_score}/100`;
}

function dismissThreatBanner() {
  document.getElementById("live-threat-banner").classList.add("hidden");
}

function appendTelemetryLog(ev) {
  const container = document.getElementById("live-log-container");
  const time = ev.timestamp ? ev.timestamp.split("T")[1]?.substring(0, 8) : new Date().toTimeString().split(" ")[0];
  const sevColor = ev.severity === "CRITICAL" ? "text-red-400 font-bold" : (ev.severity === "HIGH" ? "text-orange-400" : (ev.severity === "MEDIUM" ? "text-yellow-400" : "text-emerald-400"));

  const line = document.createElement("div");
  line.className = "hover:bg-gray-900/60 p-1 rounded text-[11px] font-mono leading-tight";
  line.innerHTML = `
    <span class="text-gray-500">[${time}]</span>
    <span class="${sevColor}">[${ev.severity}]</span>
    <span class="text-white">${ev.event_type}</span>
    ${ev.username ? `<span class="text-cyan-400">usr=${ev.username}</span>` : ''}
    <span class="text-gray-400">ip=${ev.source_ip}</span>
  `;
  container.appendChild(line);
  container.scrollTop = container.scrollHeight;
}

function clearSocLogStream() {
  document.getElementById("live-log-container").innerHTML = "<div class='text-gray-500 font-mono text-xs'>[LOG BUFFER CLEARED] Listening for telemetry...</div>";
}

function incrementCounter(id) {
  const el = document.getElementById(id);
  if (el) el.textContent = (parseInt(el.textContent) || 0) + 1;
}

// SOC Stats & Incidents
async function fetchSocStats() {
  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/stats`);
    const data = await res.json();
    document.getElementById("stat-events").textContent = data.total_security_events;
    document.getElementById("stat-incidents").textContent = data.active_incidents;
    document.getElementById("stat-locked").textContent = data.quarantined_accounts;
    document.getElementById("stat-blocked-ips").textContent = data.blocked_perimeter_ips;
  } catch (err) {}
}

async function fetchIncidents() {
  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/incidents?limit=50`);
    const incidents = await res.json();
    const tbody = document.getElementById("incidents-table-body");
    document.getElementById("incident-count-badge").textContent = `${incidents.length} INCIDENTS`;

    tbody.innerHTML = incidents.map(inc => `
      <tr class="hover:bg-gray-900/50 transition-colors cursor-pointer border-b border-gray-800/60">
        <td class="p-3 font-mono font-bold text-white flex items-center gap-1.5">
          <span class="w-1.5 h-1.5 rounded-full ${inc.severity === 'CRITICAL' ? 'bg-red-500 animate-pulse' : 'bg-amber-400'}"></span>
          ${inc.incident_number}
        </td>
        <td class="p-3 text-gray-300 font-mono">${inc.attack_type}</td>
        <td class="p-3">
          <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold ${inc.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/40' : 'bg-amber-500/20 text-amber-300'}">
            ${inc.severity}
          </span>
        </td>
        <td class="p-3 text-cyan-300 font-mono">${inc.username || 'N/A'}</td>
        <td class="p-3 text-gray-400 font-mono text-[11px]">${inc.source_ip || 'Internal'}</td>
        <td class="p-3 text-right">
          <div class="flex items-center justify-end gap-1.5">
            <button onclick="executeAction('force_password_reset', '${inc.username}')" title="Force Password Reset" class="px-2 py-1 bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-300 border border-yellow-500/30 rounded text-[11px]">
              Reset PW
            </button>
            <button onclick="executeAction('block_ip', '${inc.source_ip}')" title="Block IP at Firewall" class="px-2 py-1 bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 rounded text-[11px]">
              Block IP
            </button>
            <button onclick="executeAction('unlock_account', '${inc.username}')" title="Unlock Account" class="px-2 py-1 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded text-[11px]">
              Unlock
            </button>
          </div>
        </td>
      </tr>
    `).join("");
  } catch (err) {}
}

async function executeAction(actionType, target) {
  if (!target) {
    alert("No target available.");
    return;
  }
  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/containment`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: actionType, target: target, reason: "SOC manual action" })
    });
    const result = await res.json();
    alert(result.message);
    fetchSocStats();
    fetchIncidents();
  } catch (err) {
    alert("Action failed: " + err.message);
  }
}

// Emergency Lockout Controls (Admin Only)
async function triggerEmergencyLockdown() {
  if (!confirm("CONFIRM EMERGENCY LOCKDOWN:\n\nThis will immediately quarantine and block ALL non-SOC employees from logging into the company website! Proceed?")) {
    return;
  }
  const token = localStorage.getItem("soc_token");
  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/actions/emergency-lockdown`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}` }
    });
    const data = await res.json();
    alert(data.message);
    fetchSocStats();
  } catch (err) {
    alert("Lockdown error: " + err.message);
  }
}

async function triggerEmergencyUnlock() {
  if (!confirm("CONFIRM LIFT LOCKDOWN:\n\nThis will release all quarantined employee accounts and permit logins. Proceed?")) {
    return;
  }
  const token = localStorage.getItem("soc_token");
  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/actions/emergency-unlock`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}` }
    });
    const data = await res.json();
    alert(data.message);
    fetchSocStats();
  } catch (err) {
    alert("Unlock error: " + err.message);
  }
}

// Co-Worker Management (Admin Only)
async function fetchCoworkers() {
  const token = localStorage.getItem("soc_token");
  if (!token) return;

  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/coworkers`, {
      headers: { "Authorization": `Bearer ${token}` }
    });
    const coworkers = await res.json();
    const tbody = document.getElementById("coworkers-table-body");

    tbody.innerHTML = coworkers.map(u => `
      <tr class="hover:bg-gray-900/50 border-b border-gray-800/60 font-mono text-xs">
        <td class="p-3 font-bold text-white">${u.full_name} (${u.username})</td>
        <td class="p-3 text-gray-300">${u.email}</td>
        <td class="p-3 text-emerald-400 font-semibold">${u.role}</td>
        <td class="p-3 text-gray-400">${u.clearance_level}</td>
        <td class="p-3">
          <span class="px-2 py-0.5 rounded text-[10px] ${u.is_locked ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}">
            ${u.is_locked ? 'LOCKED' : 'ACTIVE'}
          </span>
        </td>
        <td class="p-3 text-right">
          ${currentSocUser.is_admin && u.username !== 'admin' ? `
            <div class="flex items-center justify-end gap-2">
              <button onclick="openEditCoworkerModal('${u.id}', '${u.full_name}', '${u.role}', '${u.clearance_level}', ${u.is_locked})" class="px-2 py-1 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded text-[11px]">
                Edit
              </button>
              <button onclick="deleteCoworker('${u.id}', '${u.username}')" class="px-2 py-1 bg-red-900/40 hover:bg-red-900/80 text-red-300 border border-red-500/40 rounded text-[11px]">
                Delete
              </button>
            </div>
          ` : '<span class="text-gray-500 text-[11px]">Primary Admin</span>'}
        </td>
      </tr>
    `).join("");
  } catch (err) {}
}

function openAddCoworkerModal() {
  document.getElementById("add-coworker-modal").classList.remove("hidden");
  if (window.lucide) lucide.createIcons();
}

function closeAddCoworkerModal() {
  document.getElementById("add-coworker-modal").classList.add("hidden");
}

async function handleAddCoworker(e) {
  e.preventDefault();
  const token = localStorage.getItem("soc_token");
  const payload = {
    username: document.getElementById("new-coworker-username").value.trim(),
    full_name: document.getElementById("new-coworker-name").value.trim(),
    email: document.getElementById("new-coworker-email").value.trim(),
    role: document.getElementById("new-coworker-role").value,
    clearance_level: document.getElementById("new-coworker-clearance").value,
    password: document.getElementById("new-coworker-password").value
  };

  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/coworkers`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (res.ok) {
      alert(data.message);
      closeAddCoworkerModal();
      fetchCoworkers();
    } else {
      alert("Failed: " + data.detail);
    }
  } catch (err) {
    alert("Error: " + err.message);
  }
}

function openEditCoworkerModal(id, name, role, clearance, locked) {
  document.getElementById("edit-coworker-id").value = id;
  document.getElementById("edit-coworker-name").value = name;
  document.getElementById("edit-coworker-role").value = role;
  document.getElementById("edit-coworker-clearance").value = clearance;
  document.getElementById("edit-coworker-locked").value = locked ? "true" : "false";
  document.getElementById("edit-coworker-modal").classList.remove("hidden");
  if (window.lucide) lucide.createIcons();
}

function closeEditCoworkerModal() {
  document.getElementById("edit-coworker-modal").classList.add("hidden");
}

async function handleEditCoworker(e) {
  e.preventDefault();
  const token = localStorage.getItem("soc_token");
  const id = document.getElementById("edit-coworker-id").value;
  const newPw = document.getElementById("edit-coworker-newpw").value;

  const payload = {
    full_name: document.getElementById("edit-coworker-name").value.trim(),
    role: document.getElementById("edit-coworker-role").value,
    clearance_level: document.getElementById("edit-coworker-clearance").value,
    is_locked: document.getElementById("edit-coworker-locked").value === "true"
  };
  if (newPw) payload.new_password = newPw;

  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/coworkers/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (res.ok) {
      alert(data.message);
      closeEditCoworkerModal();
      fetchCoworkers();
    } else {
      alert("Failed: " + data.detail);
    }
  } catch (err) {
    alert("Error: " + err.message);
  }
}

async function deleteCoworker(id, username) {
  if (!confirm(`Delete SOC Analyst '${username}' permanently?`)) return;
  const token = localStorage.getItem("soc_token");
  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/coworkers/${id}`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${token}` }
    });
    const data = await res.json();
    alert(data.message);
    fetchCoworkers();
  } catch (err) {
    alert("Delete failed: " + err.message);
  }
}

// Simulator Trigger inside SOC
async function runAttackSim(mode) {
  const consoleEl = document.getElementById("sim-terminal");
  consoleEl.innerHTML += `\n[SIMULATOR] Firing test pattern: ${mode}...`;

  try {
    const endpoint = mode === "burst" 
      ? "/api/v1/simulate/malware-brute-force?target_user=john.doe" 
      : "/api/v1/simulate/human-login-friction?target_user=john.doe";
    
    const res = await fetch(`${BASE_API}${endpoint}`, { method: "POST" });
    const data = await res.json();
    consoleEl.innerHTML += `\n[RESPONSE ${res.status}] ${JSON.stringify(data, null, 2)}`;
    consoleEl.scrollTop = consoleEl.scrollHeight;
    fetchIncidents();
    fetchSocStats();
  } catch (e) {
    consoleEl.innerHTML += `\n[ERROR] ${e.message}`;
  }
}

// ==================== PASSWORD REQUEST APPROVAL WORKFLOW ====================
async function fetchPasswordRequests() {
  const token = localStorage.getItem("soc_token");
  if (!token) return;

  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/password-requests`, {
      headers: { "Authorization": `Bearer ${token}` }
    });
    if (!res.ok) return;
    const requests = await res.json();
    const tbody = document.getElementById("password-requests-table-body");
    const badge = document.getElementById("pending-approvals-badge");

    const pendingCount = requests.filter(r => r.status === "PENDING").length;
    if (badge) {
      if (pendingCount > 0) {
        badge.textContent = pendingCount;
        badge.classList.remove("hidden");
      } else {
        badge.classList.add("hidden");
      }
    }

    if (!tbody) return;

    if (requests.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-gray-500 font-mono">No password reset requests found.</td></tr>`;
      return;
    }

    tbody.innerHTML = requests.map(r => {
      const timeStr = r.created_at ? new Date(r.created_at).toLocaleString() : 'N/A';
      const isPending = r.status === "PENDING";
      const statusBadge = isPending
        ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">PENDING APPROVAL</span>'
        : (r.status === "APPROVED"
          ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">APPROVED</span>'
          : '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-300 border border-red-500/40">REJECTED</span>');

      const lockBadge = r.is_locked
        ? '<span class="text-red-400 font-bold">QUARANTINED</span>'
        : '<span class="text-emerald-400 font-bold">ACTIVE</span>';

      const actions = isPending
        ? `<div class="flex items-center justify-end gap-2">
            <button onclick="approvePasswordRequest('${r.id}', '${r.username}')" class="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded text-[11px] cursor-pointer">
              Approve & Unlock
            </button>
            <button onclick="rejectPasswordRequest('${r.id}', '${r.username}')" class="px-2.5 py-1 bg-red-900/50 hover:bg-red-900 text-red-300 border border-red-500/40 rounded text-[11px] cursor-pointer">
              Reject
            </button>
           </div>`
        : `<span class="text-gray-500 text-[11px] font-mono">${r.reviewed_by ? 'By: ' + r.reviewed_by : 'Resolved'}</span>`;

      return `
        <tr class="hover:bg-gray-900/50 border-b border-gray-800/60 font-mono text-xs">
          <td class="p-3 text-gray-400">${timeStr}</td>
          <td class="p-3 font-bold text-white">${r.full_name} (<span class="text-cyan-400">${r.username}</span>)</td>
          <td class="p-3 text-gray-300">${r.department}</td>
          <td class="p-3">${lockBadge}</td>
          <td class="p-3">${statusBadge}</td>
          <td class="p-3 text-gray-400">${r.reviewed_by || '—'}</td>
          <td class="p-3 text-right">${actions}</td>
        </tr>
      `;
    }).join("");

    if (window.lucide) lucide.createIcons();
  } catch (err) {
    console.error("Error fetching password requests:", err);
  }
}

async function approvePasswordRequest(requestId, username) {
  if (!confirm(`Authorize password reset and lift quarantine for user '${username}'?`)) return;
  const token = localStorage.getItem("soc_token");
  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/password-requests/${requestId}/approve`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}` }
    });
    const data = await res.json();
    if (res.ok) {
      alert(data.message);
      fetchPasswordRequests();
      fetchSocStats();
      fetchIncidents();
    } else {
      alert("Approval failed: " + (data.detail || "Unknown error"));
    }
  } catch (err) {
    alert("Approval error: " + err.message);
  }
}

async function rejectPasswordRequest(requestId, username) {
  if (!confirm(`Reject password reset request for user '${username}'?`)) return;
  const token = localStorage.getItem("soc_token");
  try {
    const res = await fetch(`${BASE_API}/api/v1/soc/password-requests/${requestId}/reject`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}` }
    });
    const data = await res.json();
    if (res.ok) {
      alert(data.message);
      fetchPasswordRequests();
    } else {
      alert("Rejection failed: " + (data.detail || "Unknown error"));
    }
  } catch (err) {
    alert("Rejection error: " + err.message);
  }
}

