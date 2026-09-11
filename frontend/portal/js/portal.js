
let currentUser = null;
const BASE_API = "";

document.addEventListener("DOMContentLoaded", () => {
  if (window.lucide) lucide.createIcons();
  checkSession();
  fetchAnnouncements();
});

async function checkSession() {
  const token = localStorage.getItem("portal_token");
  if (!token) return;

  try {
    const res = await fetch(`${BASE_API}/api/v1/auth/me`, {
      headers: { "Authorization": `Bearer ${token}` }
    });
    if (res.ok) {
      currentUser = await res.json();
      renderDashboard();
    } else {
      localStorage.removeItem("portal_token");
    }
  } catch (err) {}
}

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;
  const frictionBox = document.getElementById("friction-banner");
  const quarantineBox = document.getElementById("quarantine-banner");

  frictionBox.classList.add("hidden");
  quarantineBox.classList.add("hidden");

  try {
    const res = await fetch(`${BASE_API}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (res.ok) {
      if (data.is_locked || data.must_reset_password) {
        quarantineBox.classList.remove("hidden");
        document.getElementById("reset-username").value = username;
      } else {
        localStorage.setItem("portal_token", data.access_token);
        currentUser = data.user;
        renderDashboard();
      }
    } else {
      if (data.detail && (data.detail.includes("friction") || data.detail.includes("Invalid password"))) {
        frictionBox.classList.remove("hidden");
        document.getElementById("friction-text").textContent = data.detail;
      } else if (res.status === 403 || (data.detail && (data.detail.includes("QUARANTINED") || data.detail.includes("Denied")))) {
        quarantineBox.classList.remove("hidden");
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
  localStorage.removeItem("portal_token");
  currentUser = null;
  document.getElementById("dashboard-view").classList.add("hidden");
  document.getElementById("auth-view").classList.remove("hidden");
  if (window.lucide) lucide.createIcons();
}

function renderDashboard() {
  document.getElementById("auth-view").classList.add("hidden");
  document.getElementById("dashboard-view").classList.remove("hidden");

  document.getElementById("user-display-name").textContent = currentUser.full_name;
  document.getElementById("user-initials").textContent = currentUser.full_name.split(" ").map(n=>n[0]).join("");
  document.getElementById("user-role-dept").textContent = `${currentUser.role} • ${currentUser.department}`;
  document.getElementById("user-email").textContent = currentUser.email;
  document.getElementById("user-clearance").textContent = currentUser.clearance_level;

  fetchDocuments();
  if (window.lucide) lucide.createIcons();
}

async function fetchDocuments() {
  const container = document.getElementById("documents-container");
  if (!container) return;

  try {
    const res = await fetch(`${BASE_API}/api/v1/portal/documents`);
    const docs = await res.json();

    container.innerHTML = docs.map(d => `
      <div class="portal-card p-4 flex flex-col justify-between space-y-3">
        <div>
          <div class="flex items-center justify-between mb-1.5">
            <span class="text-[10px] font-mono px-2 py-0.5 rounded ${d.classification === 'Top Secret' ? 'bg-red-500/20 text-red-400' : 'bg-sky-500/20 text-sky-300'}">
              ${d.classification}
            </span>
            <span class="text-[11px] text-gray-400">${d.department}</span>
          </div>
          <h4 class="text-sm font-bold text-white">${d.title}</h4>
          <p class="text-xs text-gray-400 mt-1">${d.description || ''}</p>
        </div>
        <button onclick="downloadDoc('${d.id}')" class="btn-portal-primary text-xs py-1.5 flex items-center justify-center gap-1.5 w-full">
          <i data-lucide="download" class="w-3.5 h-3.5"></i> Download Secure File
        </button>
      </div>
    `).join("");

    if (window.lucide) lucide.createIcons();
  } catch (err) {}
}

async function downloadDoc(docId) {
  const token = localStorage.getItem("portal_token");
  try {
    const res = await fetch(`${BASE_API}/api/v1/portal/documents/${docId}/download`, {
      headers: token ? { "Authorization": `Bearer ${token}` } : {}
    });
    const data = await res.json();
    if (res.ok) {
      alert(`[FILE ACCESS GRANTED: ${data.file_name}]

${data.content_preview}`);
    } else {
      alert(`SECURITY CLEARANCE DENIED:
${data.detail}`);
    }
  } catch (err) {
    alert("Download error: " + err.message);
  }
}

async function fetchAnnouncements() {
  const container = document.getElementById("announcements-container");
  if (!container) return;

  try {
    const res = await fetch(`${BASE_API}/api/v1/portal/announcements`);
    const list = await res.json();
    container.innerHTML = list.map(a => `
      <div class="p-3 rounded-lg bg-slate-900/60 border border-slate-800 flex items-start justify-between gap-3 text-xs">
        <div>
          <div class="flex items-center gap-2">
            <strong class="text-white">${a.title}</strong>
            <span class="text-[10px] px-1.5 py-0.5 rounded ${a.priority === 'HIGH' ? 'bg-red-500/20 text-red-400' : 'bg-slate-800 text-gray-400'}">${a.priority}</span>
          </div>
          <p class="text-gray-400 mt-1">${a.summary}</p>
        </div>
        <span class="text-[10px] text-gray-500 shrink-0 font-mono">${a.date}</span>
      </div>
    `).join("");
  } catch (err) {}
}

// Password Reset Modal Logic
function openResetModal(username) {
  document.getElementById("reset-modal").classList.remove("hidden");
  document.getElementById("reset-alert").classList.add("hidden");
  if (username) document.getElementById("reset-username").value = username;
  else if (currentUser) document.getElementById("reset-username").value = currentUser.username;
  if (window.lucide) lucide.createIcons();
}

function closeResetModal() {
  document.getElementById("reset-modal").classList.add("hidden");
}

async function handlePasswordReset(e) {
  e.preventDefault();
  const username = document.getElementById("reset-username").value.trim();
  const new_password = document.getElementById("reset-new-password").value;
  const confirm_password = document.getElementById("reset-confirm-password").value;
  const alertBox = document.getElementById("reset-alert");

  alertBox.classList.add("hidden");

  try {
    const res = await fetch(`${BASE_API}/api/v1/auth/reset-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, new_password, confirm_password })
    });
    const data = await res.json();

    if (res.ok) {
      alertBox.className = "p-3 rounded-lg text-xs font-mono bg-emerald-950/90 border border-emerald-500/60 text-emerald-200 block space-y-1";
      alertBox.innerHTML = `
        <div class="font-bold flex items-center gap-1.5 text-emerald-400">
          <i data-lucide="clock" class="w-4 h-4"></i> REQUEST QUEUED FOR APPROVAL
        </div>
        <p class="text-[11px] text-emerald-300 leading-relaxed">${data.message}</p>
      `;
      if (window.lucide) lucide.createIcons();
      document.getElementById("reset-new-password").value = "";
      document.getElementById("reset-confirm-password").value = "";
      setTimeout(() => {
        closeResetModal();
      }, 4000);
    } else {
      alertBox.className = "p-3 rounded-lg text-xs font-mono bg-red-950/80 border border-red-500/60 text-red-300 block";
      alertBox.textContent = data.detail || "Password reset rejected by policy.";
    }
  } catch (err) {
    alertBox.className = "p-3 rounded-lg text-xs font-mono bg-red-950/80 border border-red-500/60 text-red-300 block";
    alertBox.textContent = "Error: " + err.message;
  }
}
