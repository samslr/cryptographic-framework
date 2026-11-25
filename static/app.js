/**
 * CyberVault — SOC Cryptographic Operations Console
 * Vanilla ES6+ Application Logic
 */

const $ = (id) => document.getElementById(id);
let activeCsrfToken = "";
let currentSessionUser = null;
let pendingDeleteKeyId = null;
let auditPagination = { offset: 0, limit: 25, total: 0 };

// --- Toast Notification Engine ---
function toast(message, type = "info") {
  const container = $("toast-container");
  if (!container) return;
  const t = document.createElement("div");
  t.className = `toast ${type}`;
  const icon = type === "success" ? "✓" : type === "error" ? "⚠" : "◈";
  t.innerHTML = `<span>${icon}</span><span>${escapeHtml(message)}</span>`;
  container.appendChild(t);
  setTimeout(() => {
    t.style.opacity = "0";
    t.style.transform = "translateX(20px)";
    setTimeout(() => t.remove(), 250);
  }, 3500);
}

// --- Universal API Client ---
async function api(url, options = {}) {
  const headers = { ...options.headers };
  if (!(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }
  if (activeCsrfToken) {
    headers["X-CSRF-Token"] = activeCsrfToken;
  }

  const response = await fetch(url, { ...options, headers });
  const contentType = response.headers.get("content-type") || "";

  if (contentType.includes("application/octet-stream") || contentType.includes("text/csv")) {
    if (!response.ok) throw new Error(`Download failed with status ${response.status}`);
    return response.blob();
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data;
}

const post = (url, body) => api(url, { method: "POST", body: JSON.stringify(body) });

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// --- Navigation & Panel State Machine ---
function switchTab(tabId) {
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === tabId));
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.tab === tabId));

  const titles = {
    overview: "Overview Dashboard",
    symmetric: "01 · Symmetric Encryption (AES-GCM)",
    asymmetric: "02 · Asymmetric Encryption & Digital Signatures",
    hashing: "03 · Hashing, Integrity & Avalanche Lab",
    keys: "04 · Key Inventory & Vault Storage",
    analytics: "05 · Cryptographic Performance Analytics",
    architecture: "06 · System Architecture Visualizer",
    audit: "07 · Audit Trail & Monitoring"
  };
  $("page-title").textContent = titles[tabId] || "Overview Dashboard";

  if (tabId === "overview") { loadStats(); loadOverviewAudit(); }
  if (tabId === "keys" || tabId === "symmetric" || tabId === "asymmetric") loadKeys();
  if (tabId === "analytics") loadBenchmarks();
  if (tabId === "audit") loadAudit();
}

document.querySelectorAll("[data-tab]").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

// Sidebar Toggle
$("toggle-sidebar")?.addEventListener("click", () => {
  $("sidebar").classList.toggle("collapsed");
});

// Sub-Tab Switcher
document.querySelectorAll(".tab-pill").forEach((pill) => {
  pill.addEventListener("click", () => {
    const parent = pill.closest(".panel");
    parent.querySelectorAll(".tab-pill").forEach((p) => p.classList.remove("active"));
    parent.querySelectorAll(".subtab-content").forEach((c) => c.style.display = "none");
    pill.classList.add("active");
    const target = $(pill.dataset.subtab);
    if (target) target.style.display = "block";
  });
});

// --- Modal Helpers ---
function openModal(id) { $(id)?.classList.add("show"); }
function closeModal(id) { $(id)?.classList.remove("show"); }

// --- Authentication & User Session ---
async function checkAuthSession() {
  try {
    const data = await api("/api/auth/me");
    activeCsrfToken = data.csrf_token || "";
    currentSessionUser = data.user;
    updateUserBadge(data.user);
  } catch (err) {
    console.error("Auth check failed:", err);
  }
}

function updateUserBadge(user) {
  const username = user?.username || "guest";
  const role = user?.role || "Viewer";
  $("user-name-display").textContent = username;
  $("user-role-display").textContent = role;
  $("role-pill-text").textContent = `Role: ${role}`;
  $("user-avatar").textContent = username.charAt(0).toUpperCase();
}

$("btn-open-login")?.addEventListener("click", () => openModal("modal-login"));
$("btn-quick-role")?.addEventListener("click", () => openModal("modal-login"));

$("btn-do-login")?.addEventListener("click", async () => {
  try {
    const username = $("login-username").value.trim();
    const password = $("login-password").value;
    const res = await post("/api/auth/login", { username, password });
    activeCsrfToken = res.csrf_token;
    currentSessionUser = res.user;
    updateUserBadge(res.user);
    closeModal("modal-login");
    toast(`Authenticated as ${res.user.username} (${res.user.role})`, "success");
    loadStats();
    loadKeys();
  } catch (err) {
    toast(err.message, "error");
  }
});

// --- Overview Dashboard & Statistics ---
async function loadStats() {
  try {
    const s = await api("/api/stats");
    $("stat-ops").textContent = s.operations.toLocaleString();
    $("stat-rate").textContent = `${s.success_rate}%`;
    $("stat-keys").textContent = s.active_keys;
    $("stat-retired-keys").textContent = `${s.retired_keys} retired keys`;
    $("stat-enc").textContent = s.encryptions_count;
    $("stat-dec").textContent = `${s.decryptions_count} decryptions`;
    $("stat-signatures").textContent = s.signatures_count;
    $("stat-checks").textContent = s.verification_checks;

    renderOverviewCharts(s);
  } catch (err) {
    console.error("Stats load failed:", err);
  }
}

function renderOverviewCharts(stats) {
  // SVG Distribution Donut Chart
  const enc = stats.encryptions_count || 1;
  const dec = stats.decryptions_count || 0;
  const sig = stats.signatures_count || 0;
  const chk = stats.verification_checks || 0;
  const total = enc + dec + sig + chk || 1;

  const pEnc = (enc / total) * 100;
  const pDec = (dec / total) * 100;
  const pSig = (sig / total) * 100;
  const pChk = (chk / total) * 100;

  const donut = `
    <svg viewBox="0 0 100 100" style="width:100%; height:100%; max-height:200px;">
      <circle cx="50" cy="50" r="38" fill="none" stroke="#162238" stroke-width="14" />
      <circle cx="50" cy="50" r="38" fill="none" stroke="#00f0ff" stroke-width="14"
        stroke-dasharray="${pEnc * 2.38} 238" stroke-dashoffset="0" />
      <circle cx="50" cy="50" r="38" fill="none" stroke="#38bdf8" stroke-width="14"
        stroke-dasharray="${pDec * 2.38} 238" stroke-dashoffset="-${pEnc * 2.38}" />
      <circle cx="50" cy="50" r="38" fill="none" stroke="#818cf8" stroke-width="14"
        stroke-dasharray="${pSig * 2.38} 238" stroke-dashoffset="-${(pEnc + pDec) * 2.38}" />
      <circle cx="50" cy="50" r="38" fill="none" stroke="#10b981" stroke-width="14"
        stroke-dasharray="${pChk * 2.38} 238" stroke-dashoffset="-${(pEnc + pDec + pSig) * 2.38}" />
      <text x="50" y="48" text-anchor="middle" fill="#fff" font-size="12" font-weight="bold">${stats.operations}</text>
      <text x="50" y="60" text-anchor="middle" fill="#94a3b8" font-size="7">OPERATIONS</text>
    </svg>
    <div style="display:flex; justify-content:center; gap:12px; font-size:10px; font-family:var(--font-mono); margin-top:8px;">
      <span style="color:#00f0ff;">■ Encrypt (${Math.round(pEnc)}%)</span>
      <span style="color:#38bdf8;">■ Decrypt (${Math.round(pDec)}%)</span>
      <span style="color:#818cf8;">■ Sign (${Math.round(pSig)}%)</span>
      <span style="color:#10b981;">■ Verify (${Math.round(pChk)}%)</span>
    </div>
  `;
  $("chart-distribution").innerHTML = donut;

  // Simple SVG Operations Trend Bar Chart
  $("chart-volume").innerHTML = `
    <svg viewBox="0 0 300 120" style="width:100%; height:100%; max-height:160px; margin-top:15px;">
      <line x1="20" y1="100" x2="280" y2="100" stroke="#1e2c45" stroke-width="1" />
      <rect x="40" y="${100 - Math.min(enc * 5, 80)}" width="30" height="${Math.min(enc * 5, 80)}" fill="#00f0ff" rx="4" />
      <rect x="100" y="${100 - Math.min(dec * 5, 80)}" width="30" height="${Math.min(dec * 5, 80)}" fill="#38bdf8" rx="4" />
      <rect x="160" y="${100 - Math.min(sig * 5, 80)}" width="30" height="${Math.min(sig * 5, 80)}" fill="#818cf8" rx="4" />
      <rect x="220" y="${100 - Math.min(chk * 5, 80)}" width="30" height="${Math.min(chk * 5, 80)}" fill="#10b981" rx="4" />
      <text x="55" y="114" fill="#94a3b8" font-size="9" text-anchor="middle">ENC</text>
      <text x="115" y="114" fill="#94a3b8" font-size="9" text-anchor="middle">DEC</text>
      <text x="175" y="114" fill="#94a3b8" font-size="9" text-anchor="middle">SIGN</text>
      <text x="235" y="114" fill="#94a3b8" font-size="9" text-anchor="middle">VERIFY</text>
    </svg>
  `;
}

async function loadOverviewAudit() {
  try {
    const { logs } = await api("/api/audit?limit=6");
    const tbody = $("overview-audit-table");
    if (!logs || !logs.length) {
      tbody.innerHTML = `<tr><td colspan="7">No security operations recorded yet.</td></tr>`;
      return;
    }
    tbody.innerHTML = logs.map((l) => `
      <tr>
        <td>${new Date(l.created_at).toLocaleTimeString()}</td>
        <td class="mono" style="font-size:11px;">${escapeHtml(l.operation_id?.slice(0, 8))}...</td>
        <td><strong>${escapeHtml(l.user_id || 'system')}</strong></td>
        <td>${escapeHtml(l.action)}</td>
        <td><span class="mono">${escapeHtml(l.algorithm)}</span></td>
        <td><span class="status-badge ${l.status === 'SUCCESS' ? 'success' : 'failure'}">${l.status}</span></td>
        <td>${l.duration_ms} ms</td>
      </tr>
    `).join("");
  } catch (err) {
    console.error("Overview audit error:", err);
  }
}

// --- Key Management Engine ---
async function loadKeys() {
  try {
    const { keys } = await api("/api/keys");
    const symKeys = keys.filter((k) => k.key_type === "SYMMETRIC");
    const asymKeys = keys.filter((k) => k.key_type === "ASYMMETRIC");

    fillDropdown("aes-key", symKeys, "Select Active AES Key");
    fillDropdown("aes-decrypt-key", symKeys, "Select AES Key for Decryption", true);
    fillDropdown("file-enc-key", symKeys, "Select AES Key");
    fillDropdown("file-dec-key", symKeys, "Select AES Key", true);

    fillDropdown("rsa-encrypt-key", asymKeys, "Select Recipient's RSA Key Pair");
    fillDropdown("rsa-decrypt-key", asymKeys, "Select RSA Key Pair for Decryption", true);
    fillDropdown("sign-key", asymKeys, "Select Signing Key Pair");
    fillDropdown("verify-key", asymKeys, "Select Verification Public Key", true);

    const tbody = $("keys-table");
    if (!keys || !keys.length) {
      tbody.innerHTML = `<tr><td colspan="9">No cryptographic keys found in vault. Generate an AES or RSA key above.</td></tr>`;
      return;
    }

    tbody.innerHTML = keys.map((k) => `
      <tr>
        <td>#${k.id}</td>
        <td><strong>${escapeHtml(k.name)}</strong></td>
        <td>${k.key_type}</td>
        <td class="mono">${escapeHtml(k.algorithm)}</td>
        <td class="mono" style="font-size:11px; color:var(--cyan);">${escapeHtml(k.fingerprint || 'N/A')}</td>
        <td><span class="status-badge ${k.status === 'ACTIVE' ? 'active' : 'rotated'}">${k.status}</span></td>
        <td>${k.usage_count || 0}</td>
        <td>${new Date(k.created_at).toLocaleDateString()}</td>
        <td>
          ${k.key_type === 'ASYMMETRIC' ? `<button class="btn-secondary btn-sm" onclick="exportPublicKey(${k.id})">Export PEM</button>` : ''}
          ${k.status === 'ACTIVE' ? `<button class="btn-secondary btn-sm" onclick="rotateKeyPrompt(${k.id})">Rotate</button>` : ''}
          <button class="btn-danger btn-sm" onclick="openDeleteKeyModal(${k.id}, '${escapeHtml(k.name)}')">Delete</button>
        </td>
      </tr>
    `).join("");
  } catch (err) {
    toast(err.message, "error");
  }
}

function fillDropdown(id, items, placeholder, includeInactive = false) {
  const el = $(id);
  if (!el) return;
  const current = el.value;
  const validItems = includeInactive ? items : items.filter((k) => k.status === "ACTIVE");
  el.innerHTML = `<option value="">${placeholder}</option>` +
    validItems.map((k) => `<option value="${k.id}">#${k.id} · ${escapeHtml(k.name)} (${k.status})</option>`).join("");
  if ([...el.options].some((o) => o.value === current)) el.value = current;
}

$("create-aes-key")?.addEventListener("click", async () => {
  try {
    const name = $("aes-key-name").value.trim();
    const r = await post("/api/keys/aes", { name });
    toast(r.message, "success");
    $("aes-key-name").value = "";
    loadKeys();
    loadStats();
  } catch (err) { toast(err.message, "error"); }
});

$("create-rsa-key")?.addEventListener("click", async () => {
  try {
    const name = $("rsa-key-name").value.trim();
    toast("Generating 2048-bit RSA pair (this takes ~0.5s)...", "info");
    const r = await post("/api/keys/rsa", { name });
    toast(r.message, "success");
    $("rsa-key-name").value = "";
    loadKeys();
    loadStats();
  } catch (err) { toast(err.message, "error"); }
});

$("refresh-keys")?.addEventListener("click", loadKeys);

async function rotateKeyPrompt(id) {
  if (!confirm(`Rotate Key #${id}? The current key will be marked ROTATED and retained for historical decryption.`)) return;
  try {
    const r = await post(`/api/keys/${id}/rotate`, {});
    toast(r.message, "success");
    loadKeys();
    loadStats();
  } catch (err) { toast(err.message, "error"); }
}

function openDeleteKeyModal(id, name) {
  pendingDeleteKeyId = id;
  $("delete-key-name").textContent = `Key #${id} ("${name}")`;
  openModal("modal-delete-key");
}

$("btn-confirm-delete-key")?.addEventListener("click", async () => {
  if (!pendingDeleteKeyId) return;
  try {
    const r = await api(`/api/keys/${pendingDeleteKeyId}`, { method: "DELETE" });
    closeModal("modal-delete-key");
    toast(r.message, "success");
    loadKeys();
    loadStats();
  } catch (err) { toast(err.message, "error"); }
});

async function exportPublicKey(keyId) {
  try {
    const data = await api(`/api/keys/${keyId}/public`);
    $("export-pem-fingerprint").value = data.fingerprint;
    $("export-pem-text").value = data.public_pem;
    openModal("modal-export-pem");
  } catch (err) { toast(err.message, "error"); }
}

$("btn-copy-pem")?.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("export-pem-text").value);
    toast("Public key PEM copied to clipboard.", "success");
  } catch { toast("Clipboard write unavailable.", "error"); }
});

// --- Module 01: Symmetric Encryption (Text & File) ---
$("aes-encrypt")?.addEventListener("click", async () => {
  try {
    const key_id = $("aes-key").value;
    const text = $("aes-plain").value;
    const r = await post("/api/symmetric/encrypt", { key_id, text });
    const payloadStr = JSON.stringify(r, null, 2);
    $("aes-output").value = payloadStr;
    $("aes-input").value = JSON.stringify(r);
    $("aes-decrypt-key").value = String(r.key_id);
    $("aes-enc-telemetry").style.display = "inline-flex";
    $("aes-enc-telemetry").textContent = `⚡ Latency: ${r.duration_ms} ms | In: ${r.input_bytes} B | Out: ${r.output_bytes} B`;
    toast("AES-256-GCM encryption successful.", "success");
    loadStats();
  } catch (err) { toast(err.message, "error"); }
});

$("aes-copy")?.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("aes-output").value);
    toast("Encrypted JSON copied to clipboard.", "success");
  } catch { toast("Clipboard unavailable.", "error"); }
});

$("aes-decrypt")?.addEventListener("click", async () => {
  const resultBox = $("aes-result-box");
  try {
    const p = JSON.parse($("aes-input").value);
    const key_id = $("aes-decrypt-key").value || p.key_id;
    const r = await post("/api/symmetric/decrypt", { key_id, nonce: p.nonce, ciphertext: p.ciphertext });
    $("aes-recovered").value = r.plaintext;
    $("aes-dec-telemetry").style.display = "inline-flex";
    $("aes-dec-telemetry").textContent = `⚡ Latency: ${r.duration_ms} ms | Tag check: VALID`;
    resultBox.className = "result-box show valid";
    resultBox.textContent = `✓ ${r.message}`;
    toast("Authenticated decryption successful.", "success");
    loadStats();
  } catch (err) {
    resultBox.className = "result-box show invalid";
    resultBox.textContent = `⚠ ${err.message}`;
    toast(err.message, "error");
  }
});

// Symmetric File Encryption
$("btn-file-encrypt")?.addEventListener("click", async () => {
  const file = $("file-enc-input")?.files[0];
  const key_id = $("file-enc-key")?.value;
  if (!file) { toast("Please select a file to encrypt.", "error"); return; }
  if (!key_id) { toast("Please choose an AES key.", "error"); return; }

  const form = new FormData();
  form.append("file", file);
  form.append("key_id", key_id);

  try {
    toast("Encrypting file container...", "info");
    const blob = await api("/api/symmetric/encrypt-file", { method: "POST", body: form });
    downloadBlob(blob, `${file.name}.enc`);
    $("file-enc-status").style.display = "inline-flex";
    $("file-enc-status").textContent = `✓ Encrypted container created (${blob.size} bytes)`;
    toast("File encrypted & download started.", "success");
    loadStats();
  } catch (err) { toast(err.message, "error"); }
});

// Symmetric File Decryption
$("btn-file-decrypt")?.addEventListener("click", async () => {
  const file = $("file-dec-input")?.files[0];
  const key_id = $("file-dec-key")?.value;
  if (!file) { toast("Please select a .enc file to decrypt.", "error"); return; }
  if (!key_id) { toast("Please choose an AES key.", "error"); return; }

  const form = new FormData();
  form.append("file", file);
  form.append("key_id", key_id);

  try {
    toast("Decrypting and authenticating file container...", "info");
    const blob = await api("/api/symmetric/decrypt-file", { method: "POST", body: form });
    const outputName = file.name.endsWith(".enc") ? file.name.slice(0, -4) : `recovered_${file.name}`;
    downloadBlob(blob, outputName);
    $("file-dec-status").style.display = "inline-flex";
    $("file-dec-status").textContent = `✓ File decrypted & verified (${blob.size} bytes)`;
    toast("File decrypted & download started.", "success");
    loadStats();
  } catch (err) { toast(err.message, "error"); }
});

function downloadBlob(blob, filename) {
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

// --- Module 02: Asymmetric & Signatures ---
$("rsa-encrypt")?.addEventListener("click", async () => {
  try {
    const key_id = $("rsa-encrypt-key").value;
    const text = $("rsa-plain").value;
    const r = await post("/api/asymmetric/encrypt", { key_id, text });
    $("rsa-output").value = JSON.stringify(r, null, 2);
    $("rsa-input").value = JSON.stringify(r);
    $("rsa-decrypt-key").value = String(r.key_id);
    $("rsa-enc-telemetry").style.display = "inline-flex";
    $("rsa-enc-telemetry").textContent = `⚡ Latency: ${r.duration_ms} ms | Content Encrypted: ${r.input_bytes} B`;
    toast("RSA-OAEP hybrid encryption complete.", "success");
    loadStats();
  } catch (err) { toast(err.message, "error"); }
});

$("rsa-decrypt")?.addEventListener("click", async () => {
  try {
    const p = JSON.parse($("rsa-input").value);
    const key_id = $("rsa-decrypt-key").value || p.key_id;
    const r = await post("/api/asymmetric/decrypt", {
      key_id,
      wrapped_key: p.wrapped_key,
      nonce: p.nonce,
      ciphertext: p.ciphertext
    });
    $("rsa-recovered").value = r.plaintext;
    $("rsa-dec-telemetry").style.display = "inline-flex";
    $("rsa-dec-telemetry").textContent = `⚡ Latency: ${r.duration_ms} ms | Key unwrap: OK`;
    toast("Hybrid decryption successful.", "success");
    loadStats();
  } catch (err) { toast(err.message, "error"); }
});

$("sign-button")?.addEventListener("click", async () => {
  try {
    const key_id = $("sign-key").value;
    const text = $("sign-text").value;
    const r = await post("/api/sign", { key_id, text });
    $("signature-output").value = r.signature;
    $("verify-text").value = $("sign-text").value;
    $("verify-signature").value = r.signature;
    $("verify-key").value = String(r.key_id);
    $("sign-telemetry").style.display = "inline-flex";
    $("sign-telemetry").textContent = `⚡ Latency: ${r.duration_ms} ms | Salt: PSS_MAX`;
    toast("RSA-PSS digital signature generated.", "success");
    loadStats();
  } catch (err) { toast(err.message, "error"); }
});

$("verify-button")?.addEventListener("click", async () => {
  const box = $("signature-result");
  try {
    const key_id = $("verify-key").value;
    const text = $("verify-text").value;
    const signature = $("verify-signature").value;
    const r = await post("/api/verify", { key_id, text, signature });
    box.className = `result-box show ${r.valid ? 'valid' : 'invalid'}`;
    box.textContent = r.result;
    $("verify-telemetry").style.display = "inline-flex";
    $("verify-telemetry").textContent = `⚡ Verification Latency: ${r.duration_ms} ms`;
    loadStats();
  } catch (err) {
    box.className = "result-box show invalid";
    box.textContent = `⚠ ${err.message}`;
    toast(err.message, "error");
  }
});

// --- Module 03: Hashing & Avalanche Effect ---
$("hash-generate")?.addEventListener("click", async () => {
  try {
    const algorithm = $("hash-alg").value;
    const text = $("hash-text").value;
    const r = await post("/api/hash", { algorithm, text });
    $("hash-output").value = r.hash;
    $("expected-hash").value = r.hash;
    $("verify-hash-text").value = text;
    $("verify-hash-alg").value = r.algorithm;
    $("hash-telemetry").style.display = "inline-flex";
    $("hash-telemetry").textContent = `⚡ Digest latency: ${r.duration_ms} ms`;
    toast(`${r.algorithm} computed.`, "success");
    loadStats();
  } catch (err) { toast(err.message, "error"); }
});

$("hash-verify")?.addEventListener("click", async () => {
  const box = $("hash-result");
  try {
    const algorithm = $("verify-hash-alg").value;
    const text = $("verify-hash-text").value;
    const expected_hash = $("expected-hash").value;
    const r = await post("/api/hash/verify", { algorithm, text, expected_hash });
    box.className = `result-box show ${r.valid ? 'valid' : 'invalid'}`;
    box.textContent = `${r.result}\nComputed: ${r.actual_hash}`;
    loadStats();
  } catch (err) {
    box.className = "result-box show invalid";
    box.textContent = `⚠ ${err.message}`;
    toast(err.message, "error");
  }
});

$("file-hash-button")?.addEventListener("click", async () => {
  const file = $("hash-file")?.files[0];
  const algorithm = $("file-hash-alg")?.value;
  if (!file) { toast("Please select a file to hash.", "error"); return; }

  const form = new FormData();
  form.append("file", file);
  form.append("algorithm", algorithm);

  try {
    const r = await api("/api/hash/file", { method: "POST", body: form });
    const box = $("file-hash-result");
    box.className = "result-box show valid";
    box.textContent = `File: ${r.filename} (${r.size_bytes.toLocaleString()} bytes)\nAlgorithm: ${r.algorithm}\nDigest: ${r.hash}\nLatency: ${r.duration_ms} ms`;
    toast("File hash calculated.", "success");
    loadStats();
  } catch (err) { toast(err.message, "error"); }
});

// Avalanche Effect Lab
$("btn-flip-bit")?.addEventListener("click", () => {
  const str = $("aval-input-a").value;
  if (!str) return;
  const firstCode = str.charCodeAt(0) ^ 1;
  $("aval-input-b").value = String.fromCharCode(firstCode) + str.slice(1);
  toast("Flipped 1 bit in Input B.", "info");
});

$("btn-run-avalanche")?.addEventListener("click", async () => {
  try {
    const input_a = $("aval-input-a").value;
    const input_b = $("aval-input-b").value;
    const algorithm = $("aval-alg").value;
    const r = await post("/api/hash/avalanche", { input_a, input_b, algorithm });

    $("aval-percent").textContent = `${r.change_percentage}%`;
    $("aval-changed").textContent = r.changed_bits;
    $("aval-total-bits").textContent = `out of ${r.total_bits} bits`;
    $("aval-quality").textContent = r.avalanche_quality;

    const matrix = $("bit-matrix");
    matrix.innerHTML = r.bit_map.map((diff, idx) => `
      <div class="bit-cell ${diff ? 'changed' : 'unchanged'}" title="Bit ${idx}: ${diff ? 'CHANGED' : 'UNCHANGED'}">${diff}</div>
    `).join("");

    toast(`Avalanche metric: ${r.change_percentage}% changed bits.`, "success");
  } catch (err) { toast(err.message, "error"); }
});

// --- Module 05: Performance Benchmarks ---
async function loadBenchmarks() {
  try {
    const data = await api("/api/benchmarks/latest");
    renderBenchmarkData(data);
  } catch (err) {
    console.error("Benchmark load error:", err);
  }
}

$("btn-run-benchmark")?.addEventListener("click", async () => {
  try {
    $("benchmark-status").textContent = "Executing CPU benchmarks on server...";
    toast("Running real cryptographic hardware benchmarks...", "info");
    const data = await post("/api/benchmarks/run", {});
    renderBenchmarkData(data);
    $("benchmark-status").textContent = `Benchmark completed at ${new Date(data.timestamp * 1000).toLocaleTimeString()}`;
    toast("Benchmarks completed successfully.", "success");
  } catch (err) {
    $("benchmark-status").textContent = "Benchmark failed.";
    toast(err.message, "error");
  }
});

function renderBenchmarkData(data) {
  if (!data) return;

  // Symmetric Table
  const aesTbody = $("bench-aes-table");
  if (data.symmetric_aes_gcm) {
    aesTbody.innerHTML = data.symmetric_aes_gcm.map((row) => `
      <tr>
        <td><strong>${row.size_label}</strong></td>
        <td>${row.encrypt_ms} ms</td>
        <td style="color:var(--cyan); font-weight:700;">${row.encrypt_mb_s} MB/s</td>
        <td>${row.decrypt_ms} ms</td>
      </tr>
    `).join("");
  }

  // Hashing Table
  const hashTbody = $("bench-hash-table");
  if (data.hashing) {
    hashTbody.innerHTML = data.hashing.map((row) => `
      <tr>
        <td><strong>${row.size_label}</strong></td>
        <td style="color:var(--cyan); font-weight:700;">${row.sha256_mb_s} MB/s</td>
        <td style="color:var(--blue); font-weight:700;">${row.sha512_mb_s} MB/s</td>
      </tr>
    `).join("");
  }

  // RSA Summary
  if (data.asymmetric_rsa) {
    $("rsa-keygen-time").textContent = `${data.asymmetric_rsa.keygen_ms} ms`;
    $("rsa-enc-time").textContent = `${data.asymmetric_rsa.hybrid_encrypt_ms} ms`;
    $("rsa-dec-time").textContent = `${data.asymmetric_rsa.hybrid_decrypt_ms} ms`;
  }

  // Signature Summary
  if (data.signatures_rsa_pss) {
    $("sig-sign-time").textContent = `${data.signatures_rsa_pss.sign_ms} ms`;
    $("sig-ver-time").textContent = `${data.signatures_rsa_pss.verify_ms} ms`;
    $("sig-rate").textContent = `${data.signatures_rsa_pss.sign_ops_per_sec} ops/sec`;
  }
}

// --- Module 06: Architecture Visualizer ---
const ARCH_NODES = {
  ui: {
    title: "User Interface (Presentation Layer)",
    badge: "Client SPA · Vanilla HTML5/CSS3/JS",
    content: "Enterprise Single-Page Dashboard engineered with zero external client frameworks. Enforces client-side validation, handles Base64 serialization, manages CSRF token headers, and executes non-blocking file streaming."
  },
  api: {
    title: "Flask REST API Gateway (Application Layer)",
    badge: "Python 3.14 · Flask 3.1.3 · Werkzeug",
    content: "Central API controller layer. Implements rate limiting per IP (sliding-window), exception sanitization via @api_errors, and microsecond-level execution timing for cryptographic performance monitoring."
  },
  rbac: {
    title: "Access Control & Identity (Security Layer)",
    badge: "Scrypt KDF · Server-Side RBAC",
    content: "Protects sensitive endpoints with server-side role gating. Uses NIST-recommended Scrypt password hashing with high memory cost (n=32768, r=8, p=1) and cryptographically random 16-byte salts."
  },
  crypto: {
    title: "Cryptographic Core Engine (Engine Layer)",
    badge: "NIST SP 800-38D · RFC 8017",
    content: "Executes genuine cryptographic primitives via Python Cryptography: AES-256-GCM authenticated encryption, RSA-2048 OAEP hybrid key wrapping, RSA-PSS digital signatures, and SHA-256 / SHA-512 hashing."
  },
  vault: {
    title: "Key Vault & KMS (Key Management Layer)",
    badge: "Envelope Encryption · Fernet Vault Key",
    content: "Protects private and symmetric keys at rest. Keys are never stored unencrypted in SQLite; they are wrapped using a separate 256-bit Fernet master key stored with restricted permissions in instance/master.key."
  },
  db: {
    title: "Relational Persistence (Database Layer)",
    badge: "SQLite 3 · Request-Scoped (flask.g)",
    content: "ACID-compliant storage for key metadata, key fingerprints, user accounts, and audit logs. Employs connection lifecycle management with automated per-request cleanup."
  },
  audit: {
    title: "Audit Logging & Traceability (Monitoring Layer)",
    badge: "UUID4 Correlation · Traceability",
    content: "Every cryptographic action, signature check, and login event is recorded with execution duration, algorithm, status (SUCCESS/FAILURE), and actor attribution."
  }
};

document.querySelectorAll(".pipeline-node").forEach((node) => {
  node.addEventListener("click", () => {
    document.querySelectorAll(".pipeline-node").forEach((n) => n.classList.remove("active"));
    node.classList.add("active");
    const key = node.dataset.node;
    const detail = ARCH_NODES[key];
    if (detail) {
      $("arch-node-title").textContent = detail.title;
      $("arch-node-badge").textContent = detail.badge;
      $("arch-node-content").textContent = detail.content;
    }
  });
});

// --- Module 07: Audit Logs Console ---
async function loadAudit() {
  try {
    const search = $("audit-search")?.value.trim() || "";
    const status = $("audit-status-filter")?.value || "";
    const url = `/api/audit?limit=${auditPagination.limit}&offset=${auditPagination.offset}&search=${encodeURIComponent(search)}&status=${encodeURIComponent(status)}`;
    const { logs, total } = await api(url);
    auditPagination.total = total;

    const tbody = $("full-audit-table");
    if (!logs || !logs.length) {
      tbody.innerHTML = `<tr><td colspan="8">No matching audit events recorded.</td></tr>`;
      $("audit-pagination-info").textContent = "Showing 0 of 0";
      return;
    }

    tbody.innerHTML = logs.map((l) => `
      <tr>
        <td>${new Date(l.created_at).toLocaleString()}</td>
        <td class="mono" style="font-size:11px; color:var(--cyan);">${escapeHtml(l.operation_id?.slice(0, 12))}...</td>
        <td><strong>${escapeHtml(l.user_id || 'system')}</strong></td>
        <td>${escapeHtml(l.action)}</td>
        <td><span class="mono">${escapeHtml(l.algorithm)}</span></td>
        <td><span class="status-badge ${l.status === 'SUCCESS' ? 'success' : 'failure'}">${l.status}</span></td>
        <td>${l.duration_ms} ms</td>
        <td style="max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(l.details)}">${escapeHtml(l.details)}</td>
      </tr>
    `).join("");

    const start = auditPagination.offset + 1;
    const end = Math.min(auditPagination.offset + logs.length, total);
    $("audit-pagination-info").textContent = `Showing ${start} to ${end} of ${total} events`;
  } catch (err) { toast(err.message, "error"); }
}

$("btn-refresh-audit")?.addEventListener("click", loadAudit);
$("audit-search")?.addEventListener("input", () => { auditPagination.offset = 0; loadAudit(); });
$("audit-status-filter")?.addEventListener("change", () => { auditPagination.offset = 0; loadAudit(); });

$("btn-audit-prev")?.addEventListener("click", () => {
  if (auditPagination.offset >= auditPagination.limit) {
    auditPagination.offset -= auditPagination.limit;
    loadAudit();
  }
});

$("btn-audit-next")?.addEventListener("click", () => {
  if (auditPagination.offset + auditPagination.limit < auditPagination.total) {
    auditPagination.offset += auditPagination.limit;
    loadAudit();
  }
});

// --- Initial Startup Lifecycle ---
document.addEventListener("DOMContentLoaded", () => {
  checkAuthSession();
  loadStats();
  loadOverviewAudit();
});
