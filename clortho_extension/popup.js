"use strict";

const VAULT_URL = "http://127.0.0.1:7777";

function esc(str) {
  return String(str || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function siteIcon(site) {
  const icons = {
    github:"🐙", google:"🔍", gmail:"✉️", mail:"✉️", twitter:"🐦",
    facebook:"👤", instagram:"📷", linkedin:"💼", amazon:"📦",
    apple:"🍎", microsoft:"🪟", netflix:"🎬", spotify:"🎵",
    discord:"💬", slack:"💬", dropbox:"📦", aws:"☁️", paypal:"💳",
  };
  const key = (site || "").toLowerCase();
  for (const [k, v] of Object.entries(icons)) if (key.includes(k)) return v;
  return site ? site[0].toUpperCase() : "?";
}

let toastTimer;
function toast(msg, type = "ok") {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = `show ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 2000);
}

async function getActiveTab() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  return tabs[0] || null;
}

async function fillInTab(tabId, entryId) {
  const result = await browser.runtime.sendMessage({ type: "GET_PASSWORD", id: entryId });
  if (result.error) { toast(result.error, "err"); return; }
  await browser.tabs.sendMessage(tabId, {
    type: "FILL_ENTRY",
    username: result.username,
    password: result.password,
  });
  result.password = null;
  result.username = null;
  toast("Filled!", "ok");
  setTimeout(() => window.close(), 600);
}

// ── Password generator ────────────────────────────────────────────────

function generatePassword(length, opts) {
  let chars = "";
  if (opts.lower)   chars += "abcdefghijkmnopqrstuvwxyz";   // no l (ambiguous)
  if (opts.upper)   chars += "ABCDEFGHJKLMNPQRSTUVWXYZ";    // no I O (ambiguous)
  if (opts.digits)  chars += "23456789";                     // no 0 1 (ambiguous)
  if (opts.symbols) chars += "!@#$%^&*()-_=+[]{}|;:,.?";
  if (!chars) chars = "abcdefghijkmnopqrstuvwxyz";

  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr, n => chars[n % chars.length]).join("");
}

function buildGenerator() {
  return `
    <div class="section" id="gen-section">
      <div class="section-label">Password Generator</div>
      <div class="gen-output">
        <span id="gen-password"></span>
        <button class="gen-icon-btn" id="gen-refresh" title="New password">↻</button>
        <button class="gen-icon-btn" id="gen-copy" title="Copy">⧉</button>
      </div>
      <div class="gen-length">
        <span>Length</span>
        <input type="range" id="gen-length" min="8" max="64" value="20">
        <span id="gen-len-val">20</span>
      </div>
      <div class="gen-chars">
        <label><input type="checkbox" id="gen-upper"   checked> A–Z</label>
        <label><input type="checkbox" id="gen-lower"   checked> a–z</label>
        <label><input type="checkbox" id="gen-digits"  checked> 0–9</label>
        <label><input type="checkbox" id="gen-symbols" checked> !@#</label>
      </div>
    </div>`;
}

function attachGeneratorListeners() {
  const pwEl     = document.getElementById("gen-password");
  const lenEl    = document.getElementById("gen-length");
  const lenVal   = document.getElementById("gen-len-val");
  const copyBtn  = document.getElementById("gen-copy");
  const refreshBtn = document.getElementById("gen-refresh");

  function getOpts() {
    return {
      upper:   document.getElementById("gen-upper").checked,
      lower:   document.getElementById("gen-lower").checked,
      digits:  document.getElementById("gen-digits").checked,
      symbols: document.getElementById("gen-symbols").checked,
    };
  }

  function refresh() {
    const len = parseInt(lenEl.value);
    lenVal.textContent = len;
    pwEl.textContent = generatePassword(len, getOpts());
  }

  refresh();

  lenEl.addEventListener("input", refresh);
  refreshBtn.addEventListener("click", refresh);
  document.querySelectorAll(".gen-chars input").forEach(cb => cb.addEventListener("change", refresh));

  copyBtn.addEventListener("click", () => {
    const pw = pwEl.textContent;
    if (!pw) return;
    navigator.clipboard.writeText(pw).then(() => toast("Copied!", "ok"));
  });

  // Also copy on click of the password text
  pwEl.addEventListener("click", () => {
    const pw = pwEl.textContent;
    if (!pw) return;
    navigator.clipboard.writeText(pw).then(() => toast("Copied!", "ok"));
  });
}

// ── Main init ─────────────────────────────────────────────────────────

async function init() {
  const dot   = document.getElementById("status-dot");
  const label = document.getElementById("status-label");
  const body  = document.getElementById("body-area");

  // Open Vault button always works regardless of state
  document.getElementById("open-ui-btn").addEventListener("click", () => {
    browser.tabs.create({ url: VAULT_URL });
    window.close();
  });

  const status = await browser.runtime.sendMessage({ type: "CHECK_STATUS" });

  if (!status.running) {
    dot.className     = "status-dot off";
    label.textContent = "Server offline";
    body.innerHTML = `<div class="locked-state">
      <div class="lock-icon">⚠️</div>
      <div class="lock-msg">Clortho server isn't running.<br>Start it with:<br>
        <code style="font-size:11px;color:#cc2222">./clortho_start.sh</code>
      </div>
    </div>`;
    return;
  }

  if (status.locked) {
    dot.className     = "status-dot locked";
    label.textContent = "Locked";
    body.innerHTML = `<div class="locked-state">
      <div class="lock-icon">🔒</div>
      <div class="lock-msg">Vault is locked.<br>Unlock it to autofill credentials.</div>
      <button class="open-btn" id="open-vault">Unlock Clortho</button>
    </div>
    ${buildGenerator()}`;
    document.getElementById("open-vault").addEventListener("click", () => {
      browser.tabs.create({ url: `${VAULT_URL}/unlock` });
      window.close();
    });
    attachGeneratorListeners();
    return;
  }

  dot.className     = "status-dot ok";
  label.textContent = "Unlocked";

  const tab = await getActiveTab();
  if (!tab || !tab.url || tab.url.startsWith("about:") || tab.url.startsWith("moz-extension:")) {
    body.innerHTML = `
      <div class="section">
        <div class="empty-state">Navigate to a website to see matching credentials.</div>
      </div>
      ${buildGenerator()}`;
    attachGeneratorListeners();
    return;
  }

  let hostname = "";
  try { hostname = new URL(tab.url).hostname; } catch {}

  const result  = await browser.runtime.sendMessage({ type: "GET_MATCHES", hostname });
  const matches = result.matches || [];

  if (matches.length === 0) {
    body.innerHTML = `
      <div class="section">
        <div class="section-label">Current site: ${esc(hostname)}</div>
        <div class="empty-state">No saved credentials for this site.<br>
          <a href="#" id="add-link" style="color:#cc2222;text-decoration:none">+ Add one in Clortho</a>
        </div>
      </div>
      ${buildGenerator()}`;
    document.getElementById("add-link")?.addEventListener("click", (e) => {
      e.preventDefault();
      browser.tabs.create({ url: VAULT_URL });
      window.close();
    });
    attachGeneratorListeners();
    return;
  }

  body.innerHTML = `
    <div class="section">
      <div class="section-label">Matches for ${esc(hostname)}</div>
      ${matches.slice(0, 6).map((m, i) => `
        <div class="entry" data-idx="${i}">
          <div class="entry-icon">${siteIcon(m.site)}</div>
          <div>
            <div class="entry-site">${esc(m.site)}</div>
            <div class="entry-user">${esc(m.username)}</div>
          </div>
          <button class="fill-btn" data-idx="${i}">Fill</button>
        </div>
      `).join("")}
    </div>
    ${buildGenerator()}`;

  document.querySelectorAll(".fill-btn").forEach(btn => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      await fillInTab(tab.id, matches[parseInt(btn.dataset.idx)].id);
    });
  });
  document.querySelectorAll(".entry").forEach(row => {
    row.addEventListener("click", async () => {
      await fillInTab(tab.id, matches[parseInt(row.dataset.idx)].id);
    });
  });

  attachGeneratorListeners();
}

document.addEventListener("DOMContentLoaded", init);
