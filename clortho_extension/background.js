/**
 * Clortho Extension — Background Script
 *
 * Responsibilities:
 *  - Relay credential lookups from content scripts to the local vault server
 *  - Cache the session state (locked/unlocked) so content scripts don't need to know
 *  - Never store any passwords in extension storage — only relay in memory
 */

const VAULT_URL = "http://127.0.0.1:7777";

// ── API token (relayed from vault page content script) ────────────────
let _apiToken = null;

async function getAuthHeaders() {
  if (_apiToken) return { "Authorization": `Bearer ${_apiToken}` };
  // Try loading from storage (survives background script restarts)
  const stored = await browser.storage.local.get("clortho_api_token");
  if (stored.clortho_api_token) {
    _apiToken = stored.clortho_api_token;
    return { "Authorization": `Bearer ${_apiToken}` };
  }
  return {};
}

// ── Vault API helpers ─────────────────────────────────────────────────

async function fetchEntries() {
  try {
    const headers = await getAuthHeaders();
    const r = await fetch(`${VAULT_URL}/api/entries`, { headers });
    if (r.status === 401) return { locked: true, entries: [] };
    if (!r.ok) return { locked: false, entries: [], error: `Server error ${r.status}` };
    const data = await r.json();
    return { locked: false, entries: data.entries || [] };
  } catch (e) {
    return { locked: false, entries: [], error: "Clortho server not running" };
  }
}

async function checkStatus() {
  try {
    const headers = await getAuthHeaders();
    const r = await fetch(`${VAULT_URL}/api/entries`, { headers });
    return { running: true, locked: r.status === 401 };
  } catch {
    return { running: false, locked: true };
  }
}

// ── Match entries to a hostname ───────────────────────────────────────

function scoreEntry(entry, hostname) {
  // Normalize stored URL/site for comparison
  const normalize = (s) => {
    try {
      const u = new URL(s.startsWith("http") ? s : `https://${s}`);
      return u.hostname.replace(/^www\./, "");
    } catch {
      return s.toLowerCase().replace(/^www\./, "");
    }
  };

  const host = hostname.replace(/^www\./, "");
  const entryHost = normalize(entry.url || entry.site || "");

  if (!entryHost) return 0;

  // Exact match
  if (entryHost === host) return 100;

  // Subdomain match (e.g. auth.github.com matches github.com)
  if (host.endsWith("." + entryHost) || entryHost.endsWith("." + host)) return 80;

  // Site name fuzzy match (github.com → "github")
  const siteName = (entry.site || "").toLowerCase();
  const hostBase = host.split(".")[0];
  if (siteName === hostBase || siteName.includes(hostBase) || hostBase.includes(siteName)) return 50;

  return 0;
}

function matchEntries(entries, hostname) {
  return entries
    .map(e => ({ entry: e, score: scoreEntry(e, hostname) }))
    .filter(x => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .map(x => x.entry);
}

// ── Message handler ───────────────────────────────────────────────────

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_MATCHES") {
    fetchEntries().then(result => {
      if (result.locked || result.error) {
        sendResponse({ matches: [], locked: result.locked, error: result.error });
        return;
      }
      const matches = matchEntries(result.entries, msg.hostname);
      // Strip passwords from the list — only send on explicit fill request
      const safe = matches.map(e => ({
        id:       e.id,
        site:     e.site,
        username: e.username,
        category: e.category,
        url:      e.url,
        // password intentionally omitted from list view
      }));
      sendResponse({ matches: safe, locked: false });
    });
    return true; // keep channel open for async
  }

  if (msg.type === "GET_PASSWORD") {
    // Content script requests the password for a specific entry ID to fill
    fetchEntries().then(result => {
      if (result.locked || result.error) {
        sendResponse({ error: result.error || "Vault locked" });
        return;
      }
      const entry = result.entries.find(e => e.id === msg.id);
      if (!entry) {
        sendResponse({ error: "Entry not found" });
        return;
      }
      // Return credentials — content script will fill and immediately discard
      sendResponse({ username: entry.username, password: entry.password });
    });
    return true;
  }

  if (msg.type === "CHECK_STATUS") {
    checkStatus().then(sendResponse);
    return true;
  }

  if (msg.type === "START_SERVER") {
    let responded = false;
    let port;
    try {
      port = browser.runtime.connectNative("clortho_host");
    } catch (e) {
      sendResponse({ ok: false, error: "Native host not installed — run install_desktop.sh first." });
      return true;
    }
    port.postMessage({ type: "start_server" });
    port.onMessage.addListener((response) => {
      if (!responded) { responded = true; port.disconnect(); sendResponse(response); }
    });
    port.onDisconnect.addListener(() => {
      if (!responded) {
        responded = true;
        sendResponse({ ok: false, error: "Native host not installed — run install_desktop.sh first." });
      }
    });
    return true;
  }

  if (msg.type === "STORE_TOKEN") {
    // Relayed from content script running on the vault page after user unlocks
    if (msg.token) {
      _apiToken = msg.token;
      browser.storage.local.set({ clortho_api_token: msg.token });

    }
    return false;
  }
});
