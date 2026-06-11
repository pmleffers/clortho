/**
 * Clortho Extension — Content Script
 *
 * Runs on every page. Detects login forms, shows a subtle autofill prompt,
 * and fills credentials on user confirmation.
 *
 * Security principles:
 *  - Never stores passwords — requests them from background only at fill time
 *  - Prompt is dismissed on any outside click
 *  - Only activates when a password field is focused or a login form is detected
 *  - All injected DOM is isolated under a shadow root to avoid CSS leakage
 *  - Does not log or transmit any page content
 */

(function () {
  "use strict";

  // Don't run inside iframes
  if (window !== window.top) return;

  // On the vault UI page: read the embedded API token and relay it to the background
  if (location.hostname === "127.0.0.1") {
    const relay = () => {
      const meta = document.querySelector('meta[name="clortho-api-token"]');
      const token = meta && meta.getAttribute("content");
      if (token) browser.runtime.sendMessage({ type: "STORE_TOKEN", token });
    };
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", relay);
    else relay();
    return;
  }

  let promptEl = null;
  let shadowRoot = null;
  let lastFocusedPasswordField = null;
  let lastFocusedUsernameField = null;
  let matchCache = null;        // { hostname, matches, ts }
  let promptDismissed = false;  // don't re-show after user dismisses on this page load

  // ── Form detection ─────────────────────────────────────────────────

  function findLoginForm(passwordField) {
    // Walk up to find a <form> or the closest fieldset/div container
    let el = passwordField;
    for (let i = 0; i < 8; i++) {
      if (!el.parentElement) break;
      el = el.parentElement;
      if (el.tagName === "FORM" || el.tagName === "FIELDSET") return el;
    }
    // Fall back to document body scan
    return passwordField.closest("form") || document.body;
  }

  function findUsernameField(container) {
    const candidates = container.querySelectorAll(
      'input[type="email"], input[type="text"], input[autocomplete*="user"], ' +
      'input[autocomplete*="email"], input[name*="user"], input[name*="email"], ' +
      'input[name*="login"], input[id*="user"], input[id*="email"], input[id*="login"]'
    );
    // Return the last visible one before the password field
    return Array.from(candidates).filter(el => el.offsetParent !== null).pop() || null;
  }

  // ── Get matches (cached per hostname per page load) ────────────────

  async function getMatches() {
    const hostname = location.hostname;
    if (matchCache && matchCache.hostname === hostname && Date.now() - matchCache.ts < 30000) {
      return matchCache.matches;
    }
    const result = await browser.runtime.sendMessage({
      type: "GET_MATCHES",
      hostname,
    });
    if (result.error || result.locked) return [];
    matchCache = { hostname, matches: result.matches, ts: Date.now() };
    return result.matches;
  }

  // ── Prompt UI (shadow DOM) ─────────────────────────────────────────

  function buildPrompt(matches, pwField) {
    if (promptEl) promptEl.remove();
    promptDismissed = false;

    const host = document.createElement("div");
    host.id = "__vk_prompt_host__";
    host.style.cssText = [
      "position:fixed", "z-index:2147483647", "top:0", "left:0",
      "pointer-events:none", "width:0", "height:0",
    ].join(";");
    document.body.appendChild(host);
    promptEl = host;

    shadowRoot = host.attachShadow({ mode: "closed" });

    const rect = pwField.getBoundingClientRect();
    const top  = Math.min(rect.bottom + window.scrollY + 4, window.innerHeight - 260);
    const left = Math.max(8, Math.min(rect.left + window.scrollX, window.innerWidth - 320));

    shadowRoot.innerHTML = `
      <style>
        :host { all: initial; }
        #vk {
          position: fixed;
          top: ${rect.bottom + 6}px;
          left: ${rect.left}px;
          width: 300px;
          background: #130303;
          border: 1px solid #3a0f0f;
          border-radius: 8px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.5);
          font-family: -apple-system, 'Segoe UI', sans-serif;
          font-size: 13px;
          color: #f0e8e8;
          pointer-events: all;
          animation: vkIn 0.18s cubic-bezier(0.4,0,0.2,1);
          overflow: hidden;
        }
        @keyframes vkIn {
          from { opacity:0; transform:translateY(-6px); }
          to   { opacity:1; transform:translateY(0); }
        }
        #vk-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 10px 12px 8px;
          border-bottom: 1px solid #3a0f0f;
        }
        #vk-title {
          font-size: 11px;
          font-weight: 600;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          color: #cc2222;
        }
        #vk-close {
          background: none;
          border: none;
          color: #886666;
          cursor: pointer;
          font-size: 16px;
          line-height: 1;
          padding: 0 2px;
        }
        #vk-close:hover { color: #f0e8e8; }
        .vk-entry {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 9px 12px;
          cursor: pointer;
          border-bottom: 1px solid #1c0505;
          transition: background 0.12s;
        }
        .vk-entry:last-child { border-bottom: none; }
        .vk-entry:hover { background: #220808; }
        .vk-icon {
          width: 28px; height: 28px;
          background: #3a0f0f;
          border-radius: 6px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 13px;
          flex-shrink: 0;
        }
        .vk-site   { font-weight: 500; font-size: 13px; }
        .vk-user   { font-size: 11px; color: #886666; margin-top: 1px; font-family: monospace; }
        #vk-footer {
          padding: 7px 12px;
          background: #0a0000;
          font-size: 10px;
          color: #4a2020;
          text-align: center;
          letter-spacing: 0.04em;
        }
      </style>
      <div id="vk">
        <div id="vk-header">
          <span id="vk-title">🔐 Clortho</span>
          <button id="vk-close">×</button>
        </div>
        ${matches.slice(0, 5).map((m, i) => `
          <div class="vk-entry" data-idx="${i}">
            <div class="vk-icon">${siteIcon(m.site)}</div>
            <div>
              <div class="vk-site">${esc(m.site)}</div>
              <div class="vk-user">${esc(m.username)}</div>
            </div>
          </div>
        `).join("")}
        <div id="vk-footer">Local only · passwords never leave your machine</div>
      </div>
    `;

    // Close button
    shadowRoot.getElementById("vk-close").addEventListener("click", dismissPrompt);

    // Entry click → fill
    shadowRoot.querySelectorAll(".vk-entry").forEach((el, i) => {
      el.addEventListener("click", async () => {
        const match = matches[i];
        await fillCredentials(match.id, pwField);
        dismissPrompt();
      });
    });

    // Dismiss on outside click
    setTimeout(() => {
      document.addEventListener("mousedown", outsideClickHandler, { once: false });
    }, 200);
  }

  function outsideClickHandler(e) {
    if (!promptEl || !shadowRoot) return;
    const vkEl = shadowRoot.getElementById("vk");
    if (vkEl && e.target !== promptEl) {
      dismissPrompt();
    }
  }

  function dismissPrompt() {
    if (promptEl) {
      promptEl.remove();
      promptEl = null;
    }
    promptDismissed = true;
    document.removeEventListener("mousedown", outsideClickHandler);
  }

  // ── Fill credentials ───────────────────────────────────────────────

  async function fillCredentials(entryId, pwField) {
    const result = await browser.runtime.sendMessage({
      type: "GET_PASSWORD",
      id: entryId,
    });

    if (result.error) {
      console.warn("[Clortho] Fill failed:", result.error);
      return;
    }

    // Fill username field if found
    if (lastFocusedUsernameField && result.username) {
      simulateFill(lastFocusedUsernameField, result.username);
    } else {
      // Try to find username field relative to the password field
      const form = findLoginForm(pwField);
      const userField = findUsernameField(form);
      if (userField && result.username) simulateFill(userField, result.username);
    }

    // Fill password field
    simulateFill(pwField, result.password);

    // Clear from local scope immediately
    result.password = null;
    result.username = null;
  }

  function simulateFill(field, value) {
    // Use native input value setter to trigger React/Vue/Angular change detection
    const nativeSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, "value"
    )?.set;
    if (nativeSetter) {
      nativeSetter.call(field, value);
    } else {
      field.value = value;
    }
    field.dispatchEvent(new Event("input",  { bubbles: true }));
    field.dispatchEvent(new Event("change", { bubbles: true }));
    field.dispatchEvent(new KeyboardEvent("keydown",  { bubbles: true }));
    field.dispatchEvent(new KeyboardEvent("keyup",    { bubbles: true }));
  }

  // ── Trigger detection ──────────────────────────────────────────────

  async function onPasswordFieldFocus(e) {
    const pwField = e.target;
    if (promptDismissed) return;
    if (promptEl) return; // already showing

    // Track the username field that was focused just before
    const form = findLoginForm(pwField);
    lastFocusedUsernameField = findUsernameField(form);

    const matches = await getMatches();
    if (matches.length === 0) return;

    buildPrompt(matches, pwField);
  }

  function onUsernameFieldFocus(e) {
    lastFocusedUsernameField = e.target;
  }

  // ── Attach listeners ───────────────────────────────────────────────

  function attachListeners() {
    // Listen for password field focus via delegation
    document.addEventListener("focusin", (e) => {
      if (!(e.target instanceof HTMLInputElement)) return;

      if (e.target.type === "password") {
        lastFocusedPasswordField = e.target;
        onPasswordFieldFocus(e);
      } else if (
        e.target.type === "email" || e.target.type === "text" ||
        (e.target.autocomplete || "").includes("user") ||
        (e.target.name || "").toLowerCase().includes("user") ||
        (e.target.name || "").toLowerCase().includes("email") ||
        (e.target.name || "").toLowerCase().includes("login")
      ) {
        onUsernameFieldFocus(e);
      }
    });

    // Dismiss prompt when focus leaves the form area
    document.addEventListener("focusout", (e) => {
      if (!promptEl) return;
      // Short delay to allow click on prompt to register first
      setTimeout(() => {
        const active = document.activeElement;
        if (!active || active.type !== "password") {
          // Check if focus went into the shadow DOM (prompt itself)
          if (active && active.id !== "__vk_prompt_host__") {
            // Don't dismiss — user may have clicked prompt
          }
        }
      }, 150);
    });
  }

  // ── Helpers ────────────────────────────────────────────────────────

  function esc(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function siteIcon(site) {
    const icons = {
      github: "🐙", google: "🔍", gmail: "✉️", mail: "✉️",
      twitter: "🐦", facebook: "👤", instagram: "📷", linkedin: "💼",
      amazon: "📦", apple: "🍎", microsoft: "🪟", netflix: "🎬",
      spotify: "🎵", discord: "💬", slack: "💬", dropbox: "📦",
      aws: "☁️", azure: "☁️", paypal: "💳",
    };
    const key = (site || "").toLowerCase();
    for (const [k, v] of Object.entries(icons)) if (key.includes(k)) return v;
    return site ? site[0].toUpperCase() : "?";
  }

  // ── Init ───────────────────────────────────────────────────────────

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", attachListeners);
  } else {
    attachListeners();
  }
})();

// ── Handle fill message from popup ────────────────────────────────────
browser.runtime.onMessage.addListener((msg) => {
  if (msg.type !== "FILL_ENTRY") return;

  // Find password field on the page
  const pwFields = Array.from(document.querySelectorAll('input[type="password"]'))
    .filter(el => el.offsetParent !== null);

  const pwField = lastFocusedPasswordField || pwFields[0];
  if (!pwField) return;

  const form = findLoginForm(pwField);
  const userField = lastFocusedUsernameField || findUsernameField(form);

  if (userField && msg.username) simulateFill(userField, msg.username);
  simulateFill(pwField, msg.password);
});
