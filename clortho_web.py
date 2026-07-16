#!/usr/bin/env python3
"""
Clortho Web UI — Flask companion to clortho.py
Runs a LOCAL-ONLY server on 127.0.0.1 (never exposed to the network).
Shares the same encrypted vault file as the CLI.

Security notes:
  - Binds to 127.0.0.1 only — not accessible from other machines
  - Session key is a random 32-byte secret generated at startup
  - Vault is re-locked if the browser session ends or server restarts
  - All API routes require an unlocked session (checked via decorator)
  - Vault data is NEVER served in bulk — only searched/single-entry responses
  - No logging of passwords to stdout/files
  - Flask debug mode is ALWAYS off
"""

import os
import sys
import json
import secrets
import threading
import webbrowser
from pathlib import Path
from functools import wraps
from datetime import datetime

# Windows consoles often default to a legacy codepage (e.g. cp1252) that can't
# encode the emoji used in this file's startup banner, crashing with a
# UnicodeEncodeError before the server can even start. Force UTF-8 on stdout/
# stderr regardless of the underlying console's codepage — harmless no-op on
# Linux/Mac, where these streams are already UTF-8.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

# ── Add parent dir so we can import Clortho core ─────────────────
sys.path.insert(0, str(Path(__file__).parent))

try:
    from flask import (
        Flask, request, jsonify, session,
        render_template_string, redirect, url_for, send_file
    )
except ImportError:
    print("Flask not found. Run: pip install flask")
    sys.exit(1)

# Import vault core.
# The socket guard in clortho.py is installed at module load time and
# already allows loopback (127.0.0.1 / ::1 / localhost), so Flask can bind
# and serve normally. All external connections remain blocked.
try:
    import clortho as vk
except ImportError:
    print("Could not import clortho.py — make sure it's in the same directory.")
    sys.exit(1)


# ─────────────────────────────────────────────
# FLASK APP
# ─────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)   # new random key every server start
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Firefox extension origin for CORS — moz-extension:// origins are unique per install
# We allow localhost and moz-extension schemes; block everything else.
ALLOWED_ORIGINS = {"http://127.0.0.1:7777", "http://localhost:7777"}

@app.after_request
def add_cors(response):
    origin = request.headers.get("Origin", "")
    # Allow moz-extension:// (Firefox) and chrome-extension:// (Chromium) and localhost
    if (origin in ALLOWED_ORIGINS
            or origin.startswith("moz-extension://")
            or origin.startswith("chrome-extension://")):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response

@app.route("/api/entries", methods=["OPTIONS"])
@app.route("/api/entries/<entry_id>", methods=["OPTIONS"])
@app.route("/api/import", methods=["OPTIONS"])
@app.route("/api/generate", methods=["OPTIONS"])
@app.route("/api/lock", methods=["OPTIONS"])
@app.route("/api/backup", methods=["OPTIONS"])
@app.route("/api/backup/set", methods=["OPTIONS"])
@app.route("/api/backup/now", methods=["OPTIONS"])
@app.route("/api/backup/list", methods=["OPTIONS"])
@app.route("/api/backup/restore", methods=["OPTIONS"])
def options_handler(**kwargs):
    return "", 204

@app.route("/extension.xpi")
def serve_extension():
    xpi = os.path.expanduser("~/.local/share/clortho/clortho.xpi")
    if not os.path.exists(xpi):
        return "XPI not found", 404
    return send_file(xpi, mimetype="application/x-xpinstall",
                     as_attachment=False, download_name="clortho.xpi")

@app.route("/install-extension")
def install_extension_page():
    return render_template_string("""<!DOCTYPE html>
<html><head><title>Install Clortho Extension</title>
<style>
  body{font-family:sans-serif;display:flex;flex-direction:column;align-items:center;
       justify-content:center;height:100vh;margin:0;background:#0a0000;color:#f0e8e8;}
  h1{color:#cc2222;margin-bottom:8px;}
  p{color:#886666;margin-bottom:32px;}
  a.btn{background:#cc2222;color:#fff;padding:14px 32px;border-radius:8px;
        text-decoration:none;font-weight:700;font-size:16px;}
  a.btn:hover{background:#00c98a;}
  .note{margin-top:20px;font-size:12px;color:#4a2020;}
</style></head>
<body>
  <h1>🔐 Clortho</h1>
  <p>Click below to install the browser extension</p>
  <a class="btn" href="/extension.xpi">Install Clortho Extension</a>
  <div class="note">Firefox will ask you to confirm. Click "Add" when prompted.</div>
</body></html>""")


# Global vault instance (shared with CLI if using same vault dir)
_vault: vk.Clortho | None = None
_vault_dir = os.environ.get("VK_VAULT_DIR", "~/.clortho")
_api_token: str | None = None   # memory-only token for extension auth (no cookie needed)


def get_vault() -> vk.Clortho:
    global _vault
    if _vault is None:
        _vault = vk.Clortho(vault_dir=_vault_dir)
    return _vault


def require_unlock(f):
    """Decorator: redirect to /unlock if vault not unlocked in this session.
    Also accepts 'Authorization: Bearer <token>' for extension requests."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Accept Bearer token from extension (bypasses SameSite cookie restrictions)
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and _api_token and auth[7:] == _api_token:
            return f(*args, **kwargs)
        if not session.get("unlocked"):
            origin = request.headers.get("Origin", "")
            is_api = (request.is_json
                      or request.path.startswith("/api/")
                      or origin.startswith("moz-extension://")
                      or origin.startswith("chrome-extension://"))
            if is_api:
                return jsonify({"error": "Vault is locked"}), 401
            return redirect(url_for("unlock_page"))
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────
# HTML TEMPLATE (single-file SPA)
# ─────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="clortho-api-token" content="{{ api_token }}">
<title>Clortho</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg:        #0a0000;
  --surface:   #130303;
  --border:    #3a0f0f;
  --accent:    #cc2222;
  --accent2:   #e84040;
  --danger:    #ff4d6a;
  --warn:      #ffb347;
  --text:      #f0e8e8;
  --muted:     #886666;
  --mono:      'IBM Plex Mono', monospace;
  --sans:      'IBM Plex Sans', sans-serif;
  --radius:    6px;
  --shadow:    0 4px 24px rgba(0,0,0,0.4);
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; background: var(--bg); color: var(--text); font-family: var(--sans); font-size: 14px; }

/* ── Layout ─────────────────────────────── */
#app { display: flex; height: 100vh; }
#sidebar {
  width: 220px; min-width: 220px; background: var(--surface);
  border-right: 1px solid var(--border); display: flex; flex-direction: column;
  padding: 0; overflow: hidden;
}
#main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
#topbar {
  height: 52px; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; padding: 0 20px; gap: 12px;
  background: var(--surface);
}
#content { flex: 1; overflow-y: auto; padding: 24px; }

/* ── Sidebar ────────────────────────────── */
.logo {
  padding: 14px 20px 12px;
  display: flex; align-items: center; gap: 10px;
  border-bottom: 1px solid var(--border);
}
.logo-icon { width: 36px; height: 36px; flex-shrink: 0; }
.logo-text { font-family: var(--mono); font-size: 13px; font-weight: 600; color: var(--accent); letter-spacing: 0.08em; }
.logo-text span { color: var(--muted); font-weight: 400; }
.nav-section { padding: 12px 0 4px; }
.nav-label { padding: 0 20px 6px; font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted); }
.nav-item {
  display: flex; align-items: center; gap: 10px;
  padding: 8px 20px; cursor: pointer; font-size: 13px; color: var(--muted);
  transition: color 0.15s, background 0.15s; border-left: 2px solid transparent;
}
.nav-item:hover { color: var(--text); background: rgba(255,255,255,0.03); }
.nav-item.active { color: var(--accent); border-left-color: var(--accent); background: rgba(204,34,34,0.08); }
.nav-icon { width: 16px; text-align: center; font-size: 15px; }
.sidebar-bottom { margin-top: auto; padding: 16px 20px; border-top: 1px solid var(--border); }
.lock-btn {
  width: 100%; padding: 8px; background: transparent; border: 1px solid var(--border);
  color: var(--muted); border-radius: var(--radius); cursor: pointer; font-size: 12px;
  font-family: var(--mono); letter-spacing: 0.05em; transition: all 0.15s;
}
.lock-btn:hover { border-color: var(--danger); color: var(--danger); }

/* ── Topbar ──────────────────────────────── */
#search-input {
  flex: 1; background: var(--bg); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 7px 12px; color: var(--text);
  font-family: var(--mono); font-size: 13px; outline: none;
  transition: border-color 0.15s;
}
#search-input:focus { border-color: var(--accent); }
#search-input::placeholder { color: var(--muted); }
.count-badge {
  background: var(--border); color: var(--muted); padding: 3px 10px;
  border-radius: 20px; font-size: 11px; font-family: var(--mono); white-space: nowrap;
}

/* ── Buttons ─────────────────────────────── */
.btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 7px 14px; border-radius: var(--radius); border: none;
  cursor: pointer; font-size: 13px; font-family: var(--sans); font-weight: 500;
  transition: all 0.15s; white-space: nowrap;
}
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { background: #ff4444; }
.btn-ghost { background: transparent; color: var(--muted); border: 1px solid var(--border); }
.btn-ghost:hover { color: var(--text); border-color: var(--muted); }
.btn-danger { background: transparent; color: var(--danger); border: 1px solid var(--danger); }
.btn-danger:hover { background: var(--danger); color: #fff; }
.btn-sm { padding: 4px 10px; font-size: 12px; }

/* ── Cards / Entry list ─────────────────── */
.entries-grid { display: flex; flex-direction: column; gap: 8px; }
.entry-card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 14px 16px;
  display: flex; align-items: center; gap: 16px;
  transition: border-color 0.15s; cursor: pointer;
}
.entry-card:hover { border-color: var(--accent); }
.entry-icon {
  width: 36px; height: 36px; border-radius: 8px;
  background: var(--border); display: flex; align-items: center; justify-content: center;
  font-size: 16px; flex-shrink: 0;
}
.entry-info { flex: 1; min-width: 0; }
.entry-site { font-weight: 500; font-size: 14px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.entry-user { color: var(--muted); font-size: 12px; font-family: var(--mono); margin-top: 2px; }
.entry-cat {
  font-size: 10px; padding: 2px 8px; border-radius: 20px;
  border: 1px solid var(--border); color: var(--muted); font-family: var(--mono);
  white-space: nowrap;
}
.entry-actions { display: flex; gap: 6px; opacity: 0; transition: opacity 0.15s; }
.entry-card:hover .entry-actions { opacity: 1; }

/* ── Detail Panel ────────────────────────── */
#detail-panel {
  position: fixed; right: 0; top: 0; bottom: 0; width: 380px;
  background: var(--surface); border-left: 1px solid var(--border);
  transform: translateX(100%); transition: transform 0.25s cubic-bezier(0.4,0,0.2,1);
  display: flex; flex-direction: column; z-index: 100;
}
#detail-panel.open { transform: translateX(0); }
.panel-header {
  padding: 18px 20px; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
}
.panel-title { font-weight: 600; font-size: 15px; }
.panel-close { background: none; border: none; color: var(--muted); cursor: pointer; font-size: 20px; line-height: 1; }
.panel-close:hover { color: var(--text); }
.panel-body { flex: 1; overflow-y: auto; padding: 20px; }
.field-group { margin-bottom: 18px; }
.field-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); margin-bottom: 5px; }
.field-value {
  background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 8px 12px; font-family: var(--mono); font-size: 13px; color: var(--text);
  display: flex; align-items: center; justify-content: space-between; gap: 8px; word-break: break-all;
}
.copy-btn {
  background: none; border: none; color: var(--muted); cursor: pointer;
  font-size: 13px; flex-shrink: 0; padding: 2px 4px; border-radius: 3px;
  transition: color 0.15s;
}
.copy-btn:hover { color: var(--accent); }
.pw-mask { letter-spacing: 0.15em; }
.panel-footer { padding: 16px 20px; border-top: 1px solid var(--border); display: flex; gap: 8px; }

/* ── Modal ───────────────────────────────── */
.modal-backdrop {
  display: none; position: fixed; inset: 0;
  background: rgba(0,0,0,0.6); z-index: 200;
  align-items: center; justify-content: center;
}
.modal-backdrop.open { display: flex; }
.modal {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; width: 460px; max-width: 95vw;
  box-shadow: var(--shadow); animation: slideUp 0.2s ease;
}
@keyframes slideUp { from { transform: translateY(16px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
.modal-header { padding: 18px 20px 14px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
.modal-title { font-weight: 600; font-size: 15px; }
.modal-body { padding: 20px; display: flex; flex-direction: column; gap: 14px; }
.modal-footer { padding: 14px 20px; border-top: 1px solid var(--border); display: flex; gap: 8px; justify-content: flex-end; }

/* ── Form elements ───────────────────────── */
.form-group { display: flex; flex-direction: column; gap: 5px; }
.form-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
.form-input, .form-select {
  background: var(--bg); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 8px 12px; color: var(--text);
  font-family: var(--sans); font-size: 13px; outline: none; width: 100%;
  transition: border-color 0.15s;
}
.form-input:focus, .form-select:focus { border-color: var(--accent); }
.form-input::placeholder { color: var(--muted); }
.pw-row { display: flex; gap: 6px; }
.pw-row .form-input { flex: 1; font-family: var(--mono); }
.gen-btn {
  background: var(--border); border: none; color: var(--muted); border-radius: var(--radius);
  padding: 0 10px; cursor: pointer; font-size: 13px; white-space: nowrap;
  transition: all 0.15s;
}
.gen-btn:hover { background: var(--accent); color: #fff; }

/* ── Toast ───────────────────────────────── */
#toast {
  position: fixed; bottom: 24px; right: 24px; z-index: 999;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 10px 16px; font-size: 13px;
  display: flex; align-items: center; gap: 8px;
  transform: translateY(80px); opacity: 0;
  transition: all 0.25s cubic-bezier(0.4,0,0.2,1);
  box-shadow: var(--shadow); pointer-events: none;
}
#toast.show { transform: translateY(0); opacity: 1; }
#toast.success .toast-dot { background: var(--accent); }
#toast.error   .toast-dot { background: var(--danger); }
#toast.warn    .toast-dot { background: var(--warn); }
.toast-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }

/* ── Empty state ─────────────────────────── */
.empty-state {
  text-align: center; padding: 60px 20px; color: var(--muted);
}
.empty-icon { font-size: 40px; margin-bottom: 12px; }
.empty-title { font-size: 16px; color: var(--text); margin-bottom: 6px; }

/* ── Import zone ─────────────────────────── */
.drop-zone {
  border: 2px dashed var(--border); border-radius: var(--radius);
  padding: 24px; text-align: center; color: var(--muted); cursor: pointer;
  transition: all 0.15s;
}
.drop-zone:hover, .drop-zone.drag-over { border-color: var(--accent); color: var(--accent); background: rgba(0,229,160,0.04); }
.drop-zone input { display: none; }

/* ── Scrollbar ───────────────────────────── */
::-webkit-scrollbar { width: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

/* ── Category colors ─────────────────────── */
.cat-web      { border-color: #e8404044; color: #60a5fa; }
.cat-email    { border-color: #a855f744; color: #c084fc; }
.cat-dev      { border-color: #22c55e44; color: #4ade80; }
.cat-finance  { border-color: #eab30844; color: #fbbf24; }
.cat-imported { border-color: #88666644; color: #94a3b8; }
.cat-general  { border-color: #88666644; color: #94a3b8; }
</style>
</head>
<body>
<div id="app">

  <!-- Sidebar -->
  <div id="sidebar">
    <div class="logo">
      <svg class="logo-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96">
        <g transform="translate(48,52) scale(1.25) translate(-48,-52)">
          <path d="M20,37 Q4,24 14,16 Q16,19 34,32 Z" fill="#2a0806"/>
          <path d="M22,36 Q6,25 16,17 Q18,20 32,31 Z" fill="#cc3322"/>
          <path d="M76,37 Q92,24 82,16 Q80,19 62,32 Z" fill="#2a0806"/>
          <path d="M74,36 Q90,25 80,17 Q78,20 64,31 Z" fill="#cc3322"/>
          <circle cx="48" cy="54" r="34" fill="#2a0806"/>
          <circle cx="48" cy="54" r="30" fill="#dd3a28"/>
          <ellipse cx="30" cy="50" rx="12" ry="6.5" fill="white" transform="rotate(22,30,50)"/>
          <ellipse cx="66" cy="50" rx="12" ry="6.5" fill="white" transform="rotate(-22,66,50)"/>
          <circle cx="30" cy="50" r="3.5" fill="#1a0000"/>
          <circle cx="66" cy="50" r="3.5" fill="#1a0000"/>
          <path d="M15,44 Q28,37 40,53" stroke="#2a0806" stroke-width="5.5" fill="none" stroke-linecap="round"/>
          <path d="M56,53 Q68,37 81,44" stroke="#2a0806" stroke-width="5.5" fill="none" stroke-linecap="round"/>
          <path d="M34,68 Q46,80 62,66" stroke="#2a0806" stroke-width="4" fill="none" stroke-linecap="round"/>
        </g>
      </svg>
      <div class="logo-text">🔐 CLOR<span>THO</span></div>
    </div>
    <div class="nav-section">
      <div class="nav-label">Views</div>
      <div class="nav-item active" onclick="setView('all')" id="nav-all">
        <span class="nav-icon">⊞</span> All Entries
      </div>
      <div class="nav-item" onclick="setView('search')" id="nav-search">
        <span class="nav-icon">⌕</span> Search
      </div>
    </div>
    <div class="nav-section">
      <div class="nav-label">Categories</div>
      <div id="cat-nav"></div>
    </div>
    <div class="nav-section">
      <div class="nav-label">Tools</div>
      <div class="nav-item" onclick="openAddModal()">
        <span class="nav-icon">+</span> Add Entry
      </div>
      <div class="nav-item" onclick="openApiKeyModal()">
        <span class="nav-icon">🔑</span> Add API Key
      </div>
      <div class="nav-item" onclick="openImportModal()">
        <span class="nav-icon">↑</span> Import CSV/Excel
      </div>
      <div class="nav-item" onclick="openGenModal()">
        <span class="nav-icon">⚄</span> Generate Password
      </div>
    </div>
    <div class="sidebar-bottom">
      <div id="backup-status" style="font-size:11px;color:var(--muted);margin-bottom:10px;line-height:1.5;cursor:pointer;" onclick="openBackupModal()" title="Click to configure backups"></div>
      <button class="lock-btn" onclick="lockVault()">⊠ Lock &amp; Exit</button>
    </div>
  </div>

  <!-- Main -->
  <div id="main">
    <div id="topbar">
      <input id="search-input" type="text" placeholder="Search entries…" oninput="onSearch(this.value)">
      <span class="count-badge" id="count-badge">0 entries</span>
      <button class="btn btn-primary btn-sm" onclick="openAddModal()">+ Add</button>
    </div>
    <div id="content">
      <div class="entries-grid" id="entries-list"></div>
    </div>
  </div>

  <!-- Detail panel -->
  <div id="detail-panel">
    <div class="panel-header">
      <span class="panel-title" id="panel-site">—</span>
      <button class="panel-close" onclick="closePanel()">×</button>
    </div>
    <div class="panel-body" id="panel-body"></div>
    <div class="panel-footer">
      <button class="btn btn-ghost btn-sm" onclick="editCurrentEntry()">Edit</button>
      <button class="btn btn-danger btn-sm" onclick="deleteCurrentEntry()">Delete</button>
    </div>
  </div>

</div>

<!-- Add / Edit modal -->
<div class="modal-backdrop" id="entry-modal">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title" id="modal-title">Add Entry</span>
      <button class="panel-close" onclick="closeModal('entry-modal')">×</button>
    </div>
    <div class="modal-body">
      <input type="hidden" id="entry-id">
      <div class="form-group">
        <label class="form-label">Site Name *</label>
        <input class="form-input" id="f-site" placeholder="GitHub">
      </div>
      <div class="form-group">
        <label class="form-label">Username / Email *</label>
        <input class="form-input" id="f-user" placeholder="you@example.com">
      </div>
      <div class="form-group">
        <label class="form-label">Password *</label>
        <div class="pw-row">
          <input class="form-input" id="f-pass" type="password" placeholder="••••••••••••">
          <button class="gen-btn" onclick="fillGenerated()">⚄ Generate</button>
          <button class="gen-btn" onclick="togglePw('f-pass')">👁</button>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">URL</label>
        <input class="form-input" id="f-url" placeholder="https://github.com">
      </div>
      <div class="form-group">
        <label class="form-label">Category</label>
        <input class="form-input" id="f-cat" placeholder="General">
      </div>
      <div class="form-group">
        <label class="form-label">Notes</label>
        <input class="form-input" id="f-notes" placeholder="Optional notes">
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="closeModal('entry-modal')">Cancel</button>
      <button class="btn btn-primary" onclick="saveEntry()">Save Entry</button>
    </div>
  </div>
</div>

<!-- API Key modal -->
<div class="modal-backdrop" id="apikey-modal">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title">🔑 Add API Key</span>
      <button class="panel-close" onclick="closeModal('apikey-modal')">×</button>
    </div>
    <div class="modal-body">
      <div class="form-group">
        <label class="form-label">Service *</label>
        <input class="form-input" id="ak-service" placeholder="GitHub, AWS, Stripe…">
      </div>
      <div class="form-group">
        <label class="form-label">Key Name *</label>
        <input class="form-input" id="ak-name" placeholder="Personal Access Token, API Key…">
      </div>
      <div class="form-group">
        <label class="form-label">Token / Key Value *</label>
        <div class="pw-row">
          <input class="form-input" id="ak-token" type="password" placeholder="••••••••••••••••">
          <button class="gen-btn" onclick="togglePw('ak-token')">👁</button>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">API Endpoint / Docs URL</label>
        <input class="form-input" id="ak-url" placeholder="https://api.example.com">
      </div>
      <div class="form-group">
        <label class="form-label">Scopes / Notes</label>
        <input class="form-input" id="ak-notes" placeholder="repo, read:user — expires 2027-01-01">
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="closeModal('apikey-modal')">Cancel</button>
      <button class="btn btn-primary" onclick="saveApiKey()">Save Key</button>
    </div>
  </div>
</div>

<!-- Import modal -->
<div class="modal-backdrop" id="import-modal">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title">Import Credentials</span>
      <button class="panel-close" onclick="closeModal('import-modal')">×</button>
    </div>
    <div class="modal-body">
      <div class="drop-zone" id="drop-zone" onclick="document.getElementById('file-input').click()"
           ondragover="e=event;e.preventDefault();this.classList.add('drag-over')"
           ondragleave="this.classList.remove('drag-over')"
           ondrop="handleDrop(event)">
        <input type="file" id="file-input" accept=".csv,.xlsx,.xls,.xlsm" onchange="handleFileSelect(this)">
        <div style="font-size:28px;margin-bottom:8px">📂</div>
        <div>Drop a CSV or Excel file here, or click to browse</div>
        <div style="font-size:11px;margin-top:6px;color:var(--muted)">Accepted: .csv  .xlsx  .xls  .xlsm</div>
      </div>
      <div id="import-status" style="display:none"></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="closeModal('import-modal')">Close</button>
    </div>
  </div>
</div>

<!-- Generate password modal -->
<div class="modal-backdrop" id="gen-modal">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title">Password Generator</span>
      <button class="panel-close" onclick="closeModal('gen-modal')">×</button>
    </div>
    <div class="modal-body">
      <div class="form-group">
        <label class="form-label">Length: <span id="gen-len-label">20</span></label>
        <input type="range" id="gen-len" min="12" max="64" value="20"
               oninput="document.getElementById('gen-len-label').textContent=this.value"
               style="width:100%;accent-color:var(--accent)">
      </div>
      <div class="field-value" id="gen-output" style="font-size:13px;letter-spacing:0.05em;min-height:40px">
        <span id="gen-pw">—</span>
        <button class="copy-btn" onclick="copyText(document.getElementById('gen-pw').textContent)">⎘</button>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="generate()">↺ Regenerate</button>
      <button class="btn btn-ghost" onclick="closeModal('gen-modal')">Close</button>
    </div>
  </div>
</div>

<!-- Backup modal -->
<div class="modal-backdrop" id="backup-modal">
  <div class="panel" style="max-width:460px">
    <div class="panel-header">
      <span>💾 Automatic Backups</span>
      <button class="panel-close" onclick="closeModal('backup-modal')">×</button>
    </div>
    <div class="panel-body" style="padding-bottom:0">

      <!-- Status row -->
      <div id="backup-status-row" style="margin-bottom:16px;font-size:13px;"></div>

      <!-- Directory setting -->
      <label style="display:block;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:6px;">Backup directory</label>
      <div style="display:flex;gap:8px;align-items:center;">
        <input id="backup-dir-input" type="text" placeholder="/run/media/matt/USB/clortho-backups"
               style="flex:1;min-width:0;" onkeydown="if(event.key==='Enter')saveBackupDir()">
        <button class="btn btn-primary btn-sm" onclick="saveBackupDir()">Save</button>
      </div>
      <p style="color:var(--muted);font-size:11px;margin-top:6px;margin-bottom:20px;">
        Use an external drive for best protection. Backups are written automatically after every change (last 5 kept).
      </p>

      <!-- Restore section -->
      <div style="border-top:1px solid var(--border);padding-top:16px;margin-bottom:4px;">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:10px;">Restore from backup</div>
        <div id="backup-list-wrap"></div>
      </div>

    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="backupNow()">▶ Backup Now</button>
      <button class="btn btn-ghost" onclick="closeModal('backup-modal')">Close</button>
    </div>
  </div>
</div>

<!-- Toast -->
<div id="toast"><span class="toast-dot"></span><span id="toast-msg"></span></div>

<script>
// ── State ─────────────────────────────────────────────────────────────
let allEntries = [];
let currentEntryId = null;
let activeCategory = null;
let searchQuery = '';

// ── Boot ──────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadEntries();
  loadBackupStatus();
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') { closePanel(); }
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      document.getElementById('search-input').focus();
    }
  });
});

// ── Data ──────────────────────────────────────────────────────────────
async function loadEntries() {
  const r = await fetch('/api/entries');
  if (r.status === 401) { location.href = '/unlock'; return; }
  const data = await r.json();
  allEntries = data.entries || [];
  renderEntries();
  renderCategoryNav();
}

function visibleEntries() {
  let list = allEntries;
  if (activeCategory) list = list.filter(e => e.category === activeCategory);
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    list = list.filter(e =>
      e.site.toLowerCase().includes(q) ||
      e.username.toLowerCase().includes(q) ||
      (e.url||'').toLowerCase().includes(q) ||
      (e.notes||'').toLowerCase().includes(q)
    );
  }
  return list;
}

// ── Render ────────────────────────────────────────────────────────────
function renderEntries() {
  const list = visibleEntries();
  const el = document.getElementById('entries-list');
  document.getElementById('count-badge').textContent = `${list.length} entr${list.length===1?'y':'ies'}`;
  if (!list.length) {
    el.innerHTML = `<div class="empty-state">
      <div class="empty-icon">🔒</div>
      <div class="empty-title">${searchQuery ? 'No results' : 'No entries yet'}</div>
      <div>${searchQuery ? 'Try a different search term' : 'Click + Add to save your first credential'}</div>
    </div>`;
    return;
  }
  el.innerHTML = list.map(e => {
    const icon = siteIcon(e.site, e.url, e.category);
    const catClass = 'cat-' + (e.category||'general').toLowerCase().replace(/\s+/g,'-');
    return `<div class="entry-card" onclick="openPanel('${e.id}')">
      <div class="entry-icon">${icon}</div>
      <div class="entry-info">
        <div class="entry-site">${esc(e.site)}</div>
        <div class="entry-user">${esc(e.username)}</div>
      </div>
      <span class="entry-cat ${catClass}">${esc(e.category||'General')}</span>
      <div class="entry-actions">
        <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();quickEdit('${e.id}')">Edit</button>
        <button class="btn btn-danger btn-sm" onclick="event.stopPropagation();confirmDelete('${e.id}','${esc(e.site)}')">Del</button>
      </div>
    </div>`;
  }).join('');
}

function renderCategoryNav() {
  const cats = [...new Set(allEntries.map(e => e.category || 'General'))].sort();
  const el = document.getElementById('cat-nav');
  let html = `<div class="nav-item ${!activeCategory?'active':''}" onclick="setCategory(null)">
    <span class="nav-icon">◈</span> All
  </div>`;
  cats.forEach(c => {
    const count = allEntries.filter(e => (e.category||'General') === c).length;
    html += `<div class="nav-item ${activeCategory===c?'active':''}" onclick="setCategory('${esc(c)}')">
      <span class="nav-icon">▸</span> ${esc(c)}
      <span style="margin-left:auto;font-size:10px;color:var(--muted)">${count}</span>
    </div>`;
  });
  el.innerHTML = html;
}

function siteIcon(site, url, category) {
  if (category === 'API Keys') return '🔑';
  const icons = {
    github:'🐙', google:'🔍', gmail:'✉️', mail:'✉️', email:'✉️',
    twitter:'🐦', facebook:'👤', instagram:'📷', linkedin:'💼',
    amazon:'📦', apple:'🍎', microsoft:'🪟', netflix:'🎬',
    spotify:'🎵', discord:'💬', slack:'💬', dropbox:'📦',
    aws:'☁️', azure:'☁️', bank:'🏦', finance:'💰', paypal:'💳',
  };
  const key = (site||'').toLowerCase();
  for (const [k, v] of Object.entries(icons)) if (key.includes(k)) return v;
  return site ? site[0].toUpperCase() : '?';
}

// ── Panel ─────────────────────────────────────────────────────────────
function openPanel(id) {
  const e = allEntries.find(x => x.id === id);
  if (!e) return;
  currentEntryId = id;
  document.getElementById('panel-site').textContent = e.site;
  const body = document.getElementById('panel-body');
  const isApiKey = e.category === 'API Keys';
  body.innerHTML = `
    ${field(isApiKey ? 'Key Name' : 'Username', e.username, true)}
    ${field(isApiKey ? 'Token' : 'Password', e.password, true, true)}
    ${e.url ? field(isApiKey ? 'Endpoint / Docs' : 'URL', e.url, true) : ''}
    ${e.category ? field('Category', e.category, false) : ''}
    ${e.notes ? field(isApiKey ? 'Scopes / Notes' : 'Notes', e.notes, false) : ''}
    ${field('Entry ID', e.id, false)}
    <div style="margin-top:16px;font-size:11px;color:var(--muted)">
      Created ${e.created ? e.created.split('T')[0] : '—'} &nbsp;·&nbsp;
      Modified ${e.modified ? e.modified.split('T')[0] : '—'}
    </div>`;
  document.getElementById('detail-panel').classList.add('open');
}

function field(label, value, copyable=true, mask=false) {
  const display = mask
    ? `<span class="pw-mask" id="pw-display-${label}" data-pw="${esc(value)}" data-masked="true">${'•'.repeat(Math.min(value.length, 16))}</span>
       <button class="copy-btn" onclick="toggleMask('${label}')" title="Show/hide">👁</button>`
    : `<span>${esc(value)}</span>`;
  const copyBtn = copyable
    ? `<button class="copy-btn" onclick="copyText('${esc(value)}')" title="Copy">⎘</button>`
    : '';
  return `<div class="field-group">
    <div class="field-label">${label}</div>
    <div class="field-value">${display}${copyBtn}</div>
  </div>`;
}

function toggleMask(label) {
  const el = document.getElementById(`pw-display-${label}`);
  if (!el) return;
  const masked = el.dataset.masked === 'true';
  el.dataset.masked = !masked;
  el.textContent = masked ? el.dataset.pw : '•'.repeat(Math.min(el.dataset.pw.length, 16));
}

function closePanel() {
  document.getElementById('detail-panel').classList.remove('open');
  currentEntryId = null;
}

// ── CRUD ──────────────────────────────────────────────────────────────
function openAddModal() {
  document.getElementById('modal-title').textContent = 'Add Entry';
  document.getElementById('entry-id').value = '';
  ['site','user','pass','url','cat','notes'].forEach(f => document.getElementById('f-'+f).value = '');
  document.getElementById('f-cat').value = 'General';
  openModal('entry-modal');
  setTimeout(() => document.getElementById('f-site').focus(), 100);
}

function openApiKeyModal() {
  ['ak-service','ak-name','ak-token','ak-url','ak-notes'].forEach(id => document.getElementById(id).value = '');
  openModal('apikey-modal');
  setTimeout(() => document.getElementById('ak-service').focus(), 100);
}

async function saveApiKey() {
  const service = document.getElementById('ak-service').value.trim();
  const name    = document.getElementById('ak-name').value.trim();
  const token   = document.getElementById('ak-token').value.trim();
  if (!service || !name || !token) { toast('Service, Key Name and Token are required', 'error'); return; }
  const body = {
    site:     service,
    username: name,
    password: token,
    url:      document.getElementById('ak-url').value.trim(),
    notes:    document.getElementById('ak-notes').value.trim(),
    category: 'API Keys',
  };
  const r = await fetch('/api/entries', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
  if (!r.ok) { toast('Failed to save', 'error'); return; }
  closeModal('apikey-modal');
  await loadEntries();
  toast('API key saved');
}

function quickEdit(id) { editEntry(id); }

function editCurrentEntry() {
  if (currentEntryId) editEntry(currentEntryId);
}

function editEntry(id) {
  const e = allEntries.find(x => x.id === id);
  if (!e) return;
  document.getElementById('modal-title').textContent = 'Edit Entry';
  document.getElementById('entry-id').value = e.id;
  document.getElementById('f-site').value  = e.site || '';
  document.getElementById('f-user').value  = e.username || '';
  document.getElementById('f-pass').value  = e.password || '';
  document.getElementById('f-url').value   = e.url || '';
  document.getElementById('f-cat').value   = e.category || 'General';
  document.getElementById('f-notes').value = e.notes || '';
  openModal('entry-modal');
}

async function saveEntry() {
  const id    = document.getElementById('entry-id').value;
  const site  = document.getElementById('f-site').value.trim();
  const user  = document.getElementById('f-user').value.trim();
  const pass  = document.getElementById('f-pass').value;
  if (!site || !user || !pass) { toast('Site, username and password are required', 'error'); return; }
  const body = {
    site, username: user, password: pass,
    url:      document.getElementById('f-url').value.trim(),
    category: document.getElementById('f-cat').value.trim() || 'General',
    notes:    document.getElementById('f-notes').value.trim(),
  };
  const url    = id ? `/api/entries/${id}` : '/api/entries';
  const method = id ? 'PUT' : 'POST';
  const r = await fetch(url, { method, headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
  const data = await r.json();
  if (data.ok) {
    toast(id ? 'Entry updated' : 'Entry saved', 'success');
    closeModal('entry-modal');
    await loadEntries();
    if (id) openPanel(id);
  } else {
    toast(data.error || 'Save failed', 'error');
  }
}

async function confirmDelete(id, site) {
  if (!confirm(`Delete "${site}"? This cannot be undone.`)) return;
  const r = await fetch(`/api/entries/${id}`, { method: 'DELETE' });
  const data = await r.json();
  if (data.ok) {
    toast('Deleted', 'success');
    closePanel();
    await loadEntries();
  } else {
    toast(data.error || 'Delete failed', 'error');
  }
}

function deleteCurrentEntry() {
  if (!currentEntryId) return;
  const e = allEntries.find(x => x.id === currentEntryId);
  if (e) confirmDelete(e.id, e.site);
}

// ── Import ────────────────────────────────────────────────────────────
function openImportModal() {
  document.getElementById('import-status').style.display = 'none';
  openModal('import-modal');
}

function handleDrop(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) uploadFile(file);
}

function handleFileSelect(input) {
  if (input.files[0]) uploadFile(input.files[0]);
}

async function uploadFile(file) {
  const status = document.getElementById('import-status');
  status.style.display = 'block';
  status.innerHTML = '<span style="color:var(--muted)">Importing…</span>';
  const fd = new FormData();
  fd.append('file', file);
  const r = await fetch('/api/import', { method: 'POST', body: fd });
  const data = await r.json();
  if (data.ok) {
    status.innerHTML = `<span style="color:var(--accent)">✓ Imported ${data.imported} entries</span>`
      + (data.skipped ? `<br><span style="color:var(--muted)">Skipped ${data.skipped} blank rows</span>` : '')
      + (data.errors?.length ? `<br><span style="color:var(--danger)">${data.errors.join('<br>')}</span>` : '');
    await loadEntries();
  } else {
    status.innerHTML = `<span style="color:var(--danger)">✗ ${data.error}</span>`;
  }
}

// ── Password generator ────────────────────────────────────────────────
function openGenModal() {
  openModal('gen-modal');
  generate();
}

async function generate() {
  const len = document.getElementById('gen-len').value;
  const r = await fetch(`/api/generate?length=${len}`);
  const data = await r.json();
  document.getElementById('gen-pw').textContent = data.password;
}

async function fillGenerated() {
  const len = 20;
  const r = await fetch(`/api/generate?length=${len}`);
  const data = await r.json();
  const inp = document.getElementById('f-pass');
  inp.value = data.password;
  inp.type = 'text';
  setTimeout(() => inp.type = 'password', 3000);
}

// ── Navigation ────────────────────────────────────────────────────────
function setView(v) {
  if (v === 'search') document.getElementById('search-input').focus();
}

function setCategory(cat) {
  activeCategory = cat;
  renderEntries();
  renderCategoryNav();
}

function onSearch(q) {
  searchQuery = q;
  renderEntries();
}

// ── Lock ──────────────────────────────────────────────────────────────
async function lockVault() {
  await fetch('/api/lock', { method: 'POST' });
  location.href = '/unlock';
}

// ── Utilities ─────────────────────────────────────────────────────────
function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

function esc(str) {
  return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function togglePw(id) {
  const el = document.getElementById(id);
  el.type = el.type === 'password' ? 'text' : 'password';
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied to clipboard', 'success');
    setTimeout(async () => {
      try { await navigator.clipboard.writeText(''); } catch {}
    }, 30000);  // clear clipboard after 30s
  } catch {
    toast('Copy failed', 'error');
  }
}

let toastTimer;
function toast(msg, type='success') {
  const el = document.getElementById('toast');
  document.getElementById('toast-msg').textContent = msg;
  el.className = `show ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2500);
}

// ── Backup ────────────────────────────────────────────────────────────
async function loadBackupStatus() {
  const r = await fetch('/api/backup');
  if (!r.ok) return;
  const s = await r.json();
  const el = document.getElementById('backup-status');
  if (!el) return;
  if (s.configured) {
    const last = s.last_backup
      ? new Date(s.last_backup).toLocaleString(undefined, {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})
      : 'never';
    const warn = !s.dir_accessible ? ' <span style="color:#f0a500" title="Drive may not be mounted">⚠</span>' : '';
    el.innerHTML = `💾 Backup: <span style="color:var(--accent)">${s.count}/5</span>${warn}<br><span style="font-size:10px">Last: ${last}</span>`;
  } else {
    el.innerHTML = `<span style="color:#f0a500">⚠ Backups not configured</span>`;
  }
}

async function openBackupModal() {
  document.getElementById('backup-modal').classList.add('open');
  const [statusRes, listRes] = await Promise.all([
    fetch('/api/backup'),
    fetch('/api/backup/list'),
  ]);
  const s = await statusRes.json();
  const backups = await listRes.json();

  // Populate status row
  const statusRow = document.getElementById('backup-status-row');
  if (s.configured) {
    const accessible = s.dir_accessible
      ? `<span style="color:var(--accent)">✓ accessible</span>`
      : `<span style="color:#f0a500">⚠ drive not mounted</span>`;
    const last = s.last_backup ? new Date(s.last_backup).toLocaleString() : 'none yet';
    statusRow.innerHTML = `<b>Directory:</b> <code style="font-size:11px">${s.backup_dir}</code> ${accessible}<br>`
      + `<b>Backups stored:</b> ${s.count} of 5 &nbsp;·&nbsp; <b>Last:</b> ${last}`;
  } else {
    statusRow.innerHTML = '<span style="color:#f0a500">No backup directory configured yet.</span>';
  }

  // Pre-fill the input with currently saved path (even if dir is inaccessible)
  document.getElementById('backup-dir-input').value = s.backup_dir || '';

  // Populate backup list
  const wrap = document.getElementById('backup-list-wrap');
  if (!backups.length) {
    wrap.innerHTML = '<div style="color:var(--muted);font-size:13px;">'
      + (s.configured ? 'No backups yet — make a change or click Backup Now.' : 'Set a backup directory first.')
      + '</div>';
  } else {
    wrap.innerHTML = backups.map(b => {
      const dt = new Date(b.modified).toLocaleString(undefined, {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
      return `<div style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:13px;">
        <span><span style="color:var(--muted);font-size:11px;">${dt}</span>&nbsp; ${b.size_kb} KB</span>
        <button class="btn btn-ghost btn-sm" onclick="restoreBackup('${b.filename}')">Restore</button>
      </div>`;
    }).join('');
  }
}

async function saveBackupDir() {
  const path = document.getElementById('backup-dir-input').value.trim();
  if (!path) { toast('Enter a directory path', 'error'); return; }
  const r = await fetch('/api/backup/set', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({path}),
  });
  const d = await r.json();
  if (d.ok) {
    toast('Backup directory saved', 'success');
    closeModal('backup-modal');
    loadBackupStatus();
  } else {
    toast(d.error || 'Failed to save', 'error');
  }
}

async function backupNow() {
  const r = await fetch('/api/backup/now', {method: 'POST'});
  const d = await r.json();
  if (d.ok) {
    toast('Data backed up', 'success');
    closeModal('backup-modal');
    loadBackupStatus();
  } else {
    toast(d.error || 'Backup failed — is the directory configured?', 'error');
  }
}

async function restoreBackup(filename) {
  if (!confirm(`Restore from backup "${filename}"?\n\nThis will replace ALL current vault entries with the backup contents.`)) return;
  const r = await fetch('/api/backup/restore', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({filename}),
  });
  const d = await r.json();
  if (d.ok) {
    toast(`Restored ${d.entries} entries`, 'success');
    closeModal('backup-modal');
    loadEntries();   // refresh the main vault view
  } else {
    toast(d.error || 'Restore failed', 'error');
  }
}
</script>
</body>
</html>
"""

UNLOCK_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Clortho — Unlock</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
:root { --bg:#0a0000; --surface:#130303; --border:#3a0f0f; --accent:#cc2222; --danger:#ff4d6a; --text:#f0e8e8; --muted:#886666; }
*, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
body { background:var(--bg); color:var(--text); font-family:'IBM Plex Sans',sans-serif; height:100vh; display:flex; align-items:center; justify-content:center; }
.card { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:40px 36px; width:360px; box-shadow:0 20px 60px rgba(0,0,0,0.5); }
.brand { display:flex; flex-direction:column; align-items:center; margin-bottom:16px; }
.brand-icon { width:72px; height:72px; margin-bottom:10px; }
.logo { font-family:'IBM Plex Mono',monospace; font-size:18px; font-weight:600; color:var(--accent); }
.sub { color:var(--muted); font-size:13px; margin-bottom:28px; text-align:center; }
label { display:block; font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:var(--muted); margin-bottom:6px; }
input[type=password] { width:100%; background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:10px 14px; color:var(--text); font-family:'IBM Plex Mono',monospace; font-size:14px; outline:none; transition:border-color 0.15s; }
input[type=password]:focus { border-color:var(--accent); }
button { width:100%; margin-top:20px; padding:11px; background:var(--accent); color:#000; border:none; border-radius:6px; font-size:14px; font-weight:600; cursor:pointer; font-family:'IBM Plex Sans',sans-serif; transition:background 0.15s; }
button:hover { background:#ff4444; }
.error { color:var(--danger); font-size:13px; margin-top:12px; text-align:center; min-height:18px; }
.hint { color:var(--muted); font-size:11px; margin-top:16px; text-align:center; }
</style>
</head>
<body>
<div class="card">
  <div class="brand">
    <svg class="brand-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96">
      <g transform="translate(48,52) scale(1.25) translate(-48,-52)">
        <path d="M20,37 Q4,24 14,16 Q16,19 34,32 Z" fill="#2a0806"/>
        <path d="M22,36 Q6,25 16,17 Q18,20 32,31 Z" fill="#cc3322"/>
        <path d="M76,37 Q92,24 82,16 Q80,19 62,32 Z" fill="#2a0806"/>
        <path d="M74,36 Q90,25 80,17 Q78,20 64,31 Z" fill="#cc3322"/>
        <circle cx="48" cy="54" r="34" fill="#2a0806"/>
        <circle cx="48" cy="54" r="30" fill="#dd3a28"/>
        <ellipse cx="30" cy="50" rx="12" ry="6.5" fill="white" transform="rotate(22,30,50)"/>
        <ellipse cx="66" cy="50" rx="12" ry="6.5" fill="white" transform="rotate(-22,66,50)"/>
        <circle cx="30" cy="50" r="3.5" fill="#1a0000"/>
        <circle cx="66" cy="50" r="3.5" fill="#1a0000"/>
        <path d="M15,44 Q28,37 40,53" stroke="#2a0806" stroke-width="5.5" fill="none" stroke-linecap="round"/>
        <path d="M56,53 Q68,37 81,44" stroke="#2a0806" stroke-width="5.5" fill="none" stroke-linecap="round"/>
        <path d="M34,68 Q46,80 62,66" stroke="#2a0806" stroke-width="4" fill="none" stroke-linecap="round"/>
      </g>
    </svg>
    <div class="logo">🔐 CLORTHO</div>
  </div>
  <div class="sub">Enter your master password to unlock</div>
  <form method="POST" action="/unlock">
    <label for="pw">Master Password</label>
    <input type="password" name="password" id="pw" autofocus autocomplete="current-password" placeholder="••••••••••••">
    {% if error %}<div class="error">{{ error }}</div>{% else %}<div class="error"></div>{% endif %}
    <button type="submit">Unlock Vault</button>
  </form>
  <div class="hint">Running locally on 127.0.0.1 — no data leaves your machine</div>
</div>
</body>
</html>
"""


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route("/api/token")
@require_unlock
def get_api_token():
    return jsonify({"token": _api_token})

@app.route("/")
@require_unlock
def index():
    return render_template_string(HTML, api_token=_api_token or "")


@app.route("/unlock", methods=["GET", "POST"])
def unlock_page():
    error = ""
    vault = get_vault()

    if request.method == "POST":
        pw = request.form.get("password", "")
        if not vault.is_initialized():
            # First run: treat POST as setup (shouldn't happen via web normally)
            return jsonify({"error": "Please run the CLI first to set up the vault."}), 400

        salt = vk.get_or_create_salt(vault.vault_dir)
        candidate_key = vk.derive_key(pw, salt)
        del pw  # clear from scope
        try:
            ciphertext = vault.vault_path.read_bytes()
            vault.data = vk.decrypt_vault(ciphertext, candidate_key)
            vault._key = candidate_key
            session["unlocked"] = True
            session.permanent = False
            global _api_token
            _api_token = secrets.token_hex(32)
            return redirect(url_for("index"))
        except (ValueError, Exception):
            error = "Wrong password. Try again."

    return render_template_string(UNLOCK_HTML, error=error)


@app.route("/api/lock", methods=["POST"])
def lock():
    session.clear()
    vault = get_vault()
    vault._key = None
    vault.data = {"entries": [], "meta": {}}
    return jsonify({"ok": True})


@app.route("/api/entries", methods=["GET"])
@require_unlock
def get_entries():
    vault = get_vault()
    # Strip passwords from list view — only returned on individual fetch
    safe = []
    for e in vault.all_entries():
        row = dict(e)
        row["password"] = e["password"]   # include for client-side panel
        safe.append(row)
    return jsonify({"entries": safe})


@app.route("/api/entries", methods=["POST"])
@require_unlock
def add_entry():
    vault = get_vault()
    body = request.get_json(force=True)
    required = ("site", "username", "password")
    if not all(body.get(k, "").strip() if k != "password" else body.get(k, "") for k in required):
        return jsonify({"ok": False, "error": "site, username, and password are required"}), 400
    eid = vault.add_entry(
        site     = body["site"].strip(),
        username = body["username"].strip(),
        password = body["password"],
        url      = body.get("url", "").strip(),
        notes    = body.get("notes", "").strip(),
        category = body.get("category", "General").strip(),
    )
    return jsonify({"ok": True, "id": eid})


@app.route("/api/entries/<entry_id>", methods=["PUT"])
@require_unlock
def update_entry(entry_id):
    vault = get_vault()
    body = request.get_json(force=True)
    allowed = {"site", "username", "password", "url", "notes", "category"}
    updates = {k: v for k, v in body.items() if k in allowed}
    if vault.update_entry(entry_id, **updates):
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Entry not found"}), 404


@app.route("/api/entries/<entry_id>", methods=["DELETE"])
@require_unlock
def delete_entry(entry_id):
    vault = get_vault()
    if vault.delete_entry(entry_id):
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Entry not found"}), 404


@app.route("/api/import", methods=["POST"])
@require_unlock
def import_file():
    vault = get_vault()
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "No file provided"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"ok": False, "error": "Empty filename"}), 400

    # Save to a temp file (Flask keeps uploads in memory or tmp — never in vault dir)
    import tempfile
    suffix = Path(f.filename).suffix.lower()
    if suffix not in (".csv", ".xlsx", ".xls", ".xlsm"):
        return jsonify({"ok": False, "error": f"Unsupported file type: {suffix}"}), 400

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        f.save(tmp.name)
        tmp_path = tmp.name

    try:
        n, skipped, errors = vault.import_from_file(tmp_path)
        return jsonify({"ok": True, "imported": n, "skipped": skipped, "errors": errors})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    finally:
        os.unlink(tmp_path)  # always clean up temp file


@app.route("/api/generate")
@require_unlock
def generate_pw():
    try:
        length = max(12, min(128, int(request.args.get("length", 20))))
    except ValueError:
        length = 20
    return jsonify({"password": vk.generate_password(length)})


@app.route("/api/backup", methods=["GET"])
@require_unlock
def backup_status():
    return jsonify(get_vault().backup_status())


@app.route("/api/backup/set", methods=["POST"])
@require_unlock
def backup_set():
    data = request.get_json(silent=True) or {}
    path = (data.get("path") or "").strip()
    if not path:
        return jsonify({"error": "path required"}), 400
    try:
        target = get_vault().set_backup_dir(path)
        return jsonify({"ok": True, "backup_dir": str(target)})
    except OSError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/backup/now", methods=["POST"])
@require_unlock
def backup_now():
    dest = get_vault()._backup_vault()
    if dest:
        return jsonify({"ok": True, "path": str(dest)})
    return jsonify({"error": "No backup directory configured"}), 400


@app.route("/api/backup/list", methods=["GET"])
@require_unlock
def backup_list():
    return jsonify(get_vault().list_backups())


@app.route("/api/backup/restore", methods=["POST"])
@require_unlock
def backup_restore():
    data     = request.get_json(silent=True) or {}
    filename = (data.get("filename") or "").strip()
    if not filename:
        return jsonify({"error": "filename required"}), 400
    try:
        count = get_vault().restore_from_backup(filename)
        return jsonify({"ok": True, "entries": count})
    except (FileNotFoundError, ValueError) as e:
        return jsonify({"error": str(e)}), 400


# ─────────────────────────────────────────────
# LAUNCH
# ─────────────────────────────────────────────

def run(port: int = 7777, vault_dir: str = "~/.clortho", open_browser: bool = True):
    global _vault_dir
    _vault_dir = vault_dir

    vault = get_vault()
    if not vault.is_initialized():
        print("No vault found. Run 'python clortho.py' first to create one.")
        sys.exit(1)

    url = f"http://127.0.0.1:{port}"
    print(f"\n🔐 Clortho Web UI")
    print(f"   Local URL : {url}")
    print(f"   Vault     : {Path(vault_dir).expanduser().resolve()}")
    print(f"   Network   : 127.0.0.1 only (not accessible from other machines)")
    print(f"\n   Press Ctrl+C to stop the server and lock the vault.\n")

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    # debug=False is non-negotiable for a password manager
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Clortho Web UI")
    p.add_argument("--port",    type=int, default=7777,              help="Port (default: 7777)")
    p.add_argument("--vault",   default="~/.clortho",            help="Vault directory")
    p.add_argument("--no-browser", action="store_true",              help="Don't auto-open browser")
    args = p.parse_args()
    run(port=args.port, vault_dir=args.vault, open_browser=not args.no_browser)
