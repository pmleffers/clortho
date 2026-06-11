# 🔐 Clortho

A fully local, encrypted password manager written in Python. No cloud. No accounts. No tracking.

Three layers work together: a **CLI** for direct vault access, a **local web UI** for a full-featured browser interface, and a **Firefox extension** that autofills your credentials on any website.

---

## Features

- **AES-256 encryption** via PBKDF2-SHA256 key derivation (480,000 iterations)
- **CLI shell** — add, search, edit, delete, import, generate passwords
- **Web UI** — full GUI at `http://127.0.0.1:7777`, never accessible from other machines
- **Firefox extension** — detects login forms and shows a floating autofill prompt
- **Password generator** — in both the web UI and the extension popup
- **Import** from CSV/Excel — compatible with Chrome, Firefox, Bitwarden, LastPass, 1Password exports
- **Socket-level firewall** — blocks all outbound connections except localhost
- **No recovery by design** — if you forget your master password, the vault stays locked

---

## Architecture

```
  Firefox Extension (clortho_extension/)
       │
       │  Bearer token auth  →  fetch() to 127.0.0.1:7777
       ▼
  clortho_web.py   ◄──────────────►   ~/.clortho/vault.vk
  (Flask, localhost)                       (AES-256 encrypted)
       ▲
       │  shared vault file
       │
  clortho.py
  (CLI)
```

The extension never stores credentials. Passwords flow: vault file → server RAM → extension background → content script fill → cleared immediately.

---

## Requirements

```bash
pip install cryptography pandas openpyxl beautifulsoup4 requests rich flask
```

Python 3.10+ required.

---

## Quick Start

### CLI only

```bash
python clortho.py
```

First run creates your vault and prompts for a master password (minimum 12 characters).

```
clortho> add             # Add a credential
clortho> list            # Show all entries
clortho> search github   # Search by site, username, or URL
clortho> generate        # Generate a strong password
clortho> import file.csv # Import from CSV or Excel
clortho> quit            # Lock and exit
```

### Web UI

```bash
python clortho_web.py
# Opens http://127.0.0.1:7777
```

### Bazzite / Flatpak Firefox (recommended launcher)

```bash
chmod +x clortho_start.sh
./clortho_start.sh
```

This starts the server, opens Firefox, and guides you through loading the extension.

---

## Firefox Extension

The extension injects into every page, detects password fields, and shows a floating autofill prompt with matching credentials from your vault.

### Autofill flow

1. Start the server and unlock your vault at `http://127.0.0.1:7777/unlock`
2. The vault page embeds a session token that the extension reads automatically
3. On any login page, focus a password field — the Clortho prompt appears
4. Click an entry to fill username and password

### Extension popup

Click the 🔐 toolbar icon on any page to:
- See matching credentials for the current site
- Fill credentials manually
- Generate a new password (length slider + character set options)
- Open the Clortho web UI

### Installing the extension

Firefox Release requires extensions to be signed. The cleanest approach:

**Temporary (per session)** — no tools required:
1. `about:debugging` → **Load Temporary Add-on** → select `clortho_extension/manifest.json`
2. Must repeat each Firefox restart

**Permanent (signed via AMO)**:
```bash
npm install -g web-ext
web-ext sign --api-key=<jwt_issuer> --api-secret=<jwt_secret> \
             --source-dir=./clortho_extension --channel=unlisted
# Install the returned .xpi once — persists across restarts
```

Get API credentials at `https://addons.mozilla.org/en-US/developers/addon/api/key/`

---

## Security Model

| Layer | Detail |
|---|---|
| **Cipher** | AES-256-GCM (Fernet) |
| **Key derivation** | PBKDF2-SHA256, 480,000 iterations |
| **Salt** | 32 bytes, random, unique per vault |
| **File permissions** | `chmod 600` on vault and salt |
| **Atomic writes** | Temp file + `os.replace()` — no partial-write corruption |
| **Network** | Blocked at socket level; only localhost and explicit `webpage` command |
| **Extension auth** | Bearer token embedded in vault page, never stored to disk |
| **CORS** | Only `moz-extension://` and `localhost` origins allowed |
| **Wrong password** | 3 attempts then process exits |

### What Clortho does NOT protect against

- Compromised OS or root access (no password manager does)
- Malicious browser extensions with `<all_urls>` permission
- Physical keyloggers or screen recording

---

## Importing Passwords

Supported: `.csv`, `.xlsx`, `.xls`, `.xlsm`

Compatible with direct exports from Chrome, Firefox, Edge, Safari, Bitwarden, LastPass, 1Password, Dashlane, and KeePass. The column detector handles most naming variations automatically.

```
clortho> import ~/Downloads/passwords.csv
```

Or drag-and-drop a file onto the web UI import zone.

---

## Vault Location

```
~/.clortho/
  vault.vk      ← encrypted vault (AES-256)
  .vk_salt      ← random salt for key derivation
```

### Backup

```bash
cp -r ~/.clortho ~/backups/clortho_$(date +%Y%m%d)
```

Both files are needed to restore. Keep them together.

---

## ⚠️ Important

- **No password recovery.** A forgotten master password means the vault is permanently locked — by design.
- The `export` command writes plaintext to disk. Treat the output file like a sticky note with all your passwords.
- The `webpage` command fetches public HTML only — it does not interact with browsers or submit forms.
